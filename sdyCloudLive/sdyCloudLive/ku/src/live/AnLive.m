#import <AVFoundation/AVFoundation.h>
#import "RTCPeerConnectionFactory.h"
#import "RTCMediaStream.h"
#import "RTCVideoCapturer.h"
#import "RTCMediaConstraints.h"
#import "RTCVideoTrack.h"
#import "RTCAudioTrack.h"
#import "RTCPair.h"
#import "RTCSessionDescription.h"
#import "AnLive.h"
#import "AnLiveLocalVideoView.h"
#import "AnLivePeerConnectionManager.h"
#import "AnLiveOpenGLVideoRenderer.h"
#import "ArrownockExceptionUtils.h"

@interface AnLive () <AnLiveSignalEventDelegate>
@property id <AnLiveSignalController> controller;
@property id <AnLiveEventDelegate> delegate;
@property NSMutableDictionary* pcms;
@property BOOL localCameraType;
@end

static AnLive *sharedInstance = nil;

@implementation AnLive {
    id <AnLiveSignalController> _controller;
    id <AnLiveEventDelegate> _delegate;
    BOOL _inSession;
    void (^_successCallback)(NSString* sessionId);
    void (^_failureCallback)(ArrownockException* error);
    NSDictionary *_notification;
    NSString *_currentSessionId;
    NSString *_currentMediaType;
    NSString *_remotePartyId;
    BOOL _localCameraType; // YES - front, NO - back
    
    RTCPeerConnectionFactory *_factory;
    RTCMediaStream *_localStream;
    AnLiveLocalVideoView *_localVideoView;
    RTCVideoTrack* _localVideoTrack;
    RTCAudioTrack* _localAudioTrack;
    NSMutableDictionary *_pcms;
}

@synthesize controller = _controller;
@synthesize delegate = _delegate;
@synthesize pcms = _pcms;
@synthesize localCameraType = _localCameraType;

#pragma mark - class methods
+ (void) setup:(id <AnLiveSignalController>)controller delegate:(id <AnLiveEventDelegate>)delegate
{
    if(!controller)
    {
        @throw [ArrownockExceptionUtils generateWithErrorCode:LIVE_INVALID_IM_INSTANCE message:@"anIM instance cannot be null"];
    }
    if(!delegate)
    {
        @throw [ArrownockExceptionUtils generateWithErrorCode:LIVE_INVALID_LISTENER message:@"AnLiveEventDelegate cannot be null"];
    }
    
    [RTCPeerConnectionFactory initializeSSL];
    @synchronized(self)
    {
        if(sharedInstance == nil)
        {
            sharedInstance = [[AnLive alloc] init];
        }
        sharedInstance.controller = controller;
        [sharedInstance.controller setSignalEventDelegate:sharedInstance];
        sharedInstance.delegate = delegate;
        sharedInstance.pcms = [[NSMutableDictionary alloc] init];
        sharedInstance.localCameraType = YES;
    }
}

+ (AnLive *)shared
{
    return sharedInstance;
}

- (void) videoCall:(NSString *)partyId
             video:(BOOL)onOrOff
  notificationData:(NSDictionary *)data
      success:(void (^)(NSString* sessionId))success
      failure:(void (^)(ArrownockException* error))failure
{
    [self call:partyId audioOnly:NO initVideo:onOrOff notificationData:data success:success failure:failure];
}

- (void) voiceCall:(NSString *)partyId
  notificationData:(NSDictionary *)data
           success:(void (^)(NSString* sessionId))success
           failure:(void (^)(ArrownockException* error))failure
{
    [self call:partyId audioOnly:YES initVideo:NO notificationData:data success:success failure:failure];
}

- (void) call:(NSString *)partyId
    audioOnly:(BOOL)audioOnly
    initVideo:(BOOL)onOrOff
notificationData:(NSDictionary *)data
      success:(void (^)(NSString* sessionId))success
      failure:(void (^)(ArrownockException* error))failure
{
    if(_inSession)
    {
        failure([ArrownockExceptionUtils generateWithErrorCode:LIVE_ALREADY_IN_CALL message:@"Current device is already in a call session"]);
    }
    else
    {
        if(!partyId || partyId.length != 23)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:LIVE_INVALID_CLIENT_ID message:@"Invalid partyId"]);
            return;
        }
        [self resetResource];
        _notification = data;
        _inSession = true;
        [self prepareLocalMedia:audioOnly initVideo:onOrOff];
        _successCallback = success;
        _failureCallback = failure;
    }
    
    NSSet *parties = [[NSSet alloc] initWithObjects:partyId, [_controller getPartyId], nil];
    [_controller createSession:parties type:(audioOnly?@"voice":@"video")];
}

- (void) answer:(BOOL)videoOn;
{
    [self resetResource];
    if(_inSession && _currentSessionId && _remotePartyId)
    {
        if([@"voice" isEqualToString:_currentMediaType])
        {
            [self prepareLocalMedia:YES initVideo:NO];
        }
        else
        {
            [self prepareLocalMedia:NO initVideo:videoOn];
        }
        // create the peer connection for this party
        AnLivePeerConnectionManager *pcm = [[AnLivePeerConnectionManager alloc] initWithController:_controller delegate:_delegate partyId:_remotePartyId];
        [pcm createPeerConnection:_factory localMediaStream:_localStream];
        [pcm setLocalCameraOrientation:0];

        // sending offer to whoever already in the conference
        [pcm createOffer];
        [_pcms setObject:pcm forKey:_remotePartyId];
    }
}

- (void) hangup
{
    if(_inSession)
    {
        if(_remotePartyId)
        {
            NSSet *partyIds = [NSSet setWithObjects:_remotePartyId, nil];
            [_controller sendHangup:partyIds];
        }
        if(_currentSessionId)
        {
            [self terminateSession:_currentSessionId];
        }
    }
    [self reset];
}

- (BOOL) isOnCall
{
    return _inSession;
}

- (NSString *)getCurrentSessionType
{
    return _currentMediaType;
}

- (void) terminateSession:(NSString*)sessionId
{
    [_controller terminateSession:sessionId];
}

- (void) reset
{
    _inSession = NO;
    _currentSessionId = nil;
    _currentMediaType = nil;
    _remotePartyId = nil;
    _notification = nil;
    
    [self resetResource];
}

- (void) resetResource
{
    if(_pcms)
    {
        // free resources
        for(AnLivePeerConnectionManager *partyId in _pcms)
        {
            if(_pcms[partyId])
            {
                [_pcms[partyId] dispose];
            }
        }
        [_pcms removeAllObjects];
    }
    else
    {
        _pcms = [[NSMutableDictionary alloc] init];
    }
    
    // clear local video
    if (_localVideoTrack)
    {
        [_localVideoTrack removeRenderer:_localVideoView];
        if(_localStream)
        {
            [_localStream removeVideoTrack:_localVideoTrack];
        }
        _localVideoTrack = nil;
        //[_localVideoView renderFrame:nil];
        [_localVideoView clearView];
        _localVideoView = nil;
    }
    
    // clear local audio
    if(_localStream)
    {
        if(_localAudioTrack)
        {
            [_localStream removeAudioTrack:_localAudioTrack];
            _localAudioTrack= nil;
        }
    }
    _localStream = nil;
    
    if(_factory)
    {
        _factory = nil;
    }
}

- (void) setAudioState:(AnLiveAudioState)state
{
    [self setAudioEnabled:(state == AnLiveAudioOn)];
}

- (void) setVideoState:(AnLiveVideoState)state
{
    [self setVideoEnabled:(state == AnLiveVideoOn)];
}

#pragma mark - private methods

- (void)prepareLocalMedia:(BOOL)audioOnly initVideo:(BOOL)onOrOff
{
    _factory = [[RTCPeerConnectionFactory alloc] init];
    _localStream = [_factory mediaStreamWithLabel:@"ARDAMS"];
    
#if !TARGET_IPHONE_SIMULATOR && TARGET_OS_IPHONE
    if(!audioOnly)
    {
        NSString *cameraID = [self getCameraId:_localCameraType];
        NSAssert(cameraID, @"Unable to get the front camera id");
        RTCVideoCapturer *capturer = [RTCVideoCapturer capturerWithDeviceName:cameraID];
        
        /*
        NSArray *mandatoryConstraints = @[
                                          [[RTCPair alloc] initWithKey:@"maxWidth" value:@"1280"],
                                          [[RTCPair alloc] initWithKey:@"minWidth" value:@"640"],
                                          [[RTCPair alloc] initWithKey:@"maxHeight" value:@"720"],
                                          [[RTCPair alloc] initWithKey:@"minHeight" value:@"480"]
                                          ];
        */
        RTCMediaConstraints* mediaConstraints = [[RTCMediaConstraints alloc] initWithMandatoryConstraints:nil optionalConstraints:nil];
        RTCVideoSource *videoSource = [_factory videoSourceWithCapturer:capturer constraints:mediaConstraints];
        _localVideoTrack = [_factory videoTrackWithID:[NSString stringWithFormat:@"ARDAMSv0%d", _localCameraType] source:videoSource];
        if (_localVideoTrack)
        {
            [_localStream addVideoTrack:_localVideoTrack];
            CGRect initRect = CGRectMake(0, 0, 10, 10);
            _localVideoView = [[AnLiveLocalVideoView alloc] initWithFrame:initRect];
            _localVideoView.delegate = self;
            [_localVideoTrack addRenderer:_localVideoView];
            [_localVideoTrack setEnabled:onOrOff];
        }
    }
#endif
    
    _localAudioTrack = [_factory audioTrackWithID:@"ARDAMSa0"];
    [_localStream addAudioTrack:_localAudioTrack];
}

- (NSString *) getCameraId:(BOOL)isFront
{
    AVCaptureDevicePosition desiredPosition = AVCaptureDevicePositionFront;
    if(!isFront)
    {
        desiredPosition = AVCaptureDevicePositionBack;
    }
    NSString *cameraID = nil;
    for (AVCaptureDevice *captureDevice in [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo])
    {
        if (captureDevice.position == desiredPosition)
        {
            cameraID = [captureDevice localizedName];
            break;
        }
    }
    return cameraID;
}

- (AnLivePeerConnectionManager*) getPeerConnectionManager:(NSString*)partyId
{
    AnLivePeerConnectionManager* pcm = [self.pcms objectForKey:partyId];
    if(!pcm) {
        pcm = [[AnLivePeerConnectionManager alloc] initWithController:_controller delegate:_delegate partyId:partyId];
        
        // create the peer connection for this party
        [pcm createPeerConnection:_factory localMediaStream:_localStream];
        [_pcms setObject:pcm forKey:partyId];
    }
    [pcm setLocalCameraOrientation:0];
    return pcm;
}

#pragma mark - signal callbacks
- (void) onSessionCreated:(NSString*)sessionId partyIds:(NSSet*)partyIds type:(NSString*)type error:(ArrownockException *)error
{
    if(error)
    {
        if(_failureCallback) {
            _failureCallback(error);
        }
    }
    else
    {
        _currentSessionId = sessionId;
        _currentMediaType = type;
        _inSession = YES;
        for(NSString* partyId in partyIds) {
            if(partyId && ![partyId isEqualToString:[_controller getPartyId]]) {
                _remotePartyId = partyId;
                break;
            }
        }
        if(_successCallback)
        {
            if(_localVideoView.videoWidth && _localVideoView.videoHeight)
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [_delegate onLocalVideoViewReady:_localVideoView];
                });
            }
            [_controller sendInvitations:sessionId partyIds:partyIds type:type notificationData:_notification];
            _successCallback(sessionId);
        }
    }
    _successCallback = nil;
    _failureCallback = nil;
}

- (void) onSessionValidated:(BOOL)isValid sessionId:(NSString*)sessionId partyIds:(NSSet*)partyIds type:(NSString *)type date:(NSDate*)date
{
    if(isValid)
    {
        _currentSessionId = sessionId;
        _inSession = YES;
        _currentMediaType = type;
        _remotePartyId = [partyIds allObjects][0];
        [_delegate onReceivedInvitation:YES sessionId:sessionId partyId:[partyIds allObjects][0] type:type createdAt:date];
    }
    else
    {
        if(partyIds == nil || partyIds.count == 0)
        {
            [_delegate onReceivedInvitation:NO sessionId:nil partyId:nil type:nil createdAt:nil];
        }
        else
        {
            [_delegate onReceivedInvitation:NO sessionId:sessionId partyId:[partyIds allObjects][0] type:type createdAt:date];
        }
    }
}

- (void) onInvitationRecieved:(NSString*)sessionId
{
    [_controller validateSession:sessionId];
}

- (void) onRemoteHangup:(NSString*)partyId
{
    [_delegate onRemotePartyDisconnected:partyId];
    [self reset];
}

- (void) onOfferRecieved:(NSString*)partyId offerJson:(NSString*)offerJson orientation:(int)orientation
{
    AnLivePeerConnectionManager* pcm = [self getPeerConnectionManager:partyId];
    [pcm setRemoteDescription:@"offer" sdpString:offerJson];
    [pcm createAnswer];
}

- (void) onAnswerRecieved:(NSString*)partyId answerJson:(NSString*)answerJson orientation:(int)orientation
{
    AnLivePeerConnectionManager* pcm = [self getPeerConnectionManager:partyId];
    [pcm setRemoteDescription:@"answer" sdpString:answerJson];
}

- (void) onICECandidate:(NSString*)partyId candidateJson:(NSString*)candidateJson
{
    NSData *data = [candidateJson dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    AnLivePeerConnectionManager* pcm = [self getPeerConnectionManager:partyId];
    [pcm setICECandidate:json];
}

#pragma AnLiveMediaStreamsViewDelegate method

- (void)onVideoSizeChanged:(double)width height:(double)height isLocal:(BOOL)isLocal isFirstTime:(BOOL)isFirstTime;
{
    if(isLocal)
    {
        if(_delegate && _localVideoView)
        {
            if(isFirstTime)
            {
                if([_delegate respondsToSelector:@selector(onLocalVideoViewReady:)])
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate onLocalVideoViewReady:_localVideoView];
                    });
                }
            }
            else
            {
                if([_delegate respondsToSelector:@selector(onLocalVideoSizeChanged:)])
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate onLocalVideoSizeChanged:CGSizeMake(width, height)];
                    });
                }
            }
        }
    }
}

- (void)setVideoEnabled:(BOOL)enabled
{
    if(_localVideoTrack)
    {
        [_localVideoTrack setEnabled:enabled];
        if(!enabled)
        {
            //[_localVideoView renderFrame:nil];
            [_localVideoView clearView];
        }
        
        NSDictionary *data = [NSDictionary dictionaryWithObjects:@[@"video", (enabled?@"on":@"off")] forKeys:@[@"type", @"data"]];
        for(NSString *partyId in _pcms)
        {
            if(partyId && _pcms[partyId])
            {
                AnLivePeerConnectionManager *pcm = _pcms[partyId];
                [pcm sendDataToRemotePeer:data];
            }
        }
    }
}

- (void)setAudioEnabled:(BOOL)enabled
{
    if(_localAudioTrack)
    {
        [_localAudioTrack setEnabled:enabled];
        NSDictionary *data = [NSDictionary dictionaryWithObjects:@[@"audio", (enabled?@"on":@"off")] forKeys:@[@"type", @"data"]];
        for(NSString *partyId in _pcms)
        {
            if(partyId && _pcms[partyId])
            {
                AnLivePeerConnectionManager *pcm = _pcms[partyId];
                [pcm sendDataToRemotePeer:data];
            }
        }
    }
}

/*
- (void)switchCamera:(AnLiveOpenGLVideoRenderer*)renderer
{
#if !TARGET_IPHONE_SIMULATOR && TARGET_OS_IPHONE
    if(_factory && _localVideoTrack && _localVideoTrack.isEnabled)
    {
        _localCameraType = !_localCameraType;
        NSString* trackId = _localVideoTrack.label;
        [_localStream removeVideoTrack:_localVideoTrack];
        [_localVideoTrack removeRenderer:_localVideoView];
        [_localVideoView renderFrame:nil];
        _localVideoTrack = nil;
        
        NSString *cameraID = [self getCameraId:_localCameraType];
        NSAssert(cameraID, @"Unable to get the camera");
        RTCVideoCapturer *capturer = [RTCVideoCapturer capturerWithDeviceName:cameraID];
        
        RTCMediaConstraints* mediaConstraints = [[RTCMediaConstraints alloc] initWithMandatoryConstraints:nil optionalConstraints:nil];
        RTCVideoSource *videoSource = [_factory videoSourceWithCapturer:capturer constraints:mediaConstraints];
        RTCVideoTrack *newLocalVideoTrack = [_factory videoTrackWithID:@"ARDAMSv0back" source:videoSource];
        
        _localVideoTrack = newLocalVideoTrack;
        [_localStream addVideoTrack:newLocalVideoTrack];
        [_localVideoTrack addRenderer:_localVideoView];
        renderer.isMirror = _localCameraType;
        
        for(NSString *partyId in _pcms)
        {
            if(partyId && _pcms[partyId])
            {
                AnLivePeerConnectionManager *pcm = _pcms[partyId];
                RTCPeerConnection* pc = [pcm getPeerConnection];

                RTCSessionDescription* localSdp = pc.localDescription;
                RTCSessionDescription* remoteSdp = pc.remoteDescription;
                if (!localSdp || !remoteSdp) {
                    break;
                }
                
                NSString* newLocalDesc = [localSdp.description stringByReplacingOccurrencesOfString:trackId withString:_localVideoTrack.label];
                localSdp = [[RTCSessionDescription alloc] initWithType:localSdp.type sdp:newLocalDesc];
                
                [pc setLocalDescriptionWithDelegate:self sessionDescription:localSdp];
                [pc setRemoteDescriptionWithDelegate:self sessionDescription:remoteSdp];
            }
        }
    }
#endif
}
*/
@end