#import "AnLivePeerConnectionManager.h"
#import "RTCMediaConstraints.h"
#import "RTCPair.h"
#import "RTCICEServer.h"
#import "RTCPeerConnectionDelegate.h"
#import "RTCPeerConnectionFactory.h"
#import "RTCSessionDescription.h"
#import "RTCSessionDescriptionDelegate.h"
#import "RTCICECandidate.h"
#import "RTCMediaStream.h"
#import "RTCVideoTrack.h"
#import "RTCAudioTrack.h"
#import "RTCDataChannel.h"
#import "ArrownockConstants.h"
#import "ArrownockExceptionUtils.h"
#import "AnLiveVideoView.h"
#import "AnLiveProtocols.h"

@interface AnLivePeerConnectionManager() <RTCPeerConnectionDelegate, RTCSessionDescriptionDelegate, RTCDataChannelDelegate, AnLiveMediaStreamsDelegate>

@end

@implementation AnLivePeerConnectionManager {
    RTCPeerConnection *_peerConnection;
    id <AnLiveSignalController> _controller;
    id <AnLiveEventDelegate> _delegate;
    NSString *_partyId;
    RTCMediaConstraints *_sdpMediaConstraints;
    BOOL _connected;
    int _localCameraOrientation;
    int _remoteCameraOrientation;
    AnLiveVideoView *_remoteView;
    RTCVideoTrack *_remoteVideoTrack;
    RTCDataChannel *_dataChannel;
    RTCMediaStream *_localMediaStream;
}

- (AnLivePeerConnectionManager*) initWithController:(id <AnLiveSignalController>)controller delegate:(id <AnLiveEventDelegate>)delegate partyId:(NSString*)partyId
{
    self = [super init];
    _controller = controller;
    _partyId = partyId;
    _delegate = delegate;
    _connected = NO;
    _localCameraOrientation = 0;
    _remoteCameraOrientation = 0;
    
    NSArray *mandatoryConstraints = @[
                                      [[RTCPair alloc] initWithKey:@"OfferToReceiveAudio" value:@"true"],
                                      [[RTCPair alloc] initWithKey:@"OfferToReceiveVideo" value:@"true"]
                                      ];
    _sdpMediaConstraints = [[RTCMediaConstraints alloc] initWithMandatoryConstraints:mandatoryConstraints optionalConstraints:nil];
    
    return self;
}

- (RTCPeerConnection*) createPeerConnection:(RTCPeerConnectionFactory *)factory localMediaStream:(RTCMediaStream*)localMediaStream
{
    NSString *stunURL = [NSString stringWithFormat:@"stun:%@", ARROWNOCK_STUN_SERVER_TAG];
    NSURL *defaultSTUNServerURL = [NSURL URLWithString:stunURL];
    RTCICEServer *stunServer = [[RTCICEServer alloc] initWithURI:defaultSTUNServerURL username:@"" password:@""];
    
    NSString *turnURL = [NSString stringWithFormat:@"turn:%@", ARROWNOCK_TURN_SERVER_TAG];
    NSURL *defaultTURNServerURL = [NSURL URLWithString:turnURL];
    RTCICEServer *turnServer = [[RTCICEServer alloc] initWithURI:defaultTURNServerURL username:ARROWNOCK_TURN_SERVER_USERNAME password:ARROWNOCK_TURN_SERVER_PASSWORD];
    NSMutableArray *iceServers = [NSMutableArray arrayWithObjects:stunServer, turnServer, nil];
    
    NSArray *mandatoryConstraints = @[[[RTCPair alloc] initWithKey:@"DtlsSrtpKeyAgreement" value:@"true"]];
    NSArray *optionalConstraints = @[[[RTCPair alloc] initWithKey:@"RtpDataChannels" value:@"true"]];
    RTCMediaConstraints* constraints = [[RTCMediaConstraints alloc] initWithMandatoryConstraints:mandatoryConstraints optionalConstraints:optionalConstraints];
    
    _peerConnection = [factory peerConnectionWithICEServers:iceServers constraints:constraints delegate:self];
    [_peerConnection addStream:localMediaStream];
    _localMediaStream = localMediaStream;
    
    return _peerConnection;
}

- (RTCPeerConnection*) getPeerConnection
{
    return _peerConnection;
}

- (void) createOffer
{
    if(_peerConnection && !_connected)
    {
        // create offerer data channel
        [self createDataChannel];
        
        [_peerConnection createOfferWithDelegate:self constraints:_sdpMediaConstraints];
    }
}

- (void) createAnswer
{
    if(_peerConnection && !_connected)
    {
        [_peerConnection createAnswerWithDelegate:self constraints:_sdpMediaConstraints];
    }
}

- (void) setRemoteDescription:(NSString*)type sdpString:(NSString*)sdpString
{
    RTCSessionDescription *description = [[RTCSessionDescription alloc] initWithType:type sdp:sdpString];
    if(_peerConnection && !_connected)
    {
        [_peerConnection setRemoteDescriptionWithDelegate:self sessionDescription:description];
    }
}

- (void) setICECandidate:(NSDictionary*)json
{
    if(_peerConnection && !_connected) {
        NSString *mid = json[@"id"];
        NSString *sdp = json[@"candidate"];
        NSNumber *num = json[@"label"];
        NSInteger mLineIndex = [num integerValue];
        RTCICECandidate *candidate = [[RTCICECandidate alloc] initWithMid:mid index:mLineIndex sdp:sdp];
        [_peerConnection addICECandidate:candidate];
        NSLog(@"ICE: %@", sdp);
    }
}

- (void) setLocalCameraOrientation:(int)localCameraOrientation
{
    _localCameraOrientation = localCameraOrientation;
}

- (void) setRemoteCameraOrientation:(int)remoteCameraOrientation
{
    _remoteCameraOrientation = remoteCameraOrientation;
}

- (void) sendDataToRemotePeer:(NSDictionary *)data
{
    if(_dataChannel && _dataChannel.state == kRTCDataChannelStateOpen && data && data.count > 0)
    {
        NSError *error;
        NSData *dataToSend = [NSJSONSerialization dataWithJSONObject:data options:0 error:&error];
        [_dataChannel sendData:[[RTCDataBuffer alloc] initWithData:dataToSend isBinary:NO]];
    }
}

- (void) dispose
{
    if(_remoteVideoTrack)
    {
        [_remoteVideoTrack removeRenderer:_remoteView];
        _remoteVideoTrack = nil;
        //[_remoteView renderFrame:nil];
        [_remoteView clearView];
    }
    if(_peerConnection) {
        [_peerConnection close];
        _peerConnection = nil;
        _connected = NO;
    }
    _localMediaStream = nil;
}

#pragma RTCPeerConnectionDelegate methods

// Triggered when the SignalingState changed.
- (void)peerConnection:(RTCPeerConnection *)peerConnection signalingStateChanged:(RTCSignalingState)stateChanged
{
    
}

// Triggered when media is received on a new stream from remote peer.
- (void)peerConnection:(RTCPeerConnection *)peerConnection addedStream:(RTCMediaStream *)stream
{
    dispatch_async(dispatch_get_main_queue(), ^{
        CGRect initRect = CGRectMake(0, 0, 10, 10);
        _remoteView = [[AnLiveVideoView alloc] initWithFrame:initRect];
        _remoteView.delegate = self;
        if (stream.videoTracks.count)
        {
            _remoteVideoTrack = stream.videoTracks[0];
            [_remoteVideoTrack addRenderer:_remoteView];
        }
    });
}

// Triggered when a remote peer close a stream.
- (void)peerConnection:(RTCPeerConnection *)peerConnection removedStream:(RTCMediaStream *)stream
{
    [_delegate onRemotePartyDisconnected:_partyId];
    _connected = NO;
}

// Triggered when renegotiation is needed, for example the ICE has restarted.
- (void)peerConnectionOnRenegotiationNeeded:(RTCPeerConnection *)peerConnection
{
    _connected = NO;
}

// Called any time the ICEConnectionState changes.
- (void)peerConnection:(RTCPeerConnection *)peerConnection iceConnectionChanged:(RTCICEConnectionState)newState
{
    switch(newState) {
        case RTCICEConnectionFailed:
            [self dispose];
            if([_delegate respondsToSelector:@selector(onError:exception:)])
            {
                [_delegate onError:_partyId exception:[ArrownockExceptionUtils generateWithErrorCode:LIVE_FAILED_ESTABLISH_CONN message:@"Failed to establish connection"]];
            }
            break;
        case RTCICEConnectionConnected:
            _connected = YES;
            if([_delegate respondsToSelector:@selector(onRemotePartyConnected:)])
            {
                [_delegate onRemotePartyConnected:_partyId];
            }
            
            if(_remoteView.videoWidth && _remoteView.videoHeight)
            {
                if([_delegate respondsToSelector:@selector(onRemotePartyVideoViewReady:remoteVideoView:)])
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate onRemotePartyVideoViewReady:_partyId remoteVideoView:_remoteView];
                    });
                }
            }
            break;
        case RTCICEConnectionDisconnected:
            if(_connected && _partyId)
            {
                [self dispose];
                if([_delegate respondsToSelector:@selector(onRemotePartyDisconnected:)])
                {
                    [_delegate onRemotePartyDisconnected:_partyId];
                }
            }
            break;
    }
}

// Called any time the ICEGatheringState changes.
- (void)peerConnection:(RTCPeerConnection *)peerConnection iceGatheringChanged:(RTCICEGatheringState)newState
{
    
}

// New Ice candidate have been found.
- (void)peerConnection:(RTCPeerConnection *)peerConnection gotICECandidate:(RTCICECandidate *)candidate
{
    if(!_connected) {
        NSDictionary *dict = @{
                               @"type": @"candidate",
                               @"label": @(candidate.sdpMLineIndex),
                               @"id": candidate.sdpMid,
                               @"candidate": candidate.sdp
                               };
        NSError *error = nil;
        NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&error];
        if (!error)
        {
            NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            [_controller sendICECandidate:_partyId candidateJson:json];
        }
    }
}

// New data channel has been opened.
- (void)peerConnection:(RTCPeerConnection*)peerConnection didOpenDataChannel:(RTCDataChannel*)dataChannel
{
    // get data channel as answerer
    _dataChannel = dataChannel;
    _dataChannel.delegate = self;
    
    [self sendInitState];
}

- (void) sendInitState
{
    // initial send local video/audio status to the connected remote peer
    if(_localMediaStream)
    {
        if(_localMediaStream.videoTracks && _localMediaStream.videoTracks.count > 0 && _localMediaStream.videoTracks[0])
        {
            RTCVideoTrack *videoTrack = _localMediaStream.videoTracks[0];
            NSString *videoState;
            if(videoTrack.isEnabled)
            {
                videoState = @"on";
            }
            else
            {
                videoState = @"off";
            }
            NSDictionary *dataToSend = [NSDictionary dictionaryWithObjects:@[videoState, @"video"] forKeys:@[@"data", @"type"]];
            [self sendDataToRemotePeer:dataToSend];
        }
        if(_localMediaStream.audioTracks && _localMediaStream.audioTracks.count > 0 && _localMediaStream.audioTracks[0])
        {
            NSString *audioState;
            RTCAudioTrack *audioTrack = _localMediaStream.audioTracks[0];
            if(audioTrack.isEnabled)
            {
                audioState = @"on";
            }
            else
            {
                audioState = @"off";
            }
            NSDictionary *dataToSend = [NSDictionary dictionaryWithObjects:@[audioState, @"audio"] forKeys:@[@"data", @"type"]];
            [self sendDataToRemotePeer:dataToSend];
        }
    }
}

#pragma RTCSessionDescriptionDelegate methods

// Called when creating a session.
- (void)peerConnection:(RTCPeerConnection *)peerConnection didCreateSessionDescription:(RTCSessionDescription *)sdp error:(NSError *)error
{
    if(error)
    {
        [_delegate onError:_partyId exception:[ArrownockExceptionUtils generateWithErrorCode:LIVE_FAILED_ESTABLISH_CONN message:@"Failed to establish connection"]];
    }
    else
    {
        RTCSessionDescription *newSdp = [[RTCSessionDescription alloc] initWithType:sdp.type sdp:sdp.description];
        [_peerConnection setLocalDescriptionWithDelegate:self sessionDescription:newSdp];
        if([newSdp.type isEqualToString:@"answer"])
        {
            [_controller sendAnswer:_partyId sdp:newSdp.description orientation:_localCameraOrientation];
        }
        else if([newSdp.type isEqualToString:@"offer"])
        {
            [_controller sendOffer:_partyId sdp:newSdp.description orientation:_localCameraOrientation];
        }
    }
}

// Called when setting a local or remote description.
- (void)peerConnection:(RTCPeerConnection *)peerConnection didSetSessionDescriptionWithError:(NSError *)error
{
    
}

#pragma AnLiveMediaStreamsViewDelegate method

- (void)onVideoSizeChanged:(double)width height:(double)height isLocal:(BOOL)isLocal isFirstTime:(BOOL)isFirstTime;
{
    if(!isLocal)
    {
        if(_delegate && _partyId && _remoteView) {
            if(isFirstTime)
            {
                if([_delegate respondsToSelector:@selector(onRemotePartyVideoViewReady:remoteVideoView:)])
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate onRemotePartyVideoViewReady:_partyId remoteVideoView:_remoteView];
                    });
                }
            }
            else
            {
                if([_delegate respondsToSelector:@selector(onRemotePartyVideoSizeChanged:videoSize:)])
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate onRemotePartyVideoSizeChanged:_partyId videoSize:CGSizeMake(width, height)];
                    });
                }
            }
        }
    }
}

# pragma private methods

- (void) createDataChannel
{
    RTCDataChannelInit *dataChannelInit = [[RTCDataChannelInit alloc]init];
    dataChannelInit.isOrdered = NO;
    dataChannelInit.isNegotiated = NO;
    _dataChannel = [_peerConnection createDataChannelWithLabel:@"anLiveDataChannel" config:dataChannelInit];
    _dataChannel.delegate = self;
}

#pragma RTCDataChannelDelegate methods

// Called when the data channel state has changed.
- (void)channelDidChangeState:(RTCDataChannel*)channel
{
    switch(channel.state)
    {
        case kRTCDataChannelStateConnecting:
            break;
        case kRTCDataChannelStateOpen:
            [self sendInitState];
            break;
        case kRTCDataChannelStateClosing:
            break;
        case kRTCDataChannelStateClosed:
            _dataChannel = nil;
            break;
    }
}

// Called when a data buffer was successfully received.
- (void)channel:(RTCDataChannel*)channel didReceiveMessageWithBuffer:(RTCDataBuffer*)buffer
{
    if(_delegate)
    {
        NSData *data = [NSData dataWithBytes:buffer.data.bytes length:buffer.data.length];
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if(json)
        {
            NSString *type = [json objectForKey:@"type"];
            NSString *data = [json objectForKey:@"data"];
            if([@"video" isEqualToString:type])
            {
                if([@"on" isEqualToString:data])
                {
                    [_delegate onRemotePartyVideoStateChanged:_partyId state:AnLiveVideoOn];
                }
                else if([@"off" isEqualToString:data])
                {
                    [_delegate onRemotePartyVideoStateChanged:_partyId state:AnLiveVideoOff];
                }
            }
            else if([@"audio" isEqualToString:type]){
                if([@"on" isEqualToString:data])
                {
                    [_delegate onRemotePartyAudioStateChanged:_partyId state:AnLiveAudioOn];
                }
                else if([@"off" isEqualToString:data])
                {
                    [_delegate onRemotePartyAudioStateChanged:_partyId state:AnLiveAudioOff];
                }
            }
        }
    }
}

@end