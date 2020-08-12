#import "AnLiveProtocols.h"
#import "AnLive.h"
#import "RTCPeerConnection.h"
#import "RTCPeerConnectionFactory.h"

@interface AnLivePeerConnectionManager : NSObject

- (AnLivePeerConnectionManager*) initWithController:(id <AnLiveSignalController>)controller delegate:(id <AnLiveEventDelegate>)delegate partyId:(NSString*)partyId;

- (RTCPeerConnection*) createPeerConnection:(RTCPeerConnectionFactory *)factory localMediaStream:(RTCMediaStream*)localMediaStream;

- (RTCPeerConnection*) getPeerConnection;

- (void) createOffer;

- (void) createAnswer;

- (void) setRemoteDescription:(NSString*)type sdpString:(NSString*)sdpString;

- (void) setICECandidate:(NSDictionary*)json;

- (void) setLocalCameraOrientation:(int)localCameraOrientation;

- (void) setRemoteCameraOrientation:(int)remoteCameraOrientation;

- (void) dispose;

- (void) sendDataToRemotePeer:(NSDictionary *)data;

@end