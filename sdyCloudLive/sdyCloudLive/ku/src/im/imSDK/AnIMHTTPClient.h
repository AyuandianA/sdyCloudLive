#import "ANAFHTTPClient.h"
#import "ArrownockException.h"
#import "ArrownockConstants.h"

@interface AnIMHTTPClient : ANAFHTTPClient
- (AnIMHTTPClient*)setup;

- (void)sendHistoryRequest:(id)params
                       url:(NSString *)url
                   success:(void (^)(NSArray *response))success
                   failure:(void (^)(ArrownockException* exception))failure;

- (void)sendOfflineHistoryRequest:(id)params
                              url:(NSString *)url
                          success:(void (^)(NSArray *response, int count))success
                          failure:(void (^)(ArrownockException* exception))failure;

- (void)sendFullTopicHistoryRequest:(id)params
                                url:(NSString*)url
                            success:(void (^)(NSArray *response))success
                            failure:(void (^)(ArrownockException* exception))failure;

- (void)sendPushNotificationSettingsRequest:(id)params
                                        url:(NSString*)url
                                    success:(void (^)())success
                                    failure:(void (^)(ArrownockException* exception))failure;

- (void)sendAnLiveRequest:(id)params
                      url:(NSString*)url
                   method:(NSString*)method
                  success:(void (^)(NSDictionary *response))success
                  failure:(void (^)(NSDictionary *response, NSError *error))failure;

- (void)sendGetClientIdRequest:(NSString*)userId
                           url:(NSString*)url
                       success:(void (^)(NSString *clientId))success
                       failure:(void (^)(ArrownockException* exception))failure;

- (void)sendCreateTopicRequest:(id)params
                           url:(NSString*)url
                       success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success
                       failure:(void (^)(ArrownockException* exception))failure;

- (void)sendTopicOperationRequest:(NSString*)topicId
                             type:(int)type
                           params:(id)params
                              url:(NSString*)url
                          success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success
                          failure:(void (^)(ArrownockException* exception))failure;

- (void)sendBindOrUnBindRequest:(id)params
                            url:(NSString*)url
                        success:(void (^)())success
                        failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetTopicInfoRequest:(NSString*)url
                        success:(void (^)(NSString *topicId, NSString *topicName, NSString *owner, NSSet *parties, NSDate *createdDate, NSDictionary *customData))success
                        failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetClientsStatusRequest:(NSString*)url
                            success:(void (^)(NSDictionary *clientsStatus))success
                            failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetTopicListRequest:(NSString*)url
                        success:(void (^)(NSMutableArray *topicList))success
                        failure:(void (^)(ArrownockException* exception))failure;

- (void)sendSyncHistoryRequest:(id)params
                           url:(NSString*)url
                          success:(void (^)(NSArray *response, int count))success
                          failure:(void (^)(ArrownockException* exception))failure;

- (void)reportDeviceId:(id)params
                   url:(NSString*)url
               success:(void (^)())success
               failure:(void (^)(ArrownockException* exception))failure;

- (void)sendBlacklistOperationRequest:(int)type
                               params:(id)params
                                  url:(NSString*)url
                              success:(void (^)())success
                              failure:(void (^)(ArrownockException* exception))failure;

- (void)sendListBlacklistsRequest:(id)params
                           url:(NSString*)url
                       success:(void (^)(NSArray *clients))success
                       failure:(void (^)(ArrownockException* exception))failure;

@end