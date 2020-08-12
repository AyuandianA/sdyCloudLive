#import "ANAFHTTPClient.h"
#import "ArrownockException.h"
#import "ArrownockConstants.h"

@interface AnPushHTTPClient : ANAFHTTPClient
- (AnPushHTTPClient*)init;


- (void)sendAnPushSettingsRequest:(id)params
                              url:(NSString*)url
                             type:(int)type
                          success:(void (^)())success
                          failure:(void (^)(ArrownockException* exception))failure;

- (void)sendRegistrationRequest:(id)params
                           type:(int)type
                            url:(NSString*)url
                        success:(void (^)(NSString *anid))success
                        failure:(void (^)(ArrownockException* exception))failure;

- (void)sendFetchCachedPushNotificationsRequest:(NSString *)token
                                            url:(NSString*)url
                                        success:(void (^)(NSDictionary *messages))success
                                        failure:(void (^)(ArrownockException* exception))failure;

@end 