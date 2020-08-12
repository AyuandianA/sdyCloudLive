#import "ANAFHTTPClient.h"
#import "ArrownockException.h"

@interface AnDeskHTTPClient : ANAFHTTPClient
- (AnDeskHTTPClient*)setup;

- (void)sendGetGroupsRequest:(NSString*)url
                     success:(void (^)(NSMutableArray *groups))success
                     failure:(void (^)(ArrownockException* exception))failure;

- (void)sendCreateSessionRequest:(id)params
                         groupId:(NSString *)groupId
                        clientId:(NSString *)clientId
                             url:(NSString*)url
                         success:(void (^)(NSString *sessionId, NSString *accountId, NSString *accountName))success
                         failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetOfflineMessageRequest:(id)params
                                 url:(NSString*)url
                             success:(void (^)(NSArray *messages, int count))success
                             failure:(void (^)(ArrownockException* exception))failure;

@end