#import "ANAFHTTPClient.h"
#import "ArrownockException.h"
#import "GPUser.h"
#import "GPArticle.h"
#import "GPChannel.h"
#import "GPComment.h"
#import "GPTopic.h"
#import "GPMessage.h"
#import "AnGroupedia.h"
#import "ArrownockConstants.h"


@interface AnGroupediaHTTPClient : ANAFHTTPClient
- (AnGroupediaHTTPClient*)setup;

- (void)sendCommonRequest:(id)params
                      url:(NSString*)url
                  success:(void (^)())success
                  failure:(void (^)(ArrownockException* exception))failure;

- (void)sendInitUserRequest:(id)params
                        url:(NSString*)url
                       name:(NSString*)name
                     avatar:(NSString*)avatar
                      extId:(NSString*)extId
                    success:(void (^)(GPUser *user))success
                    failure:(void (^)(ArrownockException* exception))failure;

- (void)sendLinkUserRequest:(id)params
                        url:(NSString*)url
                    success:(void (^)(GPUser *user))success
                    failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetChannelsRequest:(id)params
                           url:(NSString*)url
                       success:(void (^)(NSArray *channels))success
                       failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetArticlesRequest:(id)params
                          url:(NSString*)url
                      success:(void (^)(NSArray *articles))success
                      failure:(void (^)(ArrownockException* exception))failure;

- (void)sendSearchArticlesRequest:(id)params
                             url:(NSString*)url
                         success:(void (^)(NSArray *articles))success
                         failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetArticleByIdRequest:(id)params
                              url:(NSString*)url
                          success:(void (^)(GPArticle *article))success
                          failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetCommentsRequest:(id)params
                        isLinkUser:(BOOL)isLinkUser
                               url:(NSString*)url
                           success:(void (^)(NSArray *comments))success
                           failure:(void (^)(ArrownockException* exception))failure;

- (void)sendCreateCommentRequest:(id)params
                          isLinkUser:(BOOL)isLinkUser
                                 url:(NSString*)url
                             success:(void (^)(GPComment *comment))success
                             failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetTopicRequest:(id)params
                            url:(NSString*)url
                        success:(void (^)(GPTopic *topic, bool isJoin, NSArray *messages))success
                        failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetTopicOfflineMessageRequest:(id)params
                                      url:(NSString*)url
                                  success:(void (^)(NSArray *messages, int count))success
                                  failure:(void (^)(ArrownockException* exception))failure;

- (void)sendGetTopicMessageRequest:(id)params
                           topicId:(NSString *)topicId
                               url:(NSString*)url
                           success:(void (^)(NSArray *messages))success
                           failure:(void (^)(ArrownockException* exception))failure;

@end