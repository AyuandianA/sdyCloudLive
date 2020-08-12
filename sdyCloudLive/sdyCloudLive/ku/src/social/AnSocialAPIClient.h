#import "ANAFHTTPClient.h"

@interface AnSocialAPIClient : ANAFHTTPClient
+ (NSDictionary *)generateErrorResponse:(NSString *)message errorCode:(int)errorCode statusCode:(int)statusCode;

- (void)setAppKey:(NSString *)appKey;
- (void)setTimeout:(NSTimeInterval)secondTimeout;
- (void)setSessionId:(NSString *)sessionId;
- (void)setBaseURL:(NSURL *)url;
- (void)setAPISecret:(NSString *)apiSecret;

- (void)sendRequest:(NSString *)path
                   method:(NSString *)method
                   params:(NSDictionary *)params
                  success:(void (^)(NSDictionary *response))success
                  failure:(void (^)(NSDictionary *response))failure;

@end
