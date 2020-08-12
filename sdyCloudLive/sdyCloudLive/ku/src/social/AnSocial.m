#import "AnSocial.h"
#import "AnSocialFile.h"
#import "ArrownockConstants.h"
#import "AnSocialAPIClient.h"
#import "DeviceManager.h"
#import "ArrownockException.h"

#define API_ROOT ARROWNOCK_SOCIAL_HOST
#define API_VERSION ARROWNOCK_SOCIAL_VERSION
@interface AnSocial ()
@property (nonatomic, strong) NSString *appKey;
@property BOOL secure;
@property (nonatomic, strong) NSString *host;
@property (nonatomic, retain) AnSocialAPIClient *client;
@end

@implementation AnSocial

@synthesize appKey = _appKey;
@synthesize secure = _secure;
@synthesize client = _client;
@synthesize host = _host;

- (NSURL *)_generateBaseURL:(BOOL)secure
{
    NSString * _baseURLString = [NSString stringWithFormat:@"%@://%@/%@/", secure?@"https":@"http", _host, API_VERSION];
    NSURL *url = [[NSURL alloc] initWithString:[_baseURLString stringByAddingPercentEscapesUsingEncoding: NSUTF8StringEncoding]];
    return  url;
}

- (AnSocial *)initWithAppKey:(NSString *)appKey
{
    if (appKey == nil)
    {
        @throw [NSException exceptionWithName:@"Invalid AppKey" reason:@"appKey is nil" userInfo:nil];
    }

    _appKey = appKey;
    _secure = YES;
    _host = API_ROOT;
    _client = [[AnSocialAPIClient alloc] initWithBaseURL:[self _generateBaseURL:YES]];
    [_client setAppKey:appKey];
    
    // load local stored session id
    /*
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *sessionId = [defaults valueForKey:@"_an.sid"];
    if(sessionId)
    {
        [_client setSessionId:sessionId];
    }
     */
    
#ifdef DM_ENABLED
    if (appKey != nil) {
        [ANDeviceManager initializeWithAppKey:appKey secure:_secure];
    }
#endif
    
    return self;
}

- (void)setTimeout:(NSTimeInterval)secondTimeout
{
    [_client setTimeout:secondTimeout];
}

- (void)setSecureConnection:(BOOL)secure
{
    _client.baseURL = [self _generateBaseURL:secure];
    _secure = secure;
    
#ifdef DM_ENABLED
    [ANDeviceManager initializeWithAppKey:_appKey secure:secure];
#endif
}

- (void)sendRequest:(NSString *)path
            method:(AnSocialMethod)method
            params:(NSDictionary *)params
           success:(void (^)(NSDictionary *response))success
           failure:(void (^)(NSDictionary *response))failure;
{
    if (path == nil)
    {
        if(failure)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:@"Invalid request path" errorCode:SOCIAL_INVALID_PATH statusCode:404];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
        }
    }
    
    
    NSDictionary *error = [self _validateParams:params];
    if(error)
    {
        if(failure)
        {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(error);
            });
        }
    }
    else
    {
        if(method == AnSocialMethodGET)
        {
            [_client sendRequest:path method:@"GET" params:params success:success failure:failure];
        }
        else if(method == AnSocialMethodPOST)
        {
            [_client sendRequest:path method:@"POST" params:params success:success failure:failure];
        }
        else
        {
            if(failure)
            {
                NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:@"Invalid request method" errorCode:SOCIAL_INVALID_METHOD_TYPE statusCode:404];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    failure(errorDict);
                });
            }
        }
    }
}

- (NSDictionary *)_validateParams:(NSDictionary *)params
{
    if(params)
    {
        for(id key in params)
        {
            if([@"photo" isEqual:key] || [@"file" isEqual:key])
            {
                if(![[params objectForKey:key] isKindOfClass:[AnSocialFile class]])
                {
                    return [AnSocialAPIClient generateErrorResponse:@"Invalid request method" errorCode:SOCIAL_INVALID_PARAMS statusCode:404];
                }
            }
        }
    }
    return nil;
}

- (void)setHost:(NSString *)host
{
    _host = host;
    _client.baseURL = [self _generateBaseURL:_secure];
}

- (void)setAPISecret:(NSString *)apiSecret
{
    [_client setAPISecret:apiSecret];
}

@end
