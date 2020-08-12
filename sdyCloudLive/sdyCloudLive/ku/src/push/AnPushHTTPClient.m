#import "AnPushHTTPClient.h"
#import "ANAFJSONRequestOperation.h"
#import "ArrownockExceptionUtils.h"
#import "ANBase64Wrapper.h"
#import "ANSBJson.h"
#import <CommonCrypto/CommonDigest.h>

#define ANID_KEY @"ANPUSH_ANID"
#define ANPUSH_LAST_REGISTER @"ANPUSH_LAST_REGISTER"

@interface AnPushHTTPClient()

@end

@implementation AnPushHTTPClient
- (AnPushHTTPClient*)init
{
    [self registerHTTPOperationClass:[ANAFJSONRequestOperation class]];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
    [self setStringEncoding:NSUTF8StringEncoding];
    return self;
}

- (void)sendAnPushSettingsRequest:(id)params
                              url:(NSString*)url
                             type:(int)type
                          success:(void (^)())success
                          failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleAnPushSettingsResponse:responseObject type:type error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleAnPushSettingsResponse:nil type:type error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleAnPushSettingsResponse:(id)responseObject
                                type:(int)type
                               error:(NSError *)error
                           isSuccess:(BOOL)isSuccess
                           operation:(ANAFHTTPRequestOperation *)operation
                             success:(void (^)())success
                             failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        if(success)
        {
            success();
        }
    } else {
        NSUInteger errCode = 0;
        if (type == 1) {
            errCode = PUSH_FAILED_SET_MUTE;
        } else if (type == 2) {
            errCode = PUSH_FAILED_SET_SILENT;
        } else if (type == 3) {
            errCode = PUSH_FAILED_CLEAR_MUTE;
        } else if (type == 4) {
            errCode = PUSH_FAILED_CLEAR_SILENT;
        } else if (type == 5) {
            errCode = PUSH_FAILED_SET_BADGE;
        }
        NSString *errorString = nil;
        NSString *localizedRecoverySuggestion = [error localizedRecoverySuggestion];
        if (localizedRecoverySuggestion) {
            NSError *err = nil;
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[localizedRecoverySuggestion dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&err];
            if (err == nil) {
                if ([dict objectForKey:@"meta"] != nil) {
                    errorString = [[dict objectForKey:@"meta"] objectForKey:@"message"];
                    if(failure)
                    {
                        failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
            }
            return;
        }
    }
}

- (void)sendRegistrationRequest:(id)params
                           type:(int)type
                            url:(NSString*)url
                        success:(void (^)(NSString *anid))success
                        failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleRegistrationResponse:responseObject type:type error:nil isSuccess:YES operation:operation params:params success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleRegistrationResponse:nil type:type error:error isSuccess:NO operation:operation params:params success:success failure:failure];
    }];
    [operation start];
}

- (void)handleRegistrationResponse:(id)responseObject
                         type:(int)type
                        error:(NSError *)error
                    isSuccess:(BOOL)isSuccess
                    operation:(ANAFHTTPRequestOperation *)operation
                       params:(id)params
                      success:(void (^)())success
                      failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* resultString = nil;
        if (type == 1)
        {
            if([[[res objectForKey:@"response"] objectForKey:@"subscription"] objectForKey:@"anid"] != nil)
            {
                resultString = [[[res objectForKey:@"response"] objectForKey:@"subscription"] objectForKey:@"anid"];
            } else {
                if (failure) {
                    NSString *errorMessage = @"no response data";
                    failure([ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_REGISTER message:errorMessage]);
                }
                return;
            }
            if (resultString) {
                NSNumber *now = [NSNumber numberWithDouble:[[NSDate date] timeIntervalSince1970]];
                NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
                [defaults setObject:now forKey:ANPUSH_LAST_REGISTER];
                [defaults synchronize];
                [self writeAnID:resultString toUserDefaultsKey:ANID_KEY];
            }
        } else if (type == 2)
        {
            resultString = [self getAnID];
            [self removeAnID:ANID_KEY];
        }
        if(success)
        {
            success(resultString);
        }
    } else {
        NSUInteger errCode = 0;
        if (type == 1) {
            errCode = PUSH_FAILED_REGISTER;
        } else if (type == 2) {
            errCode = PUSH_FAILED_UNREGISTER;
        } 
        NSString *errorString = nil;
        NSString *localizedRecoverySuggestion = [error localizedRecoverySuggestion];
        if (localizedRecoverySuggestion) {
            NSError *err = nil;
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[localizedRecoverySuggestion dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&err];
            if (err == nil) {
                if ([dict objectForKey:@"meta"] != nil) {
                    errorString = [[dict objectForKey:@"meta"] objectForKey:@"message"];
                    if(failure)
                    {
                        failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
            }
            return;
        }
    }
}

- (void)sendFetchCachedPushNotificationsRequest:(NSString *)token
                                            url:(NSString*)url
                                        success:(void (^)(NSDictionary *messages))success
                                        failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:token forKey:@"device_token"];
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleFetchCachedPushNotificationsResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleFetchCachedPushNotificationsResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleFetchCachedPushNotificationsResponse:(id)responseObject
                                             error:(NSError *)error
                                         isSuccess:(BOOL)isSuccess
                                         operation:(ANAFHTTPRequestOperation *)operation
                                           success:(void (^)(NSDictionary *messages))success
                                           failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSMutableDictionary * results = [[NSMutableDictionary alloc] init];
        NSDictionary* messages;
        
        if([res objectForKey:@"response"] != nil && [[res objectForKey:@"response"] objectForKey:@"messages"] != nil) {
            messages = [[res objectForKey:@"response"] objectForKey:@"messages"];
        }
        if(messages && messages.count > 0) {
            for (id pushId in [messages allKeys]) {
                NSObject *obj = [messages objectForKey:pushId];
                NSString *payload;
                NSString *date;
                if([obj isKindOfClass:[NSString class]]) {
                    payload = (NSString *)obj;
                } else if([obj isKindOfClass:[NSDictionary class]]) {
                    payload = [((NSDictionary *)obj) objectForKey:@"payload"];
                    date = [((NSDictionary *)obj) objectForKey:@"date"];
                }
                
                if(pushId && payload) {
                    NSDictionary *data = [[[ANSBJsonParser alloc] init] objectWithString:payload];
                    if(data) {
                        NSDictionary *ios = [data objectForKey:@"ios"];
                        if(ios) {
                            NSMutableDictionary *p = [[NSMutableDictionary alloc] init];
                            [p setObject:ios forKey:@"aps"];
                            NSDictionary *cdata = [data objectForKey:@"custom_data"];
                            if(cdata) {
                                for(id key in [cdata allKeys]) {
                                    [p setObject:[cdata objectForKey:key] forKey:key];
                                }
                            }
                            if(date) {
                                [p setObject:date forKey:@"date"];
                            }
                            [results setObject:p forKey:pushId];
                        }
                    }
                }
            }
        }
        success(results);
    } else {
        NSUInteger errCode = -1;
        NSString *errorString = nil;
        NSString *localizedRecoverySuggestion = [error localizedRecoverySuggestion];
        if (localizedRecoverySuggestion) {
            NSError *err = nil;
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[localizedRecoverySuggestion dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&err];
            if (err == nil) {
                if ([dict objectForKey:@"meta"] != nil) {
                    errorString = [[dict objectForKey:@"meta"] objectForKey:@"message"];
                    if(failure)
                    {
                        failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
            }
            return;
        }
    }
}

#ifdef SELF_SIGN
- (void)setSSLHandler:(ANAFHTTPRequestOperation *)operation
{
    [operation setWillSendRequestForAuthenticationChallengeBlock:^(NSURLConnection *connection, NSURLAuthenticationChallenge *challenge) {
        [self connection:connection willSendRequestForAuthenticationChallenge:challenge];
    }];
}
#endif

#ifdef SELF_SIGN
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    SecTrustRef trust = [challenge.protectionSpace serverTrust];
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, 0);
    NSData* serverCertificateData = (__bridge NSData*)SecCertificateCopyData(certificate);
    NSString *serverCertificateDataHash = [self SHA256:[ANBase64Wrapper base64EncodedString:serverCertificateData]];
    
    NSData *certData = [ANBase64Wrapper dataWithBase64EncodedString:ARROWNOCK_SERVER_CERT];
    CFDataRef certDataRef = (__bridge_retained CFDataRef)certData;
    SecCertificateRef localcertificate = SecCertificateCreateWithData(NULL, certDataRef);
    NSData* localCertificateData = (__bridge NSData*)SecCertificateCopyData(localcertificate);
    NSString *localCertificateDataHash = [self SHA256:[ANBase64Wrapper base64EncodedString:localCertificateData]];
    
    CFRelease(certDataRef);
    
    // Check if the certificate returned from the server is identical to the saved certificate in local
    BOOL areCertificatesEqual = ([serverCertificateDataHash isEqualToString:localCertificateDataHash]);
    
    if (areCertificatesEqual)
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
    else
    {
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}

- (NSString*) SHA256:(NSString *)input {
    const char *cStr = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, strlen(cStr), result);
    NSString *s = [NSString  stringWithFormat:
                   @"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                   result[0], result[1], result[2], result[3], result[4],
                   result[5], result[6], result[7],
                   result[8], result[9], result[10], result[11], result[12],
                   result[13], result[14], result[15],
                   result[16], result[17], result[18], result[19],
                   result[20], result[21], result[22], result[23], result[24],
                   result[25], result[26], result[27],
                   result[28], result[29], result[30], result[31]
                   ];
    return [s lowercaseString];
}
#endif

- (void)writeAnID:(NSString*)AnID toUserDefaultsKey:(NSString *)key
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *anID = [defaults objectForKey:key];
    if (!anID) {
        anID = AnID;
    } else if (![anID isEqualToString:AnID]) {
        anID = AnID;
    } else {
        return;
    }
    [defaults setObject:anID forKey:key];
    [defaults synchronize];
}

- (void)removeAnID:(NSString *)key
{
    NSUserDefaults *defaults=[NSUserDefaults standardUserDefaults];
    [defaults removeObjectForKey:key];
    [defaults synchronize];
}

- (NSString *)getAnID
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    return [defaults objectForKey:ANID_KEY];
}
@end
