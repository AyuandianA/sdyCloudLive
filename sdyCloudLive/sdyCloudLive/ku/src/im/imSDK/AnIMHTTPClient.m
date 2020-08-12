#import "AnIMHTTPClient.h"
#import "ANAFJSONRequestOperation.h"
#import "ArrownockExceptionUtils.h"
#import "ANBase64Wrapper.h"
#import "AnIMMessage.h"
#import "AnIMUtils.h"
#import "ANEmojiUtil.h"
#import <CommonCrypto/CommonDigest.h>

@interface AnIMHTTPClient()

@end

@implementation AnIMHTTPClient

- (AnIMHTTPClient*)setup
{
    [self registerHTTPOperationClass:[ANAFJSONRequestOperation class]];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
    [self setStringEncoding:NSUTF8StringEncoding];
    return self;
}

- (void)sendHistoryRequest:(id)params url:(NSString *)url success:(void (^)(NSArray *response))success failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleHistoryResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleHistoryResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)sendFullTopicHistoryRequest:(id)params url:(NSString*)url success:(void (^)(NSArray *response))success failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleHistoryResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleHistoryResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleHistoryResponse:(id)responseObject
                        error:(NSError *)error
                    isSuccess:(BOOL)isSuccess
                    operation:(ANAFHTTPRequestOperation *)operation
                      success:(void (^)(NSArray *response))success
                      failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSArray* messages;
        if([res objectForKey:@"response"] != nil)
        {
            messages = [[res objectForKey:@"response"] objectForKey:@"messages"];
        }
        NSMutableArray* returnMessages = [[NSMutableArray alloc] init];
        if(messages)
        {
            for(int i=0;i<messages.count;i++)
            {
                NSDictionary* m = messages[i];
                if(m)
                {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    NSString *msgId = [m objectForKey:@"msg_id"];
                    NSString *topicId = [m objectForKey:@"topic_id"];
                    NSString *from = [m objectForKey:@"from"];
                    NSString *message = [m objectForKey:@"message"];
                    NSNumber *timestamp = [m objectForKey:@"timestamp"];
                    NSDictionary *customData = [self converCustomDataToEmoji:[m objectForKey:@"customData"]];
                    NSString* type = (NSString *)[m objectForKey:@"content_type"];
                    if([@"text" isEqualToString:type])
                    {
                        if(message)
                        {
                            message = [ANEmojiUtil stringConvertToEmoji:message];
                        }
                        [mm initWithType:AnIMTextMessage msgId:msgId topicId:topicId message:message content:nil fileType:nil from:from to:nil customData:customData timestamp:timestamp];
                        [returnMessages addObject:mm];
                    }
                    else if([@"binary" isEqualToString:type])
                    {
                        NSData *data;
                        if(message)
                        {
                            data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                        }
                        NSString *fileType = [m objectForKey:@"fileType"];
                        [mm initWithType:AnIMBinaryMessage msgId:msgId topicId:topicId message:nil content:data fileType:fileType from:from to:nil customData:customData timestamp:timestamp];
                        [returnMessages addObject:mm];
                    }
                }
            }
        }
        NSArray* array = [[NSArray alloc] initWithArray:returnMessages];
        if(success)
        {
            success(array);
        }
        return;
    } else {
        int statusCode = [operation.response statusCode];
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
            }
            return;
        }
    }
}

- (void)sendOfflineHistoryRequest:(id)params url:(NSString *)url success:(void (^)(NSArray *response, int count))success failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleOfflineHistoryResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleOfflineHistoryResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleOfflineHistoryResponse:(id)responseObject
                        error:(NSError *)error
                    isSuccess:(BOOL)isSuccess
                    operation:(ANAFHTTPRequestOperation *)operation
                      success:(void (^)(NSArray *response, int count))success
                      failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSArray* messages;
        if([res objectForKey:@"response"] != nil)
        {
            messages = [[res objectForKey:@"response"] objectForKey:@"messages"];
        }
        NSMutableArray* returnMessages = [[NSMutableArray alloc] init];
        if(messages)
        {
            for(int i=0;i<messages.count;i++)
            {
                NSDictionary* m = messages[i];
                if(m)
                {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    NSString *msgId = [m objectForKey:@"msg_id"];
                    NSString *topicId = [m objectForKey:@"topic_id"];
                    NSString *from = [m objectForKey:@"from"];
                    NSString *message = [m objectForKey:@"message"];
                    NSNumber *timestamp = [m objectForKey:@"timestamp"];
                    NSDictionary *customData = [self converCustomDataToEmoji:[m objectForKey:@"customData"]];
                    NSString* type = (NSString *)[m objectForKey:@"content_type"];
                    if([@"text" isEqualToString:type])
                    {
                        if(message)
                        {
                            message = [ANEmojiUtil stringConvertToEmoji:message];
                        }
                        [mm initWithType:AnIMTextMessage msgId:msgId topicId:topicId message:message content:nil fileType:nil from:from to:nil customData:customData timestamp:timestamp];
                        [returnMessages addObject:mm];
                    }
                    else if([@"binary" isEqualToString:type])
                    {
                        NSData *data;
                        if(message)
                        {
                            data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                        }
                        NSString *fileType = [m objectForKey:@"fileType"];
                        [mm initWithType:AnIMBinaryMessage msgId:msgId topicId:topicId message:nil content:data fileType:fileType from:from to:nil customData:customData timestamp:timestamp];
                        [returnMessages addObject:mm];
                    }
                }
            }
        }
        NSArray* array = [[NSArray alloc] initWithArray:returnMessages];
        int count = 0;
        if([res objectForKey:@"meta"] && [[res objectForKey:@"meta"] objectForKey:@"leftCount"])
        {
            count = [[[res objectForKey:@"meta"] objectForKey:@"leftCount"] integerValue];
        }
        if(!count)
        {
            count = 0;
        }
        if(success)
        {
            success(array, count);
        }
        return;
    } else {
        int statusCode = [operation.response statusCode];
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
            }
            return;
        }
    }
}

- (void)sendPushNotificationSettingsRequest:(id)params url:(NSString*)url success:(void (^)())success failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handlePushNotificationSettingsResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handlePushNotificationSettingsResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handlePushNotificationSettingsResponse:(id)responseObject
                        error:(NSError *)error
                    isSuccess:(BOOL)isSuccess
                    operation:(ANAFHTTPRequestOperation *)operation
                      success:(void (^)())success
                      failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        success();
        return;
    } else {
        int statusCode = [operation.response statusCode];
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
            }
            return;
        }
    }
}

- (void)sendAnLiveRequest:(id)params
                      url:(NSString*)url
                   method:(NSString*)method
                  success:(void (^)(NSDictionary *response))success
                  failure:(void (^)(NSDictionary *response, NSError *error))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:method path:url parameters:params];
    [request setTimeoutInterval:120];
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleAnLiveResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleAnLiveResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleAnLiveResponse:(id)responseObject
                       error:(NSError *)error
                    isSuccess:(BOOL)isSuccess
                    operation:(ANAFHTTPRequestOperation *)operation
                      success:(void (^)(NSDictionary *response))success
                      failure:(void (^)(NSDictionary *response, NSError *error))failure
{
    if (isSuccess) {
        success(responseObject);
        return;
    } else {
        NSString *localizedRecoverySuggestion = [error localizedRecoverySuggestion];
        if (localizedRecoverySuggestion) {
            NSError *err = nil;
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[localizedRecoverySuggestion dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&err];
            failure(dict, error);
        }
        else
        {
            failure(nil, error);
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


- (void)sendGetClientIdRequest:(NSString*)userId
                           url:(NSString*)url
                       success:(void (^)(NSString *clientId))success
                       failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:nil];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetClientIdResponse:responseObject userId:userId error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetClientIdResponse:nil userId:userId error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetClientIdResponse:(id)responseObject
                           userId:(NSString*)userId
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSString *clientId))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* resultString = nil;
        if([res objectForKey:@"token"] != nil)
        {
            resultString = [res objectForKey:@"token"];
        } else {
            if (failure) {
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENT_ID message:errorMessage]);
            }
            return;
        }
       
        [AnIMUtils writeClientId:resultString toUserDefaultsKey:userId];
        
        if(success)
        {
            success(resultString);
        }
    } else {
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENT_ID message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENT_ID message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENT_ID message:errorString]);
            }
            return;
        }
    }
}

- (void)sendCreateTopicRequest:(id)params
                           url:(NSString*)url
                       success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success
                       failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleCreateTopicResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleCreateTopicResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleCreateTopicResponse:(id)responseObject
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* topicId = nil;
        NSNumber* createdTimestamp = nil;
        NSNumber *updatedTimestamp = nil;
        if([[[res objectForKey:@"response"] objectForKey:@"topic"] objectForKey:@"topic_id"] != nil)
        {
            NSDictionary *topic = [[res objectForKey:@"response"] objectForKey:@"topic"];
            if ([topic objectForKey:@"topic_id"] != nil) {
                topicId = [topic objectForKey:@"topic_id"];
            }
            if ([topic objectForKey:@"created_at"] != nil) {
                createdTimestamp = [topic objectForKey:@"created_at"];
            }
            if ([topic objectForKey:@"updated_at"] != nil) {
                updatedTimestamp = [topic objectForKey:@"updated_at"];
            }
        } else {
            if (failure) {
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_CREATE_TOPIC message:errorMessage]);
            }
            return;
        }
        if(success)
        {
            success(topicId, createdTimestamp, updatedTimestamp);
        }
    } else {
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_CREATE_TOPIC message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_CREATE_TOPIC message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_CREATE_TOPIC message:errorString]);
            }
            return;
        }
    }
}

- (void)sendTopicOperationRequest:(NSString*)topicId
                             type:(int)type
                           params:(id)params
                              url:(NSString*)url
                          success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleTopicOperationResponse:responseObject type:type topicId:topicId error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleTopicOperationResponse:nil type:type topicId:topicId  error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleTopicOperationResponse:(id)responseObject
                                type:(int)type
                             topicId:(NSString*)topicId
                               error:(NSError *)error
                           isSuccess:(BOOL)isSuccess
                           operation:(ANAFHTTPRequestOperation *)operation
                             success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success
                             failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* topicId = nil;
        NSNumber* createdTimestamp = nil;
        NSNumber *updatedTimestamp = nil;
        if([[[res objectForKey:@"response"] objectForKey:@"topic"] objectForKey:@"topic_id"] != nil)
        {
            NSDictionary *topic = [[res objectForKey:@"response"] objectForKey:@"topic"];
            if ([topic objectForKey:@"topic_id"] != nil) {
                topicId = [topic objectForKey:@"topic_id"];
            }
            if ([topic objectForKey:@"created_at"] != nil) {
                createdTimestamp = [topic objectForKey:@"created_at"];
            }
            if ([topic objectForKey:@"updated_at"] != nil) {
                updatedTimestamp = [topic objectForKey:@"updated_at"];
            }
        } else {
            if (failure) {
                NSUInteger errCode = 0;
                if (type == 1) {
                    errCode = IM_FAILED_UPDATE_TOPIC;
                } else if (type == 2) {
                    errCode = IM_FAILED_ADD_CLIENTS;
                } else if (type == 3) {
                    errCode = IM_FAILED_REMOVE_CLIENTS;
                } else if (type == 4) {
                    errCode = IM_FAILED_REMOVE_TOPIC;
                }
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorMessage]);
            }
            return;
        }
        if(success)
        {
            success(topicId, createdTimestamp, updatedTimestamp);
        }
    } else {
        NSUInteger errCode = 0;
        if (type == 1) {
            errCode = IM_FAILED_UPDATE_TOPIC;
        } else if (type == 2) {
            errCode = IM_FAILED_ADD_CLIENTS;
        } else if (type == 3) {
            errCode = IM_FAILED_REMOVE_CLIENTS;
        } else if (type == 4) {
            errCode = IM_FAILED_REMOVE_TOPIC;
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

- (void)sendBindOrUnBindRequest:(id)params
                            url:(NSString*)url
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
        [self handleBindOrUnBindResponse:responseObject  error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleBindOrUnBindResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleBindOrUnBindResponse:(id)responseObject
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_BIND_SERVICE message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_BIND_SERVICE message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_BIND_SERVICE message:errorString]);
            }
            return;
        }
    }
}

- (void)sendGetTopicInfoRequest:(NSString*)url
                        success:(void (^)(NSString *topicId, NSString *topicName, NSString *owner, NSSet *parties, NSDate *createdDate, NSDictionary *customData))success
                        failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:nil];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetTopicInfoResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetTopicInfoResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetTopicInfoResponse:(id)responseObject
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSString *topicId, NSString *topicName, NSString *owner, NSSet *parties, NSDate *createdDate, NSDictionary *customData))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString *topicId = nil;
        NSString *topicName = nil;
        NSString *owner = nil;
        NSSet *parties = nil;
        NSDate *createdDate = nil;
        NSDictionary *customData = nil;
        if([[res objectForKey:@"response"] objectForKey:@"topic"]!= nil)
        {
            id topicJson = [[res objectForKey:@"response"] objectForKey:@"topic"];
            topicId = [topicJson objectForKey:@"id"];
            topicName = [topicJson objectForKey:@"name"];
            owner = [topicJson objectForKey:@"owner"];
            parties = [NSSet setWithArray:[topicJson objectForKey:@"parties"]];
            NSDateFormatter* df = [[NSDateFormatter alloc]init];
            [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
            NSString *createdString = [topicJson objectForKey:@"created_at"];
            createdDate = [df dateFromString:createdString];
            customData = [topicJson objectForKey:@"customData"];
        } else {
            if (failure) {
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_INFO message:errorMessage]);
            }
            return;
        }
        
        if(success)
        {
            success(topicId, topicName, owner, parties, createdDate, customData);
        }
    } else {
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_INFO message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_INFO message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_INFO message:errorString]);
            }
            return;
        }
    }
}

- (void)sendGetClientsStatusRequest:(NSString*)url
                            success:(void (^)(NSDictionary *clientsStatus))success
                            failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:nil];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetClientsStatusResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetClientsStatusResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetClientsStatusResponse:(id)responseObject
                             error:(NSError *)error
                         isSuccess:(BOOL)isSuccess
                         operation:(ANAFHTTPRequestOperation *)operation
                           success:(void (^)(NSDictionary *clientsStatus))success
                           failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSMutableDictionary *statusDict = nil;
        NSArray *statusArray = nil;
        if([[res objectForKey:@"response"] objectForKey:@"status"]!= nil)
        {
            statusArray = (NSArray *)[[res objectForKey:@"response"] objectForKey:@"status"];
            statusDict = [[NSMutableDictionary alloc] init];
            for (NSDictionary *dict in statusArray) {
                NSString *clientId = (NSString *)[[dict allKeys] objectAtIndex:0];
                NSString *online = [[dict objectForKey:clientId] intValue] == 1 ? @"YES" : @"NO";
                [statusDict setObject:online forKey:clientId];
            }
        } else {
            if (failure) {
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENTS_STATUS message:errorMessage]);
            }
            return;
        }
        
        if(success)
        {
            success(statusDict);
        }
    } else {
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENTS_STATUS message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENTS_STATUS message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENTS_STATUS message:errorString]);
            }
            return;
        }
    }
}

- (void)sendGetTopicListRequest:(NSString*)url
                        success:(void (^)(NSMutableArray *topicList))success
                        failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:nil];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetTopicListResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetTopicListResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetTopicListResponse:(id)responseObject
                                 error:(NSError *)error
                             isSuccess:(BOOL)isSuccess
                             operation:(ANAFHTTPRequestOperation *)operation
                               success:(void (^)(NSMutableArray *topicList))success
                               failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSMutableArray *topicList = nil;

        if([[res objectForKey:@"response"] objectForKey:@"list"]!= nil)
        {
            topicList = [[res objectForKey:@"response"] objectForKey:@"list"];
        } else {
            if (failure) {
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LIST message:errorMessage]);
            }
            return;
        }
        
        if(success)
        {
            success(topicList);
        }
    } else {
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LIST message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LIST message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LIST message:errorString]);
            }
            return;
        }
    }
}

- (void)reportDeviceId:(id)params
                   url:(NSString*)url
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
        [self handleReportDeviceIdResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleReportDeviceIdResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleReportDeviceIdResponse:(id)responseObject
                             error:(NSError *)error
                         isSuccess:(BOOL)isSuccess
                         operation:(ANAFHTTPRequestOperation *)operation
                           success:(void (^)(NSMutableArray *topicList))success
                           failure:(void (^)(ArrownockException* exception))failure
{
    //nothing to do
}

- (void)sendSyncHistoryRequest:(id)params url:(NSString*)url success:(void (^)(NSArray *response, int count))success failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleSyncHistoryResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleSyncHistoryResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleSyncHistoryResponse:(id)responseObject
                               error:(NSError *)error
                           isSuccess:(BOOL)isSuccess
                           operation:(ANAFHTTPRequestOperation *)operation
                             success:(void (^)(NSArray *response, int count))success
                             failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSArray* messages;
        if([res objectForKey:@"response"] != nil)
        {
            messages = [[res objectForKey:@"response"] objectForKey:@"messages"];
        }
        NSMutableArray* returnMessages = [[NSMutableArray alloc] init];
        if(messages)
        {
            for(int i=0;i<messages.count;i++)
            {
                NSDictionary* m = messages[i];
                if(m)
                {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    NSString *msgId = [m objectForKey:@"msg_id"];
                    NSString *topicId = [m objectForKey:@"topic_id"];
                    NSString *from = [m objectForKey:@"from"];
                    NSString *message = [m objectForKey:@"message"];
                    NSNumber *timestamp = [m objectForKey:@"timestamp"];
                    NSDictionary *customData = [self converCustomDataToEmoji:[m objectForKey:@"customData"]];
                    NSString *type = (NSString *)[m objectForKey:@"content_type"];
                    NSArray *parties = [m objectForKey:@"parties"];
                    NSString *to = nil;
                    if(parties) {
                        for(NSString *clientId in parties) {
                            if(from != clientId) {
                                to = clientId;
                                break;
                            }
                        }
                    }
                    
                    if([@"text" isEqualToString:type])
                    {
                        if(message)
                        {
                            message = [ANEmojiUtil stringConvertToEmoji:message];
                        }
                        [mm initWithType:AnIMTextMessage msgId:msgId topicId:topicId message:message content:nil fileType:nil from:from to:to customData:customData timestamp:timestamp];
                        [returnMessages addObject:mm];
                    }
                    else if([@"binary" isEqualToString:type])
                    {
                        NSData *data;
                        if(message)
                        {
                            data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                        }
                        NSString *fileType = [m objectForKey:@"fileType"];
                        [mm initWithType:AnIMBinaryMessage msgId:msgId topicId:topicId message:nil content:data fileType:fileType from:from to:to customData:customData timestamp:timestamp];
                        [returnMessages addObject:mm];
                    }
                }
            }
        }
        NSArray* array = [[NSArray alloc] initWithArray:returnMessages];
        int count = 0;
        if([res objectForKey:@"meta"] && [[res objectForKey:@"meta"] objectForKey:@"leftCount"])
        {
            count = [[[res objectForKey:@"meta"] objectForKey:@"leftCount"] integerValue];
        }
        if(!count)
        {
            count = 0;
        }
        if(success)
        {
            success(array, count);
        }
        return;
    } else {
        int statusCode = [operation.response statusCode];
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:statusCode message:errorString]);
            }
            return;
        }
    }
}

- (void)sendBlacklistOperationRequest:(int)type
                           params:(id)params
                              url:(NSString*)url
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
        [self handleBlacklistOperationResponse:responseObject type:type error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleBlacklistOperationResponse:nil type:type error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleBlacklistOperationResponse:(id)responseObject
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
            errCode = IM_FAILED_ADD_BLACKLIST;
        } else if (type == 2) {
            errCode = IM_FAILED_REMOVE_BLACKLIST;
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

- (void)sendListBlacklistsRequest:(id)params
                              url:(NSString*)url
                          success:(void (^)(NSArray *clients))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleListBlacklistsOperationResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleListBlacklistsOperationResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleListBlacklistsOperationResponse:(id)responseObject
                                   error:(NSError *)error
                               isSuccess:(BOOL)isSuccess
                               operation:(ANAFHTTPRequestOperation *)operation
                                 success:(void (^)(NSArray *clients))success
                                 failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSArray* blacklists;
        if([res objectForKey:@"response"] != nil)
        {
            blacklists = [[res objectForKey:@"response"] objectForKey:@"blacklist"];
        }
        if(blacklists)
        {
            if(success)
            {
                success(blacklists);
            }
        } else {
            if(success)
            {
                blacklists = [[NSArray alloc] init];
                success(blacklists);
            }
        }
    } else {
        NSUInteger errCode = IM_FAILED_LIST_BLACKLISTS;
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

- (NSDictionary *) converCustomDataToEmoji:(NSDictionary *)customData
{
    if (customData) {
        NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
        for (NSString *key in customData) {
            id value = [customData objectForKey:key];
            if ([value isKindOfClass:[NSString class]]) {
                NSString *strValue = (NSString *)value;
                value = [ANEmojiUtil stringConvertToEmoji:strValue];
            }
            if(value) {
                [dict setObject:value forKey:key];
            } else {
                [dict setObject:[NSNull null] forKey:key];
            }
        }
        return dict;
    } else {
        return nil;
    }
}
@end
