#import "AnDeskHTTPClient.h"
#import "ArrownockExceptionUtils.h"
#import "ANAFJSONRequestOperation.h"
#import <CommonCrypto/CommonDigest.h>
#import "AnDeskMessage.h"
#import "ANEmojiUtil.h"
#import "ANBase64Wrapper.h"
#import "AnDeskGroup.h"

@interface AnDeskHTTPClient()

@end

@implementation AnDeskHTTPClient

- (AnDeskHTTPClient*)setup
{
    [self registerHTTPOperationClass:[ANAFJSONRequestOperation class]];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
    [self setStringEncoding:NSUTF8StringEncoding];
    return self;
}

- (void)sendGetGroupsRequest:(NSString*)url
                        success:(void (^)(NSMutableArray *groups))success
                        failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:nil];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetGroupsInfoResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetGroupsInfoResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetGroupsInfoResponse:(id)responseObject
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSMutableArray *groups))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSMutableArray *groupList = [[NSMutableArray alloc]init];
        NSMutableArray *resultList = nil;
        
        if([[res objectForKey:@"response"] objectForKey:@"groups"]!= nil)
        {
            resultList = [[res objectForKey:@"response"] objectForKey:@"groups"];
            for (int i=0; i<resultList.count; i++) {
                NSDictionary *groupResult = [resultList objectAtIndex:i];
                
                NSMutableArray *tagsList = [groupResult objectForKey:@"tags"];
                NSMutableArray *tags = nil;
                if (tagsList && tagsList.count > 0) {
                    tags = [[NSMutableArray alloc]init];
                    for (int j=0; j<tagsList.count; j++) {
                        NSString *tag = [tagsList objectAtIndex:j];
                        [tags addObject:tag];
                    }
                }
                
                AnDeskGroup *group = [[AnDeskGroup alloc] initWithId:[groupResult objectForKey:@"id"] name:[groupResult objectForKey:@"name"] tags:tags];
                [groupList addObject:group];
            }
        } else {
            if (failure) {
                NSString *errorMessage = @"no response data";
                failure([ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LIST message:errorMessage]);
            }
            return;
        }
        
        if(success)
        {
            success(groupList);
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
                        failure([ArrownockExceptionUtils generateWithErrorCode:-1 message:errorString]);
                    }
                    return;
                }
            } else {
                errorString = localizedRecoverySuggestion;
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:-1 message:errorString]);
                }
                return;
            }
        }
        else {
            errorString = [error localizedDescription];
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:-1 message:errorString]);
            }
            return;
        }
    }
}

- (void)sendCreateSessionRequest:(id)params
                         groupId:(NSString *)groupId
                        clientId:(NSString *)clientId
                             url:(NSString*)url
                         success:(void (^)(NSString *sessionId, NSString *accountId, NSString *accountName))success
                         failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleCreateSessionResponse:responseObject groupId:groupId clientId:clientId error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleCreateSessionResponse:nil groupId:groupId clientId:clientId error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleCreateSessionResponse:(id)responseObject
                            groupId:(NSString *)groupId
                          clientId:(NSString *)clientId
                             error:(NSError *)error
                         isSuccess:(BOOL)isSuccess
                         operation:(ANAFHTTPRequestOperation *)operation
                           success:(void (^)(NSString *sessionId, NSString *accountId, NSString *accountName))success
                           failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* sessionId = nil;
        NSString* accountId = nil;
        NSString* accountName = nil;
        NSString* createdAt = nil;
        NSMutableDictionary *session = [[NSMutableDictionary alloc] init];
        if([[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"id"] != nil)
        {
            sessionId = [[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"id"];
        }
        if([[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"account_id"] != nil)
        {
            accountId = [[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"account_id"];
            [session setObject:accountId forKey:@"account_id"];
        }
        if([[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"name"] != nil)
        {
            accountName = [[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"name"];
        }
        if([[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"created_at"] != nil)
        {
            createdAt = [[[res objectForKey:@"response"] objectForKey:@"session"] objectForKey:@"created_at"];
            [session setObject:createdAt forKey:@"created_at"];
        }
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *key = [[groupId stringByAppendingString:@"_"] stringByAppendingString:clientId];
        
        [session setObject:sessionId forKey:@"session_id"];
        NSDictionary *realSession = [NSDictionary dictionaryWithDictionary:session];
        [defaults setObject:realSession forKey:key];
        
        [defaults synchronize];
        
        if(success)
        {
            success(sessionId, accountId, accountName);
        }
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

- (void)sendGetOfflineMessageRequest:(id)params
                                 url:(NSString*)url
                             success:(void (^)(NSArray *messages, int count))success
                             failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetOfflineMessageResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetOfflineMessageResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetOfflineMessageResponse:(id)responseObject
                              error:(NSError *)error
                          isSuccess:(BOOL)isSuccess
                          operation:(ANAFHTTPRequestOperation *)operation
                            success:(void (^)(NSArray *messages, int count))success
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
                    AnDeskMessage* mm = [AnDeskMessage alloc];
                    NSString *msgId = [m objectForKey:@"msg_id"];
                    NSString *message = [m objectForKey:@"message"];
                    NSNumber *timestamp = [m objectForKey:@"timestamp"];
                    NSDictionary *customData = [m objectForKey:@"customData"];
                    NSString* type = (NSString *)[m objectForKey:@"content_type"];
                    if([@"text" isEqualToString:type])
                    {
                        if(message)
                        {
                            message = [ANEmojiUtil stringConvertToEmoji:message];
                        }
                        [mm initWithType:AnDeskMessageText msgId:msgId groupId:[customData objectForKey:@"groupId"]  accountId:[customData objectForKey:@"accId"] accountName:[customData objectForKey:@"name"] message:message content:nil timestamp:timestamp];
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
                        if ([@"image" isEqualToString:fileType]) {
                            [mm initWithType:AnDeskMessageImage msgId:msgId groupId:[customData objectForKey:@"groupId"]  accountId:[customData objectForKey:@"accId"] accountName:[customData objectForKey:@"name"] message:nil content:data timestamp:timestamp];
                        } else if ([@"audio" isEqualToString:fileType]){
                            [mm initWithType:AnDeskMessageAudio msgId:msgId groupId:[customData objectForKey:@"groupId"]  accountId:[customData objectForKey:@"accId"] accountName:[customData objectForKey:@"name"] message:nil content:data timestamp:timestamp];
                        }
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

@end
