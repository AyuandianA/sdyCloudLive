#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "AnSocialFile.h"
#import "AnSocialAPIClient.h"
#import "ArrownockConstants.h"
#import "ANAFJSONRequestOperation.h"
#import "ANBase64Wrapper.h"
#import "ArrownockException.h"
#import "DeviceManager.h"

@interface AnSocialAPIClient ()
@property (readwrite, nonatomic, strong) NSURL *baseURL;
@property (nonatomic, strong) NSString *appKey;
@property (nonatomic, strong) NSString *apiSecret;
@property double secondTimeout;
@property NSString *sessionId;
@end

@implementation AnSocialAPIClient
@synthesize appKey = _appKey;
@synthesize apiSecret = _apiSecret;
@synthesize sessionId = _sessionId;
@synthesize baseURL = _baseURL;

CFArrayRef certArrayRef;
SecCertificateRef cert;
CFDataRef certDataRef;

- (id)initWithBaseURL:(NSURL *)url {
    self = [super initWithBaseURL:url];
    if (!self) {
        return nil;
    }
    
    [self registerHTTPOperationClass:[ANAFJSONRequestOperation class]];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
    [self setStringEncoding:NSUTF8StringEncoding];
    self.secondTimeout = 60;
    
    return self;
}

- (void)setAppKey:(NSString *)appKey
{
    _appKey = appKey;
}

- (void)setAPISecret:(NSString *)apiSecret
{
    _apiSecret = apiSecret;
}

- (void)setTimeout:(NSTimeInterval)secondTimeout
{
    self.secondTimeout = secondTimeout;
}

- (void)setBaseURL:(NSURL *)url
{
    _baseURL = url;
}

- (void)sendRequest:(NSString *)path
             method:(NSString *)method
             params:(NSDictionary *)params
            success:(void (^)(NSDictionary *response))success
            failure:(void (^)(NSDictionary *response))failure
{    NSMutableDictionary *newParams = [params mutableCopy];
    if (newParams == nil) {
        newParams = [[NSMutableDictionary alloc] init];
    }
    [newParams setObject:_appKey forKey:@"key"];
    
    // for users/create.json and users/auth.json add deviceId
#ifdef DM_ENABLED
    if([path isEqual: @"users/create.json"] || [path isEqual: @"users/auth.json"]) {
        ANDeviceManager *manager = [ANDeviceManager shared];
        NSString *device_id = [manager getDeviceId];
        [newParams setObject:device_id forKey:@"device_id"];
    }
#endif
    
    // check custom_fields
    id cdata = [newParams objectForKey:@"custom_fields"];
    if(cdata)
    {
        NSError *error;
        NSData *jsonData;
        @try
        {
            jsonData = [NSJSONSerialization dataWithJSONObject:cdata options:0 error:&error];
        }
        @catch (NSException * e)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:@"Invalid parmas: custom_fields. Should be a valid NSDictionary" errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        
        if (!jsonData)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        else
        {
            NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            if(json)
            {
                json =[json stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
                [newParams setObject:json forKey:@"custom_fields"];
            }
            else
            {
                NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    failure(errorDict);
                });
                return;
            }
        }
    }
    
    // check properties
    id properties = [newParams objectForKey:@"properties"];
    if(properties)
    {
        NSError *error;
        NSData *jsonData;
        @try
        {
            jsonData = [NSJSONSerialization dataWithJSONObject:properties options:0 error:&error];
        }
        @catch (NSException * e)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:@"Invalid parmas: properties. Should be a valid NSDictionary" errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        
        if (!jsonData)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        else
        {
            NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            if(json)
            {
                json =[json stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
                [newParams setObject:json forKey:@"properties"];
            }
            else
            {
                NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    failure(errorDict);
                });
                return;
            }
        }
    }
    
    // check choices
    id choicesData = [newParams objectForKey:@"choices"];
    if(choicesData)
    {
        NSError *error;
        NSData *jsonData;
        @try
        {
            jsonData = [NSJSONSerialization dataWithJSONObject:choicesData options:0 error:&error];
        }
        @catch (NSException * e)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:@"Invalid parmas: choices. Should be a valid NSDictionary" errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        
        if (!jsonData)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        else
        {
            NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            if(json)
            {
                json =[json stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
                [newParams setObject:json forKey:@"choices"];
            }
            else
            {
                NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    failure(errorDict);
                });
                return;
            }
        }
    }
    
    // check resolutions
    id photoSizeData = [newParams objectForKey:@"resolutions"];
    if(photoSizeData)
    {
        NSError *error;
        NSData *jsonData;
        @try
        {
            jsonData = [NSJSONSerialization dataWithJSONObject:photoSizeData options:0 error:&error];
        }
        @catch (NSException * e)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:@"Invalid parmas: resolutions. Should be a valid NSDictionary" errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        
        if (!jsonData)
        {
            NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                failure(errorDict);
            });
            return;
        }
        else
        {
            NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            if(json)
            {
                json =[json stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
                [newParams setObject:json forKey:@"resolutions"];
            }
            else
            {
                NSDictionary *errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_INVALID_PARAMS statusCode:400];
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    failure(errorDict);
                });
                return;
            }
        }
    }
    
    NSMutableDictionary *dataParams = [[NSMutableDictionary alloc] init];
    NSMutableArray *keys = [[NSMutableArray alloc] init];
    
    if(![method isEqual: @"GET"])
    {
        for (id key in newParams) {
            id value = [newParams objectForKey:key];
            if(value && [value isKindOfClass:[AnSocialFile class]])
            {
                [dataParams setObject:value forKey:key];
                [keys addObject:key];
            }
        }
        
        for(id k in keys)
        {
            [newParams removeObjectForKey:k];
        }
        [keys removeAllObjects];
    }
    
    // encrypt data if api secret exists
    if (_apiSecret)
    {
        newParams = [self getRequestedParams:newParams];
        [newParams setObject:@"1" forKey:@"req_checker"];
        NSString *encrypted = [self encrytParameters:newParams key:_apiSecret];
        NSString *encodedString = (NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(NULL,
                                                                                                        (CFStringRef)encrypted,
                                                                                                        NULL,
                                                                                                        (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                                                                        kCFStringEncodingUTF8));
        [newParams removeAllObjects];
        [newParams setObject:encodedString forKey:@"d"];
    } else {
        if([dataParams count] == 0) {
            newParams = [self getRequestedParams:newParams];
        }
    }
    
    NSMutableURLRequest *request = nil;
    if([dataParams count] > 0)
    {
//        path = [NSString stringWithFormat:@"%@%@",self.baseURL,path];
//        NSLog(@" urlpath = %@ ",path);

        request = [self multipartFormRequestWithMethod:@"POST"
                                                  path:path
                                            parameters:newParams
                             constructingBodyWithBlock: ^(id <ANAFMultipartFormData>formData) {
                                 for(id k in dataParams)
                                 {
                                     AnSocialFile *file = (AnSocialFile*)[dataParams objectForKey:k];
                                     [formData appendPartWithFileData:file.data
                                                                 name:k
                                                             fileName:file.name
                                                             mimeType:@"application/octet-stream"];
                                 }
                             }];
    }
    else
    {
        request = [self requestWithMethod:method path:path parameters:newParams];
    }
    
    // set timeout
    [request setTimeoutInterval:self.secondTimeout];
    
    // set auth token header
    if (_apiSecret)
    {
        [request setValue:_appKey forHTTPHeaderField:@"an-auth-token"];
    }
    
    // set the session id into cookie header
    /*
    if(_sessionId != nil)
    {
        NSDictionary *properties = [NSDictionary dictionaryWithObjectsAndKeys:
                                    request.URL.host, NSHTTPCookieDomain,
                                    request.URL.path, NSHTTPCookiePath,
                                    @"_an.sid", NSHTTPCookieName,
                                    _sessionId, NSHTTPCookieValue,
                                    nil];
        NSHTTPCookie *cookie = [NSHTTPCookie cookieWithProperties:properties];
        NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        [cookieStorage setCookie: cookie];
        NSArray *cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL:request.URL];
        NSDictionary *sheaders = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
        [request setAllHTTPHeaderFields:sheaders];
    }
    */
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    }
                                     failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
                                         [self handleResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
                                     }];
    [operation start];
}

- (id)encodeString:(id)originalString
{
    if (originalString && [originalString isKindOfClass:[NSString class]]) {
        NSString *encodedString = (NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(NULL,
                                                                                                        (CFStringRef)originalString,
                                                                                                        NULL,
                                                                                                        (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                                                                        kCFStringEncodingUTF8 ));
        return encodedString;
    } else {
        return originalString;
    }
}

-(NSDictionary *) getRequestedParams:(NSDictionary *)parameters {
    NSMutableDictionary *dic = [[NSMutableDictionary alloc]init];
    NSArray *array = [self getParamsArray:parameters];
    for (NSDictionary *pair in array) {
        for (NSString *key in pair) {
            [dic setObject:[self encodeString:[pair objectForKey:key]] forKey:key];
        }
    }
    return dic;
}

-(NSArray *) getParamsArray:(NSDictionary *)dictionary {
    return [self resetParamsToArray:nil value:dictionary];
}

-(NSArray *) resetParamsToArray:(NSString *)key value:(id) value {
    NSMutableArray *paramsArray = [NSMutableArray array];
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dictionary = value;
        // Sort dictionary keys to ensure consistent ordering in query string, which is important when deserializing potentially ambiguous sequences, such as an array of dictionaries
        NSSortDescriptor *sortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"description" ascending:YES selector:@selector(caseInsensitiveCompare:)];
        for (id nestedKey in [dictionary.allKeys sortedArrayUsingDescriptors:@[ sortDescriptor ]]) {
            id nestedValue = [dictionary objectForKey:nestedKey];
            if (nestedValue) {
                [paramsArray addObjectsFromArray:[self resetParamsToArray:(key ? [NSString stringWithFormat:@"%@[%@]", key, nestedKey] : nestedKey) value:nestedValue]];
            }
        }
    } else if ([value isKindOfClass:[NSArray class]]) {
        NSArray *array = value;
        for (int i=0; i<array.count; i++) {
            id nestedValue = [array objectAtIndex:i];
            [paramsArray addObjectsFromArray:[self resetParamsToArray:[NSString stringWithFormat:@"%@[%d]", key, i] value:nestedValue]];
        }
    } else if ([value isKindOfClass:[NSSet class]]) {
        NSSet *set = value;
        int i = 0;
        for (id nestedValue in set) {
            [paramsArray addObjectsFromArray:[self resetParamsToArray:[NSString stringWithFormat:@"%@[%d]", key, i] value:nestedValue]];
            i++;
        }
    } else {
        NSMutableDictionary *dic = [[NSMutableDictionary alloc] init];
        [dic setValue:value forKey:key];
        [paramsArray addObject:dic];
    }
    
    return paramsArray;
}

- (void)handleResponse:(id)responseObject
                 error:(NSError *)error
             isSuccess:(BOOL)isSuccess
             operation:(ANAFHTTPRequestOperation *)operation
               success:(void (^)(NSDictionary *response))success
               failure:(void (^)(NSDictionary *response))failure
{
    if (isSuccess) {
        // store session id
        /*
        NSArray *cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies];
        for (NSHTTPCookie *cookie in cookies) {
            if([cookie.name isEqual: @"_an.sid"])
            {
                if(![cookie.value isEqualToString:_sessionId])
                {
                    // we have a new session id, store it
                    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
                    [defaults setValue:cookie.value forKey:@"_an.sid"];
                    [defaults synchronize];
                    [self setSessionId:cookie.value];
                }
                break;
            }
        }
         */
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            success(responseObject);
        });
        return;
    } else {
        int statusCode = [operation.response statusCode];
        NSString *localizedRecoverySuggestion = [error localizedRecoverySuggestion];
        NSDictionary *errorDict = nil;
        if (localizedRecoverySuggestion)
        {
            NSError *err = nil;
            errorDict = [NSJSONSerialization JSONObjectWithData:[localizedRecoverySuggestion dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&err];
            if (err) {
                // no response data from server
                errorDict = [AnSocialAPIClient generateErrorResponse:localizedRecoverySuggestion errorCode:SOCIAL_LOCAL_ERROR statusCode:statusCode];
            }
        }
        else
        {
            // no response data from server
            errorDict = [AnSocialAPIClient generateErrorResponse:[error localizedDescription] errorCode:SOCIAL_LOCAL_ERROR statusCode:statusCode];
        }
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            failure(errorDict);
        });
    }
}

+ (NSDictionary *)generateErrorResponse:(NSString *)message errorCode:(int)errorCode statusCode:(int)statusCode
{
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
    [dict setValue:message forKey:@"message"];
    [dict setValue:[NSNumber numberWithInt:statusCode] forKey:@"code"];
    [dict setValue:@"fail" forKey:@"status"];
    if(errorCode != -1)
    {
        [dict setValue:[NSNumber numberWithInt:errorCode] forKey:@"errorCode"];
    } else {
        [dict setValue:[NSNumber numberWithInt:-900000] forKey:@"errorCode"];
    }
    NSMutableDictionary *meta = [[NSMutableDictionary alloc] init];
    [meta setObject:dict forKey:@"meta"];
    return meta;
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

- (NSString *)encrytParameters:(NSDictionary *)params key:(NSString *)key
{
    NSMutableArray *parts = [NSMutableArray array];
    for (id k in params)
    {
        id value = [params objectForKey: k];
        NSString *part = [NSString stringWithFormat: @"%@=%@", k, value];
        [parts addObject: part];
    }
    NSString *dataString = [parts componentsJoinedByString: @"&"];
    NSData *dataToEncrypt = [dataString dataUsingEncoding:NSUTF8StringEncoding];
    
    // private key
    const char *s = [key cStringUsingEncoding:NSASCIIStringEncoding];
    NSData *keyData = [NSData dataWithBytes:s length:strlen(s)];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH]={0};
    CC_SHA256(keyData.bytes, keyData.length, digest);
    NSData *out=[NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    NSString *hash=[out description];
    hash = [hash stringByReplacingOccurrencesOfString:@" " withString:@""];
    hash = [hash stringByReplacingOccurrencesOfString:@"<" withString:@""];
    hash = [hash stringByReplacingOccurrencesOfString:@">" withString:@""];
    
    NSString *pkey;
    if(32 > [hash length]){
        pkey = hash;
    } else {
        pkey =[hash substringToIndex:32];
    }
    
    char keyPointer[kCCKeySizeAES256 + 2];
    char ivPointer[kCCBlockSizeAES128 + 2];
    BOOL patchNeeded;
    bzero(keyPointer, sizeof(keyPointer)); // fill with zeroes for padding
    patchNeeded = ([pkey length] > kCCKeySizeAES256 + 1);
    if(patchNeeded) {
        pkey = [pkey substringToIndex:kCCKeySizeAES256]; // Ensure that the key isn't longer than what's needed (kCCKeySizeAES256)
    }
    [pkey getCString:keyPointer maxLength:sizeof(keyPointer) encoding:NSUTF8StringEncoding];
    
    // generate iv
    int index = arc4random() % 8;
    NSString *iv = [pkey substringWithRange:NSMakeRange(index, 16)];
    [iv getCString:ivPointer maxLength:sizeof(ivPointer) encoding:NSUTF8StringEncoding];
    
    if (patchNeeded) {
        keyPointer[0] = '\0';  // Previous iOS version than iOS7 set the first char to '\0' if the key was longer than kCCKeySizeAES256
    }
    
    NSUInteger dataLength = [dataToEncrypt length];
    
    //see https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCryptorCreateFromData.3cc.html
    // For block ciphers, the output size will always be less than or equal to the input size plus the size of one block.
    size_t buffSize = dataLength + kCCBlockSizeAES128;
    void *buff = malloc(buffSize);
    
    size_t numBytesEncrypted = 0;
    //refer to http://www.opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h
    //for details on this function
    //Stateless, one-shot encrypt or decrypt operation.
    CCCryptorStatus status = CCCrypt(kCCEncrypt, /* kCCEncrypt, etc. */
                                     kCCAlgorithmAES128, /* kCCAlgorithmAES128, etc. */
                                     kCCOptionPKCS7Padding, /* kCCOptionPKCS7Padding, etc. */
                                     keyPointer, kCCKeySizeAES256, /* key and its length */
                                     ivPointer, /* initialization vector - use random IV everytime */
                                     [dataToEncrypt bytes], [dataToEncrypt length], /* input  */
                                     buff, buffSize,/* data RETURNED here */
                                     &numBytesEncrypted);
    if (status == kCCSuccess) {
        NSData *data = [NSData dataWithBytesNoCopy:buff length:numBytesEncrypted];
        NSString *secret = [ANBase64Wrapper base64EncodedString:data];
        return [NSString stringWithFormat:@"%d%@", (index + 1), secret];
    }
    
    free(buff);
    return nil;
}

@end
