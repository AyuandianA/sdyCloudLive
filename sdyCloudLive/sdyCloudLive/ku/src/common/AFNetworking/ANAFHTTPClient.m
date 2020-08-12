// ANAFHTTPClient.m
//
// Copyright (c) 2011 Gowalla (http://gowalla.com/)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <Foundation/Foundation.h>

#import "ANAFHTTPClient.h"
#import "ANAFHTTPRequestOperation.h"

#import <Availability.h>

#ifdef _SYSTEMCONFIGURATION_H
#import <netinet/in.h>
#import <netinet6/in6.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netdb.h>
#endif

#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
#import <UIKit/UIKit.h>
#endif

#ifdef _SYSTEMCONFIGURATION_H
NSString * const ANAFNetworkingReachabilityDidChangeNotification = @"com.alamofire.networking.reachability.change";
NSString * const ANAFNetworkingReachabilityNotificationStatusItem = @"ANAFNetworkingReachabilityNotificationStatusItem";

typedef SCNetworkReachabilityRef ANAFNetworkReachabilityRef;
typedef void (^ANAFNetworkReachabilityStatusBlock)(ANAFNetworkReachabilityStatus status);
#else
typedef id ANAFNetworkReachabilityRef;
#endif

typedef void (^ANAFCompletionBlock)(void);

static NSString * ANAFBase64EncodedStringFromString(NSString *string) {
    NSData *data = [NSData dataWithBytes:[string UTF8String] length:[string lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];
    NSUInteger length = [data length];
    NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];

    uint8_t *input = (uint8_t *)[data bytes];
    uint8_t *output = (uint8_t *)[mutableData mutableBytes];

    for (NSUInteger i = 0; i < length; i += 3) {
        NSUInteger value = 0;
        for (NSUInteger j = i; j < (i + 3); j++) {
            value <<= 8;
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }

        static uint8_t const kANAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        NSUInteger idx = (i / 3) * 4;
        output[idx + 0] = kANAFBase64EncodingTable[(value >> 18) & 0x3F];
        output[idx + 1] = kANAFBase64EncodingTable[(value >> 12) & 0x3F];
        output[idx + 2] = (i + 1) < length ? kANAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
        output[idx + 3] = (i + 2) < length ? kANAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
    }

    return [[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding];
}

static NSString * ANAFPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    static NSString * const kANAFCharactersToBeEscaped = @":/?&=;+!@#$()',*";
    static NSString * const kANAFCharactersToLeaveUnescaped = @"[].";
    /*
	return (__bridge_transfer  NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kANAFCharactersToLeaveUnescaped, (__bridge CFStringRef)kANAFCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
    */
    
    NSString *unescapedString = [string stringByReplacingPercentEscapesUsingEncoding:encoding];
    if(unescapedString == string)
    {
        return (__bridge_transfer  NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kANAFCharactersToLeaveUnescaped, (__bridge CFStringRef)kANAFCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
    }
    else
    {
        return string;
    }
    
}

#pragma mark -

@interface ANAFQueryStringPair : NSObject
@property (readwrite, nonatomic, strong) id field;
@property (readwrite, nonatomic, strong) id value;

- (id)initWithField:(id)field value:(id)value;

- (NSString *)URLEncodedStringValueWithEncoding:(NSStringEncoding)stringEncoding;
@end

@implementation ANAFQueryStringPair
@synthesize field = _field;
@synthesize value = _value;

- (id)initWithField:(id)field value:(id)value {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.field = field;
    self.value = value;

    return self;
}

- (NSString *)URLEncodedStringValueWithEncoding:(NSStringEncoding)stringEncoding {
    if (!self.value || [self.value isEqual:[NSNull null]]) {
        return ANAFPercentEscapedQueryStringPairMemberFromStringWithEncoding([self.field description], stringEncoding);
    } else {
        return [NSString stringWithFormat:@"%@=%@", ANAFPercentEscapedQueryStringPairMemberFromStringWithEncoding([self.field description], stringEncoding), ANAFPercentEscapedQueryStringPairMemberFromStringWithEncoding([self.value description], stringEncoding)];
    }
}

@end

#pragma mark -

extern NSArray * ANAFQueryStringPairsFromDictionary(NSDictionary *dictionary);
extern NSArray * ANAFQueryStringPairsFromKeyAndValue(NSString *key, id value);

NSString * ANAFQueryStringFromParametersWithEncoding(NSDictionary *parameters, NSStringEncoding stringEncoding) {
    NSMutableArray *mutablePairs = [NSMutableArray array];
    for (ANAFQueryStringPair *pair in ANAFQueryStringPairsFromDictionary(parameters)) {
        [mutablePairs addObject:[pair URLEncodedStringValueWithEncoding:stringEncoding]];
    }

    return [mutablePairs componentsJoinedByString:@"&"];
}

NSArray * ANAFQueryStringPairsFromDictionary(NSDictionary *dictionary) {
    return ANAFQueryStringPairsFromKeyAndValue(nil, dictionary);
}

NSArray * ANAFQueryStringPairsFromKeyAndValue(NSString *key, id value) {
    NSMutableArray *mutableQueryStringComponents = [NSMutableArray array];

    if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dictionary = value;
        // Sort dictionary keys to ensure consistent ordering in query string, which is important when deserializing potentially ambiguous sequences, such as an array of dictionaries
        NSSortDescriptor *sortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"description" ascending:YES selector:@selector(caseInsensitiveCompare:)];
        for (id nestedKey in [dictionary.allKeys sortedArrayUsingDescriptors:@[ sortDescriptor ]]) {
            id nestedValue = [dictionary objectForKey:nestedKey];
            if (nestedValue) {
                [mutableQueryStringComponents addObjectsFromArray:ANAFQueryStringPairsFromKeyAndValue((key ? [NSString stringWithFormat:@"%@[%@]", key, nestedKey] : nestedKey), nestedValue)];
            }
        }
    } else if ([value isKindOfClass:[NSArray class]]) {
        NSArray *array = value;
        for (id nestedValue in array) {
            [mutableQueryStringComponents addObjectsFromArray:ANAFQueryStringPairsFromKeyAndValue([NSString stringWithFormat:@"%@[]", key], nestedValue)];
        }
    } else if ([value isKindOfClass:[NSSet class]]) {
        NSSet *set = value;
        for (id obj in set) {
            [mutableQueryStringComponents addObjectsFromArray:ANAFQueryStringPairsFromKeyAndValue(key, obj)];
        }
    } else {
        [mutableQueryStringComponents addObject:[[ANAFQueryStringPair alloc] initWithField:key value:value]];
    }

    return mutableQueryStringComponents;
}

@interface ANAFStreamingMultipartFormData : NSObject <ANAFMultipartFormData>
- (id)initWithURLRequest:(NSMutableURLRequest *)urlRequest
          stringEncoding:(NSStringEncoding)encoding;

- (NSMutableURLRequest *)requestByFinalizingMultipartFormData;
@end

#pragma mark -

@interface ANAFHTTPClient ()
@property (readwrite, nonatomic, strong) NSURL *baseURL;
@property (readwrite, nonatomic, strong) NSMutableArray *registeredHTTPOperationClassNames;
@property (readwrite, nonatomic, strong) NSMutableDictionary *defaultHeaders;
@property (readwrite, nonatomic, strong) NSURLCredential *defaultCredential;
@property (readwrite, nonatomic, strong) NSOperationQueue *operationQueue;
#ifdef _SYSTEMCONFIGURATION_H
@property (readwrite, nonatomic, assign) ANAFNetworkReachabilityRef networkReachability;
@property (readwrite, nonatomic, assign) ANAFNetworkReachabilityStatus networkReachabilityStatus;
@property (readwrite, nonatomic, copy) ANAFNetworkReachabilityStatusBlock networkReachabilityStatusBlock;
#endif

#ifdef _SYSTEMCONFIGURATION_H
- (void)startMonitoringNetworkReachability;
- (void)stopMonitoringNetworkReachability;
#endif
@end

@implementation ANAFHTTPClient
@synthesize baseURL = _baseURL;
@synthesize stringEncoding = _stringEncoding;
@synthesize parameterEncoding = _parameterEncoding;
@synthesize registeredHTTPOperationClassNames = _registeredHTTPOperationClassNames;
@synthesize defaultHeaders = _defaultHeaders;
@synthesize defaultCredential = _defaultCredential;
@synthesize operationQueue = _operationQueue;
#ifdef _SYSTEMCONFIGURATION_H
@synthesize networkReachability = _networkReachability;
@synthesize networkReachabilityStatus = _networkReachabilityStatus;
@synthesize networkReachabilityStatusBlock = _networkReachabilityStatusBlock;
#endif
@synthesize defaultSSLPinningMode = _defaultSSLPinningMode;
@synthesize allowsInvalidSSLCertificate = _allowsInvalidSSLCertificate;

+ (instancetype)clientWithBaseURL:(NSURL *)url {
    return [[self alloc] initWithBaseURL:url];
}

- (id)init {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"%@ Failed to call designated initializer. Invoke `initWithBaseURL:` instead.", NSStringFromClass([self class])] userInfo:nil];
}

- (id)initWithBaseURL:(NSURL *)url {
    NSParameterAssert(url);

    self = [super init];
    if (!self) {
        return nil;
    }

    // Ensure terminal slash for baseURL path, so that NSURL +URLWithString:relativeToURL: works as expected
    if ([[url path] length] > 0 && ![[url absoluteString] hasSuffix:@"/"]) {
        url = [url URLByAppendingPathComponent:@""];
    }

    self.baseURL = url;

    self.stringEncoding = NSUTF8StringEncoding;
    self.parameterEncoding = ANAFFormURLParameterEncoding;

    self.registeredHTTPOperationClassNames = [NSMutableArray array];

	self.defaultHeaders = [NSMutableDictionary dictionary];

    // Accept-Language HTTP Header; see http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.4
    NSMutableArray *acceptLanguagesComponents = [NSMutableArray array];
    [[NSLocale preferredLanguages] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        float q = 1.0f - (idx * 0.1f);
        [acceptLanguagesComponents addObject:[NSString stringWithFormat:@"%@;q=%0.1g", obj, q]];
        *stop = q <= 0.5f;
    }];
    [self setDefaultHeader:@"Accept-Language" value:[acceptLanguagesComponents componentsJoinedByString:@", "]];

    NSString *userAgent = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu"
#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    // User-Agent Header; see http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.43
    userAgent = [NSString stringWithFormat:@"%@/%@ (%@; iOS %@; Scale/%0.2f)", [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleExecutableKey] ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleIdentifierKey], (__bridge id)CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), kCFBundleVersionKey) ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleVersionKey], [[UIDevice currentDevice] model], [[UIDevice currentDevice] systemVersion], ([[UIScreen mainScreen] respondsToSelector:@selector(scale)] ? [[UIScreen mainScreen] scale] : 1.0f)];
#elif defined(__MAC_OS_X_VERSION_MIN_REQUIRED)
    userAgent = [NSString stringWithFormat:@"%@/%@ (Mac OS X %@)", [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleExecutableKey] ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleIdentifierKey], [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"] ?: [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge NSString *)kCFBundleVersionKey], [[NSProcessInfo processInfo] operatingSystemVersionString]];
#endif
#pragma clang diagnostic pop
    if (userAgent) {
        if (![userAgent canBeConvertedToEncoding:NSASCIIStringEncoding]) {
            NSMutableString *mutableUserAgent = [userAgent mutableCopy];
            CFStringTransform((__bridge CFMutableStringRef)(mutableUserAgent), NULL, kCFStringTransformToLatin, false);
            userAgent = mutableUserAgent;
        }
        [self setDefaultHeader:@"User-Agent" value:userAgent];
    }

#ifdef _SYSTEMCONFIGURATION_H
    self.networkReachabilityStatus = ANAFNetworkReachabilityStatusUnknown;
    [self startMonitoringNetworkReachability];
#endif

    self.operationQueue = [[NSOperationQueue alloc] init];
	[self.operationQueue setMaxConcurrentOperationCount:NSOperationQueueDefaultMaxConcurrentOperationCount];

    // #ifdef included for backwards-compatibility
#ifdef _ANAFNETWORKING_ALLOW_INVALID_SSL_CERTIFICATES_
    self.allowsInvalidSSLCertificate = YES;
#endif
    
    return self;
}

- (void)dealloc {
#ifdef _SYSTEMCONFIGURATION_H
    [self stopMonitoringNetworkReachability];
#endif
}

- (NSString *)description {
    return [NSString stringWithFormat:@"<%@: %p, baseURL: %@, defaultHeaders: %@, registeredOperationClasses: %@, operationQueue: %@>", NSStringFromClass([self class]), self, [self.baseURL absoluteString], self.defaultHeaders, self.registeredHTTPOperationClassNames, self.operationQueue];
}

#pragma mark -

#ifdef _SYSTEMCONFIGURATION_H
static BOOL ANAFURLHostIsIPAddress(NSURL *url) {
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;

    return [url host] && (inet_pton(AF_INET, [[url host] UTF8String], &sa_in) == 1 || inet_pton(AF_INET6, [[url host] UTF8String], &sa_in6) == 1);
}

static ANAFNetworkReachabilityStatus ANAFNetworkReachabilityStatusForFlags(SCNetworkReachabilityFlags flags) {
    BOOL isReachable = ((flags & kSCNetworkReachabilityFlagsReachable) != 0);
    BOOL needsConnection = ((flags & kSCNetworkReachabilityFlagsConnectionRequired) != 0);
    BOOL canConnectionAutomatically = (((flags & kSCNetworkReachabilityFlagsConnectionOnDemand ) != 0) || ((flags & kSCNetworkReachabilityFlagsConnectionOnTraffic) != 0));
    BOOL canConnectWithoutUserInteraction = (canConnectionAutomatically && (flags & kSCNetworkReachabilityFlagsInterventionRequired) == 0);
    BOOL isNetworkReachable = (isReachable && (!needsConnection || canConnectWithoutUserInteraction));

    ANAFNetworkReachabilityStatus status = ANAFNetworkReachabilityStatusUnknown;
    if (isNetworkReachable == NO) {
        status = ANAFNetworkReachabilityStatusNotReachable;
    }
#if	TARGET_OS_IPHONE
    else if ((flags & kSCNetworkReachabilityFlagsIsWWAN) != 0) {
        status = ANAFNetworkReachabilityStatusReachableViaWWAN;
    }
#endif
    else {
        status = ANAFNetworkReachabilityStatusReachableViaWiFi;
    }

    return status;
}

static void ANAFNetworkReachabilityCallback(SCNetworkReachabilityRef __unused target, SCNetworkReachabilityFlags flags, void *info) {
    ANAFNetworkReachabilityStatus status = ANAFNetworkReachabilityStatusForFlags(flags);
    ANAFNetworkReachabilityStatusBlock block = (__bridge ANAFNetworkReachabilityStatusBlock)info;
    if (block) {
        block(status);
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        NSNotificationCenter *notificationCenter = [NSNotificationCenter defaultCenter];
        [notificationCenter postNotificationName:ANAFNetworkingReachabilityDidChangeNotification object:nil userInfo:[NSDictionary dictionaryWithObject:[NSNumber numberWithInteger:status] forKey:ANAFNetworkingReachabilityNotificationStatusItem]];
    });
}

static const void * ANAFNetworkReachabilityRetainCallback(const void *info) {
    return Block_copy(info);
}

static void ANAFNetworkReachabilityReleaseCallback(const void *info) {
    if (info) {
        Block_release(info);
    }
}

- (void)startMonitoringNetworkReachability {
    [self stopMonitoringNetworkReachability];

    if (!self.baseURL) {
        return;
    }

    self.networkReachability = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, [[self.baseURL host] UTF8String]);

    if (!self.networkReachability) {
        return;
    }

    __weak __typeof(&*self)weakSelf = self;
    ANAFNetworkReachabilityStatusBlock callback = ^(ANAFNetworkReachabilityStatus status) {
        __strong __typeof(&*weakSelf)strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.networkReachabilityStatus = status;
        if (strongSelf.networkReachabilityStatusBlock) {
            strongSelf.networkReachabilityStatusBlock(status);
        }
    };

    SCNetworkReachabilityContext context = {0, (__bridge void *)callback, ANAFNetworkReachabilityRetainCallback, ANAFNetworkReachabilityReleaseCallback, NULL};
    SCNetworkReachabilitySetCallback(self.networkReachability, ANAFNetworkReachabilityCallback, &context);

    /* Network reachability monitoring does not establish a baseline for IP addresses as it does for hostnames, so if the base URL host is an IP address, the initial reachability callback is manually triggered.
     */
    if (ANAFURLHostIsIPAddress(self.baseURL)) {
        SCNetworkReachabilityFlags flags;
        SCNetworkReachabilityGetFlags(self.networkReachability, &flags);
        dispatch_async(dispatch_get_main_queue(), ^{
            ANAFNetworkReachabilityStatus status = ANAFNetworkReachabilityStatusForFlags(flags);
            callback(status);
        });
    }

    SCNetworkReachabilityScheduleWithRunLoop(self.networkReachability, CFRunLoopGetMain(), kCFRunLoopCommonModes);
}

- (void)stopMonitoringNetworkReachability {
    if (self.networkReachability) {
        SCNetworkReachabilityUnscheduleFromRunLoop(self.networkReachability, CFRunLoopGetMain(), kCFRunLoopCommonModes);

        CFRelease(_networkReachability);
        _networkReachability = NULL;
    }
}

- (void)setReachabilityStatusChangeBlock:(void (^)(ANAFNetworkReachabilityStatus status))block {
    self.networkReachabilityStatusBlock = block;
}
#endif

#pragma mark -

- (BOOL)registerHTTPOperationClass:(Class)operationClass {
    if (![operationClass isSubclassOfClass:[ANAFHTTPRequestOperation class]]) {
        return NO;
    }

    NSString *className = NSStringFromClass(operationClass);
    [self.registeredHTTPOperationClassNames removeObject:className];
    [self.registeredHTTPOperationClassNames insertObject:className atIndex:0];

    return YES;
}

- (void)unregisterHTTPOperationClass:(Class)operationClass {
    NSString *className = NSStringFromClass(operationClass);
    [self.registeredHTTPOperationClassNames removeObject:className];
}

#pragma mark -

- (NSString *)defaultValueForHeader:(NSString *)header {
	return [self.defaultHeaders valueForKey:header];
}

- (void)setDefaultHeader:(NSString *)header value:(NSString *)value {
	[self.defaultHeaders setValue:value forKey:header];
}

- (void)setAuthorizationHeaderWithUsername:(NSString *)username password:(NSString *)password {
	NSString *basicAuthCredentials = [NSString stringWithFormat:@"%@:%@", username, password];
    [self setDefaultHeader:@"Authorization" value:[NSString stringWithFormat:@"Basic %@", ANAFBase64EncodedStringFromString(basicAuthCredentials)]];
}

- (void)setAuthorizationHeaderWithToken:(NSString *)token {
    [self setDefaultHeader:@"Authorization" value:[NSString stringWithFormat:@"Token token=\"%@\"", token]];
}

- (void)clearAuthorizationHeader {
	[self.defaultHeaders removeObjectForKey:@"Authorization"];
}

#pragma mark -

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters
{
    NSParameterAssert(method);

    if (!path) {
        path = @"";
    }
    NSLog(@"\n\n\n\n\n url == %@\n%@\n\n 传参 = %@",self.baseURL,path,parameters);
    NSURL *url = [NSURL URLWithString:path relativeToURL:self.baseURL];
	NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url];
    [request setHTTPMethod:method];
    [request setAllHTTPHeaderFields:self.defaultHeaders];

    if (parameters) {
        if ([method isEqualToString:@"GET"] || [method isEqualToString:@"HEAD"] || [method isEqualToString:@"DELETE"]) {
            url = [NSURL URLWithString:[[url absoluteString] stringByAppendingFormat:[path rangeOfString:@"?"].location == NSNotFound ? @"?%@" : @"&%@", ANAFQueryStringFromParametersWithEncoding(parameters, self.stringEncoding)]];
            [request setURL:url];
        } else {
            NSString *charset = (__bridge NSString *)CFStringConvertEncodingToIANACharSetName(CFStringConvertNSStringEncodingToEncoding(self.stringEncoding));
            NSError *error = nil;

            switch (self.parameterEncoding) {
                case ANAFFormURLParameterEncoding:;
                    [request setValue:[NSString stringWithFormat:@"application/x-www-form-urlencoded; charset=%@", charset] forHTTPHeaderField:@"Content-Type"];
                    [request setHTTPBody:[ANAFQueryStringFromParametersWithEncoding(parameters, self.stringEncoding) dataUsingEncoding:self.stringEncoding]];
                    break;
                case ANAFJSONParameterEncoding:;
                    [request setValue:[NSString stringWithFormat:@"application/json; charset=%@", charset] forHTTPHeaderField:@"Content-Type"];
                    [request setHTTPBody:[NSJSONSerialization dataWithJSONObject:parameters options:(NSJSONWritingOptions)0 error:&error]];
                    break;
                case ANAFPropertyListParameterEncoding:;
                    [request setValue:[NSString stringWithFormat:@"application/x-plist; charset=%@", charset] forHTTPHeaderField:@"Content-Type"];
                    [request setHTTPBody:[NSPropertyListSerialization dataWithPropertyList:parameters format:NSPropertyListXMLFormat_v1_0 options:0 error:&error]];
                    break;
            }

            if (error) {
                NSLog(@"%@ %@: %@", [self class], NSStringFromSelector(_cmd), error);
            }
        }
    }

	return request;
}

- (NSMutableURLRequest *)multipartFormRequestWithMethod:(NSString *)method
                                                   path:(NSString *)path
                                             parameters:(NSDictionary *)parameters
                              constructingBodyWithBlock:(void (^)(id <ANAFMultipartFormData> formData))block
{
    NSParameterAssert(method);
    NSParameterAssert(![method isEqualToString:@"GET"] && ![method isEqualToString:@"HEAD"]);

    NSMutableURLRequest *request = [self requestWithMethod:method path:path parameters:nil];

    __block ANAFStreamingMultipartFormData *formData = [[ANAFStreamingMultipartFormData alloc] initWithURLRequest:request stringEncoding:self.stringEncoding];

    if (parameters) {
        for (ANAFQueryStringPair *pair in ANAFQueryStringPairsFromDictionary(parameters)) {
            NSData *data = nil;
            if ([pair.value isKindOfClass:[NSData class]]) {
                data = pair.value;
            } else if ([pair.value isEqual:[NSNull null]]) {
                data = [NSData data];
            } else {
                data = [[pair.value description] dataUsingEncoding:self.stringEncoding];
            }

            if (data) {
                [formData appendPartWithFormData:data name:[pair.field description]];
            }
        }
    }

    if (block) {
        block(formData);
    }

    return [formData requestByFinalizingMultipartFormData];
}

- (ANAFHTTPRequestOperation *)HTTPRequestOperationWithRequest:(NSURLRequest *)urlRequest
                                                    success:(void (^)(ANAFHTTPRequestOperation *operation, id responseObject))success
                                                    failure:(void (^)(ANAFHTTPRequestOperation *operation, NSError *error))failure
{
    ANAFHTTPRequestOperation *operation = nil;
    
    for (NSString *className in self.registeredHTTPOperationClassNames) {
        Class operationClass = NSClassFromString(className);
        if (operationClass && [operationClass canProcessRequest:urlRequest]) {
            operation = [(ANAFHTTPRequestOperation *)[operationClass alloc] initWithRequest:urlRequest];
            break;
        }
    }

    if (!operation) {
        operation = [[ANAFHTTPRequestOperation alloc] initWithRequest:urlRequest];
    }

    [operation setCompletionBlockWithSuccess:success failure:failure];

    operation.credential = self.defaultCredential;
    operation.SSLPinningMode = self.defaultSSLPinningMode;
    operation.allowsInvalidSSLCertificate = self.allowsInvalidSSLCertificate;

    return operation;
}

#pragma mark -

- (void)enqueueHTTPRequestOperation:(ANAFHTTPRequestOperation *)operation {
    [self.operationQueue addOperation:operation];
}

- (void)cancelAllHTTPOperationsWithMethod:(NSString *)method
                                     path:(NSString *)path
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu"
    NSString *pathToBeMatched = [[[self requestWithMethod:(method ?: @"GET") path:path parameters:nil] URL] path];
#pragma clang diagnostic pop

    for (NSOperation *operation in [self.operationQueue operations]) {
        if (![operation isKindOfClass:[ANAFHTTPRequestOperation class]]) {
            continue;
        }

        BOOL hasMatchingMethod = !method || [method isEqualToString:[[(ANAFHTTPRequestOperation *)operation request] HTTPMethod]];
        BOOL hasMatchingPath = [[[[(ANAFHTTPRequestOperation *)operation request] URL] path] isEqual:pathToBeMatched];

        if (hasMatchingMethod && hasMatchingPath) {
            [operation cancel];
        }
    }
}

- (void)enqueueBatchOfHTTPRequestOperationsWithRequests:(NSArray *)urlRequests
                                          progressBlock:(void (^)(NSUInteger numberOfFinishedOperations, NSUInteger totalNumberOfOperations))progressBlock
                                        completionBlock:(void (^)(NSArray *operations))completionBlock
{
    NSMutableArray *mutableOperations = [NSMutableArray array];
    for (NSURLRequest *request in urlRequests) {
        ANAFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:nil failure:nil];
        [mutableOperations addObject:operation];
    }

    [self enqueueBatchOfHTTPRequestOperations:mutableOperations progressBlock:progressBlock completionBlock:completionBlock];
}

- (void)enqueueBatchOfHTTPRequestOperations:(NSArray *)operations
                              progressBlock:(void (^)(NSUInteger numberOfFinishedOperations, NSUInteger totalNumberOfOperations))progressBlock
                            completionBlock:(void (^)(NSArray *operations))completionBlock
{
    __block dispatch_group_t dispatchGroup = dispatch_group_create();
    NSBlockOperation *batchedOperation = [NSBlockOperation blockOperationWithBlock:^{
        dispatch_group_notify(dispatchGroup, dispatch_get_main_queue(), ^{
            if (completionBlock) {
                completionBlock(operations);
            }
        });
#if !OS_OBJECT_USE_OBJC
        dispatch_release(dispatchGroup);
#endif
    }];

    for (ANAFHTTPRequestOperation *operation in operations) {
        ANAFCompletionBlock originalCompletionBlock = [operation.completionBlock copy];
        __weak __typeof(&*operation)weakOperation = operation;
        operation.completionBlock = ^{
            __strong __typeof(&*weakOperation)strongOperation = weakOperation;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu"
            dispatch_queue_t queue = strongOperation.successCallbackQueue ?: dispatch_get_main_queue();
#pragma clang diagnostic pop
            dispatch_group_async(dispatchGroup, queue, ^{
                if (originalCompletionBlock) {
                    originalCompletionBlock();
                }

                NSUInteger numberOfFinishedOperations = [[operations indexesOfObjectsPassingTest:^BOOL(id op, NSUInteger __unused idx,  BOOL __unused *stop) {
                    return [op isFinished];
                }] count];

                if (progressBlock) {
                    progressBlock(numberOfFinishedOperations, [operations count]);
                }

                dispatch_group_leave(dispatchGroup);
            });
        };

        dispatch_group_enter(dispatchGroup);
        [batchedOperation addDependency:operation];
    }
    [self.operationQueue addOperations:operations waitUntilFinished:NO];
    [self.operationQueue addOperation:batchedOperation];
}

#pragma mark -

- (void)getPath:(NSString *)path
     parameters:(NSDictionary *)parameters
        success:(void (^)(ANAFHTTPRequestOperation *operation, id responseObject))success
        failure:(void (^)(ANAFHTTPRequestOperation *operation, NSError *error))failure
{
	NSURLRequest *request = [self requestWithMethod:@"GET" path:path parameters:parameters];
    
    NSLog(@"\n\n\n\n\n GETurl == %@%@",path,parameters);
    ANAFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:success failure:failure];
    [self enqueueHTTPRequestOperation:operation];
}

- (void)postPath:(NSString *)path
      parameters:(NSDictionary *)parameters
         success:(void (^)(ANAFHTTPRequestOperation *operation, id responseObject))success
         failure:(void (^)(ANAFHTTPRequestOperation *operation, NSError *error))failure
{
	NSURLRequest *request = [self requestWithMethod:@"POST" path:path parameters:parameters];
//    NSLog(@"\n\n\n\n\n POSTurl == %@\n\n%@",path,parameters);
	ANAFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:success failure:failure];
    [self enqueueHTTPRequestOperation:operation];
}

- (void)putPath:(NSString *)path
     parameters:(NSDictionary *)parameters
        success:(void (^)(ANAFHTTPRequestOperation *operation, id responseObject))success
        failure:(void (^)(ANAFHTTPRequestOperation *operation, NSError *error))failure
{
	NSURLRequest *request = [self requestWithMethod:@"PUT" path:path parameters:parameters];
	ANAFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:success failure:failure];
    [self enqueueHTTPRequestOperation:operation];
}

- (void)deletePath:(NSString *)path
        parameters:(NSDictionary *)parameters
           success:(void (^)(ANAFHTTPRequestOperation *operation, id responseObject))success
           failure:(void (^)(ANAFHTTPRequestOperation *operation, NSError *error))failure
{
	NSURLRequest *request = [self requestWithMethod:@"DELETE" path:path parameters:parameters];
	ANAFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:success failure:failure];
    [self enqueueHTTPRequestOperation:operation];
}

- (void)patchPath:(NSString *)path
       parameters:(NSDictionary *)parameters
          success:(void (^)(ANAFHTTPRequestOperation *operation, id responseObject))success
          failure:(void (^)(ANAFHTTPRequestOperation *operation, NSError *error))failure
{
    NSURLRequest *request = [self requestWithMethod:@"PATCH" path:path parameters:parameters];
	ANAFHTTPRequestOperation *operation = [self HTTPRequestOperationWithRequest:request success:success failure:failure];
    [self enqueueHTTPRequestOperation:operation];
}

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)aDecoder {
    NSURL *baseURL = [aDecoder decodeObjectForKey:@"baseURL"];

    self = [self initWithBaseURL:baseURL];
    if (!self) {
        return nil;
    }

    self.stringEncoding = [aDecoder decodeIntegerForKey:@"stringEncoding"];
    self.parameterEncoding = (ANAFHTTPClientParameterEncoding) [aDecoder decodeIntegerForKey:@"parameterEncoding"];
    self.registeredHTTPOperationClassNames = [aDecoder decodeObjectForKey:@"registeredHTTPOperationClassNames"];
    self.defaultHeaders = [aDecoder decodeObjectForKey:@"defaultHeaders"];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder {
    [aCoder encodeObject:self.baseURL forKey:@"baseURL"];
    [aCoder encodeInteger:(NSInteger)self.stringEncoding forKey:@"stringEncoding"];
    [aCoder encodeInteger:self.parameterEncoding forKey:@"parameterEncoding"];
    [aCoder encodeObject:self.registeredHTTPOperationClassNames forKey:@"registeredHTTPOperationClassNames"];
    [aCoder encodeObject:self.defaultHeaders forKey:@"defaultHeaders"];
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    ANAFHTTPClient *HTTPClient = [[[self class] allocWithZone:zone] initWithBaseURL:self.baseURL];

    HTTPClient.stringEncoding = self.stringEncoding;
    HTTPClient.parameterEncoding = self.parameterEncoding;
    HTTPClient.registeredHTTPOperationClassNames = [self.registeredHTTPOperationClassNames mutableCopyWithZone:zone];
    HTTPClient.defaultHeaders = [self.defaultHeaders mutableCopyWithZone:zone];
#ifdef _SYSTEMCONFIGURATION_H
    HTTPClient.networkReachabilityStatusBlock = self.networkReachabilityStatusBlock;
#endif
    return HTTPClient;
}

@end

#pragma mark -

static NSString * const kANAFMultipartFormBoundary = @"Boundary+0xAbCdEfGbOuNdArY";

static NSString * const kANAFMultipartFormCRLF = @"\r\n";

static NSInteger const kANAFStreamToStreamBufferSize = 1024 * 1024; //1 meg default

static inline NSString * ANAFMultipartFormInitialBoundary() {
    return [NSString stringWithFormat:@"--%@%@", kANAFMultipartFormBoundary, kANAFMultipartFormCRLF];
}

static inline NSString * ANAFMultipartFormEncapsulationBoundary() {
    return [NSString stringWithFormat:@"%@--%@%@", kANAFMultipartFormCRLF, kANAFMultipartFormBoundary, kANAFMultipartFormCRLF];
}

static inline NSString * ANAFMultipartFormFinalBoundary() {
    return [NSString stringWithFormat:@"%@--%@--%@", kANAFMultipartFormCRLF, kANAFMultipartFormBoundary, kANAFMultipartFormCRLF];
}

static inline NSString * ANAFContentTypeForPathExtension(NSString *extension) {
#ifdef __UTTYPE__
    NSString *UTI = (__bridge_transfer NSString *)UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, (__bridge CFStringRef)extension, NULL);
    NSString *contentType = (__bridge_transfer NSString *)UTTypeCopyPreferredTagWithClass((__bridge CFStringRef)UTI, kUTTagClassMIMEType);
    if (!contentType) {
        return @"application/octet-stream";
    } else {
        return contentType;
    }
#else
    return @"application/octet-stream";
#endif
}

NSUInteger const kANAFUploadStream3GSuggestedPacketSize = 1024 * 16;
NSTimeInterval const kANAFUploadStream3GSuggestedDelay = 0.2;

@interface ANAFHTTPBodyPart : NSObject
@property (nonatomic, assign) NSStringEncoding stringEncoding;
@property (nonatomic, strong) NSDictionary *headers;
@property (nonatomic, strong) id body;
@property (nonatomic, assign) unsigned long long bodyContentLength;
@property (nonatomic, strong) NSInputStream *inputStream;

@property (nonatomic, assign) BOOL hasInitialBoundary;
@property (nonatomic, assign) BOOL hasFinalBoundary;

@property (nonatomic, readonly, getter = hasBytesAvailable) BOOL bytesAvailable;
@property (nonatomic, readonly) unsigned long long contentLength;

- (NSInteger)read:(uint8_t *)buffer
        maxLength:(NSUInteger)length;
@end

@interface ANAFMultipartBodyStream : NSInputStream <NSStreamDelegate>
@property (nonatomic, assign) NSUInteger numberOfBytesInPacket;
@property (nonatomic, assign) NSTimeInterval delay;
@property (nonatomic, strong) NSInputStream *inputStream;
@property (nonatomic, readonly) unsigned long long contentLength;
@property (nonatomic, readonly, getter = isEmpty) BOOL empty;

- (id)initWithStringEncoding:(NSStringEncoding)encoding;
- (void)setInitialAndFinalBoundaries;
- (void)appendHTTPBodyPart:(ANAFHTTPBodyPart *)bodyPart;
@end

#pragma mark -

@interface ANAFStreamingMultipartFormData ()
@property (readwrite, nonatomic, copy) NSMutableURLRequest *request;
@property (readwrite, nonatomic, strong) ANAFMultipartBodyStream *bodyStream;
@property (readwrite, nonatomic, assign) NSStringEncoding stringEncoding;
@end

@implementation ANAFStreamingMultipartFormData
@synthesize request = _request;
@synthesize bodyStream = _bodyStream;
@synthesize stringEncoding = _stringEncoding;

- (id)initWithURLRequest:(NSMutableURLRequest *)urlRequest
          stringEncoding:(NSStringEncoding)encoding
{
    self = [super init];
    if (!self) {
        return nil;
    }

    self.request = urlRequest;
    self.stringEncoding = encoding;
    self.bodyStream = [[ANAFMultipartBodyStream alloc] initWithStringEncoding:encoding];

    return self;
}

- (BOOL)appendPartWithFileURL:(NSURL *)fileURL
                         name:(NSString *)name
                        error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(fileURL);
    NSParameterAssert(name);

    NSString *fileName = [fileURL lastPathComponent];
    NSString *mimeType = ANAFContentTypeForPathExtension([fileURL pathExtension]);
    
    return [self appendPartWithFileURL:fileURL name:name fileName:fileName mimeType:mimeType error:error];
}

- (BOOL)appendPartWithFileURL:(NSURL *)fileURL
                         name:(NSString *)name
                     fileName:(NSString *)fileName
                     mimeType:(NSString *)mimeType
                        error:(NSError * __autoreleasing *)error
{
    NSParameterAssert(fileURL);
    NSParameterAssert(name);
    NSParameterAssert(fileName);
    NSParameterAssert(mimeType);

    if (![fileURL isFileURL]) {
        NSDictionary *userInfo = [NSDictionary dictionaryWithObject:NSLocalizedStringFromTable(@"Expected URL to be a file URL", @"ANAFNetworking", nil) forKey:NSLocalizedFailureReasonErrorKey];
        if (error != NULL) {
            *error = [[NSError alloc] initWithDomain:ANAFNetworkingErrorDomain code:NSURLErrorBadURL userInfo:userInfo];
        }

        return NO;
    } else if ([fileURL checkResourceIsReachableAndReturnError:error] == NO) {
        NSDictionary *userInfo = [NSDictionary dictionaryWithObject:NSLocalizedStringFromTable(@"File URL not reachable.", @"ANAFNetworking", nil) forKey:NSLocalizedFailureReasonErrorKey];
        if (error != NULL) {
            *error = [[NSError alloc] initWithDomain:ANAFNetworkingErrorDomain code:NSURLErrorBadURL userInfo:userInfo];
        }

        return NO;
    }

    NSMutableDictionary *mutableHeaders = [NSMutableDictionary dictionary];
    [mutableHeaders setValue:[NSString stringWithFormat:@"form-data; name=\"%@\"; filename=\"%@\"", name, fileName] forKey:@"Content-Disposition"];
    [mutableHeaders setValue:mimeType forKey:@"Content-Type"];

    ANAFHTTPBodyPart *bodyPart = [[ANAFHTTPBodyPart alloc] init];
    bodyPart.stringEncoding = self.stringEncoding;
    bodyPart.headers = mutableHeaders;
    bodyPart.body = fileURL;

    NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:[fileURL path] error:nil];
    bodyPart.bodyContentLength = [[fileAttributes objectForKey:NSFileSize] unsignedLongLongValue];

    [self.bodyStream appendHTTPBodyPart:bodyPart];

    return YES;
}


- (void)appendPartWithInputStream:(NSInputStream *)inputStream
                             name:(NSString *)name
                         fileName:(NSString *)fileName
                           length:(unsigned long long)length
                         mimeType:(NSString *)mimeType
{
    NSParameterAssert(name);
    NSParameterAssert(fileName);
    NSParameterAssert(mimeType);

    NSMutableDictionary *mutableHeaders = [NSMutableDictionary dictionary];
    [mutableHeaders setValue:[NSString stringWithFormat:@"form-data; name=\"%@\"; filename=\"%@\"", name, fileName] forKey:@"Content-Disposition"];
    [mutableHeaders setValue:mimeType forKey:@"Content-Type"];


    ANAFHTTPBodyPart *bodyPart = [[ANAFHTTPBodyPart alloc] init];
    bodyPart.stringEncoding = self.stringEncoding;
    bodyPart.headers = mutableHeaders;
    bodyPart.body = inputStream;

    bodyPart.bodyContentLength = length;

    [self.bodyStream appendHTTPBodyPart:bodyPart];
}

- (void)appendPartWithFileData:(NSData *)data
                          name:(NSString *)name
                      fileName:(NSString *)fileName
                      mimeType:(NSString *)mimeType
{
    NSParameterAssert(name);
    NSParameterAssert(fileName);
    NSParameterAssert(mimeType);

    NSMutableDictionary *mutableHeaders = [NSMutableDictionary dictionary];
    [mutableHeaders setValue:[NSString stringWithFormat:@"form-data; name=\"%@\"; filename=\"%@\"", name, fileName] forKey:@"Content-Disposition"];
    [mutableHeaders setValue:mimeType forKey:@"Content-Type"];

    [self appendPartWithHeaders:mutableHeaders body:data];
}

- (void)appendPartWithFormData:(NSData *)data
                          name:(NSString *)name
{
    NSParameterAssert(name);

    NSMutableDictionary *mutableHeaders = [NSMutableDictionary dictionary];
    [mutableHeaders setValue:[NSString stringWithFormat:@"form-data; name=\"%@\"", name] forKey:@"Content-Disposition"];

    [self appendPartWithHeaders:mutableHeaders body:data];
}

- (void)appendPartWithHeaders:(NSDictionary *)headers
                         body:(NSData *)body
{
    NSParameterAssert(body);

    ANAFHTTPBodyPart *bodyPart = [[ANAFHTTPBodyPart alloc] init];
    bodyPart.stringEncoding = self.stringEncoding;
    bodyPart.headers = headers;
    bodyPart.bodyContentLength = [body length];
    bodyPart.body = body;

    [self.bodyStream appendHTTPBodyPart:bodyPart];
}

- (void)throttleBandwidthWithPacketSize:(NSUInteger)numberOfBytes
                                  delay:(NSTimeInterval)delay
{
    self.bodyStream.numberOfBytesInPacket = numberOfBytes;
    self.bodyStream.delay = delay;
}

- (NSMutableURLRequest *)requestByFinalizingMultipartFormData {
    if ([self.bodyStream isEmpty]) {
        return self.request;
    }

    // Reset the initial and final boundaries to ensure correct Content-Length
    [self.bodyStream setInitialAndFinalBoundaries];

    [self.request setValue:[NSString stringWithFormat:@"multipart/form-data; boundary=%@", kANAFMultipartFormBoundary] forHTTPHeaderField:@"Content-Type"];
    [self.request setValue:[NSString stringWithFormat:@"%llu", [self.bodyStream contentLength]] forHTTPHeaderField:@"Content-Length"];
    [self.request setHTTPBodyStream:self.bodyStream];

    return self.request;
}

@end

#pragma mark -

@interface ANAFMultipartBodyStream () <NSCopying>
@property (nonatomic, assign) NSStreamStatus streamStatus;
@property (nonatomic, strong) NSError *streamError;
@property (nonatomic, assign) NSStringEncoding stringEncoding;
@property (nonatomic, strong) NSMutableArray *HTTPBodyParts;
@property (nonatomic, strong) NSEnumerator *HTTPBodyPartEnumerator;
@property (nonatomic, strong) ANAFHTTPBodyPart *currentHTTPBodyPart;
@property (nonatomic, strong) NSOutputStream *outputStream;
@property (nonatomic, strong) NSMutableData *buffer;
@end

@implementation ANAFMultipartBodyStream
@synthesize streamStatus = _streamStatus;
@synthesize streamError = _streamError;
@synthesize stringEncoding = _stringEncoding;
@synthesize HTTPBodyParts = _HTTPBodyParts;
@synthesize HTTPBodyPartEnumerator = _HTTPBodyPartEnumerator;
@synthesize currentHTTPBodyPart = _currentHTTPBodyPart;
@synthesize inputStream = _inputStream;
@synthesize outputStream = _outputStream;
@synthesize buffer = _buffer;
@synthesize numberOfBytesInPacket = _numberOfBytesInPacket;
@synthesize delay = _delay;

- (id)initWithStringEncoding:(NSStringEncoding)encoding {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.stringEncoding = encoding;
    self.HTTPBodyParts = [NSMutableArray array];
    self.numberOfBytesInPacket = NSIntegerMax;

    return self;
}

- (void)setInitialAndFinalBoundaries {
    if ([self.HTTPBodyParts count] > 0) {
        for (ANAFHTTPBodyPart *bodyPart in self.HTTPBodyParts) {
            bodyPart.hasInitialBoundary = NO;
            bodyPart.hasFinalBoundary = NO;
        }

        [[self.HTTPBodyParts objectAtIndex:0] setHasInitialBoundary:YES];
        [[self.HTTPBodyParts lastObject] setHasFinalBoundary:YES];
    }
}

- (void)appendHTTPBodyPart:(ANAFHTTPBodyPart *)bodyPart {
    [self.HTTPBodyParts addObject:bodyPart];
}

- (BOOL)isEmpty {
    return [self.HTTPBodyParts count] == 0;
}

#pragma mark - NSInputStream

- (NSInteger)read:(uint8_t *)buffer
        maxLength:(NSUInteger)length
{
    if ([self streamStatus] == NSStreamStatusClosed) {
        return 0;
    }
    NSInteger bytesRead = 0;

    while ((NSUInteger)bytesRead < MIN(length, self.numberOfBytesInPacket)) {
        if (!self.currentHTTPBodyPart || ![self.currentHTTPBodyPart hasBytesAvailable]) {
            if (!(self.currentHTTPBodyPart = [self.HTTPBodyPartEnumerator nextObject])) {
                break;
            }
        } else {
            bytesRead += [self.currentHTTPBodyPart read:&buffer[bytesRead] maxLength:(length - (NSUInteger)bytesRead)];
            if (self.delay > 0.0f) {
                [NSThread sleepForTimeInterval:self.delay];
            }
        }
    }
    return bytesRead;
}

- (BOOL)getBuffer:(__unused uint8_t **)buffer
           length:(__unused NSUInteger *)len
{
    return NO;
}

- (BOOL)hasBytesAvailable {
    return [self streamStatus] == NSStreamStatusOpen;
}

#pragma mark - NSStream

- (void)open {
    if (self.streamStatus == NSStreamStatusOpen) {
        return;
    }

    self.streamStatus = NSStreamStatusOpen;

    [self setInitialAndFinalBoundaries];
    self.HTTPBodyPartEnumerator = [self.HTTPBodyParts objectEnumerator];
}

- (void)close {
    self.streamStatus = NSStreamStatusClosed;
}

- (id)propertyForKey:(__unused NSString *)key {
    return nil;
}

- (BOOL)setProperty:(__unused id)property
             forKey:(__unused NSString *)key
{
    return NO;
}

- (void)scheduleInRunLoop:(__unused NSRunLoop *)aRunLoop
                  forMode:(__unused NSString *)mode
{}

- (void)removeFromRunLoop:(__unused NSRunLoop *)aRunLoop
                  forMode:(__unused NSString *)mode
{}

- (unsigned long long)contentLength {
    unsigned long long length = 0;
    for (ANAFHTTPBodyPart *bodyPart in self.HTTPBodyParts) {
        length += [bodyPart contentLength];
    }

    return length;
}

#pragma mark - Undocumented CFReadStream Bridged Methods

- (void)_scheduleInCFRunLoop:(__unused CFRunLoopRef)aRunLoop
                     forMode:(__unused CFStringRef)aMode
{}

- (void)_unscheduleFromCFRunLoop:(__unused CFRunLoopRef)aRunLoop
                         forMode:(__unused CFStringRef)aMode
{}

- (BOOL)_setCFClientFlags:(__unused CFOptionFlags)inFlags
                 callback:(__unused CFReadStreamClientCallBack)inCallback
                  context:(__unused CFStreamClientContext *)inContext {
    return NO;
}

#pragma mark - NSCopying

-(id)copyWithZone:(NSZone *)zone {
    ANAFMultipartBodyStream *bodyStreamCopy = [[[self class] allocWithZone:zone] initWithStringEncoding:self.stringEncoding];

    for (ANAFHTTPBodyPart *bodyPart in self.HTTPBodyParts) {
        [bodyStreamCopy appendHTTPBodyPart:[bodyPart copy]];
    }

    [bodyStreamCopy setInitialAndFinalBoundaries];

    return bodyStreamCopy;
}

@end

#pragma mark -

typedef enum {
    ANAFEncapsulationBoundaryPhase = 1,
    ANAFHeaderPhase                = 2,
    ANAFBodyPhase                  = 3,
    ANAFFinalBoundaryPhase         = 4,
} ANAFHTTPBodyPartReadPhase;

@interface ANAFHTTPBodyPart () <NSCopying> {
    ANAFHTTPBodyPartReadPhase _phase;
    NSInputStream *_inputStream;
    unsigned long long _phaseReadOffset;
}

- (BOOL)transitionToNextPhase;
- (NSInteger)readData:(NSData *)data
           intoBuffer:(uint8_t *)buffer
            maxLength:(NSUInteger)length;
@end

@implementation ANAFHTTPBodyPart
@synthesize stringEncoding = _stringEncoding;
@synthesize headers = _headers;
@synthesize body = _body;
@synthesize bodyContentLength = _bodyContentLength;
@synthesize inputStream = _inputStream;
@synthesize hasInitialBoundary = _hasInitialBoundary;
@synthesize hasFinalBoundary = _hasFinalBoundary;

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    [self transitionToNextPhase];

    return self;
}

- (void)dealloc {
    if (_inputStream) {
        [_inputStream close];
        _inputStream = nil;
    }
}

- (NSInputStream *)inputStream {
    if (!_inputStream) {
        if ([self.body isKindOfClass:[NSData class]]) {
            _inputStream = [NSInputStream inputStreamWithData:self.body];
        } else if ([self.body isKindOfClass:[NSURL class]]) {
            _inputStream = [NSInputStream inputStreamWithURL:self.body];
        } else if ([self.body isKindOfClass:[NSInputStream class]]) {
            _inputStream = self.body;
        }
    }

    return _inputStream;
}

- (NSString *)stringForHeaders {
    NSMutableString *headerString = [NSMutableString string];
    for (NSString *field in [self.headers allKeys]) {
        [headerString appendString:[NSString stringWithFormat:@"%@: %@%@", field, [self.headers valueForKey:field], kANAFMultipartFormCRLF]];
    }
    [headerString appendString:kANAFMultipartFormCRLF];

    return [NSString stringWithString:headerString];
}

- (unsigned long long)contentLength {
    unsigned long long length = 0;

    NSData *encapsulationBoundaryData = [([self hasInitialBoundary] ? ANAFMultipartFormInitialBoundary() : ANAFMultipartFormEncapsulationBoundary()) dataUsingEncoding:self.stringEncoding];
    length += [encapsulationBoundaryData length];

    NSData *headersData = [[self stringForHeaders] dataUsingEncoding:self.stringEncoding];
    length += [headersData length];

    length += _bodyContentLength;

    NSData *closingBoundaryData = ([self hasFinalBoundary] ? [ANAFMultipartFormFinalBoundary() dataUsingEncoding:self.stringEncoding] : [NSData data]);
    length += [closingBoundaryData length];

    return length;
}

- (BOOL)hasBytesAvailable {
    // Allows `read:maxLength:` to be called again if `ANAFMultipartFormFinalBoundary` doesn't fit into the available buffer
    if (_phase == ANAFFinalBoundaryPhase) {
        return YES;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcovered-switch-default"
    switch (self.inputStream.streamStatus) {
        case NSStreamStatusNotOpen:
        case NSStreamStatusOpening:
        case NSStreamStatusOpen:
        case NSStreamStatusReading:
        case NSStreamStatusWriting:
            return YES;
        case NSStreamStatusAtEnd:
        case NSStreamStatusClosed:
        case NSStreamStatusError:
        default:
            return NO;
    }
#pragma clang diagnostic pop
}

- (NSInteger)read:(uint8_t *)buffer
        maxLength:(NSUInteger)length
{
    NSInteger bytesRead = 0;

    if (_phase == ANAFEncapsulationBoundaryPhase) {
        NSData *encapsulationBoundaryData = [([self hasInitialBoundary] ? ANAFMultipartFormInitialBoundary() : ANAFMultipartFormEncapsulationBoundary()) dataUsingEncoding:self.stringEncoding];
        bytesRead += [self readData:encapsulationBoundaryData intoBuffer:&buffer[bytesRead] maxLength:(length - (NSUInteger)bytesRead)];
    }

    if (_phase == ANAFHeaderPhase) {
        NSData *headersData = [[self stringForHeaders] dataUsingEncoding:self.stringEncoding];
        bytesRead += [self readData:headersData intoBuffer:&buffer[bytesRead] maxLength:(length - (NSUInteger)bytesRead)];
    }

    if (_phase == ANAFBodyPhase) {
        bytesRead += [self.inputStream read:&buffer[bytesRead] maxLength:(length - (NSUInteger)bytesRead)];

        if ([self.inputStream streamStatus] >= NSStreamStatusAtEnd) {
            [self transitionToNextPhase];
        }
    }

    if (_phase == ANAFFinalBoundaryPhase) {
        NSData *closingBoundaryData = ([self hasFinalBoundary] ? [ANAFMultipartFormFinalBoundary() dataUsingEncoding:self.stringEncoding] : [NSData data]);
        bytesRead += [self readData:closingBoundaryData intoBuffer:&buffer[bytesRead] maxLength:(length - (NSUInteger)bytesRead)];
    }

    return bytesRead;
}

- (NSInteger)readData:(NSData *)data
           intoBuffer:(uint8_t *)buffer
            maxLength:(NSUInteger)length
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu"
    NSRange range = NSMakeRange((NSUInteger)_phaseReadOffset, MIN([data length] - ((NSUInteger)_phaseReadOffset), length));
    [data getBytes:buffer range:range];
#pragma clang diagnostic pop

    _phaseReadOffset += range.length;

    if (((NSUInteger)_phaseReadOffset) >= [data length]) {
        [self transitionToNextPhase];
    }

    return (NSInteger)range.length;
}

- (BOOL)transitionToNextPhase {
    if (![[NSThread currentThread] isMainThread]) {
        [self performSelectorOnMainThread:@selector(transitionToNextPhase) withObject:nil waitUntilDone:YES];
        return YES;
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcovered-switch-default"
    switch (_phase) {
        case ANAFEncapsulationBoundaryPhase:
            _phase = ANAFHeaderPhase;
            break;
        case ANAFHeaderPhase:
            [self.inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSRunLoopCommonModes];
            [self.inputStream open];
            _phase = ANAFBodyPhase;
            break;
        case ANAFBodyPhase:
            [self.inputStream close];
            _phase = ANAFFinalBoundaryPhase;
            break;
        case ANAFFinalBoundaryPhase:
        default:
            _phase = ANAFEncapsulationBoundaryPhase;
            break;
    }
    _phaseReadOffset = 0;
#pragma clang diagnostic pop

    return YES;
}

#pragma mark - NSCopying

- (id)copyWithZone:(NSZone *)zone {
    ANAFHTTPBodyPart *bodyPart = [[[self class] allocWithZone:zone] init];

    bodyPart.stringEncoding = self.stringEncoding;
    bodyPart.headers = self.headers;
    bodyPart.bodyContentLength = self.bodyContentLength;
    bodyPart.body = self.body;

    return bodyPart;
}

@end
