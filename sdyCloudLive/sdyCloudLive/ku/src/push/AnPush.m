//
//  AnPush.m
//  AnPush
//
//  Created by Arrownock on 1/19/13.
//  Copyright (c) 2013 Arrownock. All rights reserved.
//

#import "AnPush.h"
#import "ArrownockConstants.h"
#import "AnPushOAuthCore.h"
#import "ANBase64Wrapper.h"
#import "AnPushHTTPClient.h"
#import "AnPushURLConnection.h"
#import "ArrownockExceptionUtils.h"
#import "ANKeychainItemWrapper.h"
#import "DeviceManager.h"
#import <CommonCrypto/CommonDigest.h>
#import <UserNotifications/UserNotifications.h>

#define NO_APP_KEY_ERROR @"No app key. Please use setup to set app key first."
#define NO_TOKEN_ERROR @"No device token. Please use setup to set device token first."
#define INVALID_BADGE @"Badge number should equal or larger than 0."
#define ANID_KEY @"ANPUSH_ANID"
#define ANPUSH_LAST_REGISTER @"ANPUSH_LAST_REGISTER"
#define DEAFULT_REGISTER_CACHE 600;

#define registerOverwriteBodyFormatString @"channel=%@&date=%@&device_token=%@&id=%@&key=%@&overwrite=true&type=ios&signature=%@"
#define registerAppendBodyFormatString @"channel=%@&date=%@&device_token=%@&id=%@&key=%@&type=ios&signature=%@"
#define registerOverwriteBodyForDeviceFormatString @"channel=%@&date=%@&device_token=%@&id=%@&key=%@&overwrite=true&real_device_id=%@&type=ios&signature=%@"
#define registerAppendBodyForDeviceFormatString @"channel=%@&date=%@&device_token=%@&id=%@&key=%@&real_device_id=%@&type=ios&signature=%@"
#define unregisterAllBodyFormatString @"date=%@&device_token=%@&key=%@&remove=true&type=ios&signature=%@"
#define unregisterSomeBodyFormatString @"channel=%@&date=%@&device_token=%@&key=%@&type=ios&signature=%@"
#define setMuteBodyFormatString @"date=%@&device_token=%@&key=%@&mute=true&type=ios&signature=%@"
#define setMutePeriodBodyFormatString @"date=%@&device_token=%@&duration=%@&hour=%@&key=%@&minute=%@&mute=true&type=ios&signature=%@"
#define setSilentBodyFormatString @"date=%@&device_token=%@&duration=%@&hour=%@&key=%@&minute=%@&type=ios&signature=%@&resend=%@&set=true"
#define clearMuteBodyFormatString @"date=%@&device_token=%@&key=%@&mute=false&type=ios&signature=%@"
#define clearSilentBodyFormatString @"date=%@&device_token=%@&key=%@&set=false&type=ios&signature=%@"
#define setBadgeBodyFormatString @"date=%@&device_token=%@&key=%@&badge=%@&type=ios&signature=%@"
#define defaultAPIHost ARROWNOCK_API_HOST
#define apiVersion ARROWNOCK_API_VERSION
#define apiURLFormatString @"%@://%@/%@/%@?key=%@"

@interface AnPush()

@end


@implementation AnPush {
    NSString *appKey;
    NSString *deviceId;
    NSString *apiHost;
    BOOL isSecure;
    id <AnPushDelegate> anPushDelegate;
    NSString *token;
    NSMutableDictionary *paramDict;
    NSString *registerEndpoint;
    NSString *unregisterEndpoint;
    NSString *muteEndpoint;
    NSString *silentEndpoint;
    NSString *setBadgeEndpoint;
    NSString *fetchCacheEndpoint;
    AnPushHTTPClient *_httpClient;
    int registerAnIdCount;
    double registerCacheTime;
}

static AnPush* _sharedInstance = nil;

+ (AnPush*)shared
{
    if (_sharedInstance == nil) {
        _sharedInstance = [super alloc];
    }
    return _sharedInstance;
}

+ (id)alloc
{
    if(_sharedInstance == nil)
    {
        _sharedInstance = [super alloc];
    }
	return _sharedInstance;
}

- (void)init:(NSString *)key deviceToken:(NSData *)deviceToken delegate:(id<AnPushDelegate>)delegate secure:(BOOL)secure
{
	if (self != nil) {
        appKey = key;
        anPushDelegate = delegate;
        isSecure = secure;
        
        registerEndpoint = @"push_notification/signed_register.json";
        unregisterEndpoint = @"push_notification/signed_unregister.json";
        muteEndpoint = @"push_notification/signed_mute.json";
        silentEndpoint = @"push_notification/signed_silent_period.json";
        setBadgeEndpoint = @"push_notification/signed_set_badge.json";
        fetchCacheEndpoint = @"push_notification/messages/fetch.json";
        
		NSString *str = [NSString stringWithFormat:@"%@", deviceToken];
        NSString *tokenString = [str stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
        token = [tokenString stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        NSArray *keyArray = [[NSArray alloc] initWithObjects:@"appKey", @"token", @"channel", @"date",  @"hour", @"minute", @"duration", @"resend", @"id", @"badge", nil];
        NSArray *valueArray = [[NSArray alloc] initWithObjects:appKey, token, [[NSArray alloc] init], @"", @"", @"", @"", @"", @"", @"", nil];
        paramDict = [[NSMutableDictionary alloc] initWithObjects: valueArray forKeys:keyArray];
        _httpClient = [[AnPushHTTPClient alloc] init];
        registerAnIdCount = 0;
        registerCacheTime = DEAFULT_REGISTER_CACHE;
	}
#ifdef DM_ENABLED
    if (key != nil) {
        [ANDeviceManager initializeWithAppKey:key secure:secure];
    }
#endif
}

- (void)init:(NSString *)key deviceToken:(NSData *)deviceToken secure:(BOOL)secure
{
    if (self != nil) {
        appKey = key;
        isSecure = secure;
        
        registerEndpoint = @"push_notification/signed_register.json";
        unregisterEndpoint = @"push_notification/signed_unregister.json";
        muteEndpoint = @"push_notification/signed_mute.json";
        silentEndpoint = @"push_notification/signed_silent_period.json";
        setBadgeEndpoint = @"push_notification/signed_set_badge.json";
        fetchCacheEndpoint = @"push_notification/messages/fetch.json";
        
        NSString *str = [NSString stringWithFormat:@"%@", deviceToken];
        NSString *tokenString = [str stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
        token = [tokenString stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        NSArray *keyArray = [[NSArray alloc] initWithObjects:@"appKey", @"token", @"channel", @"date",  @"hour", @"minute", @"duration", @"resend", @"id", @"badge", nil];
        NSArray *valueArray = [[NSArray alloc] initWithObjects:appKey, token, [[NSArray alloc] init], @"", @"", @"", @"", @"", @"", @"", nil];
        paramDict = [[NSMutableDictionary alloc] initWithObjects: valueArray forKeys:keyArray];
        _httpClient = [[AnPushHTTPClient alloc] init];
        registerAnIdCount = 0;
        registerCacheTime = DEAFULT_REGISTER_CACHE;
    }
#ifdef DM_ENABLED
    if (key != nil) {
        [ANDeviceManager initializeWithAppKey:key secure:secure];
    }
#endif
}

- (void)init:(NSString *)key secure:(BOOL)secure
{
    if (self != nil) {
        appKey = key;
        isSecure = secure;
        registerCacheTime = DEAFULT_REGISTER_CACHE;
    }
#ifdef DM_ENABLED
    if (key != nil) {
        [ANDeviceManager initializeWithAppKey:key secure:secure];
    }
#endif
}

+ (void)registerForPushNotification
{
    if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 8.0)
    {
        if([[[UIDevice currentDevice] systemVersion] floatValue] >= 10.0)
        {
            UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
            [center requestAuthorizationWithOptions:(UNAuthorizationOptionSound | UNAuthorizationOptionAlert | UNAuthorizationOptionBadge) completionHandler:^(BOOL granted, NSError * _Nullable error)
             {
                 if( !error )
                 {
                     NSLog( @"Push Notification is allowed by user" );
                 }
                 else
                 {
                     NSLog( @"Push Notification is disallowed by user" );
                 }  
             }];
            [[UIApplication sharedApplication] registerForRemoteNotifications];
        }
        else
        {
            [[UIApplication sharedApplication] registerUserNotificationSettings:[UIUserNotificationSettings settingsForTypes:(UIUserNotificationTypeSound | UIUserNotificationTypeAlert | UIUserNotificationTypeBadge) categories:nil]];
            [[UIApplication sharedApplication] registerForRemoteNotifications];
        }
    }
    else
    {
        [[UIApplication sharedApplication] registerForRemoteNotificationTypes:(UIRemoteNotificationTypeAlert | UIRemoteNotificationTypeBadge | UIRemoteNotificationTypeSound)];
    }
}

+ (void)registerForPushNotification:(UIRemoteNotificationType)types
{
    if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 8.0)
    {
        [[UIApplication sharedApplication] registerUserNotificationSettings:[UIUserNotificationSettings settingsForTypes:(UIUserNotificationType)types categories:nil]];
        [[UIApplication sharedApplication] registerForRemoteNotifications];
    }
    else
    {
        [[UIApplication sharedApplication] registerForRemoteNotificationTypes:(UIRemoteNotificationType)types];
    }
}

+ (void)setup:(NSString *)appKey deviceToken:(NSData *)deviceToken delegate:(id<AnPushDelegate>)delegate secure:(BOOL)secure __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = @"invalid appKey";
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (deviceToken == nil) {
        message = @"invalid deviceToken";
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    
    [[AnPush alloc] init:appKey deviceToken:deviceToken delegate:delegate secure:secure];
}

+ (void)setup:(NSString *)appKey deviceToken:(NSData *)deviceToken secure:(BOOL)secure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = @"invalid appKey";
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (deviceToken == nil) {
        message = @"invalid deviceToken";
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    
    [[AnPush alloc] init:appKey deviceToken:deviceToken secure:secure];
}

+ (void)setup:(NSString *)appKey secure:(BOOL)secure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = @"invalid appKey";
        errorCode = PUSH_INVALID_APP_KEY;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    
    [[AnPush alloc] init:appKey secure:secure];
}

+ (void) didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)deviceToken appKey:(NSString*) appKey delegate:(id <AnPushDelegate>)delegate secure:(BOOL)secure
{
    [AnPush setup:appKey deviceToken:deviceToken delegate:delegate secure:secure];
}

+ (void) didReceiveRemoteNotification:(NSDictionary *)userInfo
{
#ifdef LOAD_PUSH_FROM_SERVER
    [[AnPush shared] fetchCachedPushNotifications];
#else
    if([AnPush shared]->anPushDelegate && [[AnPush shared]->anPushDelegate respondsToSelector:@selector(didRecievedNotifications:)]) {
        if(userInfo) {
            NSMutableDictionary* messages = [[NSMutableDictionary alloc] init];
            [messages setObject:userInfo forKey:@"push"];
            dispatch_async(dispatch_get_main_queue(), ^{
                [[AnPush shared]->anPushDelegate didRecievedNotifications:messages];
            });
        }
    }
#endif
}

+ (void) applicationDidBecomeActive
{
#ifdef LOAD_PUSH_FROM_SERVER
    [[AnPush shared] fetchCachedPushNotifications];
#endif
}

+ (void) didRegisterForRemoteNotificationsWithDeviceToken
{
#ifdef LOAD_PUSH_FROM_SERVER
    [[AnPush shared] fetchCachedPushNotifications];
#endif
}

+ (void) didReceiveRemoteNotification
{
#ifdef LOAD_PUSH_FROM_SERVER
    [[AnPush shared] fetchCachedPushNotifications];
#endif
}

- (void)setDeviceToken:(NSData *)deviceToken
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (deviceToken == nil) {
        message = @"invalid deviceToken";
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    
    if (self != nil) {
        registerEndpoint = @"push_notification/signed_register.json";
        unregisterEndpoint = @"push_notification/signed_unregister.json";
        muteEndpoint = @"push_notification/signed_mute.json";
        silentEndpoint = @"push_notification/signed_silent_period.json";
        setBadgeEndpoint = @"push_notification/signed_set_badge.json";
        fetchCacheEndpoint = @"push_notification/messages/fetch.json";
        
        NSString *str = [NSString stringWithFormat:@"%@", deviceToken];
        NSString *tokenString = [str stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
        token = [tokenString stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        NSArray *keyArray = [[NSArray alloc] initWithObjects:@"appKey", @"token", @"channel", @"date",  @"hour", @"minute", @"duration", @"resend", @"id", @"badge", nil];
        NSArray *valueArray = [[NSArray alloc] initWithObjects:appKey, token, [[NSArray alloc] init], @"", @"", @"", @"", @"", @"", @"", nil];
        paramDict = [[NSMutableDictionary alloc] initWithObjects: valueArray forKeys:keyArray];
        _httpClient = [[AnPushHTTPClient alloc] init];
        registerAnIdCount = 0;
    }
}

- (NSString *)encodeString:(NSString *)originalString
{
    NSString *encodedString = (NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(NULL,
                                                                                                    (CFStringRef)originalString,
                                                                                                    NULL,
                                                                                                    (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                                                                    kCFStringEncodingUTF8));
    return encodedString;
}

- (void)setId:(NSString *)theId
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (token == nil) {
        message = @"AnPush enable failed: Please call setup function first.";
        errorCode = PUSH_INVALID_DEVICE_ID;
        return;
    }
    if (appKey == nil) {
        message = @"AnPush enable failed: Please call setup function first.";
        errorCode = PUSH_INVALID_DEVICE_ID;
        return;
    }
    if (theId == nil) {
        message = @"invalid deviceId.";
        errorCode = PUSH_INVALID_DEVICE_ID;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    deviceId = theId;
}

- (void)setHost:(NSString *)host
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (host == nil) {
        message = @"invalid host.";
        errorCode = PUSH_INVALID_HOST;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    
    apiHost = host;
}

- (void)enable
{
    if (token == nil) {
        NSLog(@"AnPush enable failed: Please call setup function first.");
        return;
    }
    if (appKey == nil) {
        NSLog(@"AnPush enable failed: Please call setup function first.");
        return;
    }
    if (registerAnIdCount >= 5 ) {
        registerAnIdCount = 0;
        return;
    } else {
        registerAnIdCount ++;
        //get anid then register anid without channel
        [self registerAnId:^(NSString* anid){
            NSLog(@"AnPush enable successful");
        } failure:^(ArrownockException *exception) {
            NSLog(@"AnPush enable failed: %@", exception.message);
            [self enable];
        }];
    }
}

- (void)disable
{
    if (token == nil) {
        NSLog(@"AnPush disable failed: Please call setup function first.");
        return;
    }
    [self unregister:^(NSString *anid) {
        NSLog(@"AnPush disable successful");
    } failure:^(ArrownockException *exception) {
        NSLog(@"AnPush disable failed: %@", exception.message);
    }];
}

- (void)registerAnId:(void (^)(NSString* anid))success failure:(void (^)(ArrownockException *exception))failure
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSNumber *tempLastRegister = [defaults objectForKey:ANPUSH_LAST_REGISTER];
    double lastRegister = 0;
    if(tempLastRegister != nil) {
        lastRegister = [tempLastRegister doubleValue];
    }
    BOOL isRegitered = NO;
    double now = [[NSDate date] timeIntervalSince1970];
    if((now - lastRegister) <= registerCacheTime) {
        isRegitered = YES;
    }
    
    NSString *cachedAnid = [defaults objectForKey:ANID_KEY];
    if(deviceId != nil && cachedAnid != nil && ![deviceId isEqualToString:cachedAnid]) {
        isRegitered = NO;
    }
    if(isRegitered) {
        success(cachedAnid);
        return;
    }
    
    NSString *deviceIdString = nil;
    if(deviceId != nil) {
        deviceIdString = deviceId;
    } else if(cachedAnid != nil){
        deviceIdString = cachedAnid;
    } else {
        deviceIdString = [self getAnID];
    }
    
#ifdef DM_ENABLED
    ANDeviceManager *manager = [ANDeviceManager shared];
    NSString *real_device_id = [manager getDeviceId];
    [paramDict setValue:real_device_id forKey:@"real_device_id"];
#endif
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"token"];
    [paramDict setObject:appKey forKey:@"appKey"];
    [paramDict setObject:deviceIdString forKey:@"id"];
    [paramDict setObject:@"" forKey:@"channel"];

    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodRegisterAppend, paramDict);
    signatureString = [self encodeString:signatureString];
    [params setObject:signatureString forKey:@"signature"];
    
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    deviceIdString = [self encodeString:deviceIdString];
    
    [params setObject:@"" forKey:@"channel"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:deviceIdString forKey:@"id"];
    [params setObject:@"ios" forKey:@"type"];
#ifdef DM_ENABLED
    [params setValue:real_device_id forKey:@"real_device_id"];
#endif
    
    NSString *urlString = [self getAPIURL:registerEndpoint withAppKey:appKey];
    
    if(_httpClient)
    {
        [_httpClient sendRegistrationRequest:params type:1 url:urlString success:success failure:failure];
    }
}



- (void)register:(NSArray *)channels overwrite:(BOOL)overwrite __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (channels == nil) {
        message = @"invalid channels";
        errorCode = PUSH_INVALID_CHANNELS;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }

    [paramDict setValue:channels forKey:@"channel"];
//    if(deviceId) {
//        [paramDict setValue:deviceId forKey:@"id"];
//    } else {
//        [paramDict setValue:@"" forKey:@"id"];
//    }
 
    [paramDict setValue:[self getDeviceUniqueId] forKey:@"id"];
    
    if(overwrite) {
        [self talkToAPI:AnPushMethodRegisterOverwrite withParams:paramDict];
    } else {
        [self talkToAPI:AnPushMethodRegisterAppend withParams:paramDict];
    }
}

- (void)register:(NSArray *)channels overwrite:(BOOL)overwrite success:(void (^)(NSString* anid))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (channels == nil) {
        message = @"invalid channels";
        errorCode = PUSH_INVALID_CHANNELS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    [paramDict setValue:channels forKey:@"channel"];
    [paramDict setValue:[self getAnID] forKey:@"id"];
    
    NSString *channelString = nil;
    if (nil != channels) {
        channelString = [channels componentsJoinedByString:@","];
    } else {
        channelString = @"";
    }
    [paramDict setValue:channelString forKey:@"channel"];
    
    NSString *deviceIdString = [paramDict objectForKey:@"id"];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"token"];
    [paramDict setObject:appKey forKey:@"appKey"];
#ifdef DM_ENABLED
    ANDeviceManager *manager = [ANDeviceManager shared];
    NSString *real_device_id = [manager getDeviceId];
    [paramDict setValue:real_device_id forKey:@"real_device_id"];
#endif
    
    if(overwrite) {
        [params setObject:@"true" forKey:@"overwrite"];
        NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodRegisterOverwrite, paramDict);
        signatureString = [self encodeString:signatureString];
        [params setObject:signatureString forKey:@"signature"];
    } else {
        NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodRegisterAppend, paramDict);
        signatureString = [self encodeString:signatureString];
          [params setObject:signatureString forKey:@"signature"];
    }

    NSString *tokenString = [self encodeString:token];
    channelString = [self encodeString:channelString];
    dateString = [self encodeString:dateString];
    deviceIdString = [self encodeString:deviceIdString];
#ifdef DM_ENABLED
    [params setValue:real_device_id forKey:@"real_device_id"];
#endif
    
    [params setObject:channelString forKey:@"channel"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:deviceIdString forKey:@"id"];
    [params setObject:@"ios" forKey:@"type"];
    
    NSString *urlString = [self getAPIURL:registerEndpoint withAppKey:appKey];
    
    if(_httpClient)
    {
        [_httpClient sendRegistrationRequest:params type:1 url:urlString success:success failure:failure];
    }
}

- (void)unregister __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }

    [self talkToAPI:AnPushMethodUnregisterAll withParams:paramDict];
//    if(e == nil) {
//        [self talkToAPI:AnPushMethodUnregisterAll withParams:paramDict];
//    } else {
//        if ([anPushDelegate respondsToSelector:@selector(didUnregistered:withError:)]) {
//            [anPushDelegate didUnregistered:NO withError:message];
//        }
//        if ([anPushDelegate respondsToSelector:@selector(didUnregistered:withException:)]) {
//            [anPushDelegate didUnregistered:NO withException:e];
//        }
//    }
}

- (void)unregister:(void (^)(NSString *anid))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlString = [self getAPIURL:unregisterEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodUnregisterAll, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"true" forKey:@"remove"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendRegistrationRequest:params type:2 url:urlString success:success failure:failure];
    }
}

- (void)unregister:(NSArray *)channels __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (channels == nil) {
        message = @"invalid channels";
        errorCode = PUSH_INVALID_CHANNELS;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }

    [paramDict setValue:channels forKey:@"channel"];
    [self talkToAPI:AnPushMethodUnregisterSome withParams:paramDict];
//    if(e == nil) {
//        [paramDict setValue:channels forKey:@"channel"];
//        [self talkToAPI:AnPushMethodUnregisterSome withParams:paramDict];
//    } else {
//        if ([anPushDelegate respondsToSelector:@selector(didUnregistered:withError:)]) {
//            [anPushDelegate didUnregistered:NO withError:message];
//        }
//        if ([anPushDelegate respondsToSelector:@selector(didUnregistered:withException:)]) {
//            [anPushDelegate didUnregistered:NO withException:e];
//        }
//    }
}

- (void)unregister:(NSArray *)channels success:(void (^)(NSString *anid))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (channels == nil) {
        message = @"invalid channels";
        errorCode = PUSH_INVALID_CHANNELS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *channelString = nil;
    if (nil != channels) {
        channelString = [channels componentsJoinedByString:@","];
    } else {
        channelString = @"";
    }
    [paramDict setValue:channelString forKey:@"channel"];
    
    NSString *urlString = [self getAPIURL:unregisterEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodUnregisterSome, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    channelString = [self encodeString:channelString];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setValue:channelString forKey:@"channel"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:channelString forKey:@"channel"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendRegistrationRequest:params type:2 url:urlString success:success failure:failure];
    }
}

- (void)setMute __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }
    
    [self talkToAPI:AnPushMethodSetMute withParams:paramDict];
//    if(token) {
//        [self talkToAPI:AnPushMethodSetMute withParams:paramDict];
//    } else {
//        if ([anPushDelegate respondsToSelector:@selector(didSetMute:withError:)]) {
//            [anPushDelegate didSetMute:NO withError:message];
//        }
//        if ([anPushDelegate respondsToSelector:@selector(didSetMute:withException:)]) {
//            [anPushDelegate didSetMute:NO withException:e];
//        }
//    }
}

- (void)setMute:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlString = [self getAPIURL:muteEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodSetMute, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"true" forKey:@"mute"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendAnPushSettingsRequest:params url:urlString type:1 success:success failure:failure];
    }
}


+ (BOOL)validateHour:(NSInteger)hour minute:(NSInteger)minute duration:(NSInteger)duration
{
    if (hour>-1 && hour<24 && minute>-1 && minute <60 && duration>-1 && duration<1440) {
        return YES;
    } else {
        return NO;
    }
}

- (void)setMuteWithHour:(NSInteger)startHour minute:(NSInteger)startMinute duration:(NSInteger)duration __attribute__((deprecated))
{
    BOOL right = [AnPush validateHour:startHour minute:startMinute duration:duration];
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (right == NO) {
        message = @"invalid \"startHour\", \"startMinute\", or \"duration\"";
        errorCode = PUSH_INVALID_TIME_RANGE;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }
    
    [paramDict setValue:[NSString stringWithFormat:@"%d", startHour] forKey:@"hour"];
    [paramDict setValue:[NSString stringWithFormat:@"%d", startMinute] forKey:@"minute"];
    [paramDict setValue:[NSString stringWithFormat:@"%d", duration] forKey:@"duration"];
    [self talkToAPI:AnPushMethodSetMutePeriod withParams:paramDict];
//    if(e == nil) {
//        [paramDict setValue:[NSString stringWithFormat:@"%d", startHour] forKey:@"hour"];
//        [paramDict setValue:[NSString stringWithFormat:@"%d", startMinute] forKey:@"minute"];
//        [paramDict setValue:[NSString stringWithFormat:@"%d", duration] forKey:@"duration"];
//        [self talkToAPI:AnPushMethodSetMutePeriod withParams:paramDict];
//    } else {
//        if ([anPushDelegate respondsToSelector:@selector(didSetMute:withError:)]) {
//            [anPushDelegate didSetMute:NO withError:message];
//        }
//        if ([anPushDelegate respondsToSelector:@selector(didSetMute:withException:)]) {
//            [anPushDelegate didSetMute:NO withException:e];
//        }
//    }
}

- (void)setMuteWithHour:(NSInteger)startHour minute:(NSInteger)startMinute duration:(NSInteger)duration success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    BOOL right = [AnPush validateHour:startHour minute:startMinute duration:duration];
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (right == NO) {
        message = @"invalid \"startHour\", \"startMinute\", or \"duration\"";
        errorCode = PUSH_INVALID_TIME_RANGE;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *hourString = [NSString stringWithFormat:@"%d", startHour];
    NSString *minuteString = [NSString stringWithFormat:@"%d", startMinute];
    NSString *durationString = [NSString stringWithFormat:@"%d", duration];
    [paramDict setValue:hourString forKey:@"hour"];
    [paramDict setValue:minuteString forKey:@"minute"];
    [paramDict setValue:durationString forKey:@"duration"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    
    NSString *urlString = [self getAPIURL:muteEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodSetMutePeriod, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setObject:hourString forKey:@"hour"];
    [params setObject:minuteString forKey:@"minute"];
    [params setObject:durationString forKey:@"duration"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"true" forKey:@"mute"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendAnPushSettingsRequest:params url:urlString type:1 success:success failure:failure];
    }
}

- (void)setSilentWithHour:(NSInteger)startHour minute:(NSInteger)startMinute duration:(NSInteger)duration resend:(BOOL)resend __attribute__((deprecated))
{
    BOOL right = [AnPush validateHour:startHour minute:startMinute duration:duration];
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (right == NO) {
        message = @"invalid \"startHour\", \"startMinute\", or \"duration\"";
        errorCode = PUSH_INVALID_TIME_RANGE;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }
    
    [paramDict setValue:[NSString stringWithFormat:@"%d", startHour] forKey:@"hour"];
    [paramDict setValue:[NSString stringWithFormat:@"%d", startMinute] forKey:@"minute"];
    [paramDict setValue:[NSString stringWithFormat:@"%d", duration] forKey:@"duration"];
    [paramDict setValue:resend==YES?@"true":@"false" forKey:@"resend"];
    [self talkToAPI:AnPushMethodSetSilent withParams:paramDict];
    //    if(e == nil) {
    //        [paramDict setValue:[NSString stringWithFormat:@"%d", startHour] forKey:@"hour"];
    //        [paramDict setValue:[NSString stringWithFormat:@"%d", startMinute] forKey:@"minute"];
    //        [paramDict setValue:[NSString stringWithFormat:@"%d", duration] forKey:@"duration"];
    //        [paramDict setValue:resend==YES?@"true":@"false" forKey:@"resend"];
    //        [self talkToAPI:AnPushMethodSetSilent withParams:paramDict];
    //    } else {
    //        if ([anPushDelegate respondsToSelector:@selector(didSetSilent:withError:)]) {
    //            [anPushDelegate didSetSilent:NO withError:message];
    //        }
    //        if ([anPushDelegate respondsToSelector:@selector(didSetSilent:withException:)]) {
    //            [anPushDelegate didSetSilent:NO withException:e];
    //        }
    //    }
}

- (void)setSilentWithHour:(NSInteger)startHour minute:(NSInteger)startMinute duration:(NSInteger)duration resend:(BOOL)resend success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    BOOL right = [AnPush validateHour:startHour minute:startMinute duration:duration];
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if (right == NO) {
        message = @"invalid \"startHour\", \"startMinute\", or \"duration\"";
        errorCode = PUSH_INVALID_TIME_RANGE;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *hourString = [NSString stringWithFormat:@"%d", startHour];
    NSString *minuteString = [NSString stringWithFormat:@"%d", startMinute];
    NSString *durationString = [NSString stringWithFormat:@"%d", duration];
    NSString *resendString = resend==YES?@"true":@"false";
    [paramDict setValue:hourString forKey:@"hour"];
    [paramDict setValue:minuteString forKey:@"minute"];
    [paramDict setValue:durationString forKey:@"duration"];
    [paramDict setValue:resendString forKey:@"resend"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *urlString = [self getAPIURL:silentEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodSetSilent, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setObject:hourString forKey:@"hour"];
    [params setObject:minuteString forKey:@"minute"];
    [params setObject:durationString forKey:@"duration"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"true" forKey:@"set"];
    [params setObject:resendString forKey:@"resend"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendAnPushSettingsRequest:params url:urlString type:2 success:success failure:failure];
    }
}

- (void)clearMute __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }
    
    [self talkToAPI:AnPushMethodClearMute withParams:paramDict];
//    if(e == nil) {
//        [self talkToAPI:AnPushMethodClearMute withParams:paramDict];
//    } else {
//        if ([anPushDelegate respondsToSelector:@selector(didClearMute:withError:)]) {
//            [anPushDelegate didClearMute:NO withError:message];
//        }
//        if ([anPushDelegate respondsToSelector:@selector(didClearMute:withException:)]) {
//            [anPushDelegate didClearMute:NO withException:e];
//        }
//    }
}

- (void)clearMute:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlString = [self getAPIURL:muteEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodClearMute, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    signatureString = [self encodeString:signatureString];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"false" forKey:@"mute"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendAnPushSettingsRequest:params url:urlString type:3 success:success failure:failure];
    }
}

- (void)clearSilent __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }
    
    [self talkToAPI:AnPushMethodClearSilent withParams:paramDict];
//    if(e == nil) {
//        [self talkToAPI:AnPushMethodClearSilent withParams:paramDict];
//    } else {
//        if ([anPushDelegate respondsToSelector:@selector(didClearSilent:withError:)]) {
//            [anPushDelegate didClearSilent:NO withError:message];
//        }
//        if ([anPushDelegate respondsToSelector:@selector(didClearSilent:withException:)]) {
//            [anPushDelegate didClearSilent:NO withException:e];
//        }
//    }
}

- (void)clearSilent:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlString = [self getAPIURL:silentEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodClearSilent, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:@"false" forKey:@"set"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendAnPushSettingsRequest:params url:urlString type:4 success:success failure:failure];
    }
}

- (void)setBadge:(int)number __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    ArrownockException *e = nil;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if(number < 0) {
        message = INVALID_BADGE;
        errorCode = PUSH_INVALID_BADGE;
    }
    if (errorCode != 0) {
        e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        @throw e;
    }
    [paramDict setObject:[NSString stringWithFormat:@"%d", number] forKey:@"badge"];
    [self talkToAPI:AnPushMethodSetBadge withParams:paramDict];
}

- (void)setBadge:(int)number success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = NO_APP_KEY_ERROR;
        errorCode = PUSH_INVALID_APP_KEY;
    } else if (token == nil) {
        message = NO_TOKEN_ERROR;
        errorCode = PUSH_INVALID_DEVICE_TOKEN;
    } else if(number < 0) {
        message = INVALID_BADGE;
        errorCode = PUSH_INVALID_BADGE;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    NSString *numberString = [NSString stringWithFormat:@"%d", number];
    [paramDict setObject:numberString forKey:@"badge"];
    
    NSString *urlString = [self getAPIURL:setBadgeEndpoint withAppKey:appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [paramDict setObject:dateString forKey:@"date"];
    [paramDict setObject:token forKey:@"device_token"];
    [paramDict setObject:appKey forKey:@"key"];
    NSString *signatureString = AnPushOAuthorizationSignature(AnPushMethodSetBadge, paramDict);
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    NSString *tokenString = [self encodeString:token];
    dateString = [self encodeString:dateString];
    signatureString = [self encodeString:signatureString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:tokenString forKey:@"device_token"];
    [params setObject:appKey forKey:@"key"];
    [params setObject:numberString forKey:@"badge"];
    [params setObject:@"ios" forKey:@"type"];
    [params setObject:signatureString forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendAnPushSettingsRequest:params url:urlString type:5 success:success failure:failure];
    }
}

- (NSString *)getAnID
{
    if (appKey == nil) {
        return nil;
    }
    
    NSString *anId = deviceId;
    if (anId != nil){
        return anId;
    }
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    anId = [defaults objectForKey:ANID_KEY];
    if (anId != nil){
        return anId;
    }
    
    anId = [self getDeviceUniqueId];
    return anId;

}

- (NSString *)getDeviceUniqueId
{
    ANKeychainItemWrapper *keychainItem = [[ANKeychainItemWrapper alloc] initWithIdentifier:@"com.arrownock.ANIM_DEVICE_ID" accessGroup:nil];
    
    NSString *deviceUniqueId = [keychainItem objectForKey:(__bridge id)kSecAttrService];
    if (deviceUniqueId != nil && [deviceUniqueId length] != 0) {
        return deviceUniqueId;
    } else {
        deviceUniqueId = nil;
        if ([[[UIDevice currentDevice] systemVersion] hasPrefix:@"5"]) {
            CFUUIDRef cfuuid = CFUUIDCreate(kCFAllocatorDefault);
            deviceUniqueId = (NSString*)CFBridgingRelease(CFUUIDCreateString(kCFAllocatorDefault, cfuuid));
        } else {
            deviceUniqueId = [[NSUUID UUID] UUIDString];
        }
        NSString *key = [@"K" stringByAppendingString:appKey];
        deviceUniqueId = [deviceUniqueId stringByAppendingString:key];
        deviceUniqueId = [NSString stringWithFormat:@"1%@", [self getMD5String:deviceUniqueId]];
        [keychainItem setObject:deviceUniqueId forKey:(__bridge id)kSecAttrService];
        return deviceUniqueId;
    }
}

- (NSString *)getMD5String:(NSString *)input
{
    // Create pointer to the string as UTF8
    const char *ptr = [input UTF8String];
    
    // Create byte array of unsigned chars
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
    // Create 16 byte MD5 hash value, store in buffer
    CC_MD5(ptr, strlen(ptr), md5Buffer);
    
    // Convert MD5 value in the buffer to NSString of hex values
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x",md5Buffer[i]];
    
    return output;
}

- (void)writeAnID:(NSString *)AnID toUserDefaultsKey:(NSString *)key
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

- (NSString *)getAPIURL:(NSString *)endpoint withAppKey:(NSString *)key
{
    NSString *url = [NSString stringWithFormat:apiURLFormatString, isSecure?@"https":@"http", apiHost?apiHost:defaultAPIHost, apiVersion, endpoint, key];
    return url;
}

- (void)getCallbackConnection:(AnPushURLConnection *)connection data:(NSData *)data error:(NSError *)error
{
    NSString *resultString;
    NSString *errorMessage;
    if (error) {
        errorMessage = [error localizedDescription];
    } else if (connection.response) {
        NSInteger statusCode = connection.response.statusCode;
        id jsonObjects = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&error];
        if (!error) {
            if (200 == statusCode) {
                if (data) {
                    if (![jsonObjects objectForKey:@"response"]) {
                        resultString = @"YES";
                    } else {
                        resultString = [[[jsonObjects objectForKey:@"response"] objectForKey:@"subscription"] objectForKey:@"anid"];
                        if (resultString) {
                            NSString *tempKey = [appKey stringByAppendingString:@":"];
                            NSString *tempToken = [token stringByAppendingString:@":"];
                            NSString *keyTokenAnid = [[tempKey stringByAppendingString:tempToken] stringByAppendingString:resultString];
                            
                            [self writeAnID:keyTokenAnid toUserDefaultsKey:ANID_KEY];
                        }
                    }
                }
            } else {
                errorMessage = [[jsonObjects objectForKey:@"meta"] objectForKey:@"message"];
            }
        } else {
            errorMessage = [error localizedDescription];
        }
        
    } else {
        errorMessage = @"no response";
    }
    
    BOOL success = (resultString != nil);
    if (connection.method == AnPushMethodRegisterOverwrite || connection.method == AnPushMethodRegisterAppend) {
        if ([anPushDelegate respondsToSelector:@selector(didRegistered:withError:)]) {
            [anPushDelegate didRegistered:resultString withError:errorMessage];
        }
        if ([anPushDelegate respondsToSelector:@selector(didRegistered:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_REGISTER message:errorMessage];
            }
            [anPushDelegate didRegistered:resultString withException:e];
        }
    }
    if (connection.method == AnPushMethodUnregisterAll || connection.method == AnPushMethodUnregisterSome) {
        if ([anPushDelegate respondsToSelector:@selector(didUnregistered:withError:)]) {
            [anPushDelegate didUnregistered:success withError:errorMessage];
        }
        if ([anPushDelegate respondsToSelector:@selector(didUnregistered:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_UNREGISTER message:errorMessage];
            }
            [anPushDelegate didUnregistered:success withException:e];
        }
    }
    if (connection.method == AnPushMethodSetMute || connection.method == AnPushMethodSetMutePeriod) {
        if ([anPushDelegate respondsToSelector:@selector(didSetMute:withError:)]) {
            [anPushDelegate didSetMute:success withError:errorMessage];
        }
        if ([anPushDelegate respondsToSelector:@selector(didSetMute:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_SET_MUTE message:errorMessage];
            }
            [anPushDelegate didSetMute:success withException:e];
        }
    }
    if (connection.method == AnPushMethodSetSilent) {
        if ([anPushDelegate respondsToSelector:@selector(didSetSilent:withError:)]) {
            [anPushDelegate didSetSilent:success withError:errorMessage];
        }
        if ([anPushDelegate respondsToSelector:@selector(didSetSilent:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_SET_SILENT message:errorMessage];
            }
            [anPushDelegate didSetSilent:success withException:e];
        }
    }
    if (connection.method == AnPushMethodClearMute) {
        if ([anPushDelegate respondsToSelector:@selector(didClearMute:withError:)]) {
            [anPushDelegate didClearMute:success withError:errorMessage];
        }
        if ([anPushDelegate respondsToSelector:@selector(didClearMute:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_CLEAR_MUTE message:errorMessage];
            }
            [anPushDelegate didClearMute:success withException:e];
        }
    }
    if (connection.method == AnPushMethodClearSilent) {
        if ([anPushDelegate respondsToSelector:@selector(didClearSilent:withError:)]) {
            [anPushDelegate didClearSilent:success withError:errorMessage];
        }
        if ([anPushDelegate respondsToSelector:@selector(didClearSilent:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_CLEAR_SILENT message:errorMessage];
            }
            [anPushDelegate didClearSilent:success withException:e];
        }
    }
    if (connection.method == AnPushMethodSetBadge) {
        if ([anPushDelegate respondsToSelector:@selector(didSetBadge:withException:)]) {
            ArrownockException *e = nil;
            if (success == NO) {
                e = [ArrownockExceptionUtils generateWithErrorCode:PUSH_FAILED_SET_BADGE message:errorMessage];
            }
            [anPushDelegate didSetBadge:success withException:e];
        }
    }
}

- (void)talkToAPI:(AnPushMethod)method withParams:(NSMutableDictionary *)params
{    
    @try {
        NSString *tokenString = [params objectForKey:@"token"];
        NSString *appKeyString = [params objectForKey:@"appKey"];
        NSString *deviceIdString = [params objectForKey:@"id"];
        
        NSDateFormatter* df = [[NSDateFormatter alloc]init];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
        NSDate *date = [NSDate date];
        NSString *dateString = [df stringFromDate:date];
        [params setValue:dateString forKey:@"date"];
        
#ifdef DM_ENABLED
        ANDeviceManager *manager = [ANDeviceManager shared];
        NSString *real_device_id = [manager getDeviceId];
        [params setValue:real_device_id forKey:@"real_device_id"];
#endif
        
        NSString *resendString = [params objectForKey:@"resend"];
        NSString *hourString = [params objectForKey:@"hour"];
        NSString *minuteString = [params objectForKey:@"minute"];
        NSString *durationString = [params objectForKey:@"duration"];
        
        NSString *channelString;
        if (method == AnPushMethodRegisterOverwrite || method == AnPushMethodRegisterAppend || method == AnPushMethodUnregisterSome) {
            NSArray *channels = [params objectForKey:@"channel"];
            if (nil != channels) {
                channelString = [channels componentsJoinedByString:@","];
            } else {
                channelString = @"";
            }
            [params setValue:channelString forKey:@"channel"];
        }
        
        NSString *badge = [params objectForKey:@"badge"];
        
        NSString *signatureString = AnPushOAuthorizationSignature(method, params);
        
        tokenString = [self encodeString:tokenString];
        channelString = [self encodeString:channelString];
        dateString = [self encodeString:dateString];
        signatureString = [self encodeString:signatureString];
        if(deviceIdString)
        {
            deviceIdString = [self encodeString:deviceIdString];
        }
        
        NSString *urlString = [[NSString alloc] init];
        if (method == AnPushMethodRegisterAppend || method == AnPushMethodRegisterOverwrite) {
            urlString = [self getAPIURL:registerEndpoint withAppKey:appKeyString];
        }
        if (method == AnPushMethodUnregisterAll || method == AnPushMethodUnregisterSome) {
            urlString = [self getAPIURL:unregisterEndpoint withAppKey:appKeyString];
        }
        if (method == AnPushMethodSetMute || method == AnPushMethodSetMutePeriod) {
            urlString = [self getAPIURL:muteEndpoint withAppKey:appKeyString];
        }
        if (method == AnPushMethodSetSilent) {
            urlString = [self getAPIURL:silentEndpoint withAppKey:appKeyString];
        }
        if (method == AnPushMethodClearMute) {
            urlString = [self getAPIURL:muteEndpoint withAppKey:appKeyString];
        }
        if (method == AnPushMethodClearSilent) {
            urlString = [self getAPIURL:silentEndpoint withAppKey:appKeyString];
        }
        if (method == AnPushMethodSetBadge) {
            urlString = [self getAPIURL:setBadgeEndpoint withAppKey:appKeyString];
        }
        
        NSString *bodyString = [[NSString alloc] init];
        switch (method) {
            case AnPushMethodRegisterOverwrite:
#ifdef DM_ENABLED
                bodyString = [NSString stringWithFormat:registerOverwriteBodyForDeviceFormatString, channelString, dateString, tokenString, deviceIdString, appKeyString, real_device_id, signatureString];
                break;
#else
                bodyString = [NSString stringWithFormat:registerOverwriteBodyFormatString, channelString, dateString, tokenString, deviceIdString, appKeyString, signatureString];
                break;
#endif
                
            case AnPushMethodRegisterAppend:
#ifdef DM_ENABLED
                bodyString = [NSString stringWithFormat:registerAppendBodyForDeviceFormatString, channelString, dateString, tokenString, deviceIdString, appKeyString, real_device_id,signatureString];
                break;
#else
                bodyString = [NSString stringWithFormat:registerAppendBodyFormatString, channelString, dateString, tokenString, deviceIdString, appKeyString, signatureString];
                break;
#endif
            case AnPushMethodUnregisterAll:
                bodyString = [NSString stringWithFormat:unregisterAllBodyFormatString, dateString, tokenString, appKeyString, signatureString];
                break;
            case AnPushMethodUnregisterSome:
                bodyString = [NSString stringWithFormat:unregisterSomeBodyFormatString, channelString, dateString, tokenString, appKeyString, signatureString];
                break;
            case AnPushMethodSetMute:
                bodyString = [NSString stringWithFormat:setMuteBodyFormatString, dateString, tokenString, appKeyString, signatureString];
                break;
            case AnPushMethodSetMutePeriod:
                bodyString = [NSString stringWithFormat:setMutePeriodBodyFormatString, dateString, tokenString, durationString, hourString, appKeyString, minuteString, signatureString];
                break;
            case AnPushMethodSetSilent:
                bodyString = [NSString stringWithFormat:setSilentBodyFormatString, dateString, tokenString, durationString, hourString, appKeyString, minuteString, signatureString, resendString];
                break;
            case AnPushMethodClearMute:
                bodyString = [NSString stringWithFormat:clearMuteBodyFormatString, dateString, tokenString, appKeyString, signatureString];
                break;
            case AnPushMethodClearSilent:
                bodyString = [NSString stringWithFormat:clearSilentBodyFormatString, dateString, tokenString, appKeyString, signatureString];
                break;
            case AnPushMethodSetBadge:
                bodyString = [NSString stringWithFormat:setBadgeBodyFormatString, dateString, tokenString, appKeyString, badge, signatureString];
                break;
            default:
                break;                
        }
        
        NSURL *url = [NSURL URLWithString:urlString];
        NSMutableURLRequest * request = [NSMutableURLRequest requestWithURL:url];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
        
        AnPushURLConnection *connection = [[AnPushURLConnection alloc] initWithRequest:request delegate:[AnPush shared]];
        connection.method = method;
        [connection scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSRunLoopCommonModes];
        [connection start];
    }
    @catch (NSException *exception) {
        NSLog(@"*******************NSException********************");
        if ((method == AnPushMethodRegisterOverwrite || method == AnPushMethodRegisterAppend) && [anPushDelegate respondsToSelector:@selector(didRegistered:withError:)]) {
            [anPushDelegate didRegistered:nil withError:exception.reason];
        }
        if ((method == AnPushMethodUnregisterSome || method == AnPushMethodUnregisterAll) && [anPushDelegate respondsToSelector:@selector(didUnregistered:withError:)]) {
            [anPushDelegate didUnregistered:NO withError:exception.reason];
        }
        if ((method == AnPushMethodSetMutePeriod || method == AnPushMethodSetMute) && [anPushDelegate respondsToSelector:@selector(didSetMute:withError:)]) {
            [anPushDelegate didSetMute:NO withError:exception.reason];
        }
        if (method == AnPushMethodSetSilent && [anPushDelegate respondsToSelector:@selector(didSetSilent:withError:)]) {
            [anPushDelegate didSetSilent:NO withError:exception.reason];
        }
        if (method == AnPushMethodClearMute && [anPushDelegate respondsToSelector:@selector(didClearMute:withError:)]) {
            [anPushDelegate didClearMute:NO withError:exception.reason];
        }
        if (method == AnPushMethodClearSilent && [anPushDelegate respondsToSelector:@selector(didClearSilent:withError:)]) {
            [anPushDelegate didClearSilent:NO withError:exception.reason];
        }
    }
    @finally {
        
    }
}

- (void)fetchCachedPushNotifications
{
    if(token && appKey) {
        if(_httpClient)
        {
            NSString *urlString = [self getAPIURL:fetchCacheEndpoint withAppKey:appKey];
            [_httpClient sendFetchCachedPushNotificationsRequest:token url:urlString success:^(NSDictionary *messages) {
                if(messages) {
                    if (anPushDelegate && [anPushDelegate respondsToSelector:@selector(didRecievedNotifications:)]) {
                        NSDictionary *cache = [[NSUserDefaults standardUserDefaults] objectForKey:@"com.arrownock.push.CACHED_IDS"];
                        if(cache) {
                            NSMutableDictionary *newCache;
                            if (cache.count >= 50) {
                                newCache = [[NSMutableDictionary alloc] init];
                            } else {
                                newCache = [cache mutableCopy];
                            }
                            NSMutableDictionary *results = [[NSMutableDictionary alloc] init];
                            for(id pushId in [messages allKeys]) {
                                if([cache objectForKey:pushId] != nil) {
                                    // the push notification is cached, ignore it
                                } else {
                                    [newCache setObject:@"1" forKey:pushId];
                                    [results setObject:[messages objectForKey:pushId] forKey:pushId];
                                }
                            }
                            [[NSUserDefaults standardUserDefaults] setObject:newCache forKey:@"com.arrownock.push.CACHED_IDS"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                            
                            //if(results.count > 0) {
                                dispatch_async(dispatch_get_main_queue(), ^{
                                    [anPushDelegate didRecievedNotifications:results];
                                });
                            //}
                        } else {
                            NSMutableDictionary *c = [[NSMutableDictionary alloc] init];
                            for(id pushId in [messages allKeys]) {
                                [c setObject:@"1" forKey:pushId];
                            }
                            [[NSUserDefaults standardUserDefaults] setObject:c forKey:@"com.arrownock.push.CACHED_IDS"];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                            
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [anPushDelegate didRecievedNotifications:messages];
                            });
                        }
                    }
                }
            } failure:^(ArrownockException *exception) {
                NSLog(@"An error occured in recieving push notification: %@", [exception message]);
            }];
        }
    }
}


# pragma mark - ConnectionData Delegate

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [self getCallbackConnection:(AnPushURLConnection *)connection data:data error:nil];
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    ((AnPushURLConnection *)connection).response = (NSHTTPURLResponse *)response;
}

# pragma mark - Connection Delegate

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    [self getCallbackConnection:(AnPushURLConnection *)connection data:nil error:error];
}

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
