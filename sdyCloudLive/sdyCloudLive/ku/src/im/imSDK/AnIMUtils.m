//
//  AnIMUtils.m
//  AnIM
//
//  Created by Edward Sun on 9/4/13.
//  Copyright (c) 2013 arrownock. All rights reserved.
//

#import "AnIMUtils.h"
#import "ANSBJson.h"
#import <CommonCrypto/CommonCrypto.h>

#define ARROWNOCK_SESSION_BASE_KEY @"com.arrownock.anim.session.key.prefix-"
#define ARROWNOCK_USER_ID_BASE_KEY @"com.arrownock.anim.userid.prefix-"

@implementation AnIMUtils

+ (NSString *)readClientId:(NSString *)userId
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"%@%@", ARROWNOCK_USER_ID_BASE_KEY, userId];
    return [defaults objectForKey:key];
}

+ (void)writeClientId:(NSString *)clientId toUserDefaultsKey:(NSString *)userId
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"%@%@", ARROWNOCK_USER_ID_BASE_KEY, userId];
    NSString *cId = [defaults objectForKey:key];
    if ([clientId isEqualToString:cId]) {
        return;
    }
    [defaults setObject:clientId forKey:key];
    [defaults synchronize];
}

+ (NSDictionary *)readHost:(NSString *)key
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    return [defaults objectForKey:key];
}

+ (void)writeHost:(NSDictionary *)hostDict toUserDefaultsKey:(NSString *)key
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults objectForKey:key];
    if ([dict isEqualToDictionary:hostDict]) {
        return;
    }
    [defaults setObject:hostDict forKey:key];
    [defaults synchronize];
}

+ (void)removeHost:(NSString *)key
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    [defaults removeObjectForKey:key];
    [defaults synchronize];
}

+ (NSString *)encodeString:(NSString *)originalString
{
    NSString *encodedString = (NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(NULL,
                                                                                  (CFStringRef)originalString,
                                                                                  NULL,
                                                                                  (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                                                  kCFStringEncodingUTF8 ));
    return encodedString;
}

+ (NSString *)generateAnMsgId:(NSString *)clientId
{
    if (clientId == nil) {
        clientId = @"clientId";
    }
    NSString *msString = [NSString stringWithFormat:@"%llu", (unsigned long long)[[[NSDate alloc] init] timeIntervalSince1970] * 1000];
    NSString *randString = [NSString stringWithFormat:@"%du", (arc4random() % 65535 + 1)];
    NSString *baseString = [NSString stringWithFormat:@"%@%@%@", clientId, msString, randString];
    return [NSString stringWithFormat:@"%llu", [AnIMUtils _getHash:baseString]];
}

+ (NSSet *)readParties:(NSString *)sessionKey
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"%@%@", ARROWNOCK_SESSION_BASE_KEY, sessionKey];
    NSArray *parties = [defaults objectForKey:key];
    
    if (parties != nil) {
        return [NSSet setWithArray:parties];
    }
    return nil;
}

+ (BOOL)writeParties:(NSSet *)parties sessionKey:(NSString *)sessionKey
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"%@%@", ARROWNOCK_SESSION_BASE_KEY, sessionKey];
    
    [defaults setObject:[parties allObjects] forKey:key];

    return [defaults synchronize];
}

+ (BOOL)removeSession:(NSString *)sessionKey
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = sessionKey;
    
    [defaults removeObjectForKey:key];
    
    return [defaults synchronize];
}

+ (NSString *)generateSessionKey:(NSSet *)parties
{
    NSArray *sourceData = @[@"0", @"1", @"2", @"3", @"4", @"5", @"6", @"7", @"8", @"9",
                            @"A", @"B", @"C", @"D", @"E", @"F", @"G", @"H", @"I", @"J", @"K", @"L", @"M", @"N", @"O", @"P", @"Q", @"R", @"S", @"T", @"U", @"V", @"W", @"X", @"Y", @"Z"];
    
    NSString *baseString = [[[parties allObjects] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"-"];
    NSMutableString *resultString = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH];
    
    
    NSData *baseData = [baseString dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([baseData bytes], [baseData length], digest);
    NSData *indexData = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    const char *indexBytes = [indexData bytes];
    
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        int index = indexBytes[i];
        if (index < 0) {
            index = 0 - index;
        }
        int offset = index / 36;
        
        NSString *tmp;
        if (offset < 1) {
            tmp = sourceData[index];
        } else {
            tmp = sourceData[(index + offset) % 36];
        }
        
        [resultString appendFormat:@"%@", tmp];
    }
    
    return resultString;
}

+ (unsigned long long)_getHash:(NSString *)baseString
{
    unsigned long long hash = 5381;
    int l = [baseString length];
    for (int i = 0; i < l; i++) {
        hash = ((hash << 5) + hash) + [baseString characterAtIndex:i];
    }
    return hash;
}

+ (NSString *)getJsonStringFromDict:(NSDictionary *)jsonDict
{
    return [[[ANSBJsonWriter alloc] init] stringWithObject:jsonDict];
    
//    NSError *error;
//    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jsonDict options:NSJSONWritingPrettyPrinted error:&error];
//    NSString *jsonString = [NSString stringWithCString:[jsonData bytes] encoding:NSUTF8StringEncoding];
//    
//    return jsonString;
}

+ (NSDictionary *)getDictFromJsonString:(NSString *)jsonString
{
//    return [[[SBJsonParser alloc] init] objectWithString:jsonString];
    
    NSError *error;
    NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:[jsonString dataUsingEncoding:NSUTF8StringEncoding]
                                                             options:NSJSONReadingMutableContainers
                                                               error:&error];
    return jsonDict;
}

+ (NSString*) SHA256:(NSString *)input {
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

@end
