//
//  AnIMUtils.h
//  AnIM
//
//  Created by Edward Sun on 9/4/13.
//  Copyright (c) 2013 arrownock. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AnIMUtils : NSObject

+ (NSString *)readClientId:(NSString *)userId;

+ (void)writeClientId:(NSString *)clientId toUserDefaultsKey:(NSString *)userId;

+ (NSDictionary *)readHost:(NSString *)key;

+ (void)writeHost:(NSDictionary *)hostDict toUserDefaultsKey:(NSString *)key;

+ (void)removeHost:(NSString *)key;

+ (NSString *)encodeString:(NSString *)originalString;

+ (NSString *)generateAnMsgId:(NSString *)clientId;

+ (NSString *)getJsonStringFromDict:(NSDictionary *)jsonDict;

+ (NSDictionary *)getDictFromJsonString:(NSString *)jsonString;

+ (NSString *)generateSessionKey:(NSSet *)clientIds;

+ (NSSet *)readParties:(NSString *)sessionKey;

+ (BOOL)writeParties:(NSSet *)parties sessionKey:(NSString *)sessionKey;

+ (BOOL)removeSession:(NSString *)sessionKey;

+ (NSString*) SHA256:(NSString *)input;
@end
