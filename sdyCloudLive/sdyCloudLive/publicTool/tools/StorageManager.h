//
//  StorageManager.h
//  YiMeiZhiBo
//
//  Created by Aliang Ren on 2018/6/16.
//  Copyright © 2018年 史德萌. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface StorageManager : NSObject
// 存
+ (void)setObj:(id)obj forKey:(NSString *)key;
// 取
+ (id)objForKey:(NSString *)key;
// 删
+ (void)removeKey:(NSString *)key;
//存取登录信息
+ (void)setLoginMessagesDic:(NSDictionary *)data;
//存取用户信息
+ (void)setUserMessagesDic:(NSDictionary *)data;
//退出登录清空所用登录信息和用户信息
+ (void)clearAllMessage;
@end
