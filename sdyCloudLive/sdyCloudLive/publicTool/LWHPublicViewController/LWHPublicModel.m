//
//  LWHPublicModel.m
//  zhibo
//
//  Created by mac on 2020/6/20.
//  Copyright © 2020 李武华. All rights reserved.
//

#import "LWHPublicModel.h"

@implementation LWHPublicModel

- (BOOL)modelCustomTransformFromDictionary:(NSDictionary *)dic {
  // 可以在这里处理一些数据逻辑，如NSDate格式的转换
    
  return YES;
}
//设置没有照应的字段
+ (NSDictionary *)modelCustomPropertyMapper{
    return @{@"ID" : @"id"};
}
+ (NSDictionary *)modelContainerPropertyGenericClass{
    
    return @{@"child":@"child"};
}
@end
