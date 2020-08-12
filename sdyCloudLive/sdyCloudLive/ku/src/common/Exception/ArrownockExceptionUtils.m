//
//  ArrownockExceptionUtils.m
//  Arrownock
//
//  Created by Edward Sun on 10/18/13.
//  Copyright (c) 2013 Arrownock. All rights reserved.
//

#import "ArrownockExceptionUtils.h"

@implementation ArrownockExceptionUtils

+ (ArrownockException *)generateWithErrorCode:(NSUInteger)errorCode message:(NSString *)message
{
    ArrownockException *e = [ArrownockException alloc];
    
    e.errorCode = errorCode;
    e.message = [NSString stringWithString:message];
    
    return e;
}

@end
