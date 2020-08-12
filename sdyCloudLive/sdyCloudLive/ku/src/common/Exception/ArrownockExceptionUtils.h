//
//  ArrownockExceptionUtils.h
//  Arrownock
//
//  Created by Edward Sun on 10/18/13.
//  Copyright (c) 2013 Arrownock. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ArrownockException.h"

@interface ArrownockExceptionUtils : NSObject

+ (ArrownockException *)generateWithErrorCode:(NSUInteger)errorCode message:(NSString *)message;

@end
