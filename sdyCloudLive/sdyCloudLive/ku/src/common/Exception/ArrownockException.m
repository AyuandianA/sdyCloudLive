//
//  ArrownockException.m
//  Arrownock
//
//  Created by Edward Sun on 10/18/13.
//  Copyright (c) 2013 Arrownock. All rights reserved.
//

#import "ArrownockException.h"

@implementation ArrownockException

@synthesize message = _message;
@synthesize errorCode = _errorCode;

- (NSString *)getMessage
{
    return _message;
}

- (NSUInteger)getErrorCode
{
    return _errorCode;
}

@end
