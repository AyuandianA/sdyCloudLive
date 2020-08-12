//
//  AnIMURLConnection.h
//  IMDemo
//
//  Created by Edward Sun on 5/13/13.
//  Copyright (c) 2013 arrownock. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AnIMOAuthCore.h"

@interface AnIMURLConnection : NSURLConnection

@property AnIMMethod method;
@property NSInteger statusCode;
@property (nonatomic, strong) NSString *anMsgId;
@property BOOL gotData;
@property (nonatomic, strong) NSMutableData *data;

@property (nonatomic, strong) NSString *sessionKey;
@property (nonatomic, strong) NSString *stringMessage;
@property (nonatomic, strong) NSData *binary;
@property (nonatomic, strong) NSDictionary *customData;
@property (nonatomic, strong) NSString *fileType;
@property BOOL need;

@end
