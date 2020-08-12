//
// MQTTEncoder.h
// MQTTClient.framework
//
// Copyright (c) 2013-2015, Christoph Krey
//
// based on
//
// Copyright (c) 2011, 2013, 2lemetry LLC
// 
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v1.0
// which accompanies this distribution, and is available at
// http://www.eclipse.org/legal/epl-v10.html
// 
// Contributors:
//    Kyle Roche - initial API and implementation and/or initial documentation
// 

#import <Foundation/Foundation.h>
#import "ANMQTTMessage.h"
#import "ANMQTTSSLSecurityPolicy.h"

typedef enum {
    ANMQTTEncoderEventReady,
    ANMQTTEncoderEventErrorOccurred
} ANMQTTEncoderEvent;

typedef enum {
    ANMQTTEncoderStatusInitializing,
    ANMQTTEncoderStatusReady,
    ANMQTTEncoderStatusSending,
    ANMQTTEncoderStatusEndEncountered,
    ANMQTTEncoderStatusError
} ANMQTTEncoderStatus;

@class ANMQTTEncoder;

@protocol ANMQTTEncoderDelegate <NSObject>
- (void)encoder:(ANMQTTEncoder*)sender handleEvent:(ANMQTTEncoderEvent)eventCode error:(NSError *)error;
- (void)encoder:(ANMQTTEncoder*)sender sending:(int)type qos:(int)qos retained:(BOOL)retained duped:(BOOL)duped mid:(UInt16)mid data:(NSData *)data;
@end


@interface ANMQTTEncoder : NSObject <NSStreamDelegate>
@property (nonatomic)    ANMQTTEncoderStatus       status;
@property (strong, nonatomic)    NSOutputStream* stream;
@property (strong, nonatomic)    NSRunLoop*      runLoop;
@property (strong, nonatomic)    NSString*       runLoopMode;
@property (strong, nonatomic)    NSMutableData*  buffer;
@property (nonatomic)    NSInteger       byteIndex;
@property (weak, nonatomic)    id<ANMQTTEncoderDelegate>              delegate;

- (id)initWithStream:(NSOutputStream *)stream
             runLoop:(NSRunLoop *)runLoop
         runLoopMode:(NSString *)mode;

- (id)initWithStream:(NSOutputStream *)stream
             runLoop:(NSRunLoop *)runLoop
         runLoopMode:(NSString *)mode
      securityPolicy:(ANMQTTSSLSecurityPolicy *)securityPolicy
      securityDomain:(NSString *)securityDomain;

- (void)open;
- (void)close;
- (ANMQTTEncoderStatus)status;
- (void)stream:(NSStream*)sender handleEvent:(NSStreamEvent)eventCode;
- (void)encodeMessage:(ANMQTTMessage*)msg;

@end

