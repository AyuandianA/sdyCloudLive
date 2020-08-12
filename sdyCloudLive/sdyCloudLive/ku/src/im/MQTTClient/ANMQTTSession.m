//
// MQTTSession.m
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

/**
 Using MQTT in your Objective-C application
 
 @author Christoph Krey krey.christoph@gmail.com
 @see http://mqtt.org
 */

#import "ANMQTTSession.h"
#import "ANMQTTDecoder.h"
#import "ANMQTTEncoder.h"
#import "ANMQTTMessage.h"

#import <CFNetwork/CFSocketStream.h>

@interface ANMQTTSession() <ANMQTTDecoderDelegate, ANMQTTEncoderDelegate>
@property (nonatomic, readwrite) ANMQTTSessionStatus status;

@property (strong, nonatomic) NSTimer *keepAliveTimer;
@property (strong, nonatomic) NSTimer *checkDupTimer;

@property (strong, nonatomic) ANMQTTEncoder *encoder;
@property (strong, nonatomic) ANMQTTDecoder *decoder;
@property (strong, nonatomic) ANMQTTSession *selfReference;

@property (nonatomic) BOOL synchronPub;
@property (nonatomic) UInt16 synchronPubMid;
@property (nonatomic) BOOL synchronUnsub;
@property (nonatomic) UInt16 synchronUnsubMid;
@property (nonatomic) BOOL synchronSub;
@property (nonatomic) UInt16 synchronSubMid;
@property (nonatomic) BOOL synchronConnect;
@property (nonatomic) BOOL synchronDisconnect;

@end

#define DUPTIMEOUT 20.0
#define DUPLOOP 1.0

#ifdef DEBUG
#define DEBUGSESS FALSE
#else
#define DEBUGSESS FALSE
#endif

@implementation ANMQTTSession

- (ANMQTTSession *)init
{
    return [self initWithClientId:[NSString stringWithFormat:@"MQTTClient-%f",
                                   fmod([[NSDate date] timeIntervalSince1970], 10.0)]
                         userName:nil
                         password:nil
                        keepAlive:60
                     cleanSession:YES
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:0
                   willRetainFlag:NO
                    protocolLevel:4
                          runLoop:nil
                          forMode:nil];
}

- (ANMQTTSession *)initWithClientId:(NSString *)clientId
                         userName:(NSString *)userName
                         password:(NSString *)password
                        keepAlive:(UInt16)keepAliveInterval
                     cleanSession:(BOOL)cleanSessionFlag
                             will:(BOOL)willFlag
                        willTopic:(NSString *)willTopic
                          willMsg:(NSData *)willMsg
                          willQoS:(ANMQTTQosLevel)willQoS
                   willRetainFlag:(BOOL)willRetainFlag
                    protocolLevel:(UInt8)protocolLevel
                          runLoop:(NSRunLoop *)runLoop
                          forMode:(NSString *)runLoopMode {
    return [self initWithClientId:clientId
                         userName:userName
                         password:password
                        keepAlive:keepAliveInterval
                     cleanSession:cleanSessionFlag
                             will:willFlag
                        willTopic:willTopic
                          willMsg:willMsg
                          willQoS:willQoS
                   willRetainFlag:willRetainFlag
                    protocolLevel:protocolLevel
                          runLoop:runLoop
                          forMode:runLoopMode
                   securityPolicy:nil];
}

- (ANMQTTSession *)initWithClientId:(NSString *)clientId
                         userName:(NSString *)userName
                         password:(NSString *)password
                        keepAlive:(UInt16)keepAliveInterval
                     cleanSession:(BOOL)cleanSessionFlag
                             will:(BOOL)willFlag
                        willTopic:(NSString *)willTopic
                          willMsg:(NSData *)willMsg
                          willQoS:(ANMQTTQosLevel)willQoS
                   willRetainFlag:(BOOL)willRetainFlag
                    protocolLevel:(UInt8)protocolLevel
                          runLoop:(NSRunLoop *)runLoop
                          forMode:(NSString *)runLoopMode
                   securityPolicy:(ANMQTTSSLSecurityPolicy *) securityPolicy {
    return [self initWithClientId:clientId
                         userName:userName
                         password:password
                        keepAlive:keepAliveInterval
                     cleanSession:cleanSessionFlag
                             will:willFlag
                        willTopic:willTopic
                          willMsg:willMsg
                          willQoS:willQoS
                   willRetainFlag:willRetainFlag
                    protocolLevel:protocolLevel
                          runLoop:runLoop
                          forMode:runLoopMode
                   securityPolicy:securityPolicy
                     certificates:nil];

}

- (ANMQTTSession *)initWithClientId:(NSString *)clientId
                         userName:(NSString *)userName
                         password:(NSString *)password
                        keepAlive:(UInt16)keepAliveInterval
                     cleanSession:(BOOL)cleanSessionFlag
                             will:(BOOL)willFlag
                        willTopic:(NSString *)willTopic
                          willMsg:(NSData *)willMsg
                          willQoS:(ANMQTTQosLevel)willQoS
                   willRetainFlag:(BOOL)willRetainFlag
                    protocolLevel:(UInt8)protocolLevel
                          runLoop:(NSRunLoop *)runLoop
                          forMode:(NSString *)runLoopMode
                   securityPolicy:(ANMQTTSSLSecurityPolicy *) securityPolicy
                     certificates:(NSArray *)certificates {
    self = [super init];
    if (DEBUGSESS) NSLog(@"MQTTClient %s %s", __DATE__, __TIME__);

    if (DEBUGSESS)
        NSLog(@"%@ %s:%d - initWithClientId:%@ userName:%@ keepAlive:%d cleanSession:%d will:%d willTopic:%@ "
              "willMsg:%@ willQos:%d willRetainFlag:%d protocolLevel:%d runLoop:%@ forMode:%@ "
              "securityPolicy:%@ certificates:%@", self, __func__, __LINE__,
              clientId, userName, keepAliveInterval,cleanSessionFlag, willFlag, willTopic,
              willMsg, willQoS, willRetainFlag, protocolLevel, @"runLoop", runLoopMode,
              securityPolicy, certificates);

    self.clientId = clientId;
    self.userName = userName;
    self.password = password;
    self.keepAliveInterval = keepAliveInterval;
    self.cleanSessionFlag = cleanSessionFlag;
    self.willFlag = willFlag;
    self.willTopic = willTopic;
    self.willMsg = willMsg;
    self.willQoS = willQoS;
    self.willRetainFlag = willRetainFlag;
    self.protocolLevel = protocolLevel;
    self.runLoop = runLoop;
    self.runLoopMode = runLoopMode;
    self.securityPolicy = securityPolicy;
    self.certificates = certificates;

    self.txMsgId = 1;
    self.persistence = [[ANMQTTPersistence alloc] init];
    return self;
}

- (void)setClientId:(NSString *)clientId
{
    if (!clientId) {
        clientId = [NSString stringWithFormat:@"MQTTClient%.0f",fmod([[NSDate date] timeIntervalSince1970], 1.0) * 1000000.0];
    }
    
    //NSAssert(clientId.length > 0 || self.cleanSessionFlag, @"clientId must be at least 1 character long if cleanSessionFlag is off");
    
    //NSAssert([clientId dataUsingEncoding:NSUTF8StringEncoding], @"clientId contains non-UTF8 characters");
    //NSAssert([clientId dataUsingEncoding:NSUTF8StringEncoding].length <= 65535L, @"clientId may not be longer than 65535 bytes in UTF8 representation");
    
    _clientId = clientId;
}

- (void)setUserName:(NSString *)userName
{
    if (userName) {
        //NSAssert([userName dataUsingEncoding:NSUTF8StringEncoding], @"userName contains non-UTF8 characters");
        //NSAssert([userName dataUsingEncoding:NSUTF8StringEncoding].length <= 65535L, @"userName may not be longer than 65535 bytes in UTF8 representation");
    }
    
    _userName = userName;
}

- (void)setPassword:(NSString *)password
{
    if (password) {
        //NSAssert(self.userName, @"password specified without userName");
        //NSAssert([password dataUsingEncoding:NSUTF8StringEncoding], @"password contains non-UTF8 characters");
        //NSAssert([password dataUsingEncoding:NSUTF8StringEncoding].length <= 65535L, @"password may not be longer than 65535 bytes in UTF8 representation");
    }
    _password = password;
}

- (void)setProtocolLevel:(UInt8)protocolLevel
{
    //NSAssert(protocolLevel == 3 || protocolLevel == 4, @"allowed protocolLevel values are 3 or 4 only");
    
    _protocolLevel = protocolLevel;
}

- (void)setRunLoop:(NSRunLoop *)runLoop
{
    if (!runLoop ) {
        runLoop = [NSRunLoop currentRunLoop];
    }
    _runLoop = runLoop;
}

- (void)setRunLoopMode:(NSString *)runLoopMode
{
    if (!runLoopMode) {
        runLoopMode = NSRunLoopCommonModes;
    }
    _runLoopMode = runLoopMode;
}

- (void)setTxMsgId:(UInt16)txMsgId
{
    _txMsgId = txMsgId;
}

- (id)initWithClientId:(NSString*)theClientId {

    return [self initWithClientId:theClientId
                         userName:nil
                         password:nil
                        keepAlive:60
                     cleanSession:YES
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:nil
                          forMode:nil];
}

- (id)initWithClientId:(NSString*)theClientId
               runLoop:(NSRunLoop*)theRunLoop
               forMode:(NSString*)theRunLoopMode {

    return [self initWithClientId:theClientId
                         userName:nil
                         password:nil
                        keepAlive:60
                     cleanSession:YES
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:theRunLoop
                          forMode:theRunLoopMode];
}

- (id)initWithClientId:(NSString*)theClientId
              userName:(NSString*)theUsername
              password:(NSString*)thePassword {

    return [self initWithClientId:theClientId
                         userName:theUsername
                         password:thePassword
                        keepAlive:60
                     cleanSession:YES
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:nil
                          forMode:nil];
}

- (id)initWithClientId:(NSString*)theClientId
              userName:(NSString*)theUserName
              password:(NSString*)thePassword
               runLoop:(NSRunLoop*)theRunLoop
               forMode:(NSString*)theRunLoopMode {

    return [self initWithClientId:theClientId
                         userName:theUserName
                         password:thePassword
                        keepAlive:60
                     cleanSession:YES
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:theRunLoop
                          forMode:theRunLoopMode];
}

- (id)initWithClientId:(NSString*)theClientId
              userName:(NSString*)theUsername
              password:(NSString*)thePassword
             keepAlive:(UInt16)theKeepAliveInterval
          cleanSession:(BOOL)cleanSessionFlag {

    return [self initWithClientId:theClientId
                         userName:theUsername
                         password:thePassword
                        keepAlive:theKeepAliveInterval
                     cleanSession:cleanSessionFlag
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:nil
                          forMode:nil];
}

- (id)initWithClientId:(NSString*)theClientId
              userName:(NSString*)theUsername
              password:(NSString*)thePassword
             keepAlive:(UInt16)theKeepAlive
          cleanSession:(BOOL)theCleanSessionFlag
               runLoop:(NSRunLoop*)theRunLoop
               forMode:(NSString*)theMode {

    return [self initWithClientId:theClientId
                         userName:theUsername
                         password:thePassword
                        keepAlive:theKeepAlive
                     cleanSession:theCleanSessionFlag
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:theRunLoop
                          forMode:theMode];
}

- (id)initWithClientId:(NSString*)theClientId
              userName:(NSString*)theUserName
              password:(NSString*)thePassword
             keepAlive:(UInt16)theKeepAliveInterval
          cleanSession:(BOOL)theCleanSessionFlag
             willTopic:(NSString*)willTopic
               willMsg:(NSData*)willMsg
               willQoS:(UInt8)willQoS
        willRetainFlag:(BOOL)willRetainFlag {

    return [self initWithClientId:theClientId
                         userName:theUserName
                         password:thePassword
                        keepAlive:theKeepAliveInterval
                     cleanSession:theCleanSessionFlag
                             will:YES
                        willTopic:willTopic
                          willMsg:willMsg
                          willQoS:willQoS
                   willRetainFlag:willRetainFlag
                    protocolLevel:4
                          runLoop:nil
                          forMode:nil];
}

- (id)initWithClientId:(NSString*)theClientId
              userName:(NSString*)theUserName
              password:(NSString*)thePassword
             keepAlive:(UInt16)theKeepAliveInterval
          cleanSession:(BOOL)theCleanSessionFlag
             willTopic:(NSString*)willTopic
               willMsg:(NSData*)willMsg
               willQoS:(UInt8)willQoS
        willRetainFlag:(BOOL)willRetainFlag
               runLoop:(NSRunLoop*)theRunLoop
               forMode:(NSString*)theRunLoopMode {

    return [self initWithClientId:theClientId
                         userName:theUserName
                         password:thePassword
                        keepAlive:theKeepAliveInterval
                     cleanSession:theCleanSessionFlag
                             will:YES
                        willTopic:willTopic
                          willMsg:willMsg
                          willQoS:willQoS
                   willRetainFlag:willRetainFlag
                    protocolLevel:4
                          runLoop:theRunLoop
                          forMode:theRunLoopMode];
}

- (id)initWithClientId:(NSString*)theClientId
             keepAlive:(UInt16)theKeepAliveInterval
        connectMessage:(ANMQTTMessage*)theConnectMessage
               runLoop:(NSRunLoop*)theRunLoop
               forMode:(NSString*)theRunLoopMode {

    self.connectMessage = theConnectMessage;
    return [self initWithClientId:theClientId
                         userName:nil
                         password:nil
                        keepAlive:theKeepAliveInterval
                     cleanSession:YES
                             will:NO
                        willTopic:nil
                          willMsg:nil
                          willQoS:ANMQTTQosLevelAtMostOnce
                   willRetainFlag:FALSE
                    protocolLevel:4
                          runLoop:theRunLoop
                          forMode:theRunLoopMode];
}

- (void)connectToHost:(NSString*)host port:(UInt32)port usingSSL:(BOOL)usingSSL
{
    if (DEBUGSESS) NSLog(@"%@ connectToHost:%@ port:%d usingSSL:%d]", self, host, (unsigned int)port, usingSSL);
    
    self.selfReference = self;
    
    if (!host) {
        host = @"localhost";
    }
    
    if (self.cleanSessionFlag) {
        [self.persistence deleteAllFlowsForClientId:self.clientId];
    }
    [self tell];
    

    NSError* connectError;
    self.status = ANMQTTSessionStatusCreated;
    
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)host, port, &readStream, &writeStream);
    
    CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    
    if (usingSSL) {
        NSMutableDictionary *sslOptions = [[NSMutableDictionary alloc] init];

        if (!self.securityPolicy)
        {
            // use OS CA model
            [sslOptions setObject:(NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL
                           forKey:(NSString*)kCFStreamSSLLevel];
            if (self.certificates) {
                [sslOptions setObject:self.certificates
                               forKey:(NSString *)kCFStreamSSLCertificates];
            }
        }
        else
        {
            // delegate certificates verify operation to our secure policy.
            // by disabling chain validation, it becomes our responsibility to verify that the host at the other end can be trusted.
            // the server's certificates will be verified during MQTT encoder/decoder processing.
            [sslOptions setObject:(NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL
                           forKey:(NSString*)kCFStreamSSLLevel];
            [sslOptions setObject:[NSNumber numberWithBool:NO]
                           forKey:(NSString *)kCFStreamSSLValidatesCertificateChain];
            if (self.certificates) {
                [sslOptions setObject:self.certificates
                               forKey:(NSString *)kCFStreamSSLCertificates];
            }

        }

        if(!CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)(sslOptions))){
            connectError = [NSError errorWithDomain:@"MQTT"
                                               code:errSSLInternal
                                           userInfo:@{NSLocalizedDescriptionKey : @"Fail to init ssl input stream!"}];
        }
        if(!CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)(sslOptions))){
            connectError = [NSError errorWithDomain:@"MQTT"
                                               code:errSSLInternal
                                           userInfo:@{NSLocalizedDescriptionKey : @"Fail to init ssl output stream!"}];
        }
    }

    if(!connectError){
        self.encoder = [[ANMQTTEncoder alloc] initWithStream:CFBridgingRelease(writeStream)
                                                   runLoop:self.runLoop
                                               runLoopMode:self.runLoopMode
                                            securityPolicy:usingSSL? self.securityPolicy : nil
                                            securityDomain:usingSSL? host : nil];

        self.decoder = [[ANMQTTDecoder alloc] initWithStream:CFBridgingRelease(readStream)
                                                   runLoop:self.runLoop
                                               runLoopMode:self.runLoopMode
                                            securityPolicy:usingSSL? self.securityPolicy : nil
                                            securityDomain:usingSSL? host : nil];

        self.encoder.delegate = self;
        self.decoder.delegate = self;

        [self.encoder open];
        [self.decoder open];
    }
    else{
        [self error:ANMQTTSessionEventConnectionError error: connectError];
    }
}

- (void)connectToHost:(NSString*)ip port:(UInt32)port {
    [self connectToHost:ip port:port usingSSL:NO];
}

- (void)connectToHost:(NSString*)ip port:(UInt32)port withConnectionHandler:(void (^)(ANMQTTSessionEvent event))connHandler messageHandler:(void (^)(NSData* data, NSString* topic))messHandler {
    self.messageHandler = messHandler;
    self.connectionHandler = connHandler;
    
    [self connectToHost:ip port:port usingSSL:NO];
}

- (void)connectToHost:(NSString*)ip port:(UInt32)port usingSSL:(BOOL)usingSSL withConnectionHandler:(void (^)(ANMQTTSessionEvent event))connHandler messageHandler:(void (^)(NSData* data, NSString* topic))messHandler {
    self.messageHandler = messHandler;
    self.connectionHandler = connHandler;
    
    [self connectToHost:ip port:port usingSSL:usingSSL];
}


- (BOOL)connectAndWaitToHost:(NSString*)host port:(UInt32)port usingSSL:(BOOL)usingSSL
{
    self.synchronConnect = TRUE;
    
    [self connectToHost:host port:port usingSSL:usingSSL];
    
    while (self.synchronConnect) {
        if (DEBUGSESS) NSLog(@"%@ waiting for connect", self);
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
    }
    
    if (DEBUGSESS) NSLog(@"%@ end connect", self);
    
    return (self.status == ANMQTTSessionStatusConnected);
}

- (UInt16)subscribeToTopic:(NSString *)topic
                   atLevel:(ANMQTTQosLevel)qosLevel
{
    if (DEBUGSESS) NSLog(@"%@ subscribeToTopic:%@ atLevel:%d]", self, topic, qosLevel);
    
    //NSAssert(qosLevel >= 0 && qosLevel <= 2, @"qosLevel must be 0, 1, or 2");
    
    UInt16 mid = [self nextMsgId];
    [self send:[ANMQTTMessage subscribeMessageWithMessageId:mid
                                                   topics:topic ? @{topic: @(qosLevel)} : @{}]];
    return mid;
}

- (void)subscribeTopic:(NSString*)theTopic {
    [self subscribeToTopic:theTopic atLevel:ANMQTTQosLevelAtLeastOnce];
}

- (BOOL)subscribeAndWaitToTopic:(NSString *)topic atLevel:(ANMQTTQosLevel)qosLevel
{
    self.synchronSub = TRUE;
    UInt16 mid = [self subscribeToTopic:topic atLevel:qosLevel];
    self.synchronSubMid = mid;
    
    while (self.synchronSub) {
        if (DEBUGSESS) NSLog(@"%@ waiting for suback %d", self, mid);
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
    }
    
    if (DEBUGSESS) NSLog(@"%@ end subscribe", self);
    
    if (self.synchronSubMid == mid) {
        return TRUE;
    } else {
        return FALSE;
    }
}

- (UInt16)subscribeToTopics:(NSDictionary *)topics
{
    if (DEBUGSESS) NSLog(@"%@ subscribeToTopics:%@]", self, topics);
    
    //for (NSNumber *qos in [topics allValues]) {
    //NSAssert([qos intValue] >= 0 && [qos intValue] <= 2, @"qosLevel must be 0, 1, or 2");
    //}
    
    UInt16 mid = [self nextMsgId];
    [self send:[ANMQTTMessage subscribeMessageWithMessageId:mid
                                                   topics:topics]];
    return mid;
}

- (BOOL)subscribeAndWaitToTopics:(NSDictionary *)topics
{
    self.synchronSub = TRUE;
    UInt16 mid = [self subscribeToTopics:topics];
    self.synchronSubMid = mid;
    
    while (self.synchronSub) {
        if (DEBUGSESS) NSLog(@"%@ waiting for suback %d", self, mid);
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
    }
    
    if (DEBUGSESS) NSLog(@"%@ end subscribe", self);
    
    if (self.synchronSubMid == mid) {
        return TRUE;
    } else {
        return FALSE;
    }
}

- (UInt16)unsubscribeTopic:(NSString*)theTopic
{
    if (DEBUGSESS) NSLog(@"%@ unsubscribeTopic:%@", self, theTopic);
    UInt16 mid = [self nextMsgId];
    [self send:[ANMQTTMessage unsubscribeMessageWithMessageId:mid
                                                     topics:theTopic ? @[theTopic] : @[]]];
    return mid;
}

- (BOOL)unsubscribeAndWaitTopic:(NSString *)theTopic
{
    self.synchronUnsub = TRUE;
    UInt16 mid = [self unsubscribeTopic:theTopic];
    self.synchronUnsubMid = mid;
    
    while (self.synchronUnsub) {
        if (DEBUGSESS) NSLog(@"%@ waiting for unsuback %d", self, mid);
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
    }
    
    if (DEBUGSESS) NSLog(@"%@ end unsubscribe", self);
    
    if (self.synchronUnsubMid == mid) {
        return TRUE;
    } else {
        return FALSE;
    }
}

- (UInt16)unsubscribeTopics:(NSArray *)theTopics
{
    if (DEBUGSESS) NSLog(@"%@ unsubscribeTopics:%@", self, theTopics);
    UInt16 mid = [self nextMsgId];
    [self send:[ANMQTTMessage unsubscribeMessageWithMessageId:mid
                                                     topics:theTopics]];
    return mid;
}

- (BOOL)unsubscribeAndWaitTopics:(NSArray *)theTopics
{
    self.synchronUnsub = TRUE;
    UInt16 mid = [self unsubscribeTopics:theTopics];
    self.synchronUnsubMid = mid;
    
    while (self.synchronUnsub) {
        if (DEBUGSESS) NSLog(@"%@ waiting for unsuback %d", self, mid);
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
    }
    
    if (DEBUGSESS) NSLog(@"%@ end unsubscribe", self);
    
    if (self.synchronUnsubMid == mid) {
        return TRUE;
    } else {
        return FALSE;
    }
}

- (UInt16)publishData:(NSData*)data
              onTopic:(NSString*)topic
               retain:(BOOL)retainFlag
                  qos:(ANMQTTQosLevel)qos
{
    return [self publishData:data onTopic:topic retain:retainFlag qos:qos messageId:nil];
}

- (UInt16)publishData:(NSData*)data
              onTopic:(NSString*)topic
               retain:(BOOL)retainFlag
                  qos:(ANMQTTQosLevel)qos
            messageId:(NSString *)messageId
{
    if (DEBUGSESS) NSLog(@"%@ publishData:%@... onTopic:%@ retain:%d qos:%ld",
                         self,
                         [data subdataWithRange:NSMakeRange(0, MIN(16, data.length))],
                         topic,
                         retainFlag,
                         (long)qos);
    
    if (!data) {
        data = [[NSData alloc] init];
    }
    
    //NSAssert(qos >= 0 && qos <= 2, @"qos must be 0, 1, or 2");
    
    UInt16 msgId = 0;
    if (qos) {
        msgId = [self nextMsgId];
    }
    ANMQTTMessage *msg = [ANMQTTMessage publishMessageWithData:data
                                                   onTopic:topic
                                                       qos:qos
                                                     msgId:msgId
                                                retainFlag:retainFlag
                                                   dupFlag:FALSE];
    if (qos) {
        ANMQTTFlow *flow = [self.persistence storeMessageForClientId:self.clientId
                                                             topic:topic
                                                              data:data
                                                        retainFlag:retainFlag
                                                               qos:qos
                                                             msgId:msgId
                                                      incomingFlag:NO
                                                       anMessageId:messageId];

        if (!flow) {
            if (DEBUGSESS) NSLog(@"%@ dropping outgoing messages", self);
            msgId = 0;
        } else {
            [self tell];
            if ([self.persistence windowSize:self.clientId] <= self.persistence.maxWindowSize) {
                if ([self send:msg]) {
                    flow.deadline = [NSDate dateWithTimeIntervalSinceNow:DUPTIMEOUT];
                }
            }
        }
    } else {
        [self send:msg];
    }
    
    return msgId;
}

- (BOOL)publishAndWaitData:(NSData*)data
                   onTopic:(NSString*)topic
                    retain:(BOOL)retainFlag
                       qos:(ANMQTTQosLevel)qos
{
    if (qos != ANMQTTQosLevelAtMostOnce) {
        self.synchronPub = TRUE;
    }
    
    UInt16 mid = [self publishData:data onTopic:topic retain:retainFlag qos:qos];
    if (qos == ANMQTTQosLevelAtMostOnce) {
        return TRUE;
    } else {
        self.synchronPubMid = mid;
        
        while (self.synchronPub) {
            if (DEBUGSESS) NSLog(@"%@ waiting for mid %d", self, mid);
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
        }
        
        if (DEBUGSESS) NSLog(@"%@ end publish", self);
        
        if (self.synchronPubMid == mid) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
}

- (void)publishData:(NSData*)theData onTopic:(NSString*)theTopic {
    [self publishData:theData onTopic:theTopic retain:NO qos:ANMQTTQosLevelAtLeastOnce];
}

- (void)publishDataAtLeastOnce:(NSData*)theData onTopic:(NSString*)theTopic {
    [self publishData:theData onTopic:theTopic retain:NO qos:ANMQTTQosLevelAtLeastOnce];
}

- (void)publishDataAtLeastOnce:(NSData*)theData onTopic:(NSString*)theTopic retain:(BOOL)retainFlag {
    [self publishData:theData onTopic:theTopic retain:retainFlag qos:ANMQTTQosLevelAtLeastOnce];
}

- (void)publishDataAtMostOnce:(NSData*)theData onTopic:(NSString*)theTopic {
    [self publishData:theData onTopic:theTopic retain:NO qos:ANMQTTQosLevelAtMostOnce];
}

- (void)publishDataAtMostOnce:(NSData*)theData onTopic:(NSString*)theTopic retain:(BOOL)retainFlag {
    [self publishData:theData onTopic:theTopic retain:retainFlag qos:ANMQTTQosLevelAtMostOnce];
}

- (void)publishDataExactlyOnce:(NSData*)theData onTopic:(NSString*)theTopic {
    [self publishData:theData onTopic:theTopic retain:NO qos:ANMQTTQosLevelExactlyOnce];
}

- (void)publishDataExactlyOnce:(NSData*)theData onTopic:(NSString*)theTopic retain:(BOOL)retainFlag {
    [self publishData:theData onTopic:theTopic retain:retainFlag qos:ANMQTTQosLevelExactlyOnce];
}

- (void)publishJson:(id)payload onTopic:(NSString*)theTopic {
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (data) {
        [self publishData:data onTopic:theTopic retain:FALSE qos:ANMQTTQosLevelAtLeastOnce];
    }
}

- (void)close
{
    if (DEBUGSESS) NSLog(@"%@ close", self);
    
    if (self.status == ANMQTTSessionStatusConnected) {
        if (DEBUGSESS) NSLog(@"%@ disconnecting", self);
        self.status = ANMQTTSessionStatusDisconnecting;
        // 2016/11/20 do not need to inform server that we are getting offline
        // [self send:[ANMQTTMessage disconnectMessage]];
        [self closeInternal];
    } else {
        [self closeInternal];
    }
}

- (void)closeAndWait
{
    self.synchronDisconnect = TRUE;
    [self close];
    
    while (self.synchronDisconnect) {
        if (DEBUGSESS) NSLog(@"%@ waiting for close", self);
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:.1]];
    }
    if (DEBUGSESS) NSLog(@"%@ end close", self);
    
}

- (void)closeInternal
{
    if (DEBUGSESS) NSLog(@"%@ closeInternal", self);
    
    if (self.checkDupTimer) {
        [self.checkDupTimer invalidate];
        self.checkDupTimer = nil;
    }
    
    if (self.keepAliveTimer) {
        [self.keepAliveTimer invalidate];
        self.keepAliveTimer = nil;
    }

    if(self.encoder){
        [self.encoder close];
        self.encoder.delegate = nil;
    }

    if(self.decoder){
        [self.decoder close];
        self.decoder.delegate = nil;
    }

    self.status = ANMQTTSessionStatusClosed;
    if ([self.delegate respondsToSelector:@selector(handleEvent:event:error:)]) {
        [self.delegate handleEvent:self event:ANMQTTSessionEventConnectionClosed error:nil];
    }
    if ([self.delegate respondsToSelector:@selector(connectionClosed:)]) {
        [self.delegate connectionClosed:self];
    }
    
    [self tell];
    self.synchronPub = FALSE;
    self.synchronSub = FALSE;
    self.synchronUnsub = FALSE;
    self.synchronConnect = FALSE;
    self.synchronDisconnect = FALSE;
    self.selfReference = nil;
}


- (void)keepAlive:(NSTimer *)timer
{
    if (DEBUGSESS)  NSLog(@"%@ keepAlive %@ @%.0f", self, self.clientId, [[NSDate date] timeIntervalSince1970]);
    if ([self.encoder status] == ANMQTTEncoderStatusReady) {
        ANMQTTMessage *msg = [ANMQTTMessage pingreqMessage];
        [self.encoder encodeMessage:msg];
    }
}

- (void)checkDup:(NSTimer *)timer
{
    if (DEBUGSESS)  NSLog(@"%@ checkDup %@ @%.0f", self, self.clientId, [[NSDate date] timeIntervalSince1970]);
    [self checkTxFlows];
}

- (void)checkTxFlows {
    NSUInteger windowSize;
    ANMQTTMessage *message;
    NSArray *flows = [self.persistence allFlowsforClientId:self.clientId
                                              incomingFlag:NO];
    windowSize = 0;
    message = nil;
    
    for (ANMQTTFlow *flow in flows) {
        if ([flow.commandType intValue] != 0) {
            windowSize++;
        }
    }
    for (ANMQTTFlow *flow in flows) {
        if (DEBUGSESS)  NSLog(@"%@ %@ flow %@ %@ %@", self, self.clientId, flow.deadline, flow.commandType, flow.messageId);
        if ([flow.deadline compare:[NSDate date]] == NSOrderedAscending) {
            switch ([flow.commandType intValue]) {
                case 0:
                    if (windowSize <= self.persistence.maxWindowSize) {
                        message = [ANMQTTMessage publishMessageWithData:flow.data
                                                              onTopic:flow.topic
                                                                  qos:[flow.qosLevel intValue]
                                                                msgId:[flow.messageId intValue]
                                                           retainFlag:[flow.retainedFlag boolValue]
                                                              dupFlag:NO];
                        [self send:message];
                        flow.commandType = @(ANMQTTPublish);
                        flow.deadline = [NSDate dateWithTimeIntervalSinceNow:DUPTIMEOUT];
                        windowSize++;
                    }
                    break;
                case ANMQTTPublish:
                    message = [ANMQTTMessage publishMessageWithData:flow.data
                                                          onTopic:flow.topic
                                                              qos:[flow.qosLevel intValue]
                                                            msgId:[flow.messageId intValue]
                                                       retainFlag:[flow.retainedFlag boolValue]
                                                          dupFlag:YES];
                    [self send:message];
                    flow.deadline = [NSDate dateWithTimeIntervalSinceNow:DUPTIMEOUT];
                    break;
                case ANMQTTPubrel:
                    message = [ANMQTTMessage pubrelMessageWithMessageId:[flow.messageId intValue]];
                    [self send:message];
                    flow.deadline = [NSDate dateWithTimeIntervalSinceNow:DUPTIMEOUT];
                    break;
                default:
                    break;
            }
        }
    }
    [self.persistence sync];
}

- (void)encoder:(ANMQTTEncoder*)sender handleEvent:(ANMQTTEncoderEvent)eventCode error:(NSError *)error
{
    if (DEBUGSESS) {
        NSArray *events = @[
                            @"MQTTEncoderEventReady",
                            @"MQTTEncoderEventErrorOccurred"
                            ];
        
        NSLog(@"%@ encoder handleEvent: %@ (%d) %@", self, events[eventCode % [events count]], eventCode, [error description]);
    }
    switch (eventCode) {
        case ANMQTTEncoderEventReady:
            switch (self.status) {
                case ANMQTTSessionStatusCreated:
                    if (!self.connectMessage) {
                        [sender encodeMessage:[ANMQTTMessage connectMessageWithClientId:self.clientId
                                                                             userName:self.userName
                                                                             password:self.password
                                                                            keepAlive:self.keepAliveInterval
                                                                         cleanSession:self.cleanSessionFlag
                                                                                 will:self.willFlag
                                                                            willTopic:self.willTopic
                                                                              willMsg:self.willMsg
                                                                              willQoS:self.willQoS
                                                                           willRetain:self.willRetainFlag
                                                                        protocolLevel:self.protocolLevel]];
                    } else {
                        [sender encodeMessage:self.connectMessage];
                    }
                    self.status = ANMQTTSessionStatusConnecting;
                    break;
                case ANMQTTSessionStatusConnecting:
                    break;
                case ANMQTTSessionStatusConnected:
                    [self tell];
                    [self checkTxFlows];
                    break;
                case ANMQTTSessionStatusDisconnecting:
                    if (DEBUGSESS) NSLog(@"%@ disconnect sent", self);
                    // [self closeInternal]; rather wait until server closes connect, see issue #10
                    break;
                case ANMQTTSessionStatusClosed:
                    break;
                case ANMQTTSessionStatusError:
                    break;
            }
            break;
        case ANMQTTEncoderEventErrorOccurred:
            [self connectionError:error];
            break;
    }
}

- (void)encoder:(ANMQTTEncoder *)sender sending:(int)type qos:(int)qos retained:(BOOL)retained duped:(BOOL)duped mid:(UInt16)mid data:(NSData *)data
{
    if ([self.delegate respondsToSelector:@selector(sending:type:qos:retained:duped:mid:data:)]) {
        [self.delegate sending:self type:type qos:qos retained:retained duped:duped mid:mid data:data];
    }
}

- (void)decoder:(ANMQTTDecoder*)sender handleEvent:(ANMQTTDecoderEvent)eventCode error:(NSError *)error
{
    if (DEBUGSESS) {
        NSArray *events = @[
                            @"ANMQTTDecoderEventProtocolError",
                            @"ANMQTTDecoderEventConnectionClosed",
                            @"ANMQTTDecoderEventConnectionError"
                            ];
        
        NSLog(@"%@ decoder handleEvent: %@ (%d) %@", self, events[eventCode % [events count]], eventCode, [error description]);
    }
    switch (eventCode) {
        case ANMQTTDecoderEventConnectionClosed:
            [self error:ANMQTTSessionEventConnectionClosedByBroker error:error];
            break;
        case ANMQTTDecoderEventConnectionError:
            [self connectionError:error];
            break;
        case ANMQTTDecoderEventProtocolError:
            [self protocolError:error];
            break;
    }
}

- (void)decoder:(ANMQTTDecoder*)sender newMessage:(ANMQTTMessage*)msg
{
    if ([self.delegate respondsToSelector:@selector(received:type:qos:retained:duped:mid:data:)]) {
        [self.delegate received:self
                           type:msg.type
                            qos:msg.qos
                       retained:msg.retainFlag
                          duped:msg.dupFlag
                            mid:0
                           data:msg.data];
    }
    if ([self.delegate respondsToSelector:@selector(ignoreReceived:type:qos:retained:duped:mid:data:)]) {
        if ([self.delegate ignoreReceived:self
                                     type:msg.type
                                      qos:msg.qos
                                 retained:msg.retainFlag
                                    duped:msg.dupFlag
                                      mid:0
                                     data:msg.data]) {
            return;
        }
    }
    switch (self.status) {
        case ANMQTTSessionStatusConnecting:
            switch ([msg type]) {
                case ANMQTTConnack:
                    if ([[msg data] length] != 2) {
                        [self protocolError:[NSError errorWithDomain:@"MQTT"
                                                                code:-2
                                                            userInfo:@{NSLocalizedDescriptionKey : @"MQTT protocol CONNACK expected"}]];
                    }
                    else {
                        const UInt8 *bytes = [[msg data] bytes];
                        if (bytes[1] == 0) {
                            self.status = ANMQTTSessionStatusConnected;
                            
                            self.checkDupTimer = [NSTimer timerWithTimeInterval:DUPLOOP
                                                                         target:self
                                                                       selector:@selector(checkDup:)
                                                                       userInfo:nil
                                                                        repeats:YES];
                            [self.runLoop addTimer:self.checkDupTimer forMode:self.runLoopMode];
                            [self checkDup:self.checkDupTimer];
                            
                            self.keepAliveTimer = [NSTimer timerWithTimeInterval:self.keepAliveInterval
                                                                          target:self
                                                                        selector:@selector(keepAlive:)
                                                                        userInfo:nil
                                                                         repeats:YES];
                            [self.runLoop addTimer:self.keepAliveTimer forMode:self.runLoopMode];
                            
                            if ([self.delegate respondsToSelector:@selector(handleEvent:event:error:)]) {
                                [self.delegate handleEvent:self event:ANMQTTSessionEventConnected error:nil];
                            }
                            if ([self.delegate respondsToSelector:@selector(connected:)]) {
                                [self.delegate connected:self];
                            }
                            if ([self.delegate respondsToSelector:@selector(connected:sessionPresent:)]) {
                                [self.delegate connected:self sessionPresent:((bytes[0] & 0x01) == 0x01)];
                            }
                            
                            if(self.connectionHandler){
                                self.connectionHandler(ANMQTTSessionEventConnected);
                            }
                            
                            self.synchronConnect = FALSE;
                        } else {
                            NSString *errorDescription;
                            switch (bytes[1]) {
                                case 1:
                                    errorDescription = @"MQTT CONNACK: unacceptable protocol version";
                                    break;
                                case 2:
                                    errorDescription = @"MQTT CONNACK: identifier rejected";
                                    break;
                                case 3:
                                    errorDescription = @"MQTT CONNACK: server unavailable";
                                    break;
                                case 4:
                                    errorDescription = @"MQTT CONNACK: bad user name or password";
                                    break;
                                case 5:
                                    errorDescription = @"MQTT CONNACK: not authorized";
                                    break;
                                default:
                                    errorDescription = @"MQTT CONNACK: reserved for future use";
                                    break;
                            }
                            
                            NSError *error = [NSError errorWithDomain:@"MQTT"
                                                                 code:bytes[1]
                                                             userInfo:@{NSLocalizedDescriptionKey : errorDescription}];
                            [self error:ANMQTTSessionEventConnectionRefused error:error];
                            if ([self.delegate respondsToSelector:@selector(connectionRefused:error:)]) {
                                [self.delegate connectionRefused:self error:error];
                            }
                            
                        }
                    }
                    break;
                default:
                    [self protocolError:[NSError errorWithDomain:@"MQTT"
                                                            code:-1
                                                        userInfo:@{NSLocalizedDescriptionKey : @"MQTT protocol no CONNACK"}]];
                    break;
            }
            break;
        case ANMQTTSessionStatusConnected:
            switch ([msg type]) {
                case ANMQTTPublish:
                    [self handlePublish:msg];
                    break;
                case ANMQTTPuback:
                    [self handlePuback:msg];
                    break;
                case ANMQTTPubrec:
                    [self handlePubrec:msg];
                    break;
                case ANMQTTPubrel:
                    [self handlePubrel:msg];
                    break;
                case ANMQTTPubcomp:
                    [self handlePubcomp:msg];
                    break;
                case ANMQTTSuback:
                    [self handleSuback:msg];
                    break;
                case ANMQTTUnsuback:
                    [self handleUnsuback:msg];
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
}

- (void)handlePublish:(ANMQTTMessage*)msg
{
    NSData *data = [msg data];
    if ([data length] < 2) {
        return;
    }
    UInt8 const *bytes = [data bytes];
    UInt16 topicLength = 256 * bytes[0] + bytes[1];
    if ([data length] < 2 + topicLength) {
        return;
    }
    NSData *topicData = [data subdataWithRange:NSMakeRange(2, topicLength)];
    NSString *topic = [[NSString alloc] initWithData:topicData
                                            encoding:NSUTF8StringEncoding];
    NSRange range = NSMakeRange(2 + topicLength, [data length] - topicLength - 2);
    data = [data subdataWithRange:range];
    if ([msg qos] == 0) {
        if ([self.delegate respondsToSelector:@selector(newMessage:data:onTopic:qos:retained:mid:)]) {
            [self.delegate newMessage:self data:data onTopic:topic qos:msg.qos retained:msg.retainFlag mid:0];
        }
        if(self.messageHandler){
            self.messageHandler(data, topic);
        }
    } else {
        if ([data length] >= 2) {
            bytes = [data bytes];
            UInt16 msgId = 256 * bytes[0] + bytes[1];
            msg.mid = msgId;
            data = [data subdataWithRange:NSMakeRange(2, [data length] - 2)];
            if ([msg qos] == 1) {
                if ([self.delegate respondsToSelector:@selector(newMessage:data:onTopic:qos:retained:mid:)]) {
                    [self.delegate newMessage:self data:data onTopic:topic qos:msg.qos retained:msg.retainFlag mid:msgId];
                }
                if(self.messageHandler){
                    self.messageHandler(data, topic);
                }
                [self send:[ANMQTTMessage pubackMessageWithMessageId:msgId]];
                return;
            } else {
                if (![self.persistence storeMessageForClientId:self.clientId
                                                         topic:topic
                                                          data:data
                                                    retainFlag:msg.retainFlag
                                                           qos:msg.qos
                                                         msgId:msgId
                                                  incomingFlag:YES
                                                   anMessageId:nil]) {
                    if (DEBUGSESS) NSLog(@"%@ dropping incoming messages", self);
                } else {
                    [self tell];
                    [self send:[ANMQTTMessage pubrecMessageWithMessageId:msgId]];
                }
            }
        }
    }
}

- (void)handlePuback:(ANMQTTMessage*)msg
{
    if ([[msg data] length] == 2) {
        UInt8 const *bytes = [[msg data] bytes];
        UInt16 messageId = (256 * bytes[0] + bytes[1]);
        msg.mid = messageId;
        ANMQTTFlow *flow = [self.persistence flowforClientId:self.clientId
                                              incomingFlag:NO
                                                 messageId:messageId];
        if (flow) {
            if ([flow.commandType intValue] == ANMQTTPublish && [flow.qosLevel intValue] == ANMQTTQosLevelAtLeastOnce) {
                [self.persistence deleteFlow:flow];
                [self.persistence sync];
                [self tell];
                if ([self.delegate respondsToSelector:@selector(messageDelivered:msgID:)]) {
                    [self.delegate messageDelivered:self msgID:messageId];
                }
                if (self.synchronPub && self.synchronPubMid == messageId) {
                    self.synchronPub = FALSE;
                }
            }
        }
    }
}

- (void)handleSuback:(ANMQTTMessage*)msg
{
    if ([[msg data] length] >= 3) {
        UInt8 const *bytes = [[msg data] bytes];
        UInt16 messageId = (256 * bytes[0] + bytes[1]);
        msg.mid = messageId;
        NSMutableArray *qoss = [[NSMutableArray alloc] init];
        for (int i = 2; i < [[msg data] length]; i++) {
            [qoss addObject:@(bytes[i])];
        }
        if ([self.delegate respondsToSelector:@selector(subAckReceived:msgID:grantedQoss:)]) {
            [self.delegate subAckReceived:self msgID:msg.mid grantedQoss:qoss];
        }
        if (self.synchronSub && self.synchronSubMid == msg.mid) {
            self.synchronSub = FALSE;
        }
    }
}

- (void)handleUnsuback:(ANMQTTMessage*)msg
{
    if ([[msg data] length] == 2) {
        UInt8 const *bytes = [[msg data] bytes];
        UInt16 messageId = (256 * bytes[0] + bytes[1]);
        msg.mid = messageId;
        if ([self.delegate respondsToSelector:@selector(unsubAckReceived:msgID:)]) {
            [self.delegate unsubAckReceived:self msgID:msg.mid];
        }
        if (self.synchronUnsub && self.synchronUnsubMid == msg.mid) {
            self.synchronUnsub = FALSE;
        }
    }
}

- (void)handlePubrec:(ANMQTTMessage*)msg
{
    int totalLength = [[msg data] length];
    if (totalLength >= 2) {
        UInt8 const *bytes = [[msg data] bytes];
        UInt16 messageId = (256 * bytes[0] + bytes[1]);
        msg.mid = messageId;
        
        ANMQTTMessage *pubrelmsg = [ANMQTTMessage pubrelMessageWithMessageId:messageId];
        ANMQTTFlow *flow = [self.persistence flowforClientId:self.clientId
                                              incomingFlag:NO
                                                 messageId:messageId];
        if (flow) {
            if ([flow.commandType intValue] == ANMQTTPublish && [flow.qosLevel intValue] == ANMQTTQosLevelExactlyOnce) {
                flow.commandType = @(ANMQTTPubrel);
                flow.topic = nil;
                flow.data = nil;
                flow.deadline = [NSDate dateWithTimeIntervalSinceNow:DUPTIMEOUT];
                
                if (totalLength > 2) {
                    NSData *extra = [[msg data] subdataWithRange:NSMakeRange(2, totalLength - 2)];
                    NSString *extraPayload = [[NSString alloc] initWithData:extra encoding:NSUTF8StringEncoding];
                    flow.extraPayload = extraPayload;
                }
                [self.persistence sync];
            }
        }
        [self send:pubrelmsg];
    }
}

- (void)handlePubrel:(ANMQTTMessage*)msg
{
    if ([[msg data] length] == 2) {
        UInt8 const *bytes = [[msg data] bytes];
        UInt16 messageId = (256 * bytes[0] + bytes[1]);
        ANMQTTFlow *flow = [self.persistence flowforClientId:self.clientId
                                              incomingFlag:YES
                                                 messageId:messageId];
        if (flow) {
            if ([self.delegate respondsToSelector:@selector(newMessage:data:onTopic:qos:retained:mid:)]) {
                [self.delegate newMessage:self
                                     data:flow.data
                                  onTopic:flow.topic
                                      qos:[flow.qosLevel intValue]
                                 retained:[flow.retainedFlag boolValue]
                                      mid:[flow.messageId intValue]
                 ];
            }
            if(self.messageHandler){
                self.messageHandler(flow.data, flow.topic);
            }
            
            [self.persistence deleteFlow:flow];
            [self.persistence sync];
            [self tell];
        }
        [self send:[ANMQTTMessage pubcompMessageWithMessageId:messageId]];
    }
}

- (void)handlePubcomp:(ANMQTTMessage*)msg {
    if ([[msg data] length] == 2) {
        UInt8 const *bytes = [[msg data] bytes];
        UInt16 messageId = (256 * bytes[0] + bytes[1]);
        ANMQTTFlow *flow = [self.persistence flowforClientId:self.clientId
                                              incomingFlag:NO
                                                 messageId:messageId];
        if (flow && [flow.commandType intValue] == ANMQTTPubrel) {
            NSString *extraPayload = flow.extraPayload;
            NSString *anMessageId = flow.anMessageId;
            
            [self.persistence deleteFlow:flow];
            [self.persistence sync];
            [self tell];
            if ([self.delegate respondsToSelector:@selector(messageDelivered:messageId:extra:)]) {
                [self.delegate messageDelivered:self messageId:anMessageId extra:extraPayload];
            }
            if (self.synchronPub && self.synchronPubMid == messageId) {
                self.synchronPub = FALSE;
            }
        }
    }
}

- (void)connectionError:(NSError *)error {
    [self error:ANMQTTSessionEventConnectionError error:error];
    if ([self.delegate respondsToSelector:@selector(connectionError:error:)]) {
        [self.delegate connectionError:self error:error];
    }
}

- (void)protocolError:(NSError *)error {
    [self error:ANMQTTSessionEventProtocolError error:error];
    if ([self.delegate respondsToSelector:@selector(protocolError:error:)]) {
        [self.delegate protocolError:self error:error];
    }
}

- (void)error:(ANMQTTSessionEvent)eventCode error:(NSError *)error {
    
    self.status = ANMQTTSessionStatusError;
    [self closeInternal];
    if ([self.delegate respondsToSelector:@selector(handleEvent:event:error:)]) {
        [self.delegate handleEvent:self event:eventCode error:error];
    }
    
    if(self.connectionHandler){
        self.connectionHandler(eventCode);
    }
    
    self.synchronPub = FALSE;
    self.synchronSub = FALSE;
    self.synchronUnsub = FALSE;
    self.synchronConnect = FALSE;
    self.synchronDisconnect = FALSE;
}

- (BOOL)send:(ANMQTTMessage*)msg {
    if ([self.encoder status] == ANMQTTEncoderStatusReady) {
        [self.encoder encodeMessage:msg];
        return TRUE;
    }
    return FALSE;
}

- (UInt16)nextMsgId {
    self.txMsgId++;
    while (self.txMsgId == 0 || [self.persistence flowforClientId:self.clientId
                                                     incomingFlag:NO
                                                        messageId:self.txMsgId] != nil) {
        self.txMsgId++;
    }
    return self.txMsgId;
}

- (void)tell {
    NSUInteger incoming = [self.persistence allFlowsforClientId:self.clientId
                                                   incomingFlag:YES].count;
    NSUInteger outflowing = [self.persistence allFlowsforClientId:self.clientId
                                                     incomingFlag:NO].count;
    if ([self.delegate respondsToSelector:@selector(buffered:flowingIn:flowingOut:)]) {
        [self.delegate buffered:self
                      flowingIn:incoming
                     flowingOut:outflowing];
    }
    if ([self.delegate respondsToSelector:@selector(buffered:queued:flowingIn:flowingOut:)]) {
        [self.delegate buffered:self
                         queued:0
                      flowingIn:incoming
                     flowingOut:outflowing];
    }
}

+ (NSArray *)clientCertsFromP12:(NSString *)path passphrase:(NSString *)passphrase {
    if (!path) {
        NSLog(@"no p12 path given");
        return nil;
    }
    
    NSData *pkcs12data = [[NSData alloc] initWithContentsOfFile:path];
    if (!pkcs12data) {
        NSLog(@"reading p12 failed");
        return nil;
    }
    
    if (!passphrase) {
        NSLog(@"no passphrase given");
        return nil;
    }
    CFArrayRef keyref = NULL;
    OSStatus importStatus = SecPKCS12Import((__bridge CFDataRef)pkcs12data,
                                            (__bridge CFDictionaryRef)[NSDictionary
                                                                       dictionaryWithObject:passphrase
                                                                       forKey:(__bridge id)kSecImportExportPassphrase],
                                            &keyref);
    if (importStatus != noErr) {
        NSLog(@"Error while importing pkcs12 [%d]", (int)importStatus);
        return nil;
    }
    
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(keyref, 0);
    if (!identityDict) {
        NSLog(@"could not CFArrayGetValueAtIndex");
        return nil;
    }
    
    SecIdentityRef identityRef = (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                                                      kSecImportItemIdentity);
    if (!identityRef) {
        NSLog(@"could not CFDictionaryGetValue");
        return nil;
    };
    
    SecCertificateRef cert = NULL;
    OSStatus status = SecIdentityCopyCertificate(identityRef, &cert);
    if (status != noErr) {
        NSLog(@"SecIdentityCopyCertificate failed [%d]", (int)status);
        return nil;
    }
    
    NSArray *clientCerts = [[NSArray alloc] initWithObjects:(__bridge id)identityRef, (__bridge id)cert, nil];
    return clientCerts;
}

@end
