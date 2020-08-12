//
//  MQTTSessionManager.m
//  MQTTClient
//
//  Created by Christoph Krey on 09.07.14.
//  Copyright (c) 2013-2015 Christoph Krey. All rights reserved.
//

#import "ANMQTTSessionManager.h"

@interface ANMQTTSessionManager()
@property (nonatomic, readwrite) ANMQTTSessionManagerState state;
@property (nonatomic, readwrite) NSError *lastErrorCode;

@property (strong, nonatomic) NSTimer *reconnectTimer;
@property (nonatomic) double reconnectTime;
@property (nonatomic) BOOL reconnectFlag;

@property (strong, nonatomic) ANMQTTSession *session;

@property (strong, nonatomic) NSString *host;
@property (nonatomic) UInt32 port;
@property (nonatomic) BOOL tls;
@property (nonatomic) NSInteger keepalive;
@property (nonatomic) BOOL clean;
@property (nonatomic) BOOL auth;
@property (nonatomic) BOOL will;
@property (strong, nonatomic) NSString *user;
@property (strong, nonatomic) NSString *pass;
@property (strong, nonatomic) NSString *willTopic;
@property (strong, nonatomic) NSData *willMsg;
@property (nonatomic) NSInteger willQos;
@property (nonatomic) BOOL willRetainFlag;
@property (strong, nonatomic) NSString *clientId;

@property (strong, nonatomic) NSTimer *disconnectTimer;
@property (strong, nonatomic) NSTimer *activityTimer;
@property (nonatomic) UIBackgroundTaskIdentifier backgroundTask;
@property (strong, nonatomic) void (^completionHandler)(UIBackgroundFetchResult);

@end

#define RECONNECT_TIMER 1.0
#define RECONNECT_TIMER_MAX 64.0
#define BACKGROUND_DISCONNECT_AFTER 8.0

@implementation ANMQTTSessionManager
- (id)init
{
    self = [super init];


    self.state = ANMQTTSessionManagerStateStarting;
    self.backgroundTask = UIBackgroundTaskInvalid;
    self.completionHandler = nil;

    NSNotificationCenter *defaultCenter = [NSNotificationCenter defaultCenter];

    [defaultCenter addObserver:self
                      selector:@selector(appWillResignActive)
                          name:UIApplicationWillResignActiveNotification
                        object:nil];

    [defaultCenter addObserver:self
                      selector:@selector(appDidEnterBackground)
                          name:UIApplicationDidEnterBackgroundNotification
                        object:nil];

    [defaultCenter addObserver:self
                      selector:@selector(appDidBecomeActive)
                          name:UIApplicationDidBecomeActiveNotification
                        object:nil];
    return self;
}

- (void)appWillResignActive
{
    [self disconnect];
}

- (void)appDidEnterBackground
{
    self.backgroundTask = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
        if (self.backgroundTask) {
            [[UIApplication sharedApplication] endBackgroundTask:self.backgroundTask];
            self.backgroundTask = UIBackgroundTaskInvalid;
        }
    }];
}

- (void)appDidBecomeActive
{
    [self connectToLast];
}

- (void)connectTo:(NSString *)host
             port:(NSInteger)port
              tls:(BOOL)tls
        keepalive:(NSInteger)keepalive
            clean:(BOOL)clean
             auth:(BOOL)auth
             user:(NSString *)user
             pass:(NSString *)pass
        willTopic:(NSString *)willTopic
             will:(NSData *)will
          willQos:(ANMQTTQosLevel)willQos
   willRetainFlag:(BOOL)willRetainFlag
     withClientId:(NSString *)clientId
{
  [self connectTo:host
               port:port
                tls:tls
          keepalive:keepalive
              clean:clean
               auth:auth
               user:user
               pass:pass
               will:YES
          willTopic:willTopic
            willMsg:will
            willQos:willQos
     willRetainFlag:willRetainFlag
       withClientId:clientId];
}

- (void)connectTo:(NSString *)host
             port:(NSInteger)port
              tls:(BOOL)tls
        keepalive:(NSInteger)keepalive
            clean:(BOOL)clean
             auth:(BOOL)auth
             user:(NSString *)user
             pass:(NSString *)pass
             will:(BOOL)will
        willTopic:(NSString *)willTopic
          willMsg:(NSData *)willMsg
          willQos:(ANMQTTQosLevel)willQos
   willRetainFlag:(BOOL)willRetainFlag
     withClientId:(NSString *)clientId
{
    if (!self.session ||
        ![host isEqualToString:self.host] ||
        port != self.port ||
        tls != self.tls ||
        keepalive != self.keepalive ||
        clean != self.clean ||
        auth != self.auth ||
        ![user isEqualToString:self.user] ||
        ![pass isEqualToString:self.pass] ||
        ![willTopic isEqualToString:self.willTopic] ||
        ![willMsg isEqualToData:self.willMsg] ||
        willQos != self.willQos ||
        willRetainFlag != self.willRetainFlag ||
        ![clientId isEqualToString:self.clientId]) {
        self.host = host;
        self.port = (int)port;
        self.tls = tls;
        self.keepalive = keepalive;
        self.clean = clean;
        self.auth = auth;
        self.user = user;
        self.pass = pass;
        self.will = will;
        self.willTopic = willTopic;
        self.willMsg = willMsg;
        self.willQos = willQos;
        self.willRetainFlag = willRetainFlag;
        self.clientId = clientId;

        self.session = [[ANMQTTSession alloc] initWithClientId:clientId
                                                    userName:auth ? user : nil
                                                    password:auth ? pass : nil
                                                   keepAlive:keepalive
                                                cleanSession:clean
                                                        will:will
                                                   willTopic:willTopic
                                                     willMsg:willMsg
                                                     willQoS:willQos
                                              willRetainFlag:willRetainFlag
                                               protocolLevel:4
                                                     runLoop:[NSRunLoop currentRunLoop]
                                                     forMode:NSDefaultRunLoopMode];
        self.session.delegate = self;
        self.reconnectTime = RECONNECT_TIMER;
        self.reconnectFlag = FALSE;
    }
    [self connectToInternal];
}

- (UInt16)sendData:(NSData *)data topic:(NSString *)topic qos:(ANMQTTQosLevel)qos retain:(BOOL)retainFlag
{
    if (self.state != ANMQTTSessionManagerStateConnected) {
        [self connectToLast];
    }
    UInt16 msgId = [self.session publishData:data
                                     onTopic:topic
                                      retain:retainFlag
                                         qos:qos];
    return msgId;
}

- (void)disconnect
{
    self.state = ANMQTTSessionManagerStateClosing;
    [self.session close];

    if (self.reconnectTimer) {
        [self.reconnectTimer invalidate];
        self.reconnectTimer = nil;
    }
}

#pragma mark - MQTT Callback methods

- (void)handleEvent:(ANMQTTSession *)session event:(ANMQTTSessionEvent)eventCode error:(NSError *)error
{
#ifdef DEBUG
    const NSDictionary *events = @{
                                   @(ANMQTTSessionEventConnected): @"connected",
                                   @(ANMQTTSessionEventConnectionRefused): @"connection refused",
                                   @(ANMQTTSessionEventConnectionClosed): @"connection closed",
                                   @(ANMQTTSessionEventConnectionError): @"connection error",
                                   @(ANMQTTSessionEventProtocolError): @"protocoll error",
                                   @(ANMQTTSessionEventConnectionClosedByBroker): @"connection closed by broker"
                                   };
    NSLog(@"MQTTSession eventCode: %@ (%ld) %@", events[@(eventCode)], (long)eventCode, error);
#endif
    [self.reconnectTimer invalidate];
    switch (eventCode) {
        case ANMQTTSessionEventConnected:
        {
            self.lastErrorCode = nil;
            self.state = ANMQTTSessionManagerStateConnected;
            break;
        }
        case ANMQTTSessionEventConnectionClosed:
        case ANMQTTSessionEventConnectionClosedByBroker:
            self.state = ANMQTTSessionManagerStateClosed;
            if (self.backgroundTask) {
                [[UIApplication sharedApplication] endBackgroundTask:self.backgroundTask];
                self.backgroundTask = UIBackgroundTaskInvalid;
            }
            if (self.completionHandler) {
                self.completionHandler(UIBackgroundFetchResultNewData);
                self.completionHandler = nil;
            }

            self.state = ANMQTTSessionManagerStateStarting;
            break;
        case ANMQTTSessionEventProtocolError:
        case ANMQTTSessionEventConnectionRefused:
        case ANMQTTSessionEventConnectionError:
        {
            self.reconnectTimer = [NSTimer timerWithTimeInterval:self.reconnectTime
                                                          target:self
                                                        selector:@selector(reconnect)
                                                        userInfo:Nil repeats:FALSE];
            NSRunLoop *runLoop = [NSRunLoop currentRunLoop];
            [runLoop addTimer:self.reconnectTimer
                      forMode:NSDefaultRunLoopMode];

            self.state = ANMQTTSessionManagerStateError;
            self.lastErrorCode = error;
            break;
        }
        default:
            break;
    }
}

- (void)newMessage:(ANMQTTSession *)session data:(NSData *)data onTopic:(NSString *)topic qos:(ANMQTTQosLevel)qos retained:(BOOL)retained mid:(unsigned int)mid
{
    [self.delegate handleMessage:data onTopic:topic retained:retained];
}

- (void)connected:(ANMQTTSession *)session sessionPresent:(BOOL)sessionPresent {
    if (self.clean || !self.reconnectFlag || !sessionPresent) {
        if (self.subscriptions && [self.subscriptions count]) {
            [self.session subscribeToTopics:self.subscriptions];
        }
        self.reconnectFlag = TRUE;
    }
}


- (void)connectToInternal
{
    if (self.state == ANMQTTSessionManagerStateStarting) {
        self.state = ANMQTTSessionManagerStateConnecting;
        [self.session connectToHost:self.host
                               port:self.port
                           usingSSL:self.tls];
    }
}

- (void)reconnect
{
    self.reconnectTimer = nil;
    self.state = ANMQTTSessionManagerStateStarting;

    if (self.reconnectTime < RECONNECT_TIMER_MAX) {
        self.reconnectTime *= 2;
    }
    [self connectToInternal];
}

- (void)connectToLast
{
    self.reconnectTime = RECONNECT_TIMER;

    [self connectToInternal];
}

- (void)setSubscriptions:(NSMutableDictionary *)newSubscriptions
{
    if (self.state==ANMQTTSessionManagerStateConnected) {
        for (NSString *topicFilter in self.subscriptions) {
            if (![newSubscriptions objectForKey:topicFilter]) {
                [self.session unsubscribeAndWaitTopic:topicFilter];
            }
        }
        
        for (NSString *topicFilter in newSubscriptions) {
            if (![self.subscriptions objectForKey:topicFilter]) {
                NSNumber *number = newSubscriptions[topicFilter];
                ANMQTTQosLevel qos = [number unsignedIntValue];
                [self.session subscribeToTopic:topicFilter atLevel:qos];
            }
        }
    }
    _subscriptions=newSubscriptions;
}

@end
