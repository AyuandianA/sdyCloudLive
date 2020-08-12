//
//  LWHAnIMTool.m
//  sdyCloudLive
//
//  Created by genghui on 2020/8/1.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHAnIMTool.h"
#import "Header.h"
#import "AnLive.h"
#import "AnSocial.h"

static LWHAnIMTool *_anIMTool = nil;
static dispatch_once_t onceToken;

@interface LWHAnIMTool ()<AnIMDelegate>


@property(assign, nonatomic)BOOL isConnect; // socket是否处于连接状态
@end

@implementation LWHAnIMTool

+ (instancetype)shareAnIM {
    dispatch_once(&onceToken, ^{
        if (!_anIMTool) {
            _anIMTool = [[LWHAnIMTool alloc] init];
        }
    });
    return _anIMTool;
}
- (instancetype)init {
    if ([super init]) {
        self.isConnect = NO;
        self.anIM = [[AnIM alloc] initWithAppKey:k_AppKey delegate:self secure:NO];
        self.ansocial = [[AnSocial alloc]initWithAppKey:k_AppKey];
        [self.ansocial setSecureConnection:NO];
    }
    return self;
}

// 连接
- (void)connectAnIM
{
    Weak_LiveSelf;
    NSString* userID = [StorageManager objForKey:k_User_ids];
    if (![userID isEmptyString]) {
        [self.anIM getClientId:userID success:^(NSString *clientId) {
            NSLog(@"clientId  == %@",clientId);
            [StorageManager setObj:clientId forKey:k_ClientId];
            [weakSelf.anIM connect:clientId];
            self.isConnect = YES;
        } failure:^(ArrownockException *exception) {
            NSLog(@"%@",exception.message);
        }];
    }
}

// 断开
- (void)breakAnIM
{
    [self.anIM disconnect];
    self.isConnect = NO;
}
//客户端唯一标识
-(NSString *)currentClientId
{
    return self.anIM.getCurrentClientId;
}
// 发送数据
- (void)sendDataDic:(NSDictionary *)dic
{
}
// socket是否处于连接状态
-(BOOL)isConnectsss
{
    return self.isConnect;
}
// 当连接成功时下面的回调方法会被触发
- (void)anIM:(AnIM *)anIM didUpdateStatus:(BOOL)status exception:(ArrownockException *)exception{
    NSLog(@"连接成功了！");
    
    if (self.delegate && [self.delegate respondsToSelector:@selector(didUpdateStatus)]) {
        
        [self.delegate didUpdateStatus];
    }
}

- (void)anIM:(AnIM *)anIM didReceiveMessage:(NSString *)message customData:(NSDictionary *)customData from:(NSString *)from parties:(NSSet *)parties messageId:(NSString *)messageId at:(NSNumber *)timestamp
{
//    NSLog(@"the message is: %@", message);
//    NSLog(@"the messageId is: %@", messageId);
//    NSString * sendMsg;
//    sendMsg = [NSString stringWithFormat:@"接收消息：%@\n",message];
    NSDictionary *dic = [self dictionaryWithJsonString:message];

    if (self.delegate && [self.delegate respondsToSelector:@selector(didReceiveMessageData:)]) {
        
        [self.delegate didReceiveMessageData:dic];
    }
}
- (NSDictionary *)dictionaryWithJsonString:(NSString *)jsonString
{
    if (jsonString == nil) {
        return nil;
    }
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&err];
    if(err) {
        //        NSLog(@"json解析失败：%@",err);
        return nil;
    }
    return dic;
}
//设置视频代理
-(void)videoSetDelegate:(id)videoDelegate
{
    [AnLive setup:self.anIM delegate:videoDelegate];
}

//#pragma 视频
//- (void)touchVideoClick:(id)sender {
//    [[AnLive shared] videoCall:@"此处填写对方的ClientId" video:YES notificationData:nil
//    success:^(NSString *sessionId) {
//        // 视频通话请求建立成功，正在等待对方应答
//        NSLog(@"Waiting for target client to answer the call...");
//    } failure:^(ArrownockException *exception) {
//        // 视频通话建立失败
//    }];
//}


////当两个用户间的视频通话建立成功时，此方法会被回调
//- (void) onRemotePartyConnected:(NSString*)partyId{
//    NSLog(@"视频通话连接成功");
//}
////当有来自其他用户发出的建立视频通话请求时，此方法会被调用。
//- (void) onReceivedInvitation:(BOOL)isValid sessionId:(NSString*)sessionId partyId:(NSString*)partyId type:(NSString*)type createdAt:(NSDate*)createdAt{
//    NSLog(@"收到视频");
//    [[AnLive shared] answer:YES];    // 接听视频通话
//}
//
//- (void) onRemotePartyVideoStateChanged:(NSString*)partyId state:(AnLiveVideoState)state{
//}
//- (void) onRemotePartyAudioStateChanged:(NSString*)partyId state:(AnLiveAudioState)state{
//
//}
//- (void) onRemotePartyVideoSizeChanged:(NSString*)partyId videoSize:(CGSize)size{
//
//}
//- (void) onLocalVideoSizeChanged:(CGSize)size{
//
//}
//
//
//- (void) onLocalVideoViewReady:(AnLiveLocalVideoView*)view{
//    NSLog(@"自己的视频消息");
//
//}
//- (void)onRemotePartyVideoViewReady:(NSString*)partyId remoteVideoView:(AnLiveVideoView*)view{
//    NSLog(@"对方的视频消息");
//}
//- (void) onError:(NSString*)partyId exception:(ArrownockException*)exception{
//    NSLog(@"视频错误信息：%@",exception);
//}
@end
