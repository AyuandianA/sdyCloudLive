//
//  LWHAnIMTool.h
//  sdyCloudLive
//
//  Created by genghui on 2020/8/1.
//  Copyright © 2020 sdy. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AnIM.h"
@class AnSocial;
NS_ASSUME_NONNULL_BEGIN

@protocol LWHAnIMToolDelegate <NSObject>
@optional
// 收到一条消息数据
- (void)didReceiveMessageData:(NSDictionary *)messageDic;
-(void)didUpdateStatus;
@end

@interface LWHAnIMTool : NSObject

@property(weak, nonatomic) id <LWHAnIMToolDelegate> delegate;

@property(nonatomic,strong)AnIM *anIM;
@property(nonatomic,strong) AnSocial *ansocial;

+ (instancetype)shareAnIM;
// 连接
- (void)connectAnIM;
// 断开
- (void)breakAnIM;
// socket是否处于连接状态
-(BOOL)isConnectsss;
//客户端唯一标识
-(NSString *)currentClientId;
//设置视频代理
-(void)videoSetDelegate:(id)videoDelegate;
// 发送数据
- (void)sendDataDic:(NSDictionary *)dic;

@end

NS_ASSUME_NONNULL_END
