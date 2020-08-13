//
//  LWHChatListViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/7/30.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHChatListViewController.h"
#import "LWHChatDetaliViewController.h"
#import "AnIM.h"
#import "AnLive.h"
#import "Header.h"
#import "AnSocial.h"
#import "AppDelegate.h"

@interface LWHChatListViewController ()<AnIMDelegate,LWHAnIMToolDelegate,UITextFieldDelegate>

@property(nonatomic,strong) AnIM * anIM;
@property(nonatomic,strong) NSString* clientId;
@property(nonatomic,strong) LWHPublicTableView *tableView;

@end

@implementation LWHChatListViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    [self.view addSubview:self.tableView];
    
    [self connectImServer];
    [self didUpdateStatus];
}
//连接im服务器
-(void)connectImServer
{
    [[LWHAnIMTool shareAnIM]connectAnIM];
    [LWHAnIMTool shareAnIM].delegate = self;
}

-(LWHPublicTableView *)tableView
{
    if (!_tableView) {
        Weak_LiveSelf;
        _tableView = [LWHPublicTableView creatPublicTableViewWithFrame:CGRectMake(0, TopHeight, KScreenWidth, KScreenHeight - SafeAreaH - TopHeight)];
        _tableView.cellName = @"LWHChatListTableViewCell";
        _tableView.tapSectionAndModel = ^(NSIndexPath *section, id model) {
            LWHChatDetaliViewController *detaliVC = [[LWHChatDetaliViewController alloc]init];
            
            [weakSelf.navigationController pushViewController:detaliVC animated:YES];
        };
    }
    return _tableView;
}
//
-(void)didUpdateStatus
{
    [self updateChatList];
}
-(void)updateChatList
{
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
//    [params setObject:@"10" forKey:@"limit"];
    [params setObject:[StorageManager objForKey:k_ClientId] forKey:@"client_id"];
    [params setObject:k_AppServer forKey:@"server_secret"];
    [params setObject:k_AppKey forKey:@"key"];
    
    NSString *path = [NSString stringWithFormat:@"http://%@/%@/%@", k_API_hosttt,k_API_versionnn,@"im/sessions/list.json"];
    [ansocial sendRequest:path method:AnSocialMethodGET params:params success:^
     (NSDictionary *response) {
         NSLog(@"key: %@",response);
        dispatch_async(dispatch_get_main_queue(), ^{
            
            self.tableView.PublicSourceArray = [response[@"response"][@"sessions"] mutableCopy];
            [self.tableView reloadData];
        });
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];
}

-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    [self.view endEditing:YES];
}


//#pragma 视频
//- (void)touchVideoClick:(id)sender {
//    [AnLive setup:_anIM delegate:self];
//    [[AnLive shared] videoCall:@"此处填写对方的ClientId" video:YES notificationData:nil
//    success:^(NSString *sessionId) {
//        // 视频通话请求建立成功，正在等待对方应答
//        NSLog(@"Waiting for target client to answer the call...");
//    } failure:^(ArrownockException *exception) {
//        // 视频通话建立失败
//    }];
//}
//#pragma 文字
//- (void)sendBtnClick:(id)sender {
//    [self sendMsg];
//}
//#pragma 发送消息
//-(void)sendMsg{
//  [_anIM sendMessage:@"此处填写对方的ClientId" toClient:@"此处填写对方的ClientId" needReceiveACK:NO];
//
//}
//
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
