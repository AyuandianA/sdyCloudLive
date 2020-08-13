//
//  LWHChatDetaliViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/7/31.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHChatDetaliViewController.h"
#import "AnIM.h"
#import "AnLive.h"
#import "AnIMMessage.h"
#import "Header.h"
#import "AnSocial.h"
#import "AnSocialFile.h"
#import "AppDelegate.h"
#import "BaseNaviController.h"
#import "TZImagePickerController.h"
@interface LWHChatDetaliViewController ()<TZImagePickerControllerDelegate,UITextFieldDelegate>

@property(nonatomic,strong) LWHPublicTableView *tableView;
@property(nonatomic,strong) UITextField *textfields;
@property (nonatomic, assign) CGRect keyboardFrame;
@property (nonatomic,strong)UIButton *searchButton;
@property(nonatomic,copy) NSString*cliented;

@end

@implementation LWHChatDetaliViewController
- (instancetype)init
{
    self = [super init];
    if (self) {
        self.type = @"";
        self.cliented = @"";
    }
    return self;
}
-(void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    Weak_LiveSelf;
    if (![self.ID isEmptyString]) {
        [[LWHAnIMTool shareAnIM].anIM getClientId:self.ID success:^(NSString *clientId) {
//            NSLog(@"clientId  == %@",clientId);
            weakSelf.cliented = clientId;
            [weakSelf huoQuOfflineMessages];
        } failure:^(ArrownockException *exception) {
            NSLog(@"%@",exception.message);
        }];
    }
//    self.cliented = [];
    [self creatTableView];
    
    /**
     *  添加两个键盘回收通知
     */
    // 即将隐藏
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardWillHide:) name:UIKeyboardWillHideNotification object:nil];
    // 键盘的Frame值即将发生变化的时候创建的额监听
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyboardFrameWillChange:) name:UIKeyboardWillChangeFrameNotification object:nil];
}
-(void)huoQuOfflineMessages
{
    NSMutableArray *muArray = @[].mutableCopy;
    NSSet *clientIdss = [NSSet setWithArray:@[[StorageManager objForKey:k_ClientId],self.cliented]];
    [[LWHAnIMTool shareAnIM].anIM getOfflineHistory:clientIdss clientId:[StorageManager objForKey:k_ClientId] limit:20 success:^(NSArray *messages, int count) {

        if (messages.count != 0) {
            for (AnIMMessage *messagea in messages) {
                [muArray insertObject:messagea atIndex:0];
            }
        }
        if (count != 0) {
            [[LWHAnIMTool shareAnIM].anIM getOfflineHistory:clientIdss clientId:[StorageManager objForKey:k_ClientId] limit:count success:^(NSArray *messages, int count) {
                
                for (AnIMMessage *message in messages) {
                    [muArray insertObject:message atIndex:0];
                }
                
            } failure:^(ArrownockException *exception) {
                
            }];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.tableView.PublicSourceArray addObjectsFromArray:muArray];
            [self.tableView reloadData];
        });
    } failure:^(ArrownockException *exception) {
        
    }];
}
/**
 *   在控制器里面添加键盘的监听，
 */
#pragma mark - Private Methods
- (void)keyboardWillHide:(NSNotification *)notification{
    self.keyboardFrame = CGRectZero;
    self.tableView.top = TopHeight;
    self.textfields.bottom = KScreenHeight - SafeAreaH;
    self.searchButton.top = self.textfields.top;
    self.tableView.bottom = self.textfields.top;
}

- (void)keyboardFrameWillChange:(NSNotification *)notification{
//    NSLog(@"222");
    // 键盘的Frame

    self.keyboardFrame = [notification.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    
    self.textfields.bottom = KScreenHeight - self.keyboardFrame.size.height;
    self.tableView.bottom = self.textfields.top;
    self.searchButton.top = self.textfields.top;
    
}
-(void)creatTableView
{
    self.tableView = [LWHPublicTableView creatPublicTableViewWithFrame:CGRectMake(0, TopHeight, KScreenWidth, KScreenHeight - BottomHeight - TopHeight)];
    self.tableView.cellName = @"LWHChatDetaliTableViewCell";
    Weak_LiveSelf;
    self.tableView.tapSectionAndModel = ^(NSIndexPath *section, id model) {
//        LWHChatDetaliViewController *detaliVC = [[LWHChatDetaliViewController alloc]init];
//        [weakSelf.navigationController pushViewController:detaliVC animated:YES];
    };
    self.tableView.rowHeightSection = ^CGFloat(NSIndexPath *indexPath) {
        return 80;
    };
    self.tableView.mj_header = [MJRefreshStateHeader headerWithRefreshingBlock:^{
        [weakSelf.tableView.mj_header beginRefreshing];

        [weakSelf updataTabelView:NO];
    }];
    [self.view addSubview:self.tableView];

    [self updataTabelView:YES];
    
    self.textfields = [LWHUIQuicklyCreateTool LWH_UI_Field:nil font:TextFont textAlignment:NSTextAlignmentLeft borderStyle:(UITextBorderStyleRoundedRect) clearOnBeginEditing:YES secure:NO keyBoardStyle:(UIKeyboardTypeASCIICapable)];
    [self.view addSubview:self.textfields];
    self.textfields.frame = CGRectMake(20, KScreenHeight - BottomHeight, KScreenWidth - 20*2-60, TabbarH);
    
    
    UIButton *searchButton = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"文字" Color:[UIColor blueColor] selecteColor:nil Font:TextFont bgimage:nil selecteImage:nil target:self action:@selector(sendMsg)];
    self.searchButton = searchButton;
    [self.view addSubview:searchButton];
    searchButton.frame = CGRectMake(self.textfields.right , self.textfields.top, 60, TabbarH);
    searchButton.imageEdgeInsets = UIEdgeInsetsMake(9.5f, 10, 9.5f, 25);
    
    
    UIButton *sendImage = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"图片" Color:[UIColor blueColor] selecteColor:nil Font:TextFont bgimage:nil selecteImage:nil target:self action:@selector(sendImageMsg)];
    sendImage.frame = CGRectMake(0, 0, 60, 44);
    sendImage.imageEdgeInsets = UIEdgeInsetsMake(9.5f, 10, 9.5f, 25);
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]initWithCustomView:sendImage];
    
    
}
-(void)updataTabelView:(BOOL)isScrToBottom
{
    NSMutableArray *muArray = @[].mutableCopy;
    NSSet *clientIdss = [NSSet setWithArray:@[[StorageManager objForKey:k_ClientId],self.cliented]];
    AnIMMessage *messagess = (AnIMMessage *)self.tableView.PublicSourceArray.firstObject;
    NSNumber *timestamp =messagess.timestamp;
    [[LWHAnIMTool shareAnIM].anIM getHistory:clientIdss clientId:[StorageManager objForKey:k_ClientId] limit:20 timestamp:timestamp success:^(NSArray *messages) {
        [self.tableView.mj_header endRefreshing];
        for (AnIMMessage *message in messages) {
            [muArray insertObject:message atIndex:0];
        }
        [self.tableView.PublicSourceArray insertObjects:muArray atIndex:0];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [self.tableView reloadData];
            if (isScrToBottom) {
                [self.tableView layoutIfNeeded];
                [self.tableView scrollToBottomAnimated:YES];
            }
        });
    } failure:^(ArrownockException *exception) {
        [self.tableView.mj_header endRefreshing];
    }];
}
-(void)sendImageMsg
{
    TZImagePickerController *imagePickerVc = [[TZImagePickerController alloc] initWithMaxImagesCount:1 columnNumber:3 delegate:self pushPhotoPickerVc:YES];
    if (@available(iOS 13.0, *)) {
        imagePickerVc.statusBarStyle = UIStatusBarStyleDarkContent;
    } else {
        imagePickerVc.statusBarStyle = UIStatusBarStyleDefault;
    }
    
    imagePickerVc.maxImagesCount = 1;
    
    imagePickerVc.allowTakeVideo = NO;   // 在内部显示拍视频按钮
    imagePickerVc.allowPickingVideo = NO;
    imagePickerVc.alwaysEnableDoneBtn = YES;
    imagePickerVc.allowPickingOriginalPhoto = NO;
    imagePickerVc.allowPickingMultipleVideo = NO; // 是否可以多选视频
    imagePickerVc.showPhotoCannotSelectLayer = YES;
    imagePickerVc.cannotSelectLayerColor = [UIColor colorWithWhite:1 alpha:.5];
    imagePickerVc.showSelectBtn = NO;
    imagePickerVc.allowCrop = YES;
    imagePickerVc.cropRect = CGRectMake(0, (KScreenHeight-KScreenWidth)/2, KScreenWidth, KScreenWidth);
    imagePickerVc.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:imagePickerVc animated:YES completion:nil];
    
}
#pragma ---mark TZImagePickerControllerDelegate
// 点取消
- (void)tz_imagePickerControllerDidCancel:(TZImagePickerController *)picker {
    
}
// 点完成
- (void)imagePickerController:(TZImagePickerController *)picker didFinishPickingPhotos:(NSArray<UIImage *> *)photos sourceAssets:(NSArray *)assets isSelectOriginalPhoto:(BOOL)isSelectOriginalPhoto infos:(NSArray<NSDictionary *> *)infos {
//    NSLog(@"222222");
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:[StorageManager objForKey:k_User_ids] forKey:@"user_id"];

    UIImage *image = [photos lastObject];//从相册中选择出的图片
    NSData *imageData = UIImageJPEGRepresentation(image, 0.4);
    AnSocialFile* file = [AnSocialFile createWithFileName:@"test.jpg" data:imageData];
    [params setObject:file forKey:@"photo"];
    [params setObject:@"image/png" forKey:@"mime_type"];
    
//    NSMutableDictionary *resolutions = @{}.mutableCopy;
//    resolutions[@"small"] = @"200x200";
//    resolutions[@"middle"] = @"400x400";
//    params[@"resolutions"] = resolutions;
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    [ansocial sendRequest:@"photos/create.json" method:AnSocialMethodPOST params:params success:^
     (NSDictionary *response) {
//        for (id key in response)
//        {
//            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
//        }
        NSString *urlString = response[@"response"][@"photo"][@"url"];
//        NSLog(@"urlString == %@",urlString);
        NSString *msgId = [[LWHAnIMTool shareAnIM].anIM sendBinary:[NSData data] fileType:@"image" customData:@{@"url":urlString} toClient:self.cliented needReceiveACK:NO];
        AnIMMessage *message = [[AnIMMessage alloc]initWithType:AnIMBinaryMessage msgId:msgId topicId:nil message:nil content:nil fileType:@"image" from:[LWHAnIMTool shareAnIM].anIM.getCurrentClientId to:self.cliented customData:@{@"url":urlString} timestamp:[NSNumber numberWithString:[self getCurrentTimestamp]]];
        [self.tableView.PublicSourceArray addObject:message];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.tableView reloadData];
            [self.tableView layoutIfNeeded];
            [self.tableView scrollToBottomAnimated:YES];
        });
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];
    
}

// 当连接成功时下面的回调方法会被触发


#pragma 视频
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

#pragma 发送文字
-(void)sendMsg{
    if (![self.textfields.text isEmptyString]) {
        NSString *msgId = [[LWHAnIMTool shareAnIM].anIM sendMessage:self.textfields.text toClient:self.cliented needReceiveACK:NO];
        AnIMMessage *message = [[AnIMMessage alloc]initWithType:AnIMTextMessage msgId:msgId topicId:nil message:self.textfields.text content:nil fileType:nil from:[LWHAnIMTool shareAnIM].anIM.getCurrentClientId to:self.cliented customData:nil timestamp:[NSNumber numberWithString:[self getCurrentTimestamp]]];
        [self.tableView.PublicSourceArray addObject:message];
        [self.tableView reloadData];
        [self.tableView layoutIfNeeded];
        [self.tableView scrollToBottomAnimated:YES];
        self.textfields.text = @"";
    }
  
}
// 获取当前时间戳
- (NSString *)getCurrentTimestamp {
    NSDate *date = [NSDate dateWithTimeIntervalSinceNow:0]; // 获取当前时间0秒后的时间
//    NSTimeInterval time = [date timeIntervalSince1970]*1000;// *1000 是精确到毫秒(13位),不乘就是精确到秒(10位)
    NSTimeInterval time = [date timeIntervalSince1970];
    NSString *timeString = [NSString stringWithFormat:@"%.0f", time];
    return timeString;
}
//当两个用户间的视频通话建立成功时，此方法会被回调
- (void) onRemotePartyConnected:(NSString*)partyId{
    NSLog(@"视频通话连接成功");
}
//当有来自其他用户发出的建立视频通话请求时，此方法会被调用。
- (void) onReceivedInvitation:(BOOL)isValid sessionId:(NSString*)sessionId partyId:(NSString*)partyId type:(NSString*)type createdAt:(NSDate*)createdAt{
    NSLog(@"收到视频");
    [[AnLive shared] answer:YES];    // 接听视频通话
}

- (void) onRemotePartyVideoStateChanged:(NSString*)partyId state:(AnLiveVideoState)state{
}
- (void) onRemotePartyAudioStateChanged:(NSString*)partyId state:(AnLiveAudioState)state{
    
}
- (void) onRemotePartyVideoSizeChanged:(NSString*)partyId videoSize:(CGSize)size{
    
}
- (void) onLocalVideoSizeChanged:(CGSize)size{
    
}


- (void) onLocalVideoViewReady:(AnLiveLocalVideoView*)view{
    NSLog(@"自己的视频消息");

}
- (void)onRemotePartyVideoViewReady:(NSString*)partyId remoteVideoView:(AnLiveVideoView*)view{
    NSLog(@"对方的视频消息");
}
- (void) onError:(NSString*)partyId exception:(ArrownockException*)exception{
    NSLog(@"视频错误信息：%@",exception);
}
-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    [self.view endEditing:YES];
}
//这个函数的最后一个参数text代表你每次输入的的那个字，所以：
-(BOOL)textField:(UITextField *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)string
{
    if ([string isEqualToString:@"\n"]){ //判断输入的字是否是回车，即按下return
        //在这里做你响应return键的代码
        [self sendMsg];
        return NO;
    }

    return YES;
}

@end
