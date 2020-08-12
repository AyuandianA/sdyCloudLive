//
//  LWHTestSignInViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/8/12.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHTestSignInViewController.h"

#import "LWHTestChatDetailViewController.h"
#import "AnSocial.h"
#import "CustomerTextView.h"
#import "Header.h"

@interface LWHTestSignInViewController ()<UITextFieldDelegate>

@property(nonatomic,strong) CustomerTextView * accountTextView;
@property(nonatomic,strong) CustomerTextView * passWordTextView;
@property(nonatomic,strong) CustomerTextView * passWordTwoTextView;
@property(nonatomic,strong) AnSocial *ansocial;

@end

@implementation LWHTestSignInViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = RGB(0, 141, 174, 1);
    self.ansocial = [LWHAnIMTool shareAnIM].ansocial;
    
    UILabel *toplable = [LWHUIQuicklyCreateTool LWH_UI_Label:@"注册" color:[UIColor blackColor] textAlignment:NSTextAlignmentCenter textFont:TextFont preferredMaxLayoutWidth:60 forAxis:(UILayoutConstraintAxisHorizontal)];
    toplable.frame = CGRectMake(0, TopHeight, KScreenWidth, 50);
    [self.view addSubview:toplable];
    
    self.accountTextView = [[CustomerTextView alloc]initWithFrame:CGRectMake(30, 100+ TopHeight, KScreenWidth - 30*2, 50)];
    self.accountTextView.backgroundColor = RGB(50, 50, 50, 0.02);
    self.accountTextView.placeHolder = @"用户名";
    self.accountTextView.placeHolderColor = RGB(200, 200, 200, 1);
    [self.view addSubview:self.accountTextView];
    
    
    UIView *viewOne = [LWHUIQuicklyCreateTool LWH_UI_View:[UIColor whiteColor] andBorderColor:nil andCorner:0];
    viewOne.frame = CGRectMake(30, self.accountTextView.bottom , KScreenWidth - 30*2, 1);
    [self.view addSubview:viewOne];
    
    self.passWordTextView = [[CustomerTextView alloc]initWithFrame:CGRectMake(30, self.accountTextView.bottom + 20, KScreenWidth - 30*2, 50)];
    self.passWordTextView.backgroundColor = RGB(50, 50, 50, 0.02);
    self.passWordTextView.placeHolder = @"密码";
    self.passWordTextView.placeHolderColor = RGB(200, 200, 200, 1);
    [self.view addSubview:self.passWordTextView];
    
    UIView *viewTwo = [LWHUIQuicklyCreateTool LWH_UI_View:[UIColor whiteColor] andBorderColor:nil andCorner:0];
    viewTwo.frame = CGRectMake(30, self.passWordTextView.bottom , KScreenWidth - 30*2, 1);
    [self.view addSubview:viewTwo];
    
    self.passWordTwoTextView = [[CustomerTextView alloc]initWithFrame:CGRectMake(30, self.passWordTextView.bottom + 20, KScreenWidth - 30*2, 50)];
    self.passWordTwoTextView.backgroundColor = RGB(50, 50, 50, 0.02);
    self.passWordTwoTextView.placeHolder = @"确认密码";
    self.passWordTwoTextView.placeHolderColor = RGB(200, 200, 200, 1);
    [self.view addSubview:self.passWordTwoTextView];
    
    UIView *viewThree = [LWHUIQuicklyCreateTool LWH_UI_View:[UIColor whiteColor] andBorderColor:nil andCorner:0];
    viewThree.frame = CGRectMake(30, self.passWordTwoTextView.bottom , KScreenWidth - 30*2, 1);
    [self.view addSubview:viewThree];
    
    UIButton *commitButton = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"注册" Color:[UIColor whiteColor] selecteColor:nil Font:TextFont + 1 bgimage:nil selecteImage:nil target:self action:@selector(commitButtonAction:)];
    commitButton.frame = CGRectMake(30 , self.passWordTwoTextView.bottom + 30, KScreenWidth - 30 * 2, 50);
    commitButton.backgroundColor = RGB(0, 115, 143, 1);
    commitButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    [self.view addSubview:commitButton];
    
}
-(void)commitButtonAction:(UIButton *)button
{

    LWHTestChatDetailViewController *shuFu = [[LWHTestChatDetailViewController alloc]init];
    [self.navigationController pushViewController:shuFu animated:YES];
//    if (self.accountTextView.text.length != 0 || self.accountTextView.text.length != 0 || self.accountTextView.text.length != 0 ) {
//        NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
//        [params setObject:self.accountTextView.text forKey:@"username"];
//        [params setObject:self.passWordTextView.text forKey:@"password"];
//        [params setObject:self.passWordTwoTextView.text forKey:@"password_confirmation"];
//        [params setObject:k_AppKey forKey:@"key"];
//        
//        [self.ansocial sendRequest:@"users/create.json" method:AnSocialMethodPOST params:params success:^
//         (NSDictionary *response) {
//            for (id key in response)
//            {
//                NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
//            }
//            dispatch_async(dispatch_get_main_queue(), ^{
//                [self saveID:response[@"response"][@"user"][@"id"] AndName:response[@"response"][@"user"][@"username"]];
//            });
//         } failure:^(NSDictionary *response) {
//            for (id key in response)
//            {
//                NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
//            }
//         }];
//    }
    
}
-(void)saveID:(id)IDs AndName:(id)name
{
    //保存id和name
    NSString *ID = [NSString stringWithFormat:@"%@",IDs];
    NSString *username = name;
    [StorageManager setObj:ID forKey:k_User_ids];
    [StorageManager setObj:username forKey:k_User_Name];
    LWHTestChatDetailViewController *shuFu = [[LWHTestChatDetailViewController alloc]init];
    [UIApplication sharedApplication].keyWindow.rootViewController = nil;
    [UIApplication sharedApplication].keyWindow.rootViewController = shuFu;
}

@end
