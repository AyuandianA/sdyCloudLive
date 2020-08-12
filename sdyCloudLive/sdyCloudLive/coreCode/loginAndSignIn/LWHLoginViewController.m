//
//  LWHLoginViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/7/29.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHLoginViewController.h"
#import "LWHSignInViewController.h"
#import "BaseTabbarController.h"
#import "CustomerTextView.h"
#import "AnSocial.h"
#import "Header.h"
#import "AppDelegate.h"

@interface LWHLoginViewController ()<UITextFieldDelegate>

@property(nonatomic,strong) CustomerTextView * accountTextView;
@property(nonatomic,strong) CustomerTextView * passWordTextView;

@property(nonatomic,weak) AnSocial *ansocial;

@end

@implementation LWHLoginViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = RGB(0, 141, 174, 1);
    self.navigationController.navigationBar.hidden = YES;
    UILabel *toplable = [LWHUIQuicklyCreateTool LWH_UI_Label:@"字符云" color:[UIColor blackColor] textAlignment:NSTextAlignmentCenter textFont:TextFont preferredMaxLayoutWidth:60 forAxis:(UILayoutConstraintAxisHorizontal)];
    self.ansocial = [LWHAnIMTool shareAnIM].ansocial;
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
    
    
    UIButton *commitButton = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"登录" Color:[UIColor whiteColor] selecteColor:nil Font:TextFont + 1 bgimage:nil selecteImage:nil target:self action:@selector(commitButtonAction:)];
    commitButton.frame =CGRectMake(30, self.passWordTextView.bottom + 20, KScreenWidth - 30 * 2, 50);
    commitButton.backgroundColor = RGB(0, 115, 143, 1);
    
    commitButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    [self.view addSubview:commitButton];
    
    UIButton *rightButton = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"新用户注册" Color:[UIColor whiteColor] selecteColor:nil Font:TextFont - 1 bgimage:nil selecteImage:nil target:self action:@selector(rightButtonAction:)];
    rightButton.frame = CGRectMake(30, commitButton.bottom + 20, KScreenWidth - 30 * 2, 50);
    [self.view addSubview:rightButton];
    rightButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    rightButton.layer.cornerRadius = 4;
    rightButton.layer.borderWidth = 0.5;
    rightButton.layer.borderColor = [UIColor whiteColor].CGColor;
    Weak_LiveSelf;
    [self.view addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithActionBlock:^(id  _Nonnull sender) {
        [weakSelf.view endEditing:YES];
    }]];
}
-(void)commitButtonAction:(UIButton *)button
{
    if (![self.accountTextView.text isEmptyString]) {
        NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
        [params setObject:self.accountTextView.text forKey:@"username"];
        [params setObject:self.passWordTextView.text forKey:@"password"];
        [params setObject:k_AppKey forKey:@"key"];

        [self.ansocial sendRequest:@"users/auth.json" method:AnSocialMethodPOST params:params success:^
         (NSDictionary *response) {
            for (id key in response)
            {
                NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
            }
            
            dispatch_async(dispatch_get_main_queue(), ^{
                [self saveID:response[@"response"][@"user"][@"id"] AndName:response[@"response"][@"user"][@"username"]];
            });
         } failure:^(NSDictionary *response) {
            for (id key in response)
            {
                NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
            }
         }];
        
    }
}

-(void)saveID:(id)IDs AndName:(id)name
{
    //保存id和name
    NSString *ID = [NSString stringWithFormat:@"%@",IDs];
    NSString *username = name;
    [StorageManager setObj:ID forKey:k_User_ids];
    [StorageManager setObj:username forKey:k_User_Name];
    BaseTabbarController *shuFu = [[BaseTabbarController alloc]init];
    [UIApplication sharedApplication].keyWindow.rootViewController = nil;
    [UIApplication sharedApplication].keyWindow.rootViewController = shuFu;
}
-(void)rightButtonAction:(UIButton *)button
{
    LWHSignInViewController *signIn = [[LWHSignInViewController alloc]init];
    [self.navigationController pushViewController:signIn animated:YES];
}

@end
