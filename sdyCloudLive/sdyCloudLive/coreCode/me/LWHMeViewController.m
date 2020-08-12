//
//  LWHMeViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/8/1.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHMeViewController.h"
#import "Header.h"
#import "LWHLoginViewController.h"
@interface LWHMeViewController ()

@end

@implementation LWHMeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    UIButton *commitButton = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"退出登录" Color:[UIColor whiteColor] selecteColor:nil Font:TextFont + 1 bgimage:nil selecteImage:nil target:self action:@selector(commitButtonAction:)];
    commitButton.frame =CGRectMake(30, 300, KScreenWidth - 30 * 2, 50);
    commitButton.backgroundColor = RGB(0, 115, 143, 1);
    
    commitButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    [self.view addSubview:commitButton];
}
-(void)commitButtonAction:(UIButton *)button
{
    [StorageManager clearAllMessage];
    [self loginAndSignIn];
}
-(void)loginAndSignIn
{
    LWHLoginViewController *login = [[LWHLoginViewController alloc]init];
    UINavigationController *navigaVC = [[UINavigationController alloc]initWithRootViewController:login];
    [UIApplication sharedApplication].keyWindow.rootViewController = nil;
    [UIApplication sharedApplication].keyWindow.rootViewController = navigaVC;
}

@end
