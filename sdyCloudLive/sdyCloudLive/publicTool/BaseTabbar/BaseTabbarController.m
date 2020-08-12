//
//  BaseTabbarController.m
//  ChengXianApp
//
//  Created by Aliang Ren on 2019/5/6.
//  Copyright © 2019 Aliang Ren. All rights reserved.
//

#import "BaseTabbarController.h"
#import "BaseNaviController.h"
#import "LWHChatListViewController.h"
#import "LWHFriendsViewController.h"
#import "LWHMeViewController.h"
@interface BaseTabbarController ()<UITabBarControllerDelegate> {
     NSString *_message_id;
}

@end

@implementation BaseTabbarController

- (void)viewDidLoad {
    
    [super viewDidLoad];
    
    // 修改TabBar背景色
    [[UITabBar appearance] setBarTintColor:[UIColor whiteColor]];
    // 取消TabBar透明效果
    [UITabBar appearance].translucent = NO;

    [self createSubCtrlssss];
    
}
- (void)createSubCtrlssss {

    LWHChatListViewController *viewVC = [[LWHChatListViewController alloc]init];
    BaseNaviController *navCtrl = [[BaseNaviController alloc] initWithRootViewController:viewVC];
    UITabBarItem *item = navCtrl.tabBarItem;
    item.title = @"会话";
    item.image = [ImageWithName(@"shouye.png") imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
    item.selectedImage = [ImageWithName(@"shouye0.png") imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
    [item setTitleTextAttributes:@{NSForegroundColorAttributeName:MainTopColor} forState:UIControlStateSelected];
    navCtrl.cancelGesture = NO;
    
    LWHFriendsViewController *friendsViewVC = [[LWHFriendsViewController alloc]init];
    BaseNaviController *friendsCtrl = [[BaseNaviController alloc] initWithRootViewController:friendsViewVC];
    UITabBarItem *friendsItem = friendsCtrl.tabBarItem;
    friendsItem.title = @"好友";
    friendsItem.image = [ImageWithName(@"shouye.png") imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
    friendsItem.selectedImage = [ImageWithName(@"shouye0.png") imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
    [friendsItem setTitleTextAttributes:@{NSForegroundColorAttributeName:MainTopColor} forState:UIControlStateSelected];
    friendsCtrl.cancelGesture = NO;
    
    LWHMeViewController *meViewVC = [[LWHMeViewController alloc]init];
    BaseNaviController *meCtrl = [[BaseNaviController alloc] initWithRootViewController:meViewVC];
    UITabBarItem *meItem = meViewVC.tabBarItem;
    meItem.title = @"好友";
    meItem.image = [ImageWithName(@"shouye.png") imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
    meItem.selectedImage = [ImageWithName(@"shouye0.png") imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
    [meItem setTitleTextAttributes:@{NSForegroundColorAttributeName:MainTopColor} forState:UIControlStateSelected];
    meViewVC.cancelGesture = NO;
    
//    self.viewControllers = @[navCtrl,friendsCtrl,meCtrl];
    self.viewControllers = @[friendsCtrl,meCtrl];
    
}



@end
