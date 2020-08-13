//
//  AppDelegate.m
//  sdyCloudLive
//
//  Created by sdy on 2020/6/29.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "AppDelegate.h"
#import "LWHLoginViewController.h"
#import "Header.h"
#import "BaseTabbarController.h"
@interface AppDelegate ()

@end
@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    //ArrownockConstants
   //实例化window
    self.window = [[UIWindow alloc]initWithFrame:[[UIScreen mainScreen]bounds]];

    if ([StorageManager objForKey:k_User_ids]) {
        BaseTabbarController *shuFu = [[BaseTabbarController alloc]init];
        self.window.rootViewController = shuFu;
    }else{
        LWHLoginViewController *login = [[LWHLoginViewController alloc]init];
        UINavigationController *navigaVC = [[UINavigationController alloc]initWithRootViewController:login];
        self.window.rootViewController = navigaVC;
    }
    
    [self.window makeKeyAndVisible];
    return YES;
}


#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options  API_AVAILABLE(ios(13.0)){
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions  API_AVAILABLE(ios(13.0)){
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}


@end
