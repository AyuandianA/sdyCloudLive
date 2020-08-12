//
//  SceneDelegate.m
//  sdyCloudLive
//
//  Created by sdy on 2020/6/29.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "SceneDelegate.h"
#import "LWHLoginViewController.h"
#import "Header.h"
#import "BaseTabbarController.h"
#import "LWHTestLoginViewController.h"
#import "BaseNaviController.h"
@interface SceneDelegate ()

@end

@implementation SceneDelegate


- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions  API_AVAILABLE(ios(13.0)){
    UIWindowScene *sceneWindow;
    if (scene) {
        sceneWindow = (UIWindowScene *)scene;
    }else{
        return;
    }
    self.window = [[UIWindow alloc]initWithWindowScene:sceneWindow];
//    if ([StorageManager objForKey:k_User_ids]) {
//        BaseTabbarController *shuFu = [[BaseTabbarController alloc]init];
//        self.window.rootViewController = shuFu;
//    }else{
//        LWHTestLoginViewController *login = [[LWHTestLoginViewController alloc]init];
//        UINavigationController *navigaVC = [[UINavigationController alloc]initWithRootViewController:login];
//        self.window.rootViewController = navigaVC;
//    }
    LWHTestLoginViewController *login = [[LWHTestLoginViewController alloc]init];
    BaseNaviController *navigaVC = [[BaseNaviController alloc]initWithRootViewController:login];
    self.window.rootViewController = navigaVC;
    [self.window makeKeyAndVisible];
}


- (void)sceneDidDisconnect:(UIScene *)scene  API_AVAILABLE(ios(13.0)){
    // Called as the scene is being released by the system.
    // This occurs shortly after the scene enters the background, or when its session is discarded.
    // Release any resources associated with this scene that can be re-created the next time the scene connects.
    // The scene may re-connect later, as its session was not neccessarily discarded (see `application:didDiscardSceneSessions` instead).
}


- (void)sceneDidBecomeActive:(UIScene *)scene  API_AVAILABLE(ios(13.0)){
    // Called when the scene has moved from an inactive state to an active state.
    // Use this method to restart any tasks that were paused (or not yet started) when the scene was inactive.
    
    [[LWHAnIMTool shareAnIM] connectAnIM];
}


- (void)sceneWillResignActive:(UIScene *)scene  API_AVAILABLE(ios(13.0)){
    // Called when the scene will move from an active state to an inactive state.
    // This may occur due to temporary interruptions (ex. an incoming phone call).
}


- (void)sceneWillEnterForeground:(UIScene *)scene  API_AVAILABLE(ios(13.0)){
    // Called as the scene transitions from the background to the foreground.
    // Use this method to undo the changes made on entering the background.
}


- (void)sceneDidEnterBackground:(UIScene *)scene  API_AVAILABLE(ios(13.0)){
    // Called as the scene transitions from the foreground to the background.
    // Use this method to save data, release shared resources, and store enough scene-specific state information
    // to restore the scene back to its current state.
    [[LWHAnIMTool shareAnIM] breakAnIM];
}


@end
