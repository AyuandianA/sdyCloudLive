//
//  LJCProgressHUD.m
//  ChengXianApp
//
//  Created by Aliang Ren on 2019/6/11.
//  Copyright © 2019 WuHua . All rights reserved.
//

#import "LJCProgressHUD.h"
#import "Header.h"
#define kdelay 1
@implementation LJCProgressHUD

+ (void)showIndicator {
    
    [SVProgressHUD setDefaultAnimationType:SVProgressHUDAnimationTypeNative];
    
    [SVProgressHUD setForegroundColor:[UIColor whiteColor]];
    
    [SVProgressHUD setRingNoTextRadius:HudSize];

    [SVProgressHUD setRingRadius:HudSize];
    
    [SVProgressHUD setFont:[UIFont systemFontOfSize:TextFont]];
   
    [SVProgressHUD setCornerRadius:5];

    [SVProgressHUD setDefaultMaskType:SVProgressHUDMaskTypeClear];
   
    [SVProgressHUD setBackgroundColor:[UIColor colorWithWhite:0 alpha:.8]];
  
    [SVProgressHUD show];
    
    
}
+ (void)showIndicatorWithText:(NSString *)text {
    
    [SVProgressHUD setDefaultAnimationType:SVProgressHUDAnimationTypeNative];
    
    [SVProgressHUD setForegroundColor:[UIColor whiteColor]];
    
    [SVProgressHUD setRingNoTextRadius:HudSize];
    
    [SVProgressHUD setRingRadius:HudSize];
    
    [SVProgressHUD setFont:[UIFont systemFontOfSize:TextFont]];
    
    [SVProgressHUD setCornerRadius:5];
    
    [SVProgressHUD setDefaultMaskType:SVProgressHUDMaskTypeClear];
    
    [SVProgressHUD setBackgroundColor:[UIColor colorWithWhite:0 alpha:.8]];
    
    [SVProgressHUD showWithStatus:text];
    
}
+ (void)showAnnulusHud {
    [SVProgressHUD setDefaultAnimationType:SVProgressHUDAnimationTypeFlat];
    // 无文本的圆环半径
    [SVProgressHUD setRingNoTextRadius:HudSize];
    // 有文本的圆环半径
    [SVProgressHUD setRingRadius:HudSize];
    //
    [SVProgressHUD setCornerRadius:14];
    //
    [SVProgressHUD setFont:[UIFont systemFontOfSize:TextFont]];
    
//    [SVProgressHUD setMinimumSize:CGSizeMake(40, 40)];
    // 提示框显示时不允许交互(SVProgressHUDMaskTypeNone->允许交互)
    [SVProgressHUD setDefaultMaskType:SVProgressHUDMaskTypeClear];
    // 旋转进度条的颜色
    [SVProgressHUD setForegroundColor:[UIColor orangeColor]];
    // 提示框背景色
    [SVProgressHUD setBackgroundColor:[UIColor colorWithWhite:0 alpha:.8]];
    // 显示
    [SVProgressHUD show];

}
// 状态提示(纯文本)
+ (void)showStatueText:(NSString *)text {
    
    if ([text isEmptyString]) {
        
        return;
    }
    [SVProgressHUD setCornerRadius:14];
    // 提示框背景色
    [SVProgressHUD setBackgroundColor:[UIColor colorWithWhite:0 alpha:1]];
    
    [SVProgressHUD setForegroundColor:[UIColor whiteColor]];
    
    [SVProgressHUD setFont:[UIFont systemFontOfSize:TextFont]];
    
    [SVProgressHUD showImage:[UIImage imageNamed:@"哈哈哈啊哈哈"] status:text];
    
    [SVProgressHUD dismissWithDelay:kdelay];
    
}
// 错误状态提示(带图片)
+ (void)showErrorText:(NSString *)text {
    [SVProgressHUD setCornerRadius:14];
    // 提示框背景色
    [SVProgressHUD setBackgroundColor:[UIColor colorWithWhite:0 alpha:1]];
    
    [SVProgressHUD setForegroundColor:[UIColor whiteColor]];
    
    [SVProgressHUD setFont:[UIFont systemFontOfSize:TextFont]];
    
    [SVProgressHUD showErrorWithStatus:text];
    
    [SVProgressHUD dismissWithDelay:kdelay];
   
    
}
// 成功状态提示(带图片)
+ (void)showSuccText:(NSString *)text {
    [SVProgressHUD setCornerRadius:14];
    // 提示框背景色
    [SVProgressHUD setBackgroundColor:[UIColor colorWithWhite:0 alpha:1]];
    
    [SVProgressHUD setForegroundColor:[UIColor whiteColor]];
    
    [SVProgressHUD setFont:[UIFont systemFontOfSize:TextFont]];
    
    [SVProgressHUD showSuccessWithStatus:text];
    
    [SVProgressHUD dismissWithDelay:kdelay];
    
}

+ (void)hiddenHud {
    [SVProgressHUD dismiss];
}

@end
