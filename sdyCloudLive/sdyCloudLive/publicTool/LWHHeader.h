
#ifndef LWHHeader_h
#define LWHHeader_h

//经常引入的头文件


// 参数一：当前控制器(适配iOS11以下)，参数二：scrollview或子类
#define AdjustsScrollViewInsetNever(controller,view) if(@available(iOS 11.0, *)) {view.contentInsetAdjustmentBehavior = UIScrollViewContentInsetAdjustmentNever;} else if([controller isKindOfClass:[UIViewController class]]) {controller.automaticallyAdjustsScrollViewInsets = false;}


//屏幕宽高
#define KScreenWidth [UIScreen mainScreen].bounds.size.width
#define KScreenHeight [UIScreen mainScreen].bounds.size.height
#define  kScreenWidth [UIScreen mainScreen].bounds.size.width
#define  kScreenHeight [UIScreen mainScreen].bounds.size.height
//是否刘海屏
#define isIponeX \
({\
BOOL isYes = NO; \
if(@available(iOS 11.0, *)){ \
UIWindow *mainWindow = [UIApplication sharedApplication].keyWindow; \
if (mainWindow.safeAreaInsets.bottom > 0.0) { \
isYes = YES; \
} \
}\
(isYes);\
})\

//状态栏高度
#define StatusHeight \
({\
    CGFloat statH = 0.0; \
    if ([[UIApplication sharedApplication] isStatusBarHidden]) {\
        statH = SafeAreaH > 0 ? 44 : 20;\
    } else {\
        if(@available(iOS 13.0, *)){\
            statH = [[UIApplication sharedApplication].keyWindow.windowScene.statusBarManager statusBarFrame].size.height;\
        } else {\
            statH = [[UIApplication sharedApplication] statusBarFrame].size.height;\
        }\
    }\
    (statH);\
})\
//导航条高度
#define NaviH 44
//tabbar条高度
#define TabbarH 49
//下屏幕边缘系统横线高度
#define SafeAreaH (isIponeX ? 34 : 0)
//顶部高度
#define TopHeight (NaviH + StatusHeight)
//底部高度
#define BottomHeight (TabbarH + SafeAreaH)

//颜色
#define ColorHex(hex) ([UIColor colorWithRed:(((hex) & 0xFF0000) >> 16)/255.0f green:(CGFloat) (((hex) & 0xFF00) >> 8)/255.0f blue:((hex) & 0xFF)/255.0f alpha:1])
#define RGB(a,b,c,d)   [UIColor colorWithRed:(a)/255.0 green:(b)/255.0 blue:(c)/255.0 alpha:d]
#define MainBackColor RGB(243, 243, 243, 1)
#define MainTopColor RGB(205, 160, 80, 1)
// 字体
#define TextFont ((KScreenWidth > 375) ? 17 : (KScreenWidth > 320) ? 16 : 15)
// HUD提示框半径
#define HudSize ((KScreenWidth > 375) ? 24 : (KScreenWidth > 320) ? 20 : 15)
#define buttonColorImage     [UIImage convertViewToImagearray:@[(__bridge id)RGB(110, 160, 250, 1).CGColor,(__bridge id)RGB(77, 130, 240, 1).CGColor] andLocations:@[@0.3,@0.7] startPoint:CGPointMake(0, 0) endPoint:CGPointMake(1, 0)]

#define WmplayerFinishedThePlay @"wmplayerFinishedThePlay"//视频播放完成通知
// 获取图片路径
#define BundleTabeImage(name) [UIImage imageWithContentsOfFile:[[NSBundle bundleWithPath:[[NSBundle mainBundle] pathForResource:@"image.bundle" ofType:nil]] pathForResource:name ofType:nil]]

#define ImageWithName(name) [UIImage imageNamed:name]

#define LoginSuccess @"dengluchenggong"
#define LoginCancel @"cancelDengLu"


#define k_User_ids @"User_ids"
#define k_User_Name @"User_name"
#define k_ClientId @"clientIdd"
#define k_AppKey  @"vfe9DhZRj81csb2G9aEVXMLLBmWPu4i0"
#define k_AppServer @"0b0qIR00F3016K9RQeC0Mh2o6zy3vKjg"
#define Weak_LiveSelf __weak typeof(self) weakSelf = self
#define k_API_hosttt   @"10.10.10.101:3000"
#define k_API_versionnn @"v1"
#define User_User_Id    @"1"
#endif /*   */




/* 兼容  */
#define ImageWithName(name) [UIImage imageNamed:name]

#define LoginSuccess @"dengluchenggong"
#define LoginCancel @"cancelDengLu"
// 公共参数
#define Source_Id @"api_id"
#define Source_Type @"api_type"  //传 2
#define Source_Genre @"source_type" //传 1
#define Source_Version @"version"
#define Source_Model @"imei"
#define Source_System @"platform"
//登录返回信息
//用户信息

//个人资料
#define User_sex @"user_sex"
#define User_Headimg @"user_headimg"
#define User_Username @"user_username"
#define User_intro @"user_intro"
#define User_birth_time @"user_birth_time"

#define User_Openid @"user_openid"
#define User_Phone @"user_phone"
#define User_Grade @"user_grade"
#define User_Ip @"user_ip"
#define User_Role @"user_role"
#define User_Types @"user_types"
#define User_Is_Admin @"user_is_admin"
#define User_Add_Time @"user_add_time"
#define User_Teacher_Status @"user_teacher_status"
#define User_Teacher_Status_Remark @"user_teacher_status_remark"
#define User_Token @"user_token"
#define User_Code_Invite @"user_code_invite"
#define User_Vip_Status @"user_vip_status"
#define User_account_url @"user_account_url"
#define User_haibao_url @"user_haibao_url"
#define User_money_water @"user_money_water"
#define User_agreement_privacy @"user_agreement_privacy"
#define User_agreement_user @"user_agreement_user"

