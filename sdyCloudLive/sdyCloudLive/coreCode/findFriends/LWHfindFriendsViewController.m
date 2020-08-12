
//
//  LWHfindFriendsViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/8/3.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHfindFriendsViewController.h"
#import "BaseNaviController.h"
#import "CustomerTextView.h"
#import "AppDelegate.h"
#import "Header.h"
@interface LWHfindFriendsViewController ()
@property(nonatomic,strong) CustomerTextView*accountTextView;
@property(nonatomic,strong) LWHPublicTableView*tableview;

@end

@implementation LWHfindFriendsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    self.navigationBar.hidden = YES;
    self.accountTextView = [[CustomerTextView alloc]initWithFrame:CGRectMake(20, StatusHeight, KScreenWidth - 20*2-60, NaviH)];
    self.accountTextView.backgroundColor = RGB(50, 50, 50, 0.02);
    self.accountTextView.placeHolder = @"请输入用户名";
    self.accountTextView.placeHolderColor = RGB(200, 200, 200, 1);
    self.accountTextView.placeholderLabel.top = 5;
    [self.view addSubview:self.accountTextView];
    
    
    UIButton *searchButton = [LWHUIQuicklyCreateTool LWH_UI_Btn:@"搜索" Color:[UIColor blueColor] selecteColor:nil Font:TextFont bgimage:nil selecteImage:nil target:self action:@selector(searchButtonAction)];
    [self.view addSubview:searchButton];
    searchButton.frame = CGRectMake(self.accountTextView.right, StatusHeight, 60, NaviH);
    
    
    
    self.tableview = [LWHPublicTableView creatPublicTableViewWithFrame:CGRectMake(0, TopHeight + 4, KScreenWidth, KScreenHeight - TopHeight - SafeAreaH)];
    self.tableview.cellName = @"LWHChatListTableViewCell";
    [self.view addSubview:self.tableview];
    Weak_LiveSelf;
    self.tableview.tapSectionAndModel = ^(NSIndexPath *section, id model) {
        NSDictionary *dic = model;
        [weakSelf sendQuery:dic[@"id"]];
    };
    
}

-(void)searchButtonAction
{
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:self.accountTextView.text forKey:@"username"];
    [params setObject:k_AppKey forKey:@"key"];
    
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    
//    NSString *path = [NSString stringWithFormat:@"http://%@/%@/%@", k_API_hosttt,k_API_versionnn,@"users/query.json"];
    [ansocial sendRequest:@"users/query.json" method:AnSocialMethodGET params:params success:^
     (NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            self.tableview.PublicSourceArray = [response[@"response"][@"users"] mutableCopy];
            [self.tableview reloadData];
        });
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];
}
-(void)sendQuery:(NSString *)target_user_id
{
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:[StorageManager objForKey:k_User_ids] forKey:@"target_user_id"];
    [params setObject:target_user_id forKey:@"user_id"];
    [params setObject:@"hello" forKey:@"message"];
    [params setObject:k_AppKey forKey:@"key"];
    
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    Weak_LiveSelf;
//    NSString *path = [NSString stringWithFormat:@"http://%@/%@/%@", k_API_hosttt,k_API_versionnn,@"friends/requests/send.json"];
    [ansocial sendRequest:@"friends/requests/send.json" method:AnSocialMethodPOST params:params success:^
     (NSDictionary *response) {
//        for (id key in response)
//        {
//            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
//        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [weakSelf.navigationController popViewControllerAnimated:YES];
        });
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];
}


@end
