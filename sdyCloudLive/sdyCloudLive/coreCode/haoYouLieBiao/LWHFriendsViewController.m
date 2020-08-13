//
//  LWHFriendsViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/7/30.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHFriendsViewController.h"
#import "LWHChatDetaliViewController.h"
#import "LWHAskFriendsListViewController.h"
#import "LWHfindFriendsViewController.h"
#import "AppDelegate.h"
#import "Header.h"
#import "AnSocial.h"
@interface LWHFriendsViewController ()
@property(nonatomic,strong) LWHPublicTableView *tableView;
@property(nonatomic,copy) NSString *user_id;
@property(nonatomic,copy) NSString*target_user_id;
@end

@implementation LWHFriendsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.user_id = [StorageManager objForKey:k_User_ids];
    [self creatRightButtonItem];
    [self.view addSubview:self.tableView];
    [self updateChatList];
}
-(void)updateChatList
{
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:[StorageManager objForKey:k_User_ids] forKey:@"user_id"];
    [params setObject:k_AppKey forKey:@"key"];
    [params setObject:@"100" forKey:@"limit"];
//    NSString *path = [NSString stringWithFormat:@"http://%@/%@/%@", k_API_hosttt,k_API_versionnn,@"friends/list.json"];
    [ansocial sendRequest:@"friends/list.json" method:AnSocialMethodGET params:params success:^
     (NSDictionary *response) {
        
        
        for (id key in response[@"response"][@"friends"])
        {
            NSLog(@"%@\n\n",key);
            [self.tableView.PublicSourceArray addObject:key];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [self.tableView reloadData];
        });
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];
}

-(void)creatRightButtonItem
{
    UIButton *right = [[UIButton alloc]init];
    right.frame = CGRectMake(0, 0, 60, 44);
    [right setTitle:@"添加" forState:(UIControlStateNormal)];
    [right setTitleColor:[UIColor blackColor] forState:(UIControlStateNormal)];
    right.imageEdgeInsets = UIEdgeInsetsMake(9.5f, 10, 9.5f, 25);
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]initWithCustomView:right];
    [right addTarget:self action:@selector(rightAction) forControlEvents:(UIControlEventTouchUpInside)];
    
    [self.leftBtn setTitle:@"新请求" forState:(UIControlStateNormal)];
    [self.leftBtn setTitleColor:[UIColor blackColor] forState:(UIControlStateNormal)];
    
}
-(void)backAction
{
    LWHAskFriendsListViewController *askfriend = [[LWHAskFriendsListViewController alloc]init];
    [self.navigationController pushViewController:askfriend animated:YES];
    
}
-(LWHPublicTableView *)tableView
{
    if (!_tableView) {
        Weak_LiveSelf;
        _tableView = [LWHPublicTableView creatPublicTableViewWithFrame:CGRectMake(0, TopHeight, KScreenWidth, KScreenHeight - SafeAreaH - TopHeight)];
        _tableView.cellName = @"LWHFriendsListTableViewCell";
        _tableView.tapSectionAndModel = ^(NSIndexPath *section, id model) {
            NSDictionary *dic = weakSelf.tableView.PublicSourceArray[section.row];
            NSLog(@"%@\n\n",dic);
            LWHChatDetaliViewController *detaliVC = [[LWHChatDetaliViewController alloc]init];
            detaliVC.ID = dic[@"id"];
            [weakSelf.navigationController pushViewController:detaliVC animated:YES];
        };
    }
    return _tableView;
}
-(void)rightAction
{
    LWHfindFriendsViewController *friendsVC = [[LWHfindFriendsViewController alloc]init];
    [self.navigationController pushViewController:friendsVC animated:YES];
    
}


@end
