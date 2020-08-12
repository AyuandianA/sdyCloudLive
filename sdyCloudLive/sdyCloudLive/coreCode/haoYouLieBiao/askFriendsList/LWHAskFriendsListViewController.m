//
//  LWHAskFriendsListViewController.m
//  sdyCloudLive
//
//  Created by genghui on 2020/7/31.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHAskFriendsListViewController.h"
#import "Header.h"
#import "AnSocial.h"
#import "AppDelegate.h"
@interface LWHAskFriendsListViewController ()

@property(nonatomic,strong) LWHPublicTableView *tableView;
@property(nonatomic,strong) AnSocial *ansocial;
@property(nonatomic,copy) NSString *user_id;
@property(nonatomic,copy) NSString *target_user_id;
@end

@implementation LWHAskFriendsListViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.target_user_id = @"";
    self.user_id = [StorageManager objForKey:k_User_ids];
    [self creatTableView];
    [self updateChatList];
}
-(void)updateChatList
{
    
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    Weak_LiveSelf;
//    5f27b275f715d53d3b6a861b
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:self.user_id forKey:@"to_user_id"];
    [params setObject:k_AppKey forKey:@"key"];
    [params setObject:@"100" forKey:@"limit"];
    
//    NSString *path = [NSString stringWithFormat:@"http://%@/%@/%@", k_API_hosttt,k_API_versionnn,@"friends/requests/list.json"];
    [ansocial sendRequest:@"friends/requests/list.json" method:AnSocialMethodGET params:params success:^
     (NSDictionary *response) {
//        for (id key in response)
//        {
//            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
//        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            
            weakSelf.tableView.PublicSourceArray = [response[@"response"][@"friendRequests"] mutableCopy];
            [weakSelf.tableView reloadData];
        });
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];

}
-(void)creatTableView
{
    self.tableView = [LWHPublicTableView creatPublicTableViewWithFrame:CGRectMake(0, TopHeight, KScreenWidth, KScreenHeight - SafeAreaH - TopHeight)];
    self.tableView.cellName = @"LWHChatListTableViewCell";
    Weak_LiveSelf;
    self.tableView.tapSectionAndModel = ^(NSIndexPath *section, id model) {
        NSDictionary *dic = model;
        weakSelf.target_user_id = dic[@"from"][@"id"];
        [weakSelf keep_request:dic andIsTrue:YES ];
    };
    self.tableView.tapSubViewSection = ^(NSString *type, NSIndexPath *indexPath) {
        if ([type isEqualToString:@"1"]) {
            
        }else if ([type isEqualToString:@"2"]) {
            
        }
        
    };
    [self.view addSubview:self.tableView];
}
-(void)keep_request:(NSDictionary *)dic andIsTrue:(BOOL)isTrue
{
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:dic[@"id"] forKey:@"request_id"];
    [params setObject:isTrue ?  @"true" : @"false" forKey:@"keep_request"];
    Weak_LiveSelf;
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    NSString *path = isTrue ? @"friends/requests/approve.json" : @"friends/requests/reject.json";
    [ansocial sendRequest:path method:AnSocialMethodPOST params:params success:^
     (NSDictionary *response) {
//        for (id key in response)
//        {
//            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
//        }
        [weakSelf addFriend];
     } failure:^(NSDictionary *response) {
        for (id key in response)
        {
            NSLog(@"key: %@ ,value: %@",key,[response objectForKey:key]);
        }
     }];
}

-(void)addFriend
{
    Weak_LiveSelf;
    AnSocial *ansocial = [LWHAnIMTool shareAnIM].ansocial;
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:[StorageManager objForKey:k_User_ids] forKey:@"user_id"];
    [params setObject:k_AppKey forKey:@"key"];
    [params setObject:@"100" forKey:@"limit"];
    [params setObject:self.target_user_id forKey:@"target_user_id"];
    [ansocial sendRequest:@"friends/add.json" method:AnSocialMethodPOST params:params success:^
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
