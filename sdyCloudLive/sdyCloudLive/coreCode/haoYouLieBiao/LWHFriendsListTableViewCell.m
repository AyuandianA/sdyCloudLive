//
//  LWHFriendsListTableViewCell.m
//  sdyCloudLive
//
//  Created by genghui on 2020/8/12.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHFriendsListTableViewCell.h"

@implementation LWHFriendsListTableViewCell

//初始化数据
-(void)chuShiHua
{
    [super chuShiHua];
    self.textLabel.textColor = [UIColor blackColor];
}

-(void)changeDataWithModel:(id)model andSection:(NSIndexPath *)section
{
    [super changeDataWithModel:model andSection:section];
    self.textLabel.text = model[@"username"];
}

@end
