//
//  LWHChatListTableViewCell.m
//  sdyCloudLive
//
//  Created by genghui on 2020/7/31.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHChatListTableViewCell.h"

@implementation LWHChatListTableViewCell

//初始化数据
-(void)chuShiHua
{
    self.textLabel.textColor = [UIColor blackColor];
}

-(void)changeDataWithModel:(id)model andSection:(NSIndexPath *)section
{
    self.section = section;
    self.textLabel.text = @"6";
}

@end
