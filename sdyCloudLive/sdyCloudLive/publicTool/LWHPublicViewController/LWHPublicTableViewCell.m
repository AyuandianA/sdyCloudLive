//
//  LWHPublicTableViewCell.m
//  zhibo
//
//  Created by 李武华 on 2020/5/21.
//  Copyright © 2020 李武华. All rights reserved.
//

#import "LWHPublicTableViewCell.h"

@interface LWHPublicTableViewCell ()


@end

@implementation LWHPublicTableViewCell

+(instancetype)creatPublicTableViewCellWithTableView:(UITableView *)tableView
{
    id cell = [tableView dequeueReusableCellWithIdentifier:NSStringFromClass(self)];
    // 判断如果没有可以重用的cell，创建
    if (!cell) {
        cell = [[NSClassFromString(NSStringFromClass(self)) alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:NSStringFromClass(self)];
    }
    return cell;
}
-(instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier
{
    if (self = [super initWithStyle:style reuseIdentifier:reuseIdentifier]) {
        //初始化
        [self chuShiHua];
    }
    return self;
}

//初始化数据
-(void)chuShiHua
{
    self.backgroundColor = [UIColor whiteColor];
    self.selectionStyle = UITableViewCellSelectionStyleNone;
    self.margin = 10;
}

-(void)changeDataWithModel:(id)model andSection:(NSIndexPath *)section
{
    self.section = model;
}
@end
/*
//初始化数据
-(void)chuShiHua
{
    [super chuShiHua];
    self.textLabel.textColor = [UIColor blackColor];
}

-(void)changeDataWithModel:(id)model andSection:(NSIndexPath *)section
{
    [super changeDataWithModel:model andSection:section];
    self.textLabel.text = model;
}
*/
