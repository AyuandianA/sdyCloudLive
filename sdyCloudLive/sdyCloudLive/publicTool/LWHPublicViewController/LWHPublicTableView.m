//
//  LWHPublicTableView.m
//  zhibo
//
//  Created by 李武华 on 2020/5/21.
//  Copyright © 2020 李武华. All rights reserved.
//

#import "LWHPublicTableView.h"
#import <objc/message.h>
#import "UIView+Controller.h"
@interface LWHPublicTableView ()<UITableViewDataSource,UITableViewDelegate>
@end

@implementation LWHPublicTableView
+(instancetype)creatPublicTableViewWithFrame:(CGRect)frame
{
    return [[self alloc]initWithFrame:frame style:UITableViewStylePlain];
}
+(instancetype)creatPublicTableViewWithFrame:(CGRect)frame  style:(UITableViewStyle)style
{
    return [[self alloc]initWithFrame:frame style:style];
}
-(instancetype)initWithFrame:(CGRect)frame style:(UITableViewStyle)style
{
    if (self = [super initWithFrame:frame style:style]) {
        //初始化自带属性
        [self chuShiHua];
    }
    return self;
}

//初始化自带属性
-(void)chuShiHua
{
    self.backgroundColor = [UIColor whiteColor];
    self.cellName = @"LWHPublicTableViewCell";
    self.cellSections = NO;
    //设置代理
    self.delegate = self;
    self.dataSource = self;
    self.separatorStyle = UITableViewCellSelectionStyleNone;
    self.separatorColor = MainBackColor;
    self.separatorInset = UIEdgeInsetsMake(0, 0, 0, 0);
    self.showsVerticalScrollIndicator = NO;
    self.estimatedRowHeight = 10;
    self.estimatedSectionHeaderHeight = 0;
    self.estimatedSectionFooterHeight = 0;
    self.rowHeight = UITableViewAutomaticDimension;
    self.showsVerticalScrollIndicator = NO;
    AdjustsScrollViewInsetNever([self viewControll], self)

}

- (void)setCellName:(NSString *)cellName
{
    _cellName = cellName;
}
#pragma mark - Table view data source和代理方法

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    if (self.cellSections) {
        return self.PublicSourceArray.count;
    }else{
        return 1;
    }
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (self.cellSections) {
        if ([self.PublicSourceArray[section] count] != 0) {
            return [self.PublicSourceArray[section] count];
        }else{
            return 0;
        }
    }else{
        if (self.PublicSourceArray.count != 0) {
            return self.PublicSourceArray.count;
        }else{
            return 0;
        }
    }
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    id (*action)(id, SEL, id) = (id (*)(id, SEL, id)) objc_msgSend;
    void (*actionTwo)(id, SEL, id,id) = (void (*)(id, SEL, id,NSIndexPath *)) objc_msgSend;
    
    SEL sel = sel_registerName("creatPublicTableViewCellWithTableView:");
    Weak_LiveSelf;
    Class cellName = NSClassFromString(self.cellName);
    id cell = action(cellName,sel,tableView);
    [cell setTapSubViewSection:^(NSString *type, NSIndexPath *indexPath) {
        if (weakSelf.tapSubViewSection) {
            weakSelf.tapSubViewSection(type, indexPath);
        }
    }];
    id model ;
    if (self.cellSections) {
        model = self.PublicSourceArray[indexPath.section][indexPath.row];
    }else{
        model = self.PublicSourceArray[indexPath.row];
    }
    SEL selTwo = sel_registerName("changeDataWithModel:andSection:");
    actionTwo(cell,selTwo,model,indexPath);
    return cell;
}
-(void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (self.cellSections) {
        if (self.tapSectionAndModel) {
            self.tapSectionAndModel(indexPath, self.PublicSourceArray[indexPath.section][indexPath.row]);
        }
    }else{
        if (self.tapSectionAndModel) {
            self.tapSectionAndModel(indexPath,self.PublicSourceArray[indexPath.row]);
        }
    }
    
}
-(UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section
{
    if (self.headerView) {
        return self.headerView(section);
    }else{
        return [UIView new];
    }
}
-(UIView *)tableView:(UITableView *)tableView viewForFooterInSection:(NSInteger)section
{
    if (self.footerView) {
        return self.footerView(section);
    }else{
        return [UIView new];
    }
}
-(CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section
{
    if (self.headerHeight) {
        return self.headerHeight(section);
    }else{
        return 0.01;
    }
}
-(CGFloat)tableView:(UITableView *)tableView heightForFooterInSection:(NSInteger)section
{
    if (self.footerHeight) {
        return self.footerHeight(section);
    }else{
        return 0.01;
    }
}
-(CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath
{
    if (self.rowHeightSection) {
        return self.rowHeightSection(indexPath);
    }else{
        return UITableViewAutomaticDimension;
    }
    
}
-(NSMutableArray *)PublicSourceArray
{
    if (!_PublicSourceArray) {
        _PublicSourceArray = [NSMutableArray arrayWithCapacity:0];
    }
    return _PublicSourceArray;
}
-(void)scrollViewDidScroll:(UIScrollView *)scrollView
{
    if (self.scrollSection) {
        self.scrollSection();
    }
}
-(CGFloat)getCellTableViewHeight
{
    CGFloat heightAll = 0;
    if (self.cellSections) {
    }else{
        id (*action)(id, SEL, id) = (id (*)(id, SEL, id)) objc_msgSend;
        void (*actionTwo)(id, SEL, id,id) = (void (*)(id, SEL, id,NSIndexPath *)) objc_msgSend;
        SEL sel = sel_registerName("creatPublicTableViewCellWithTableView:");
        Class cellName = NSClassFromString(self.cellName);
        id cell = action(cellName,sel,self);
        id model ;
        if (self.PublicSourceArray.count) {
            for (int i = 0; i < self.PublicSourceArray.count; i++) {
                model = self.PublicSourceArray[i];
                SEL selTwo = sel_registerName("changeDataWithModel:andSection:");
                actionTwo(cell,selTwo,model,[NSIndexPath indexPathForRow:i inSection:0]);
                    //使用systemLayoutSizeFittingSize获取高度
                CGFloat heitht = [((UITableViewCell *)cell).contentView systemLayoutSizeFittingSize:UILayoutFittingCompressedSize].height;
                heightAll += heitht;
            }
        }
    }
    
    return heightAll;
}
@end
