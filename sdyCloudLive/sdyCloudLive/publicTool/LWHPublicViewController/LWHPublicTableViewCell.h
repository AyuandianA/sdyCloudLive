//
//  LWHPublicTableViewCell.h
//  zhibo
//
//  Created by 李武华 on 2020/5/21.
//  Copyright © 2020 李武华. All rights reserved.
//

#import <UIKit/UIKit.h>
NS_ASSUME_NONNULL_BEGIN
typedef void(^tapSubViewSections)(NSString *type,NSIndexPath *indexPath);
@interface LWHPublicTableViewCell : UITableViewCell

//cell上面所有点击触发，根据type区分不同的点击
@property (nonatomic,copy) tapSubViewSections tapSubViewSection;
@property (nonatomic,assign) CGFloat margin;
@property(nonatomic,strong) NSIndexPath *section;

+(instancetype)creatPublicTableViewCellWithTableView:(UITableView *)tableView;
//初始化数据
-(void)chuShiHua;
//赋值
-(void)changeDataWithModel:(id)model andSection:(NSIndexPath *)section;
@end

NS_ASSUME_NONNULL_END
