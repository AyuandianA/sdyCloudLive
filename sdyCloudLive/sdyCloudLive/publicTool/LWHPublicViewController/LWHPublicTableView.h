//
//  LWHPublicTableView.h
//  zhibo
//
//  Created by 李武华 on 2020/5/21.
//  Copyright © 2020 李武华. All rights reserved.
//

#import <UIKit/UIKit.h>

typedef void(^tapSubViewSections)(NSString *type,NSIndexPath *indexPath);
typedef void(^tapSectionsAndModel)(NSIndexPath *section,id model);
typedef void(^scrollSection)(void);
typedef CGFloat(^headerHeight)(NSInteger section);
typedef UIView *(^headerView)(NSInteger section);
typedef CGFloat(^footerHeight)(NSInteger section);
typedef UIView *(^footerView)(NSInteger section);
typedef CGFloat(^rowHeightSection)(NSIndexPath *indexPath);

@interface LWHPublicTableView : UITableView
//数据源
@property (nonatomic,strong) NSMutableArray *PublicSourceArray;
//cell类名
@property (nonatomic,copy) NSString *cellName;
//cell上面所有点击触发，根据type区分不同的点击
@property (nonatomic,copy) tapSubViewSections tapSubViewSection;
//cell点击触发
@property (nonatomic,copy) tapSectionsAndModel tapSectionAndModel;
//滚动触发
@property (nonatomic,copy) scrollSection scrollSection;
//判断是否多分区，NO指单分区，YES指多分区。默认NO
@property (nonatomic,assign) BOOL cellSections;
//区头高
@property (nonatomic,copy) headerHeight headerHeight;
//区头
@property (nonatomic,copy) headerView headerView;
//区尾高
@property (nonatomic,copy) footerHeight footerHeight;
//区尾
@property (nonatomic,copy) footerView footerView;
//如果自动布局刷新跳动，预备计算高度填充
@property (nonatomic,copy) rowHeightSection rowHeightSection;
//初始化方法1
+(instancetype)creatPublicTableViewWithFrame:(CGRect)frame;
//初始化方法2
+(instancetype)creatPublicTableViewWithFrame:(CGRect)frame style:(UITableViewStyle)style;
//不带表头表尾的中间内容总高度
-(CGFloat)getCellTableViewHeight;
@end
