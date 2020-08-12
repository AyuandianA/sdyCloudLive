//
//  LWHPublicCollectionView.h
//  zhibo
//
//  Created by 李武华 on 2020/5/21.
//  Copyright © 2020 李武华. All rights reserved.
//


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

typedef void(^tapSubViewSections)(NSString *type,NSIndexPath *indexPath);
typedef UIEdgeInsets(^insets)(NSInteger section);
typedef CGFloat(^Hmargin)(NSInteger section);
typedef CGFloat(^Vmargin)(NSInteger section);
typedef CGFloat(^headerHeight)(NSInteger section);
typedef CGFloat(^footerHeight)(NSInteger section);

typedef void(^tapSections)(id model);
typedef void(^scrollSection)(void);

@interface LWHPublicCollectionView : UICollectionView

@property (nonatomic,strong) NSMutableArray *PublicSourceArray;

@property (nonatomic,copy) NSString *cellName;

//预估cell宽高，尽量等于实际cell宽高
@property (nonatomic) CGSize estimatedItemSize;
@property (nonatomic) UICollectionViewScrollDirection scrollDirections;
@property (nonatomic,copy) insets insets;
@property (nonatomic,copy) Hmargin Hmargin;
@property (nonatomic,copy) Vmargin Vmargin;
@property (nonatomic,copy) tapSections tapSection;
//cell上面所有点击触发，根据type区分不同的点击
@property (nonatomic,copy) tapSubViewSections tapSubViewSection;
@property (nonatomic,copy) scrollSection scrollSection;
@property (nonatomic,copy) headerHeight headerHeight;
@property (nonatomic,copy) footerHeight footerHeight;
+(instancetype)creatPublicCollectionViewWithFrame:(CGRect)frame;

@end
