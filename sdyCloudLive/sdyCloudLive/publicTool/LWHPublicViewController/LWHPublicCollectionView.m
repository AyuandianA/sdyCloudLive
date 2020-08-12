//
//  LWHPublicCollectionView.m
//  zhibo
//
//  Created by 李武华 on 2020/5/21.
//  Copyright © 2020 李武华. All rights reserved.
//

#import "LWHPublicCollectionView.h"
#import "LWHPublicCollectionViewCell.h"
#import <objc/message.h>
@interface LWHPublicCollectionView ()<UICollectionViewDataSource,UICollectionViewDelegate,UICollectionViewDelegateFlowLayout>

@end

@implementation LWHPublicCollectionView

+(instancetype)creatPublicCollectionViewWithFrame:(CGRect)frame
{
    UICollectionViewFlowLayout *layout = [[UICollectionViewFlowLayout alloc]init];
    layout.scrollDirection = UICollectionViewScrollDirectionVertical;
    layout.estimatedItemSize = CGSizeMake(100, 100);
    return [[self alloc]initWithFrame:frame collectionViewLayout:layout];
}
-(instancetype)initWithFrame:(CGRect)frame collectionViewLayout:(UICollectionViewLayout *)layout
{
    if (self = [super initWithFrame:frame collectionViewLayout:layout]) {
        //初始化自带属性
        [self chuShiHua];
    }
    return self;
}
-(void)setEstimatedItemSize:(CGSize)estimatedItemSize
{
    _estimatedItemSize = estimatedItemSize;
    UICollectionViewFlowLayout *layout = (UICollectionViewFlowLayout *)self.collectionViewLayout;
    layout.estimatedItemSize = estimatedItemSize;
    self.collectionViewLayout = layout;
}

-(void)setScrollDirections:(UICollectionViewScrollDirection)scrollDirection
{
    _scrollDirections = scrollDirection;
    UICollectionViewFlowLayout *layout = (UICollectionViewFlowLayout *)self.collectionViewLayout;
    layout.scrollDirection = scrollDirection;
    self.collectionViewLayout = layout;
}
//初始化自带属性
-(void)chuShiHua
{
    self.showsVerticalScrollIndicator = NO;
    self.showsHorizontalScrollIndicator = NO;
    self.backgroundColor = [UIColor whiteColor];
    self.cellName = @"LWHPublicCollectionViewCell";
    //注册collectionViewCell
    [self registerClass:NSClassFromString(self.cellName) forCellWithReuseIdentifier:self.cellName];
    #pragma mark -- 注册头部视图
    [self registerClass:[UICollectionReusableView class] forSupplementaryViewOfKind:UICollectionElementKindSectionHeader withReuseIdentifier:@"HeaderView"];
    [self registerClass:[UICollectionReusableView class] forSupplementaryViewOfKind:UICollectionElementKindSectionFooter withReuseIdentifier:@"HeaderView"];
    //设置代理
    self.delegate = self;
    self.dataSource = self;
//    AdjustsScrollViewInsetNever([self viewController], self)
    
}
-(void)dealloc{
    [[NSNotificationCenter defaultCenter]removeObserver:self];
}
-(void)tapSubviewsAction:(NSNotification *)info
{
    NSDictionary *userDic = info.userInfo;
    if (self.tapSubViewSection) {
        self.tapSubViewSection(userDic[@"type"], userDic[@"indexPath"]);
    }
}
- (void)setCellName:(NSString *)cellName
{
    _cellName = cellName;
    [self registerClass:NSClassFromString(cellName) forCellWithReuseIdentifier:cellName];
//    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(tapSubviewsAction:) name:cellName object:[self viewController]];
}
#pragma mark collectionView代理方法
//返回section个数
- (NSInteger)numberOfSectionsInCollectionView:(UICollectionView *)collectionView{
    return 1;
}

//每个section的item个数
- (NSInteger)collectionView:(UICollectionView *)collectionView numberOfItemsInSection:(NSInteger)section
{
    if (self.PublicSourceArray.count != 0) {
        return self.PublicSourceArray.count;
    }else{
        return 0;
    }
}

- (UICollectionViewCell *)collectionView:(UICollectionView *)collectionView cellForItemAtIndexPath:(NSIndexPath *)indexPath
{
    void (*actionThree)(id, SEL, id,id) = (void (*)(id, SEL, id,id)) objc_msgSend;
    id cell = [collectionView dequeueReusableCellWithReuseIdentifier:self.cellName forIndexPath:indexPath];
    id model = self.PublicSourceArray[indexPath.row];
    SEL selTwo = sel_registerName("changeDataWithModel:andSection:");
    actionThree(cell,selTwo,model,indexPath);
    return cell;
}
//点击item方法
- (void)collectionView:(UICollectionView *)collectionView didSelectItemAtIndexPath:(NSIndexPath *)indexPath
{
    self.tapSection(self.PublicSourceArray[indexPath.row]);
        
}
 //设置区头尺寸高度
-(CGSize)collectionView:(UICollectionView *)collectionView layout:(UICollectionViewLayout *)collectionViewLayout referenceSizeForHeaderInSection:(NSInteger)section{
    CGFloat height = 0;
    CGSize size;
    if (self.headerHeight) {
        height = self.headerHeight(section);
        size = CGSizeMake(KScreenWidth, height);
    }else{
        size = CGSizeMake(0, 0);
    }
    return size;
}
// 设置区尾尺寸高度
-(CGSize)collectionView:(UICollectionView *)collectionView layout:(UICollectionViewLayout *)collectionViewLayout referenceSizeForFooterInSection:(NSInteger)section{
    CGFloat height = 0;
    CGSize size;
    if (self.footerHeight) {
        height = self.footerHeight(section);
        size = CGSizeMake(KScreenWidth, height);
    }else{
        size = CGSizeMake(0, 0);
    }
    return size;
}
- (UICollectionReusableView *)collectionView:(UICollectionView *)collectionView viewForSupplementaryElementOfKind:(NSString *)kind atIndexPath:(NSIndexPath *)indexPath{
    if ([kind isEqualToString:UICollectionElementKindSectionHeader]) {
        UICollectionReusableView *headerView =[collectionView dequeueReusableSupplementaryViewOfKind:UICollectionElementKindSectionHeader withReuseIdentifier:@"HeaderView" forIndexPath:indexPath];
        headerView.backgroundColor = [UIColor colorWithWhite:0.7 alpha:0.9];
        return headerView;
    }else {
        UICollectionReusableView *footerView =[collectionView dequeueReusableSupplementaryViewOfKind:UICollectionElementKindSectionFooter withReuseIdentifier:@"HeaderView" forIndexPath:indexPath];
        footerView.backgroundColor = [UIColor colorWithWhite:0.7 alpha:0.9];
        return footerView;
    }
}
//同一个section内部间item的 和滚动方向垂直方向的间距
- (CGFloat)collectionView:(UICollectionView *)collectionView layout:(UICollectionViewLayout *)collectionViewLayout minimumInteritemSpacingForSectionAtIndex:(NSInteger)section
{
    if (self.Hmargin) {
        return self.Hmargin(section);
    }else{
        return 0;
    }
}


//同一个section 内部 item 的滚动方向的间距
- (CGFloat)collectionView:(UICollectionView *)collectionView layout:(UICollectionViewLayout *)collectionViewLayout minimumLineSpacingForSectionAtIndex:(NSInteger)section
{
    if (self.Vmargin) {
        return self.Vmargin(section);
    }else{
        return 0;
    }
}
//设置每个Section的UIEdgeInsets
- (UIEdgeInsets)collectionView:(UICollectionView *)collectionView layout:(UICollectionViewLayout *)collectionViewLayout insetForSectionAtIndex:(NSInteger)section
{
    if (self.insets) {
        return self.insets(section);
    }else{
        return UIEdgeInsetsZero;
    }
}

-(NSMutableArray *)PublicSourceArray
{
    if (!_PublicSourceArray) {
        _PublicSourceArray = [NSMutableArray array];
    }
    return _PublicSourceArray;
    
}
-(void)scrollViewDidScroll:(UIScrollView *)scrollView
{
    if (self.scrollSection) {
        self.scrollSection();
    }
}

@end
