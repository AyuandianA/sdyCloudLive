//
//  BaseViewController.m
//  ChengXianApp
//
//  Created by Aliang Ren on 2019/5/7.
//  Copyright © 2019 Aliang Ren. All rights reserved.
//

#import "BaseViewController.h"
#import "UIImage+Category.h"
#import "LSNavigationController.h"

@interface BaseViewController ()

@property (nonatomic, strong)UILabel *titleLabel;

@end

@implementation BaseViewController

- (UILabel *)titleLabel {
    
    if (!_titleLabel) {
        _titleLabel = [[UILabel alloc]initWithFrame:CGRectMake(64, 0, KScreenWidth-64*2, 44)];
        _titleLabel.textAlignment = NSTextAlignmentCenter;
        _titleLabel.textColor = [UIColor blackColor];
        _titleLabel.font = [UIFont boldSystemFontOfSize:((KScreenWidth > 375) ? 18 : (KScreenWidth > 320) ? 16 : 15)];
    }
    return _titleLabel;
}

- (UIButton *)leftBtn {
    
    if (!_leftBtn) {
        _leftBtn = [[UIButton alloc]init];
        _leftBtn.frame = CGRectMake(0, 0, 60, 44);
        [_leftBtn setImage:[UIImage imageNamed:@"返回"] forState:UIControlStateNormal];
        [_leftBtn setImage:[UIImage imageNamed:@"返回"] forState:UIControlStateHighlighted];
        _leftBtn.imageEdgeInsets = UIEdgeInsetsMake(9.5f, 10, 9.5f, 25);
        [_leftBtn addTarget:self action:@selector(backAction) forControlEvents:UIControlEventTouchUpInside];
    }
    
    return _leftBtn;
    
}

- (void)viewDidLoad {
    
    [super viewDidLoad];
    
    [self reloadNavigationBar];
    
    
    self.automaticallyAdjustsScrollViewInsets = NO;
    
    [self.navigationBar setShadowImage:[UIImage new]];
    
    // 设置导航栏字体
    NSDictionary *attributesDic = @{
                                    NSForegroundColorAttributeName:[UIColor whiteColor],
                                    NSFontAttributeName:[UIFont boldSystemFontOfSize:17]
                                    };
    
    self.navigationBar.titleTextAttributes = attributesDic;
    
    [self.navigationBar setBackgroundImage:[UIImage createImageWithColor:[UIColor whiteColor]] forBarMetrics:UIBarMetricsDefault];
    
    self.view.backgroundColor = [UIColor whiteColor];
    
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]initWithCustomView:self.leftBtn];
    UIButton *right = [[UIButton alloc]init];
    right.frame = CGRectMake(0, 0, 60, 44);
    right.imageEdgeInsets = UIEdgeInsetsMake(9.5f, 10, 9.5f, 25);
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]initWithCustomView:right];
    
    self.navigationItem.titleView = self.titleLabel;
   
}
- (void)setTitle:(NSString *)title {
    self.titleLabel.text = title;

}
- (void)setNaviTitleFont:(UIFont *)font {
    self.titleLabel.font = font;
}
- (void)setNaviTitleColor:(UIColor *)naviTitleColor {
    self.titleLabel.textColor = naviTitleColor;
}
- (void)setIsHiddenReturnButton:(BOOL)isHiddenReturnButton {

    if (isHiddenReturnButton) {
//        self.navigationItem.leftBarButtonItem = nil;
        UIView *leftView = [[UIView alloc]initWithFrame:self.leftBtn.frame];
        self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]initWithCustomView:leftView];
    } else {
        self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]initWithCustomView:self.leftBtn];
    }
    [self.view layoutIfNeeded];

}
- (void)backAction {
    
    [self.navigationController popViewControllerAnimated:YES];
    
}

//- (void)setTitleString:(NSString *)titleString {
//
//    _titleString = titleString;
//
//    self.titleLabel.text = _titleString;
//
//}
//- (void)injected{
//    NSLog(@"I've been injected: %@", self);
//    [self viewDidLoad];
//}

@end
