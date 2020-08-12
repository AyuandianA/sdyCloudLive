//
//  CustomerTextView.h
//  ChengXianApp
//
//  Created by Aliang Ren on 2019/6/6.
//  Copyright © 2019 WuHua . All rights reserved.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface CustomerTextView : UITextView

/** 占位文字label */
@property (nonatomic, strong)UILabel *placeholderLabel;
@property(copy, nonatomic)NSString *placeHolder;
@property(strong, nonatomic)UIColor *placeHolderColor;
@property(assign, nonatomic)NSTextAlignment placeHolderTextAlignment;

@end

NS_ASSUME_NONNULL_END
