//
//  LWHUIQuicklyCreateTool.h
//  zhibo
//
//  Created by 李武华 on 2020/6/11.
//  Copyright © 2020 李武华. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <YYKit/YYKit.h>
//#import >
//不需要设置的参数 数字传 0 或者 对象传nil 即可
@interface LWHUIQuicklyCreateTool : NSObject

//UIView
+(nonnull UIView *)LWH_UI_View:(nullable UIColor *)color  andBorderColor:(nullable UIColor *)borderColor andCorner:(NSInteger)cornerRadiud;

//UILabel
+(nullable UILabel *)LWH_UI_Label:(nullable NSString *)text color:(nullable UIColor *)textcolor textAlignment:(NSTextAlignment)textAlignment textFont:(NSInteger)sizeNum preferredMaxLayoutWidth:(NSInteger)preferredMaxLayoutWidth forAxis:(UILayoutConstraintAxis)axis;
//创建NSMutableAttributedString
+(nonnull NSMutableAttributedString *)LWH_UI_AttributedWithMessage:(nonnull NSString *)message  textColor:(nullable UIColor *)textcolor  textFontSize:(CGFloat )fontSize  kern:(CGFloat)kern strokeWidthss:(CGFloat) strokeWidth lineSpacing:(CGFloat)lineSpacing textAlignment:(NSTextAlignment)textAlignment paragraphSpacing:(CGFloat) paragraphSpacing   textFontName:(nullable NSString *)fontName;
//删除线或者下划线
+(void)LWH_UI_AttributedStrikethrough:(nonnull NSMutableAttributedString *)messageAtt  Style:(YYTextLineStyle)style width:(CGFloat)width color:(nullable UIColor *)color isUnderLine:(BOOL)isUnderLine;
//加边框
+(void)LWH_UI_AttributedTextBorder:(nonnull NSMutableAttributedString *)messageAtt  strokeColor:(nullable UIColor *)strokeColor strokeWidth:(CGFloat)width lineStyle:(YYTextLineStyle)LineStyle cornerRadius:(CGFloat)cornerRadius insets:(UIEdgeInsets)insets;
//生成图片或者gif
+(nonnull NSMutableAttributedString *)LWH_UI_AttributedAddViewimageName:(nullable NSString *)imageName WithContentView:(nullable id)content
contentMode:(UIViewContentMode)contentMode
attachmentSize:(CGSize)attachmentSize
   alignToFont:(CGFloat )font
      alignment:(YYTextVerticalAlignment)alignment;
//UIButton
+(nonnull UIButton *)LWH_UI_Btn:(nullable NSString *)title Color:(nullable UIColor *)titleColor selecteColor:(nullable UIColor *)selecteColor Font:( NSInteger)sizeNum bgimage:(nullable UIImage *)image selecteImage:(nullable UIImage *)selecteImage target:(nullable id)target action:(nullable SEL)action;

//UIImageView

+(nonnull UIImageView *)LWH_UI_Img:(nullable NSString *)image andCorner:(NSInteger)cornerRadiud;


//UITextfield

+(nonnull UITextField *)LWH_UI_Field:(nullable NSString *)placeholderString font:(NSInteger)sizeNum textAlignment:(NSTextAlignment)textAlignment borderStyle:(UITextBorderStyle)borderStyle clearOnBeginEditing:(BOOL)clear secure:(BOOL)secure keyBoardStyle:(UIKeyboardType)keyBoardStyle;
+(nonnull YYLabel *)LWH_UI_YYLabel:(nullable NSString *)text color:(nullable UIColor *)textcolor textAlignment:(NSTextAlignment)textAlignment textFont:(NSInteger)sizeNum preferredMaxLayoutWidth:( NSInteger)preferredMaxLayoutWidth forAxis:(UILayoutConstraintAxis)axis;
@end

