//
//  LWHUIQuicklyCreateTool.m
//  zhibo
//
//  Created by 李武华 on 2020/6/11.
//  Copyright © 2020 李武华. All rights reserved.
//

#import "LWHUIQuicklyCreateTool.h"

@implementation LWHUIQuicklyCreateTool

+(nonnull UIView *)LWH_UI_View:(nullable UIColor *)color  andBorderColor:(nullable UIColor *)borderColor andCorner:(NSInteger)cornerRadiud
{
    UIView *backViews = [[UIView alloc]init];
        backViews.backgroundColor = color;
    if (cornerRadiud) {
        backViews.layer.cornerRadius = cornerRadiud;
    }
    if (borderColor) {
        backViews.layer.borderColor = borderColor.CGColor;
        backViews.layer.borderWidth = 1;
    }
    return backViews;
}


+(nonnull NSMutableAttributedString *)LWH_UI_AttributedWithMessage:(nonnull NSString *)message  textColor:(nullable UIColor *)textcolor  textFontSize:(CGFloat )fontSize  kern:(CGFloat)kern strokeWidthss:(CGFloat) strokeWidth lineSpacing:(CGFloat)lineSpacing textAlignment:(NSTextAlignment)textAlignment paragraphSpacing:(CGFloat) paragraphSpacing   textFontName:(nullable NSString *)fontName
{
    NSMutableAttributedString *messageAtt = [[NSMutableAttributedString alloc]initWithString:message];
    if (fontSize) {
        messageAtt.font = [UIFont systemFontOfSize:fontSize];
        if (fontName != nil) {
            messageAtt.font = [UIFont fontWithName:fontName size:fontSize];
        }
    }
    if (textcolor) {
        messageAtt.color = textcolor;
    }
    if (lineSpacing) {
        messageAtt.lineSpacing = lineSpacing;
    }
    if (kern) {
        messageAtt.kern = @(kern);
    }
    if (textAlignment) {
        messageAtt.alignment = textAlignment;
    }
    if (paragraphSpacing) {
        messageAtt.paragraphSpacing = paragraphSpacing;
    }
    if (strokeWidth) {
        messageAtt.strokeWidth = @(strokeWidth);
    }
    return messageAtt;
}
//加删除线或者下划线
+(void)LWH_UI_AttributedStrikethrough:(nonnull NSMutableAttributedString *)messageAtt  Style:(YYTextLineStyle)style width:(CGFloat)width color:(nullable UIColor *)color isUnderLine:(BOOL)isUnderLine
{
    YYTextDecoration *decoration = [YYTextDecoration decorationWithStyle:style
    width:@(width)
    color:color];
    if (isUnderLine) {
        messageAtt.textUnderline = decoration;
    }else{
        messageAtt.textStrikethrough = decoration;
    }
}
//加边框
+(void)LWH_UI_AttributedTextBorder:(nonnull NSMutableAttributedString *)messageAtt  strokeColor:(nullable UIColor *)strokeColor strokeWidth:(CGFloat)width lineStyle:(YYTextLineStyle)LineStyle cornerRadius:(CGFloat)cornerRadius insets:(UIEdgeInsets)insets
{
    YYTextBorder *border = [YYTextBorder new];
    if (strokeColor) {
        border.strokeColor = strokeColor;
        border.fillColor = strokeColor;
    }
    if (width) {
        border.strokeWidth = width;
    }
    if (LineStyle) {
        border.lineStyle = LineStyle;
    }
    if (cornerRadius) {
        border.cornerRadius = cornerRadius;
    }
    border.insets = insets;
    messageAtt.textBorder = border;
}
//加图片或者gif
+(nonnull NSMutableAttributedString *)LWH_UI_AttributedAddViewimageName:(nullable NSString *)imageName WithContentView:(nullable id)content
contentMode:(UIViewContentMode)contentMode
attachmentSize:(CGSize)attachmentSize
   alignToFont:(CGFloat )font
      alignment:(YYTextVerticalAlignment)alignment
{
    if (!content) {
        UIImage *image = [UIImage imageNamed:imageName];
        UIImageView *imageView = [[UIImageView alloc] initWithImage:image];
        imageView.frame = CGRectMake(0, 0, attachmentSize.width, attachmentSize.height);
        NSMutableAttributedString *attachText = [NSMutableAttributedString attachmentStringWithContent:imageView contentMode:contentMode attachmentSize:attachmentSize alignToFont:[UIFont systemFontOfSize:font] alignment:alignment];
        return attachText;
    }else{
        NSMutableAttributedString *attachText = [NSMutableAttributedString attachmentStringWithContent:content contentMode:contentMode attachmentSize:attachmentSize alignToFont:[UIFont systemFontOfSize:font] alignment:alignment];
        return attachText;
    }
}

//baselineOffset                       // 基线偏移量,取值为 NSNumber （float）,正值上偏，负值下偏
//CGFloat lineSpacing;                 // 字体的行间距
//CGFloat paragraphSpacing;            // 段与段之间的间距
//NSTextAlignment alignment;           // (两端对齐的)文本对齐方式(左,中,右,两端对齐,自然)
//CGFloat firstLineHeadIndent;         // 首行缩进
//CGFloat headIndent;                  // 整体缩进(首行除外)
//CGFloat tailIndent;                  // 尾部缩进
//NSLineBreakMode lineBreakMode;       // 结尾部分的内容以……方式省略
//CGFloat minimumLineHeight;           // 最低行高
//CGFloat maximumLineHeight;           // 最大行高
//NSWritingDirection baseWritingDirection; // 书写方向
//CGFloat lineHeightMultiple;          // 行间距多少倍
//CGFloat paragraphSpacingBefore;      // 段首行空白空
//float hyphenationFactor;             // 连字属性 在iOS，唯一支持的值分别为0和1

// NSFontAttributeName                设置字体属性，默认值：字体：Helvetica(Neue) 字号：12
// NSForegroundColorAttributeNam      设置字体颜色，取值为 UIColor对象，默认值为黑色
// NSBackgroundColorAttributeName     设置字体所在区域背景颜色，取值为 UIColor对象，默认值为nil, 透明色
// NSLigatureAttributeName            设置连体属性，取值为NSNumber 对象(整数)，0 表示没有连体字符，1 表示使用默认的连体字符
// NSKernAttributeName                设定字符间距，取值为 NSNumber 对象（整数），正值间距加宽，负值间距变窄
// NSStrikethroughStyleAttributeName  设置删除线，取值为 NSNumber 对象（整数）
// NSStrikethroughColorAttributeName  设置删除线颜色，取值为 UIColor 对象，默认值为黑色
// NSUnderlineStyleAttributeName      设置下划线，取值为 NSNumber 对象（整数），枚举常量 NSUnderlineStyle中的值，与删除线类似
// NSUnderlineColorAttributeName      设置下划线颜色，取值为 UIColor 对象，默认值为黑色
// NSStrokeWidthAttributeName         设置笔画宽度，取值为 NSNumber 对象（整数），负值填充效果，正值中空效果
// NSStrokeColorAttributeName         填充部分颜色，不是字体颜色，取值为 UIColor 对象
// NSShadowAttributeName              设置阴影属性，取值为 NSShadow 对象
// NSTextEffectAttributeName          设置文本特殊效果，取值为 NSString 对象，目前只有图版印刷效果可用：
// NSObliquenessAttributeName         设置字形倾斜度，取值为 NSNumber （float）,正值右倾，负值左倾
// NSExpansionAttributeName           设置文本横向拉伸属性，取值为 NSNumber （float）,正值横向拉伸文本，负值横向压缩文本
// NSWritingDirectionAttributeName    设置文字书写方向，从左向右书写或者从右向左书写
// NSVerticalGlyphFormAttributeName   设置文字排版方向，取值为 NSNumber 对象(整数)，0 表示横排文本，1 表示竖排文本
// NSLinkAttributeName                设置链接属性，点击后调用浏览器打开指定URL地址
// NSAttachmentAttributeName          设置文本附件,取值为NSTextAttachment对象,常用于文字图片混排
// NSParagraphStyleAttributeName      设置文本段落排版格式，取值为 NSParagraphStyle 对象
+(nonnull YYLabel *)LWH_UI_YYLabel:(nullable NSString *)text color:(nullable UIColor *)textcolor textAlignment:(NSTextAlignment)textAlignment textFont:(NSInteger)sizeNum preferredMaxLayoutWidth:( NSInteger)preferredMaxLayoutWidth forAxis:(UILayoutConstraintAxis)axis
{
    YYLabel * label =[[YYLabel alloc]init];
    if (text) {
        label.text=text;
    }
    if (textcolor) {
        label.textColor=textcolor;
    }
    if (textAlignment) {
        label.textAlignment=textAlignment;
    }
    if (sizeNum) {
        label.font=[UIFont systemFontOfSize:sizeNum weight:-0.3];;
    }
    label.preferredMaxLayoutWidth=preferredMaxLayoutWidth;
    [label setContentHuggingPriority:(UILayoutPriorityRequired) forAxis:axis];
    label.numberOfLines = 0;
    return label;
}
+(nonnull UIButton *)LWH_UI_Btn:(nullable NSString *)title Color:(nullable UIColor *)titleColor selecteColor:(nullable UIColor *)selecteColor Font:( NSInteger)sizeNum bgimage:(nullable UIImage *)image selecteImage:(nullable UIImage *)selecteImage target:(nullable id)target action:(nullable SEL)action

{
    UIButton *btn =[UIButton buttonWithType:UIButtonTypeCustom];
    if (title) {
        [btn setTitle:title forState:UIControlStateNormal];
    }
    if (titleColor) {
        [btn setTitleColor:titleColor forState:UIControlStateNormal];
    }
    if (selecteColor) {
        [btn setTitleColor:selecteColor forState:UIControlStateSelected];
    }
    if (sizeNum) {
        btn.titleLabel.font =[UIFont systemFontOfSize:sizeNum];
    }
    if (image) {
        [btn setImage:image forState:UIControlStateNormal];
    }
    if (selecteImage) {
        [btn setImage:selecteImage forState:UIControlStateSelected];
    }
    if (target && action) {
        [btn addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    }
    return btn;
}

+(nonnull UIImageView *)LWH_UI_Img:(nullable NSString *)image andCorner:(NSInteger)cornerRadiud
{
    UIImageView *imageName =[[UIImageView alloc]init];
    if (image) {
        [imageName setImage:[UIImage imageNamed:image]];
    }
    if (cornerRadiud != 0) {
        imageName.layer.cornerRadius = cornerRadiud;
        imageName.layer.masksToBounds = YES;
    }
    return imageName;
}

+(nonnull UITextField *)LWH_UI_Field:(nullable NSString *)placeholderString font:(NSInteger)sizeNum textAlignment:(NSTextAlignment)textAlignment borderStyle:(UITextBorderStyle)borderStyle clearOnBeginEditing:(BOOL)clear secure:(BOOL)secure keyBoardStyle:(UIKeyboardType)keyBoardStyle
{
    UITextField * textField =[[UITextField alloc]init];
    if (placeholderString) {
        textField.placeholder =placeholderString;
    }
    textField.font =[UIFont boldSystemFontOfSize:sizeNum];
    textField.textAlignment =textAlignment;
    textField.borderStyle = borderStyle;
    textField.clearsOnBeginEditing = clear;
    textField.secureTextEntry = secure;
    textField.keyboardType = keyBoardStyle;
    return textField;

}
+(nullable UILabel *)LWH_UI_Label:(nullable NSString *)text color:(nullable UIColor *)textcolor textAlignment:(NSTextAlignment)textAlignment textFont:(NSInteger)sizeNum preferredMaxLayoutWidth:(NSInteger)preferredMaxLayoutWidth forAxis:(UILayoutConstraintAxis)axis
{
    UILabel * label =[[UILabel alloc]init];
    if (text) {
        label.text=text;
    }
    if (textcolor) {
        label.textColor =textcolor;
    }
    label.font=[UIFont systemFontOfSize:sizeNum];
    label.textAlignment =textAlignment;
    label.numberOfLines =0;
    label.preferredMaxLayoutWidth = preferredMaxLayoutWidth;
    [label setContentHuggingPriority:(UILayoutPriorityRequired) forAxis:axis];
    return label;
}

@end
