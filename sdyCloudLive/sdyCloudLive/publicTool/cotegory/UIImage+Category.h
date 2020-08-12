//
//  UIImage+Category.h
//  VarietyDelivery
//
//  Created by zsy on 2016/12/2.
//  Copyright © 2016年 zsy. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface UIImage (Category)

//将绘制的内容生成图片
+ (UIImage *)vd_imageWithSize:(CGSize)size drawBlock:(void (^)(CGContextRef context))drawBlock;
//单一颜色图片
+ (UIImage *)createImageWithColor:(UIColor *)color;
//固定渐变色的图片
+ (UIImage *)convertViewToImage;
//渐变色图片
+ (UIImage *)convertViewToImagearray:(NSArray *)colors andLocations:(NSArray *)locations startPoint:(CGPoint)startPoint endPoint:(CGPoint)endPoint;
//压缩图片
+ (NSData *)reSizeImageData:(UIImage *)sourceImage maxImageSize:(CGFloat)maxImageSize maxSizeWithKB:(CGFloat)maxSize;

//暂时不懂
+ (UIImage *)vd_maskRoundCornerRadiusImageWithColor:(UIColor *)color cornerRadii:(CGSize)cornerRadii size:(CGSize)size corners:(UIRectCorner)corners borderColor:(UIColor *)borderColor borderWidth:(CGFloat)borderWidth;
@end
