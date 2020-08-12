#import <Foundation/Foundation.h>

@interface ANBase64Wrapper: NSObject

+ (NSData *)dataWithBase64EncodedString:(NSString *)string;
+ (NSString *) base64EncodedString:(NSData *)data;
@end