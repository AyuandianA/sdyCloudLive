#import "ANBase64Wrapper.h"

@implementation ANBase64Wrapper

+ (NSData *)dataWithBase64EncodedString:(NSString *)string
{
    if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_6_1)
    {
        return [[NSData alloc] initWithBase64EncodedString:string options:0];   // iOS 7+
    }
    else
    {
        return [[NSData alloc] initWithBase64Encoding:string]; // pre iOS 7
    }
}

+ (NSString *) base64EncodedString:(NSData *)data
{
    if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_6_1)
    {
        return [data base64EncodedStringWithOptions:0];   // iOS 7+
    }
    else
    {
        return [data base64Encoding]; // pre iOS 7
    }
}

@end