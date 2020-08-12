#import "AnDeviceManager.h"
#import "ArrownockConstants.h"

@implementation AnDeviceManager

+ (void) setHost:(NSString *)host
{
    ARROWNOCK_DEVICE_HOST = host;
}

@end