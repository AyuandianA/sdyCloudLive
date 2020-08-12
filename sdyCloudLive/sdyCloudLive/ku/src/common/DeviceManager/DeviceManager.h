#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

@interface ANDeviceManager : NSObject

+ (ANDeviceManager *)shared;
+ (ANDeviceManager *)initializeWithAppKey:(NSString *)appKey secure:(BOOL)secure;
- (NSString *)getDeviceId;
- (void)reportLocation;

@end