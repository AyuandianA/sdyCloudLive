#import <Foundation/Foundation.h>
#import "ArrownockException.h"

@protocol AnGroupediaMessageDelegate <NSObject>
@required
- (void) didReceiveMessage:(NSString *)message customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp;
- (void) didReceiveBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp;
@end