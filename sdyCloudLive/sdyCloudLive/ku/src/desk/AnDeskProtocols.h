#import <Foundation/Foundation.h>
#import "ArrownockException.h"

@protocol AnDeskMessageDelegate <NSObject>
@required
- (void) messageSent:(NSString *)messageId at:(NSNumber *)timestamp;
- (void) sendReturnedException:(ArrownockException *)exception messageId:(NSString *)messageId;
- (void) didReceiveMessage:(NSString *)message customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp;
- (void) didReceiveBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp;
- (void) sessionClosed:(NSString *)groupId sessionId:(NSString *)sessionId at:(NSNumber *)timestamp;
- (void) accountAddedToSession:(NSString *)sessionId groupId:(NSString *)groupId accountId:(NSString *)accountId accountName:(NSString *)accountName at:(NSNumber *)timestamp;
@end