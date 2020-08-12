#import "AnDesk.h"

@interface AnDeskMessage : NSObject {

}

@property (readonly, nonatomic, assign) AnDeskMessageType type;
@property (readonly, nonatomic, retain) NSString *msgId;
@property (readonly, nonatomic, retain) NSString *groupId;
@property (readonly, nonatomic, retain) NSString *accountId;
@property (readonly, nonatomic, retain) NSString *accountName;
@property (readonly, nonatomic, retain) NSString *message;
@property (readonly, nonatomic, retain) NSData *content;
@property (readonly, nonatomic, retain) NSNumber *timestamp;

- (id)initWithType:(AnDeskMessageType)type msgId:(NSString*)msgId groupId:(NSString*)groupId accountId:(NSString*)accountId accountName:(NSString*)accountName message:(NSString*)message content:(NSData*)content timestamp:(NSNumber*)timestamp;
@end