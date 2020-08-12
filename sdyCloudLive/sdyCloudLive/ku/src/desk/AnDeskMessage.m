
#import "AnDeskMessage.h"

@interface AnDeskMessage ()
@property (nonatomic, assign) AnDeskMessageType type;
@property (nonatomic, retain) NSString *msgId;
@property (nonatomic, retain) NSString *groupId;
@property (nonatomic, retain) NSString *accountId;
@property (nonatomic, retain) NSString *accountName;
@property (nonatomic, retain) NSString *message;
@property (nonatomic, retain) NSData *content;
@property (nonatomic, retain) NSNumber *timestamp;
@end

@implementation AnDeskMessage

- (id)initWithType:(AnDeskMessageType)type msgId:(NSString*)msgId groupId:(NSString*)groupId accountId:(NSString*)accountId accountName:(NSString*)accountName message:(NSString*)message content:(NSData*)content timestamp:(NSNumber*)timestamp
{
    self = [super init];
    if(self)
    {
        self.type = type;
        self.msgId = msgId;
        self.groupId = groupId;
        self.accountId = accountId;
        self.accountName = accountName;
        self.message = message;
        self.content = content;
        self.timestamp = timestamp;
    }
    return self;
}
@end