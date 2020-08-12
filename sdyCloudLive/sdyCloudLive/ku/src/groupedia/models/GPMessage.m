#import "GPMessage.h"
#import "AnGroupedia.h"


@interface GPMessage ()
@property (nonatomic, assign) AnGroupediaMessageType type;
@property (nonatomic, retain) NSString *msgId;
@property (nonatomic, retain) NSString *topicId;
@property (nonatomic, retain) GPUser *user;
@property (nonatomic, retain) NSString *message;
@property (nonatomic, retain) NSData *data;
@property (nonatomic, retain) NSNumber *timestamp;

@end

@implementation GPMessage

- (id)initWithType:(AnGroupediaMessageType)type msgId:(NSString*)msgId topicId:(NSString*)topicId user:(GPUser*)user message:(NSString*)message data:(NSData*)data timestamp:(NSNumber*)timestamp
{
    self = [super init];
    if(self)
    {
        self.type = type;
        self.timestamp = timestamp;
        self.msgId = msgId;
        self.topicId = topicId;
        self.user = user;
        self.message = message;
        self.data = data;
    }
    return self;
}
@end