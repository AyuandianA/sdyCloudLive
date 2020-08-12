
#import "AnIMMessage.h"

@interface AnIMMessage ()
@property (nonatomic, assign) AnIMMessageType type;
@property (nonatomic, retain) NSString *msgId;
@property (nonatomic, retain) NSString *topicId;
@property (nonatomic, retain) NSString *message;
@property (nonatomic, retain) NSData *content;
@property (nonatomic, copy) NSString *fileType;
@property (nonatomic, copy) NSString *from;
@property (nonatomic, copy) NSString *to;
@property (nonatomic, retain) NSDictionary *customData;
@property (nonatomic, retain) NSNumber *timestamp;
@end

@implementation AnIMMessage

- (id)initWithType:(AnIMMessageType)type msgId:(NSString*)msgId topicId:(NSString*)topicId message:(NSString*)message content:(NSData*)content fileType:(NSString*)fileType from:(NSString*)from customData:(NSDictionary*)customData timestamp:(NSNumber*)timestamp
{
    self = [super init];
    if(self)
    {
        self.type = type;
        self.msgId = msgId;
        self.topicId = topicId;
        self.message = message;
        self.content = content;
        self.fileType = fileType;
        self.from = from;
        self.customData = customData;
        self.timestamp = timestamp;
    }
    return self;
}

- (id)initWithType:(AnIMMessageType)type msgId:(NSString*)msgId topicId:(NSString*)topicId message:(NSString*)message content:(NSData*)content fileType:(NSString*)fileType from:(NSString*)from to:(NSString*)to customData:(NSDictionary*)customData timestamp:(NSNumber*)timestamp
{
    self = [super init];
    if(self)
    {
        self.type = type;
        self.msgId = msgId;
        self.topicId = topicId;
        self.message = message;
        self.content = content;
        self.fileType = fileType;
        self.from = from;
        self.to = to;
        self.customData = customData;
        self.timestamp = timestamp;
    }
    return self;
}
@end