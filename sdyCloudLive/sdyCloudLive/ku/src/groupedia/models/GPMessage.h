#import "AnGroupedia.h"
#import "GPUser.h"

@interface GPMessage : NSObject {
    
}

@property (readonly, nonatomic, assign) AnGroupediaMessageType type;
@property (readonly, nonatomic, retain) NSString *msgId;
@property (readonly, nonatomic, retain) NSString *topicId;
@property (readonly, nonatomic, retain) GPUser *user;
@property (readonly, nonatomic, retain) NSString *message;
@property (readonly, nonatomic, retain) NSData *data;
@property (readonly, nonatomic, retain) NSNumber *timestamp;

- (id)initWithType:(AnGroupediaMessageType)type msgId:(NSString*)msgId topicId:(NSString*)topicId user:(GPUser*)user message:(NSString*)message data:(NSData*)data timestamp:(NSNumber*)timestamp;
@end