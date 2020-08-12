#import "AnGroupedia.h"

@interface GPTopic ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *name;

@end

@implementation GPTopic

- (id)initWithId:(NSString *)id name:(NSString *)name members:(int)members
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.members = members;
        self.name = name;
    }
    return self;
}
@end