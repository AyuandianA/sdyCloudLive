#import "AnGroupedia.h"
#import "GPUser.h"

@interface GPComment ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *content;
@property (nonatomic, retain) NSNumber *createdAt;
@property (nonatomic, retain) GPUser *user;

@end

@implementation GPComment

- (id)initWithId:(NSString *)id content:(NSString *)content createdAt:(NSNumber *)createdAt user:(GPUser *)user
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.content = content;
        self.createdAt = createdAt;
        self.user = user;
    }
    return self;
}
@end