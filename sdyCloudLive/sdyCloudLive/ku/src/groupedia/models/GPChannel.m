#import "AnGroupedia.h"

@interface GPChannel ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *name;

@end

@implementation GPChannel

- (id)initWithId:(NSString *)id name:(NSString *)name
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.name = name;
    }
    return self;
}
@end