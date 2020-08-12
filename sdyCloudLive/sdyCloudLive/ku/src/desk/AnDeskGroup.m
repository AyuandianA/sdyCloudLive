
#import "AnDesk.h"

@interface AnDeskGroup ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *name;
@property (nonatomic, retain) NSArray *tags;
@end

@implementation AnDeskGroup

- (id)initWithId:(NSString *)id name:(NSString*)name tags:(NSArray*)tags
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.name = name;
        self.tags = tags;
    }
    return self;
}
@end