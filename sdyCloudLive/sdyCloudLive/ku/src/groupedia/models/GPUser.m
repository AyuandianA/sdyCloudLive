#import "AnGroupedia.h"

@interface GPUser ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *imId;
@property (nonatomic, retain) NSString *name;
@property (nonatomic, retain) NSString *avatar;
@property (nonatomic, retain) NSString *extId;
@property (nonatomic, retain) NSDictionary *fields;

@end

@implementation GPUser

- (id)initWithId:(NSString *)id imId:(NSString *)imId name:(NSString *)name avatar:(NSString *)avatar extId:(NSString *)extId fields:(NSDictionary *)fields
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.imId = imId;
        self.name = name;
        self.avatar = avatar;
        self.extId = extId;
        self.fields = fields;
    }
    return self;
}
@end