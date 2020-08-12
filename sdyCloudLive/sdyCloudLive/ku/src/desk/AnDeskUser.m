
#import "AnDesk.h"

@interface AnDeskUser ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *name;
@property (nonatomic, retain) NSString *photo;
@property (nonatomic, retain) NSNumber *age;
@property (nonatomic, retain) NSString *gender;
@property (nonatomic, retain) NSString *phone;
@end

@implementation AnDeskUser

- (id)initWithId:(NSString *)id name:(NSString *)name photo:(NSString *)photo age:(NSNumber *)age gender:(NSString *)gender phone:(NSString *)phone
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.name = name;
        self.photo = photo;
        if (age && age >= 0) {
            self.age = age;
        } else {
            self.age = @(-1);
        }
        self.gender = gender;
        self.phone = phone;
    }
    return self;
}
@end