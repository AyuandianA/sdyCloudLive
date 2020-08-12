#import "AnSocialFile.h"


@interface AnSocialFile()

@property (nonatomic, retain) NSString *name;
@property (nonatomic, retain) NSData *data;

@end

@implementation AnSocialFile

@synthesize name = _name;
@synthesize data = _data;

+ (AnSocialFile *)createWithFileName:(NSString *)name data:(NSData *)data
{
    if(!name)
    {
        return nil;
    }
    if(!data)
    {
        return nil;
    }
    
    AnSocialFile *file = [[AnSocialFile alloc] init];
    file.name = name;
    file.data = data;
    return file;
}

@end