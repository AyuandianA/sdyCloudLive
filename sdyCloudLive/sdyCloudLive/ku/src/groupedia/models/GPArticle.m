#import "AnGroupedia.h"
#import "GPUser.h"

@interface GPArticle ()
@property (nonatomic, retain) NSString *id;
@property (nonatomic, retain) NSString *columnId;
@property (nonatomic, retain) NSString *columnName;
@property (nonatomic, retain) NSString *columnDescription;
@property (nonatomic, retain) NSString *columnPhotoUrl;
@property (nonatomic, retain) NSString *title;
@property (nonatomic, retain) NSString *descript;
@property (nonatomic, retain) NSString *url;
@property (nonatomic, retain) NSString *content;
@property (nonatomic, retain) NSString *photoUrl;
@property (nonatomic, retain) NSNumber *createdAt;
@property (nonatomic, retain) GPUser *user;

@end

@implementation GPArticle

- (id)initWithId:(NSString *)id columnId:(NSString *)columnId columnName:(NSString *)columnName columnDescription:(NSString *)columnDescription columnPhotoUrl:(NSString *)columnPhotoUrl title:(NSString *)title descript:(NSString *)descript url:(NSString *)url content:(NSString *)content photoUrl:(NSString *)photoUrl isLike:(Boolean)isLike createdAt:(NSNumber *)createdAt readCount:(int)readCount likeCount:(int)likeCount user:(GPUser *)user
{
    self = [super init];
    if(self)
    {
        self.id = id;
        self.columnId = columnId;
        self.columnName = columnName;
        self.columnDescription = columnDescription;
        self.columnPhotoUrl = columnPhotoUrl;
        self.title = title;
        self.descript = descript;
        self.url = url;
        self.content = content;
        self.photoUrl = photoUrl;
        self.createdAt = createdAt;
        self.user = user;
        self.isLike = isLike;
        self.readCount = readCount;
        self.likeCount = likeCount;
    }
    return self;
}
@end