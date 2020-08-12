#import "GPUser.h"
@interface GPArticle : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *columnId;
@property (readonly, nonatomic, retain) NSString *columnName;
@property (readonly, nonatomic, retain) NSString *columnDescription;
@property (readonly, nonatomic, retain) NSString *columnPhotoUrl;
@property (readonly, nonatomic, retain) NSString *title;
@property (readonly, nonatomic, retain) NSString *descript;
@property (readonly, nonatomic, retain) NSString *url;
@property (readonly, nonatomic, retain) NSString *content;
@property (readonly, nonatomic, retain) NSString *photoUrl;
@property Boolean isLike;
@property (readonly, nonatomic, retain) NSNumber *createdAt;
@property int readCount;
@property int likeCount;
@property (readonly, nonatomic, retain) GPUser *user;



- (id)initWithId:(NSString *)id columnId:(NSString *)columnId columnName:(NSString *)columnName columnDescription:(NSString *)columnDescription columnPhotoUrl:(NSString *)columnPhotoUrl title:(NSString *)title descript:(NSString *)descript url:(NSString *)url content:(NSString *)content photoUrl:(NSString *)photoUrl isLike:(Boolean)isLike createdAt:(NSNumber *)createdAt readCount:(int)readCount likeCount:(int)likeCount user:(GPUser *)user;
@end