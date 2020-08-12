#import <Foundation/Foundation.h>
#import "ArrownockException.h"
#import "AnGroupediaProtocols.h"
#import "AnIM.h"
#import "GPUser.h"
#import "GPArticle.h"
#import "GPTopic.h"
#import "GPChannel.h"
#import "GPComment.h"
typedef enum {
    AnGroupediaMessageText,
    AnGroupediaMessageImage,
    AnGroupediaMessageAudio
} AnGroupediaMessageType;
#import "GPMessage.h"

@protocol AnGroupediaDelegate <NSObject>
@required

- (void)AnGroupedia:(AnGroupedia *)AnGroupedia didReceiveMessage:(NSString *)message topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp user:(GPUser *)user;
- (void)AnGroupedia:(AnGroupedia *)AnGroupedia didReceiveImage:(NSData *)data topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp user:(GPUser *)user;
- (void)AnGroupedia:(AnGroupedia *)AnGroupedia didReceiveAudio:(NSData *)data topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp user:(GPUser *)user;

@end

@interface AnGroupedia : NSObject
- (AnGroupedia *)initWithAppKey:(NSString *)appKey anIM:(AnIM *)anIM delegate:(id <AnGroupediaDelegate>)delegate;
- (AnGroupedia *)initWithAppKey:(NSString *)appKey;
- (void)setSecure:(BOOL)secure;

- (void)initUser:(NSString *)extId name:(NSString *)name avatar:(NSString *)avatar success:(void (^)(GPUser *user))success failure:(void (^)(ArrownockException *exception))failure;
- (void)linkUser:(NSString *)userId success:(void (^)(GPUser *user))success failure:(void (^)(ArrownockException *exception))failure;
- (void)updateUser:(NSString *)userId name:(NSString *)name avatar:(NSString *)avatar success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure;
- (void)getChannels:(void (^)(NSArray *channels))success failure:(void (^)(ArrownockException *exception))failure;
- (void)getArticles:(NSString *)channelId page:(int)page limit:(int)limit success:(void (^)(NSArray *articles))success failure:(void (^)(ArrownockException *exception))failure;
- (void)searchArticles:(NSString *)content page:(int)page limit:(int)limit success:(void (^)(NSArray *articles))success failure:(void (^)(ArrownockException *exception))failure;
- (void)getArticleByArticleId:(NSString *)articleId userId:(NSString *)userId success:(void (^)(GPArticle *article))success failure:(void (^)(ArrownockException *exception))failure;
- (void)createLike:(NSString *)articleId userId:(NSString *)userId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure;
- (void)cancelLike:(NSString *)articleId userId:(NSString *)userId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure;
- (void)getComments:(NSString *)articleId page:(int)page limit:(int)limit success:(void (^)(NSArray *comments))success failure:(void (^)(ArrownockException *exception))failure;
- (void)createComment:(NSString *)articleId userId:(NSString *)userId content:(NSString *)content success:(void (^)(GPComment *comment))success failure:(void (^)(ArrownockException *exception))failure;
- (void)removeComment:(NSString *)articleId commentId:(NSString *)commentId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure;
- (void)joinTopic:(NSString *)userImId topicId:(NSString *)topicId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure;
- (void)quitTopic:(NSString *)userImId topicId:(NSString *)topicId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure;
- (void)getTopic:(NSString *)userImId columnId:(NSString *)columnId success:(void (^)(GPTopic *topic, bool isJoin, NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure;

- (NSString *)sendMessage:(NSString *)message topicId:(NSString *)topicId user:(GPUser *)user;
- (NSString *)sendImage:(NSData *)data topicId:(NSString *)topicId user:(GPUser *)user;
- (NSString *)sendAudio:(NSData *)data topicId:(NSString *)topicId user:(GPUser *)user;

- (void)getTopicOfflineHistory:(NSString *)userImId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure;
- (void)getTopicHistory:(NSString *)userImId topicId:(NSString *)topicId limit:(int)limit timestamp:(NSNumber *)timestamp success:(void (^)(NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure;

@end

