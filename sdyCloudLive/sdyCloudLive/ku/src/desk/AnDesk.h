#import <Foundation/Foundation.h>
#import "ArrownockException.h"
#import "AnDeskProtocols.h"
#import "AnIM.h"

typedef enum {
    AnDeskMessageText,
    AnDeskMessageImage,
    AnDeskMessageAudio
} AnDeskMessageType;

@protocol AnDeskDelegate <NSObject>
@required

- (void)anDesk:(AnDesk *)anDesk messageSent:(NSString *)messageId at:(NSNumber *)timestamp;
- (void)anDesk:(AnDesk *)anDesk sendReturnedException:(ArrownockException *)exception messageId:(NSString *)messageId;
- (void)anDesk:(AnDesk *)anDesk didReceiveMessage:(NSString *)message accountId:(NSString *)accountId accountName:(NSString *)accountName groupId:(NSString *)groupId messageId:(NSString *)messageId at:(NSNumber *)timestamp;
- (void)anDesk:(AnDesk *)anDesk didReceiveImage:(NSData *)data accountId:(NSString *)accountId accountName:(NSString *)accountName groupId:(NSString *)groupId messageId:(NSString *)messageId at:(NSNumber *)timestamp;
- (void)anDesk:(AnDesk *)anDesk sessionClosed:(NSString *)groupId sessionId:(NSString *)sessionId at:(NSNumber *)timestamp;
- (void)anDesk:(AnDesk *)anDesk accountAddedToSession:(NSString *)sessionId groupId:(NSString *)groupId accountId:(NSString *)accountId accountName:(NSString *)accountName at:(NSNumber *)timestamp;

@end

@interface AnDeskGroup : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *name;
@property (readonly, nonatomic, retain) NSArray *tags;

- (id)initWithId:(NSString *)id name:(NSString*)name tags:(NSArray*)tags;
@end

@interface AnDeskUser : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *name;
@property (readonly, nonatomic, retain) NSString *photo;
@property (readonly, nonatomic, retain) NSNumber *age;
@property (readonly, nonatomic, retain) NSString *gender;
@property (readonly, nonatomic, retain) NSString *phone;

- (id)initWithId:(NSString *)id name:(NSString *)name photo:(NSString *)photo age:(NSNumber *)age gender:(NSString *)gender phone:(NSString *)phone;
@end

@interface AnDesk : NSObject
- (AnDesk *)initWithAppKey:(AnDeskUser *)user appKey:(NSString *)appKey anIM:(AnIM *)anIM delegate:(id <AnDeskDelegate>)delegate;

- (void)getGroups:(void (^)(NSMutableArray *groups))success failure:(void (^)(ArrownockException *exception))failure;
- (NSString *)getCurrentSessionId:(NSString *)groupId clientId:(NSString *)clientId;
- (void)createSession:(NSString *)groupId clientId:(NSString *)clientId success:(void (^)(NSString *sessionId, NSString *accountId, NSString *accountName))success failure:(void (^)(ArrownockException *exception))failure;
- (void)getOfflineMessage:(NSString *)clientId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure;
- (void)closeSession:(NSString *)sessionId;

- (NSString *)sendMessage:(NSString *)message sessionId:(NSString *)sessionId;
- (NSString *)sendImage:(NSData *)data sessionId:(NSString *)sessionId;
- (NSString *)sendImage:(NSData *)data sessionId:(NSString *)sessionId originalImageUrl:(NSString *)originalImageUrl;
- (NSString *)sendAudio:(NSData *)data sessionId:(NSString *)sessionId;
@end

