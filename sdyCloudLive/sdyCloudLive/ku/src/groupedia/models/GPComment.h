@interface GPComment : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *content;
@property (readonly, nonatomic, retain) NSNumber *createdAt;
@property (readonly, nonatomic, retain) GPUser *user;

- (id)initWithId:(NSString *)id content:(NSString *)content createdAt:(NSNumber *)createdAt user:(GPUser *)user;
@end