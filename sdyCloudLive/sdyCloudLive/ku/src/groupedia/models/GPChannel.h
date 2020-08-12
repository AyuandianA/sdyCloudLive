@interface GPChannel : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *name;

- (id)initWithId:(NSString *)id name:(NSString *)name;
@end