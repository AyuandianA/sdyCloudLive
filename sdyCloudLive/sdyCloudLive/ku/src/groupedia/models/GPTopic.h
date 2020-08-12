@interface GPTopic : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *name;
@property int members;

- (id)initWithId:(NSString *)id name:(NSString *)name members:(int)members;
@end