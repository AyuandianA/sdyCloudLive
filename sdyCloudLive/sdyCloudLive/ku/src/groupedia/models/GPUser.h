@interface GPUser : NSObject {
    
}

@property (readonly, nonatomic, retain) NSString *id;
@property (readonly, nonatomic, retain) NSString *imId;
@property (readonly, nonatomic, retain) NSString *name;
@property (readonly, nonatomic, retain) NSString *avatar;
@property (readonly, nonatomic, retain) NSString *extId;
@property (readonly, nonatomic, retain) NSDictionary *fields;

- (id)initWithId:(NSString *)id imId:(NSString *)imId name:(NSString *)name avatar:(NSString *)avatar extId:(NSString *)extId fields:(NSDictionary *)fields;
@end