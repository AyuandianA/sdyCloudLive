#import <Foundation/Foundation.h>
#import "AnPushOAuthCore.h"

@interface AnPushURLConnection : NSURLConnection

@property AnPushMethod method;
@property (nonatomic, strong) NSHTTPURLResponse *response;

@end
