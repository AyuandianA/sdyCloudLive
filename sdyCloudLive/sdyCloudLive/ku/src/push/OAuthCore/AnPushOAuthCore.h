#import <Foundation/Foundation.h>

typedef enum {
    AnPushMethodRegisterOverwrite = 1,
    AnPushMethodRegisterAppend = 2,
    AnPushMethodUnregisterAll = 3,
    AnPushMethodUnregisterSome = 4,
    AnPushMethodSetMute = 5,
    AnPushMethodSetMutePeriod = 6,
    AnPushMethodClearMute = 7,
    AnPushMethodSetSilent = 8,
    AnPushMethodClearSilent = 9,
    AnPushMethodSetBadge = 10
} AnPushMethod;

extern NSString *AnPushOAuthorizationSignature(AnPushMethod method, NSDictionary *dict);