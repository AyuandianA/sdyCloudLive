#import <Foundation/Foundation.h>
#import "AnGroupedia.h"
#import "AnIM.h"
#import "AnGroupediaHTTPClient.h"
#import <UIKit/UIKit.h>
#import "AnIMUtils.h"
#import "ArrownockExceptionUtils.h"
#import "ArrownockConstants.h"

@interface AnGroupedia () <AnGroupediaMessageDelegate>
@property id <AnGroupediaDelegate> delegate;
@end

@implementation AnGroupedia {
    id <AnGroupediaDelegate> _delegate;
    NSString *_appKey;
    NSString *_apiURL;
    NSString *_gsURL;
    AnIM *_anIM;
    AnGroupediaHTTPClient *_httpClient;
    bool _isLinkUser;
    bool _isSecure;
}

@synthesize delegate = _delegate;

- (AnGroupedia *)initWithAppKey:(NSString *)appKey anIM:(AnIM *)anIM delegate:(id <AnGroupediaDelegate>)delegate;
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (appKey == nil || appKey.length == 0) {
        message = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (anIM == nil) {
        message = @"invalid anIM";
        errorCode = GROUPEDIA_INVALID_ANIM;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        return nil;
    }
    
    _appKey = appKey;
    _anIM = anIM;
    _isSecure = YES;
    
    _apiURL = [NSString stringWithFormat:@"%@://%@/%@", _isSecure?@"https":@"http", ARROWNOCK_API_HOST, ARROWNOCK_API_VERSION];;
    _gsURL = [NSString stringWithFormat:@"%@://%@", _isSecure?@"https":@"http", ARROWNOCK_GS_HOST];
    
    _delegate = delegate;
    _httpClient = [[AnGroupediaHTTPClient alloc] setup];
    [anIM setGroupediaMessageDelegate:self];
    
    return self;
}

- (AnGroupedia *)initWithAppKey:(NSString *)appKey
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (appKey == nil || appKey.length == 0) {
        message = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        return nil;
    }
    
    _appKey = appKey;
    _isSecure = YES;
    
    _apiURL = [NSString stringWithFormat:@"%@://%@/%@", _isSecure?@"https":@"http", ARROWNOCK_API_HOST, ARROWNOCK_API_VERSION];;
    _gsURL = [NSString stringWithFormat:@"%@://%@", _isSecure?@"https":@"http", ARROWNOCK_GS_HOST];
    
    _httpClient = [[AnGroupediaHTTPClient alloc] setup];
    
    return self;
}

- (void)setSecure:(BOOL)secure
{
    _isSecure = secure;
    _apiURL = [NSString stringWithFormat:@"%@://%@/%@", _isSecure?@"https":@"http", ARROWNOCK_API_HOST, ARROWNOCK_API_VERSION];;
    _gsURL = [NSString stringWithFormat:@"%@://%@", _isSecure?@"https":@"http", ARROWNOCK_GS_HOST];
}

- (void)initUser:(NSString *)extId name:(NSString *)name avatar:(NSString *)avatar success:(void (^)(GPUser *user))success failure:(void (^)(ArrownockException *exception))failure
{
    _isLinkUser = NO;
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (extId == nil || extId.length == 0) {
        message = @"Invalid value of extId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/users/info"];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:extId forKey:@"userid"];
    if (name && name.length > 0) {
        name = [name stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        [params setObject:name forKey:@"name"];
    }
    if (avatar && avatar.length > 0) {
        [params setObject:avatar forKey:@"avatar"];
    }
    
    if(_httpClient)
    {
        [_httpClient sendInitUserRequest:params url:urlFormat name:name avatar:avatar extId:extId success:success failure:failure];
    }
}

- (void)linkUser:(NSString *)userId success:(void (^)(GPUser *user))success failure:(void (^)(ArrownockException *exception))failure
{
    _isLinkUser = YES;
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userId == nil || userId.length == 0) {
        message = @"UserId can not be empty.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/users/link"];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userId forKey:@"userid"];
    
    if(_httpClient)
    {
        [_httpClient sendLinkUserRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)updateUser:(NSString *)userId name:(NSString *)name avatar:(NSString *)avatar success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userId == nil || userId.length == 0) {
        message = @"Invalid value of userId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if ((name == nil || name.length == 0) && (avatar == nil || avatar.length == 0)) {
        message = @"Name and avatar cannot be both empty.";
        errorCode = GROUPEDIA_INVALID_NAME_AVATAR;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/users/update"];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userId forKey:@"id"];
    if (name && name.length > 0) {
        name = [name stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        [params setObject:name forKey:@"name"];
    }
    if (avatar && avatar.length > 0) {
        [params setObject:avatar forKey:@"avatar"];
    }
    
    if(_httpClient)
    {
        [_httpClient sendCommonRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)getChannels:(void (^)(NSArray *channels))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/channels"];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    
    if(_httpClient)
    {
        [_httpClient sendGetChannelsRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)getArticles:(NSString *)channelId page:(int)page limit:(int)limit success:(void (^)(NSArray *articles))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    
    if (channelId == nil || channelId.length == 0) {
        message = @"Invalid value of channelId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (page <= 0) {
        message = @"Invalid value of page.";
        errorCode = GROUPEDIA_INVALID_PAGE_OR_LIMIT;
    }
    
    if (limit <= 0) {
        message = @"Invalid value of limit.";
        errorCode = GROUPEDIA_INVALID_PAGE_OR_LIMIT;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/articles/channel/%@"];
    urlFormat = [NSString stringWithFormat:urlFormat, channelId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:[NSNumber numberWithInt:page] forKey:@"page"];
    [params setObject:[NSNumber numberWithInt:limit] forKey:@"limit"];
    
    if(_httpClient)
    {
        [_httpClient sendGetArticlesRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)searchArticles:(NSString *)content page:(int)page limit:(int)limit success:(void (^)(NSArray *articles))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    
    if (content == nil || content.length == 0) {
        message = @"Invalid value of content.";
        errorCode = GROUPEDIA_INVALID_CONTENT;
    }
    
    if (page <= 0) {
        message = @"Invalid value of page.";
        errorCode = GROUPEDIA_INVALID_PAGE_OR_LIMIT;
    }
    
    if (limit <= 0) {
        message = @"Invalid value of limit.";
        errorCode = GROUPEDIA_INVALID_PAGE_OR_LIMIT;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/search/app/articles"];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    content = [content stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    [params setObject:content forKey:@"condition"];
    [params setObject:[NSNumber numberWithInt:page] forKey:@"page"];
    [params setObject:[NSNumber numberWithInt:limit] forKey:@"limit"];
    
    if(_httpClient)
    {
        [_httpClient sendSearchArticlesRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)getArticleByArticleId:(NSString *)articleId userId:(NSString *)userId success:(void (^)(GPArticle *article))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (articleId == nil || articleId.length == 0) {
        message = @"Invalid value of articleId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (userId == nil || userId.length == 0) {
        message = @"Invalid value of userId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/articles/%@"];
    urlFormat = [NSString stringWithFormat:urlFormat, articleId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userId forKey:@"like_user_id"];
    
    if(_httpClient)
    {
        [_httpClient sendGetArticleByIdRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)createLike:(NSString *)articleId userId:(NSString *)userId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userId == nil || userId.length == 0) {
        message = @"Invalid value of userId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (articleId == nil || articleId.length == 0) {
        message = @"Invalid value of articleId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/likes/%@/add"];
    urlFormat = [NSString stringWithFormat:urlFormat, articleId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userId forKey:@"id"];
    
    if(_httpClient)
    {
        [_httpClient sendCommonRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)cancelLike:(NSString *)articleId userId:(NSString *)userId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userId == nil || userId.length == 0) {
        message = @"Invalid value of userId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (articleId == nil || articleId.length == 0) {
        message = @"Invalid value of articleId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/likes/%@/remove"];
    urlFormat = [NSString stringWithFormat:urlFormat, articleId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userId forKey:@"id"];
    
    if(_httpClient)
    {
        [_httpClient sendCommonRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)getComments:(NSString *)articleId page:(int)page limit:(int)limit success:(void (^)(NSArray *comments))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    
    if (articleId == nil || articleId.length == 0) {
        message = @"Invalid value of articleId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (page <= 0) {
        message = @"Invalid value of page.";
        errorCode = GROUPEDIA_INVALID_PAGE_OR_LIMIT;
    }
    
    if (limit <= 0) {
        message = @"Invalid value of limit.";
        errorCode = GROUPEDIA_INVALID_PAGE_OR_LIMIT;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/comments/%@"];
    urlFormat = [NSString stringWithFormat:urlFormat, articleId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:[NSNumber numberWithInt:page] forKey:@"page"];
    [params setObject:[NSNumber numberWithInt:limit] forKey:@"limit"];
    
    if(_httpClient)
    {
        [_httpClient sendGetCommentsRequest:params isLinkUser:_isLinkUser url:urlFormat success:success failure:failure];
    }
}

- (void)createComment:(NSString *)articleId userId:(NSString *)userId content:(NSString *)content success:(void (^)(GPComment *comment))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    
    if (articleId == nil || articleId.length == 0) {
        message = @"Invalid value of articleId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (userId == nil || userId.length == 0) {
        message = @"Invalid value of userId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (content == nil || content.length == 0) {
        message = @"Invalid value of content.";
        errorCode = GROUPEDIA_INVALID_CONTENT;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/comments/%@/add"];
    urlFormat = [NSString stringWithFormat:urlFormat, articleId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userId forKey:@"id"];
    content = [content stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    [params setObject:content forKey:@"content"];
    
    if(_httpClient)
    {
        [_httpClient sendCreateCommentRequest:params isLinkUser:_isLinkUser url:urlFormat success:success failure:failure];
    }
}

- (void)removeComment:(NSString *)articleId commentId:(NSString *)commentId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (commentId == nil || commentId.length == 0) {
        message = @"Invalid value of commentId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (articleId == nil || articleId.length == 0) {
        message = @"Invalid value of articleId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/comments/%@/remove/%@"];
    urlFormat = [NSString stringWithFormat:urlFormat, articleId, commentId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    
    if(_httpClient)
    {
        [_httpClient sendCommonRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)joinTopic:(NSString *)userImId topicId:(NSString *)topicId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userImId == nil || userImId.length == 0) {
        message = @"Invalid value of userImId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (topicId == nil || topicId.length == 0) {
        message = @"Invalid value of topicId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/im/topics/%@/join"];
    urlFormat = [NSString stringWithFormat:urlFormat, topicId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userImId forKey:@"client_id"];
    
    if(_httpClient)
    {
        [_httpClient sendCommonRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)quitTopic:(NSString *)userImId topicId:(NSString *)topicId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userImId == nil || userImId.length == 0) {
        message = @"Invalid value of userImId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (topicId == nil || topicId.length == 0) {
        message = @"Invalid value of topicId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/im/topics/%@/leave"];
    urlFormat = [NSString stringWithFormat:urlFormat, topicId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userImId forKey:@"client_id"];
    
    if(_httpClient)
    {
        [_httpClient sendCommonRequest:params url:urlFormat success:success failure:failure];
    }
}

- (void)getTopic:(NSString *)userImId columnId:(NSString *)columnId success:(void (^)(GPTopic *topic, bool isJoin, NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userImId == nil || userImId.length == 0) {
        message = @"Invalid value of userImId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (columnId == nil || columnId.length == 0) {
        message = @"Invalid value of columnId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlFormat = [_gsURL stringByAppendingString:@"/v1/im/topics/get/%@"];
    urlFormat = [NSString stringWithFormat:urlFormat, columnId];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:userImId forKey:@"client_id"];
    
    if(_httpClient)
    {
        [_httpClient sendGetTopicRequest:params url:urlFormat success:success failure:failure];
    }
}

- (NSString *)sendMessage:(NSString *)message topicId:(NSString *)topicId user:(GPUser *)user
{
    NSString *errorMessage = nil;
    NSInteger errorCode = 0;
    if (topicId == nil || topicId.length == 0) {
        errorMessage = @"Invalid value of topicId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (message == nil || message.length == 0) {
        errorMessage = @"Invalid value of message.";
        errorCode = GROUPEDIA_INVALID_MESSAGE;
    }
    if (user == nil || user.id == nil || user.id.length == 0) {
        errorMessage = @"User can not be empty.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (_anIM == nil) {
        errorMessage = @"Init anIM first.";
        errorCode = GROUPEDIA_INVALID_ANIM;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:errorMessage];
        return nil;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:@"gp" forKey:@"message_type"];
    [params setObject:user.id forKey:@"id"];
    if (_isLinkUser) {
        if (user.fields) {
            [params setObject:user.fields forKey:@"fields"];
        }
    } else {
        if (user.name) {
            [params setObject:user.name forKey:@"name"];
        }
        if (user.avatar) {
            [params setObject:user.avatar forKey:@"avatar"];
        }
        if (user.extId) {
            [params setObject:user.extId forKey:@"ext_id"];
        }
    }
    
    return [_anIM sendMessage:message customData:params toTopicId:topicId needReceiveACK:NO];
}

- (NSString *)sendImage:(NSData *)data topicId:(NSString *)topicId user:(GPUser *)user
{
    NSString *errorMessage = nil;
    NSInteger errorCode = 0;
    if (topicId == nil || topicId.length == 0) {
        errorMessage = @"Invalid value of topicId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (user == nil || user.id == nil || user.id.length == 0) {
        errorMessage = @"User can not be empty.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (data == nil || data.length == 0) {
        errorMessage = @"data can not be empty.";
        errorCode = GROUPEDIA_INVALID_DATA;
    }
    if (_anIM == nil) {
        errorMessage = @"Init anIM first.";
        errorCode = GROUPEDIA_INVALID_ANIM;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:errorMessage];
        return nil;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:@"gp" forKey:@"message_type"];
    [params setObject:user.id forKey:@"id"];
    if (_isLinkUser) {
        if (user.fields) {
            [params setObject:user.fields forKey:@"fields"];
        }
    } else {
        if (user.name) {
            [params setObject:user.name forKey:@"name"];
        }
        if (user.avatar) {
            [params setObject:user.avatar forKey:@"avatar"];
        }
        if (user.extId) {
            [params setObject:user.extId forKey:@"ext_id"];
        }
    }
    
    return [_anIM sendBinary:data fileType:@"image" customData:params toTopicId:topicId needReceiveACK:NO];
}

- (NSString *)sendAudio:(NSData *)data topicId:(NSString *)topicId user:(GPUser *)user
{
    NSString *errorMessage = nil;
    NSInteger errorCode = 0;
    if (topicId == nil || topicId.length == 0) {
        errorMessage = @"Invalid value of topicId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (user == nil || user.id == nil || user.id.length == 0) {
        errorMessage = @"User can not be empty.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (data == nil || data.length == 0) {
        errorMessage = @"data can not be empty.";
        errorCode = GROUPEDIA_INVALID_DATA;
    }
    if (_anIM == nil) {
        errorMessage = @"Init anIM first.";
        errorCode = GROUPEDIA_INVALID_ANIM;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:errorMessage];
        return nil;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:@"gp" forKey:@"message_type"];
    [params setObject:user.id forKey:@"id"];
    if (_isLinkUser) {
        if (user.fields) {
            [params setObject:user.fields forKey:@"fields"];
        }
    } else {
        if (user.name) {
            [params setObject:user.name forKey:@"name"];
        }
        if (user.avatar) {
            [params setObject:user.avatar forKey:@"avatar"];
        }
        if (user.extId) {
            [params setObject:user.extId forKey:@"ext_id"];
        }
    }
    
    return [_anIM sendBinary:data fileType:@"audio" customData:params toTopicId:topicId needReceiveACK:NO];
}

- (void)getTopicOfflineHistory:(NSString *)userImId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userImId == nil || userImId.length == 0) {
        message = @"Invalid value of userImId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *getOfflineMessageURLFormat = [_apiURL stringByAppendingString:@"/im/history.json?key=%@"];
    
    NSString *urlString = [NSString stringWithFormat:getOfflineMessageURLFormat, _appKey];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"topic" forKey:@"type"];
    [params setObject:@"1" forKey:@"all"];
    [params setObject:@"1" forKey:@"offline"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:userImId forKey:@"me"];
    [params setObject:@"mobile" forKey:@"device_type"];
    [params setObject:@"gp" forKey:@"ext_type"];
    if (limit > 0) {
        [params setObject:[NSString stringWithFormat:@"%d",limit] forKey:@"limit"];
    }
    if(_httpClient)
    {
        [_httpClient sendGetTopicOfflineMessageRequest:params url:urlString success:success failure:failure];
    }
}

- (void)getTopicHistory:(NSString *)userImId topicId:(NSString *)topicId limit:(int)limit timestamp:(NSNumber *)timestamp success:(void (^)(NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (_appKey == nil || _appKey.length == 0) {
        message = @"Invalid value of appkey.";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (userImId == nil || userImId.length == 0) {
        message = @"Invalid value of userImId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    if (topicId == nil || topicId.length == 0) {
        message = @"Invalid value of topicId.";
        errorCode = GROUPEDIA_INVALID_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *urlString = [_apiURL stringByAppendingString:@"/im/history.json"];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"topic" forKey:@"type"];
    [params setObject:topicId forKey:@"topic_id"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:userImId forKey:@"me"];
    [params setObject:@"mobile" forKey:@"device_type"];
    [params setObject:@"gp" forKey:@"ext_type"];
    if (limit > 0) {
        [params setObject:[NSString stringWithFormat:@"%d",limit] forKey:@"limit"];
    }
    if(timestamp != nil && timestamp > 0)
    {
        [params setObject:timestamp forKey:@"timestamp"];
    }
    if(_httpClient)
    {
        [_httpClient sendGetTopicMessageRequest:params topicId:topicId url:urlString success:success failure:failure];
    }
}

#pragma private function
- (NSDictionary *)dictionaryWithJsonString:(NSString *)jsonString
{
    if (jsonString == nil) {
        return nil;
    }
    
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData
                                                        options:NSJSONReadingMutableContainers
                                                          error:&err];
    if(err)
    {
        NSLog(@"json解析失败：%@",err);
        return nil;
    }
    return dic;
}

#pragma mark - message callbacks
- (void) didReceiveMessage:(NSString *)message customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp
{
    if ([_delegate respondsToSelector:@selector(AnGroupedia:didReceiveMessage:topicId:messageId:at:user:)]) {
        NSString *userId = [customData objectForKey:@"id"];
        NSString *imId = from;
        NSDictionary *fields = nil;
        NSString *name = nil;
        NSString *avatar = nil;
        NSString *extId = nil;
        if ([customData objectForKey:@"fields"]) {
            id fieldsTemp = [customData objectForKey:@"fields"];
            if ([fieldsTemp isKindOfClass:[NSDictionary class]]) {
                fields = fieldsTemp;
            } else {
                fields = [self dictionaryWithJsonString:[customData objectForKey:@"fields"]];
            }
        } else {
            if ([customData objectForKey:@"name"]) {
                name = [customData objectForKey:@"name"];
            }
            if ([customData objectForKey:@"avatar"]) {
                avatar = [customData objectForKey:@"avatar"];
            }
            if ([customData objectForKey:@"ext_id"]) {
                extId = [customData objectForKey:@"ext_id"];
            }
        }
        GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:fields];
        
        [_delegate AnGroupedia:self didReceiveMessage:message topicId:topicId messageId:messageId at:timestamp user:user];
    }
}

- (void) didReceiveBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp
{
    NSString *userId = [customData objectForKey:@"id"];
    NSString *imId = from;
    NSDictionary *fields = nil;
    NSString *name = nil;
    NSString *avatar = nil;
    NSString *extId = nil;
    if ([customData objectForKey:@"fields"]) {
        id fieldsTemp = [customData objectForKey:@"fields"];
        if ([fieldsTemp isKindOfClass:[NSDictionary class]]) {
            fields = fieldsTemp;
        } else {
            fields = [self dictionaryWithJsonString:[customData objectForKey:@"fields"]];
        }
    } else {
        if ([customData objectForKey:@"name"]) {
            name = [customData objectForKey:@"name"];
        }
        if ([customData objectForKey:@"avatar"]) {
            avatar = [customData objectForKey:@"avatar"];
        }
        if ([customData objectForKey:@"ext_id"]) {
            extId = [customData objectForKey:@"ext_id"];
        }
    }
    GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:fields];
    
    if ([fileType isEqualToString:@"image"]) {
        if ([_delegate respondsToSelector:@selector(AnGroupedia:didReceiveImage:topicId:messageId:at:user:)]) {
            [_delegate AnGroupedia:self didReceiveImage:data topicId:topicId messageId:messageId at:timestamp user:user];
        }
    } else if ([fileType isEqualToString:@"audio"]) {
        if ([_delegate respondsToSelector:@selector(AnGroupedia:didReceiveAudio:topicId:messageId:at:user:)]) {
            [_delegate AnGroupedia:self didReceiveAudio:data topicId:topicId messageId:messageId at:timestamp user:user];
        }
    }
}

@end

