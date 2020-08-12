#import <Foundation/Foundation.h>
#import "AnDesk.h"
#import "AnIM.h"
#import "AnDeskHTTPClient.h"
#import <UIKit/UIKit.h>
#import "AnIMUtils.h"
#import "ArrownockExceptionUtils.h"

@interface AnDesk () <AnDeskMessageDelegate>
@property id <AnDeskDelegate> delegate;
@end

@implementation AnDesk {
    id <AnDeskDelegate> _delegate;
    NSString *_appKey;
    AnDeskUser *_user;
    NSString *_dsURL;
    NSString *_apiURL;
    AnIM *_anIM;
    AnDeskHTTPClient *_httpClient;
}

@synthesize delegate = _delegate;

- (AnDesk *)initWithAppKey:(AnDeskUser *)user appKey:(NSString *)appKey anIM:(AnIM*)anIM delegate:(id <AnDeskDelegate>)delegate
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (appKey == nil || appKey.length == 0) {
        message = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (anIM == nil) {
        message = @"invalid anIM";
        errorCode = DESK_INVALID_ANIM;
    }
    if (user == nil) {
        message = @"invalid user";
        errorCode = DESK_INVALID_USER;
    } else {
        if (user.id == nil || user.id.length == 0) {
            message = @"user id can not be empty.";
            errorCode = DESK_INVALID_USER_ID;
        }
        if (user.name == nil || user.name.length == 0) {
            message = @"user name can not be empty.";
            errorCode = DESK_INVALID_USER_NAME;
        }
        if (user.age) {
            if (user.age < 0 && ![user.age isEqual: @(-1)]) {
                message = @"user age should greater than 0";
                errorCode = DESK_INVALID_USER_AGE;
            }
        }
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        return nil;
    }
    
    _user = user;
    _appKey = appKey;
    _anIM = anIM;
    _dsURL = [_anIM getDSURL];
    _apiURL = [_anIM getAPIURL];
    _delegate = delegate;
    _httpClient = [[AnDeskHTTPClient alloc] setup];
    [anIM setDeskMessageDelegate:self];
    
    return self;
}

- (void)getGroups:(void (^)(NSMutableArray *groups))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *getGroupURLFormat = [_apiURL stringByAppendingString:@"/desks/groups/query.json?key=%@"];
    
    NSString *urlString = [NSString stringWithFormat:getGroupURLFormat, _appKey];
    if(_httpClient)
    {
        [_httpClient sendGetGroupsRequest:urlString success:success failure:failure];
    }
}

- (NSString *)getCurrentSessionId:(NSString *)groupId clientId:(NSString *)clientId
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (groupId == nil || groupId.length == 0) {
        message = @"groupId can not be empty.";
        errorCode = DESK_INVALID_GROUP_ID;
    }
    if (clientId == nil || clientId.length == 0) {
        message = @"clientId can not be empty.";
        errorCode = DESK_INVALID_CLIENT_ID;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        return nil;
    }
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [[groupId stringByAppendingString:@"_"] stringByAppendingString:clientId];
    NSDictionary *session = [defaults objectForKey:key];
    
    return [session objectForKey:@"session_id"];
}

- (void)createSession:(NSString *)groupId clientId:(NSString *)clientId success:(void (^)(NSString *sessionId, NSString *accountId, NSString *accountName))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (groupId == nil || groupId.length == 0) {
        message = @"groupId can not be empty.";
        errorCode = DESK_INVALID_GROUP_ID;
    }
    if (clientId == nil || clientId.length == 0) {
        message = @"clientId can not be empty.";
        errorCode = DESK_INVALID_CLIENT_ID;
    }
    
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    NSString *createSessionURLFormat = [_apiURL stringByAppendingString:@"/desks/sessions/create.json?key=%@"];
    
    NSString *urlString = [NSString stringWithFormat:createSessionURLFormat, _appKey];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:groupId forKey:@"group_id"];
    [params setObject:clientId forKey:@"client_id"];
    if (_user.name) {
        [params setObject:_user.name forKey:@"name"];
    }
    if (_user.id) {
        [params setObject:_user.id forKey:@"user_id"];
    }
    if (_user.photo) {
        [params setObject:_user.photo forKey:@"photo"];
    }
    if (_user.age && ![_user.age isEqual:@(-1)]) {
        [params setObject:_user.age forKey:@"age"];
    }
    if (_user.phone) {
        [params setObject:_user.phone forKey:@"phone"];
    }
    if (_user.gender) {
        [params setObject:_user.gender forKey:@"gender"];
    }
    if(_httpClient)
    {
        [_httpClient sendCreateSessionRequest:params groupId:groupId clientId:clientId url:urlString success:success failure:failure];
    }
}

- (void)getOfflineMessage:(NSString *)clientId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSInteger errorCode = 0;
    if (clientId == nil || clientId.length == 0) {
        message = @"clientId can not be empty.";
        errorCode = DESK_INVALID_CLIENT_ID;
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
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"mobile" forKey:@"device_type"];
    [params setObject:@"desk" forKey:@"ext_type"];
    if (limit > 0) {
        [params setObject:[NSString stringWithFormat:@"%d",limit] forKey:@"limit"];
    }
    if(_httpClient)
    {
        [_httpClient sendGetOfflineMessageRequest:params url:urlString success:success failure:failure];
    }
}

- (void)closeSession:(NSString *)sessionId
{
    
}

- (NSString *)sendMessage:(NSString *)message sessionId:(NSString *)sessionId
{
    NSString *errorMessage = nil;
    NSInteger errorCode = 0;
    if (sessionId == nil || sessionId.length == 0) {
        errorMessage = @"sessionId can not be empty.";
        errorCode = DESK_INVALID_SESSION_ID;
    }
    if (message == nil || message.length == 0) {
        errorMessage = @"message can not be empty.";
        errorCode = DESK_INVALID_MESSAGE;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:errorMessage];
        return nil;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    if (_user.name) {
        [params setObject:_user.name forKey:@"name"];
    }
    if (_user.id) {
        [params setObject:_user.id forKey:@"id"];
    }
    if (_user.photo) {
        [params setObject:_user.photo forKey:@"photo"];
    }
    if (_user.age && ![_user.age isEqual:@(-1)]) {
        [params setObject:_user.age forKey:@"age"];
    }
    if (_user.phone) {
        [params setObject:_user.phone forKey:@"phone"];
    }
    if (_user.gender) {
        [params setObject:_user.gender forKey:@"gender"];
    }
    return [_anIM sendMessage:message customData:params toTopicId:sessionId needReceiveACK:false mentionedClientIds:nil msgIdPrefix:@"D"];
}

- (NSString *)sendImage:(NSData *)data sessionId:(NSString *)sessionId
{
    return [self sendImage:data sessionId:sessionId originalImageUrl:nil];
}

- (NSString *)sendImage:(NSData *)data sessionId:(NSString *)sessionId originalImageUrl:(NSString *)originalImageUrl
{
    NSString *errorMessage = nil;
    NSInteger errorCode = 0;
    if (sessionId == nil || sessionId.length == 0) {
        errorMessage = @"sessionId can not be empty.";
        errorCode = DESK_INVALID_SESSION_ID;
    }
    if (data == nil || data.length == 0) {
        errorMessage = @"data can not be empty.";
        errorCode = DESK_INVALID_DATA;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:errorMessage];
        return nil;
    }
    
    NSString *anMsgId = [AnIMUtils generateAnMsgId:[_anIM getCurrentClientId]];
    anMsgId = [@"D" stringByAppendingString:anMsgId];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *compressdData = [self compressImageDataByOriginalImage:data maxFileSize:50];
        NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
        if (_user.name) {
            [params setObject:_user.name forKey:@"name"];
        }
        if (_user.id) {
            [params setObject:_user.id forKey:@"id"];
        }
        if (_user.photo) {
            [params setObject:_user.photo forKey:@"photo"];
        }
        if (_user.age && ![_user.age isEqual:@(-1)]) {
            [params setObject:_user.age forKey:@"age"];
        }
        if (_user.phone) {
            [params setObject:_user.phone forKey:@"phone"];
        }
        if (_user.gender) {
            [params setObject:_user.gender forKey:@"gender"];
        }
        if (originalImageUrl && originalImageUrl.length > 0) {
            [params setObject:originalImageUrl forKey:@"originalImage"];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            if (compressdData && compressdData.length > 0) {
                [_anIM sendBinary:compressdData fileType:@"image" customData:params toTopicId:sessionId needReceiveACK:false msgId:anMsgId];
            } else {
                [_anIM sendBinary:data fileType:@"image" customData:params toTopicId:sessionId needReceiveACK:false msgId:anMsgId];
            }
        });
    });
    return anMsgId;
    
}

//压缩图片到指定大小
- (NSData *)compressImageDataByOriginalImage:(NSData *)data maxFileSize:(int)maxFileSize
{
    maxFileSize = maxFileSize * 1024;
    if([data length] <= maxFileSize) {
        return data;
    }
    
    UIImage *image = [UIImage imageWithData:data];
    NSData *compressedData = data;
    compressedData = [self compressImageData:compressedData maxFileSize:maxFileSize];
    
    //当压图片到不了指定大小时，再缩图片
    while (compressedData.length > maxFileSize) {
        //每次缩图片为原图的1/2尺寸
        image = [self imageWithImage:image andWidth:image.size.width/2 andHeight:image.size.height/2];
        compressedData = UIImagePNGRepresentation(image);
        compressedData = [self compressImageData:compressedData maxFileSize:maxFileSize];
    }
    
    return compressedData;
}

//压图片到指定大小
- (NSData *)compressImageData:(NSData *)data maxFileSize:(int)maxFileSize
{
    CGFloat compression = 0.9f;
    CGFloat maxCompression = 0.1f;
    UIImage *image = [UIImage imageWithData:data];
    NSData *compressedData = UIImageJPEGRepresentation(image, compression);
    //每次压图片以原图质量0.2百分比的方式递减
    while ([compressedData length] > maxFileSize && compression > maxCompression)
    {
        compression -= 0.2;
        compressedData = UIImageJPEGRepresentation(image, compression);
    }
    return compressedData;
}

//缩图片到指定大小
-(UIImage*)imageWithImage:(UIImage*)image andWidth:(CGFloat)width andHeight:(CGFloat)height
{
    UIGraphicsBeginImageContext( CGSizeMake(width, height));
    [image drawInRect:CGRectMake(0,0,width,height)];
    UIImage* newImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    
    return newImage;
}

- (NSString *)sendAudio:(NSData *)data sessionId:(NSString *)sessionId
{
    NSString *errorMessage = nil;
    NSInteger errorCode = 0;
    if (sessionId == nil || sessionId.length == 0) {
        errorMessage = @"sessionId can not be empty.";
        errorCode = DESK_INVALID_SESSION_ID;
    }
    if (data == nil || data.length == 0) {
        errorMessage = @"data can not be empty.";
        errorCode = DESK_INVALID_DATA;
    }
    
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:errorMessage];
        return nil;
    }
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    if (_user.name) {
        [params setObject:_user.name forKey:@"name"];
    }
    if (_user.id) {
        [params setObject:_user.id forKey:@"id"];
    }
    if (_user.photo) {
        [params setObject:_user.photo forKey:@"photo"];
    }
    if (_user.age && ![_user.age isEqual:@(-1)]) {
        [params setObject:_user.age forKey:@"age"];
    }
    if (_user.phone) {
        [params setObject:_user.phone forKey:@"phone"];
    }
    if (_user.gender) {
        [params setObject:_user.gender forKey:@"gender"];
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:[_anIM getCurrentClientId]];
    anMsgId = [@"D" stringByAppendingString:anMsgId];
    return [_anIM sendBinary:data fileType:@"audio" customData:params toTopicId:sessionId needReceiveACK:false msgId:anMsgId];
}

#pragma mark - message callbacks
- (void) messageSent:(NSString *)messageId at:(NSNumber *)timestamp
{
    if ([_delegate respondsToSelector:@selector(anDesk:messageSent:at:)]) {
       [_delegate anDesk:self messageSent:messageId at:timestamp];
    }
}

- (void) sendReturnedException:(ArrownockException *)exception messageId:(NSString *)messageId
{
    if ([_delegate respondsToSelector:@selector(anDesk:sendReturnedException:messageId:)]) {
        [_delegate anDesk:self sendReturnedException:exception messageId:messageId];
    }
}

- (void) didReceiveMessage:(NSString *)message customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp
{
    if ([_delegate respondsToSelector:@selector(anDesk:didReceiveMessage:accountId:accountName:groupId:messageId:at:)]) {
        [_delegate anDesk:self didReceiveMessage:message accountId:[customData objectForKey:@"accId"]  accountName:[customData objectForKey:@"name"] groupId:[customData objectForKey:@"groupId"] messageId:messageId at:timestamp];
    }
}

- (void) didReceiveBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData from:(NSString *)from topicId:(NSString *)topicId messageId:(NSString *)messageId at:(NSNumber *)timestamp
{
    if ([_delegate respondsToSelector:@selector(anDesk:didReceiveImage:accountId:accountName:groupId:messageId:at:)]) {
        if ([fileType isEqualToString:@"image"]) {
            [_delegate anDesk:self didReceiveImage:data accountId:[customData objectForKey:@"accId"] accountName:[customData objectForKey:@"name"] groupId:[customData objectForKey:@"groupId"] messageId:messageId at:timestamp];
        }
    }
}

- (void) sessionClosed:(NSString *)groupId sessionId:(NSString *)sessionId at:(NSNumber *)timestamp
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [[groupId stringByAppendingString:@"_"] stringByAppendingString:[_anIM getCurrentClientId]];
    NSDictionary *session = [defaults objectForKey:key];
    NSString *defaultSessionId = [session objectForKey:@"session_id"];
    if ([defaultSessionId isEqualToString:sessionId]) {
        [defaults removeObjectForKey:key];
        [defaults synchronize];
    }
    
    if ([_delegate respondsToSelector:@selector(anDesk:sessionClosed:sessionId:at:)]) {
        [_delegate anDesk:self sessionClosed:groupId sessionId:sessionId at:timestamp];
    }
}

- (void) accountAddedToSession:(NSString *)sessionId groupId:(NSString *)groupId accountId:(NSString *)accountId accountName:(NSString *)accountName at:(NSNumber *)timestamp
{
    if ([_delegate respondsToSelector:@selector(anDesk:accountAddedToSession:groupId:accountId:accountName:at:)]) {
        [_delegate anDesk:self accountAddedToSession:sessionId groupId:groupId accountId:accountId accountName:accountName at:timestamp];
    }
}

@end

