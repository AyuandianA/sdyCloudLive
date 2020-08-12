#import "AnGroupediaHTTPClient.h"
#import "ArrownockExceptionUtils.h"
#import "ANAFJSONRequestOperation.h"
#import <CommonCrypto/CommonDigest.h>
#import "AnDeskMessage.h"
#import "ANEmojiUtil.h"
#import "ANBase64Wrapper.h"


@interface AnGroupediaHTTPClient()

@end

@implementation AnGroupediaHTTPClient

- (AnGroupediaHTTPClient*)setup
{
    [self registerHTTPOperationClass:[ANAFJSONRequestOperation class]];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
    [self setStringEncoding:NSUTF8StringEncoding];
    return self;
}

- (void)sendCommonRequest:(id)params
                      url:(NSString*)url
                  success:(void (^)())success
                  failure:(void (^)(ArrownockException* exception))failure
{
    
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleCommonResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleCommonResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleCommonResponse:(id)responseObject
                       error:(NSError *)error
                   isSuccess:(BOOL)isSuccess
                   operation:(ANAFHTTPRequestOperation *)operation
                     success:(void (^)())success
                     failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        if(success)
        {
            success();
        }
    } else {
        [self processOnError:error failure:failure];
        
    }
}

- (void)sendInitUserRequest:(id)params
                        url:(NSString*)url
                       name:(NSString*)name
                     avatar:(NSString*)avatar
                      extId:(NSString*)extId
                    success:(void (^)(GPUser *user))success
                    failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleInitUserResponse:responseObject name:name avatar:avatar extId:extId error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleInitUserResponse:nil name:name avatar:avatar extId:extId error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleInitUserResponse:(id)responseObject
                          name:(NSString*)name
                        avatar:(NSString*)avatar
                         extId:(NSString*)extId
                         error:(NSError *)error
                     isSuccess:(BOOL)isSuccess
                     operation:(ANAFHTTPRequestOperation *)operation
                       success:(void (^)(GPUser *user))success
                       failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* userId = nil;
        NSString* imId = nil;
        
        if([[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"id"] != nil)
        {
            userId = [[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"id"];
        }
        if([[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"clientId"] != nil)
        {
            imId = [[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"clientId"];
        }
        GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:nil];
        
        if(success)
        {
            success(user);
        }
    } else {
        [self processOnError:error failure:failure];
        
    }
}

- (void)sendLinkUserRequest:(id)params
                        url:(NSString*)url
                    success:(void (^)(GPUser *user))success
                    failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleLinkUserResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleLinkUserResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleLinkUserResponse:(id)responseObject
                         error:(NSError *)error
                     isSuccess:(BOOL)isSuccess
                     operation:(ANAFHTTPRequestOperation *)operation
                       success:(void (^)(GPUser *user))success
                       failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* userId = nil;
        NSString* imId = nil;
        NSDictionary *fields = nil;
        
        if([[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"id"] != nil)
        {
            userId = [[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"id"];
        }
        if([[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"clientId"] != nil)
        {
            imId = [[[res objectForKey:@"response"] objectForKey:@"user"] objectForKey:@"clientId"];
        }
        fields = [[res objectForKey:@"response"] objectForKey:@"user"];
        GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:nil avatar:nil extId:nil fields:fields];
        
        if(success)
        {
            success(user);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetChannelsRequest:(id)params
                           url:(NSString*)url
                       success:(void (^)(NSArray *channels))success
                       failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetChannelsResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetChannelsResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetChannelsResponse:(id)responseObject
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSArray *channels))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* channelId = nil;
        NSString* channelName = nil;
        NSMutableArray *channels = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([[res objectForKey:@"response"] objectForKey:@"channels"])
        {
            NSArray *channelResponse = [[res objectForKey:@"response"] objectForKey:@"channels"];
            for (int i=0; i<channelResponse.count; i++) {
                NSDictionary *channelDic = [channelResponse objectAtIndex:i];
                channelId = [channelDic objectForKey:@"id"];
                channelName = [channelDic objectForKey:@"name"];
                GPChannel *channel = [[GPChannel alloc] initWithId:channelId name:channelName];
                [channels addObject:channel];
            }
        }
        
        if(success)
        {
            success(channels);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetArticlesRequest:(id)params
                          url:(NSString*)url
                      success:(void (^)(NSArray *articles))success
                      failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetArticlesResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetArticlesResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetArticlesResponse:(id)responseObject
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSArray *articles))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* articleId = nil;
        NSString* columnId = @"";
        NSString* columnName = @"";
        NSString* columnPhotoUrl = @"";
        NSString* columnDescription = @"";
        NSString* title = nil;
        NSString* description = nil;
        NSString* url = @"";
        NSString* content = @"";
        NSString* photoUrl = nil;
        NSNumber *createdAt= nil;
        int readCount = 0;
        int likeCount = 0;
        bool isLike = NO;
        NSString *userId = nil;
        NSString *username = nil;
        NSString *clientId = nil;
        NSString *avatar = nil;
        NSMutableArray *articles = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([[res objectForKey:@"response"] objectForKey:@"articles"])
        {
            NSArray *articleResponse = [[res objectForKey:@"response"] objectForKey:@"articles"];
            for (int i=0; i<articleResponse.count; i++) {
                NSDictionary *articleDic = [articleResponse objectAtIndex:i];
                articleId = [articleDic objectForKey:@"id"];
                if([articleDic objectForKey:@"wall"])
                {
                    NSDictionary *wallDic = [articleDic objectForKey:@"wall"];
                    columnId = [wallDic objectForKey:@"id"];
                    columnName = [wallDic objectForKey:@"name"];
                    columnDescription = [wallDic objectForKey:@"description"];
                    if([wallDic objectForKey:@"cover"]) {
                        columnPhotoUrl = [wallDic objectForKey:@"cover"];
                    } else {
                        columnPhotoUrl = @"";
                    }
                } else {
                    columnId = @"";
                    columnName = @"";
                    columnPhotoUrl = @"";
                    columnDescription = @"";
                }
                title = [articleDic objectForKey:@"title"];
                description = [articleDic objectForKey:@"description"];
//                if([articleDic objectForKey:@"url"]) {
//                    url = [articleDic objectForKey:@"url"];
//                } else {
//                    url = @"";
//                }
//                if([articleDic objectForKey:@"content"]) {
//                    content = [articleDic objectForKey:@"content"];
//                } else {
//                    content = @"";
//                }
                if([articleDic objectForKey:@"cover"]) {
                    photoUrl = [articleDic objectForKey:@"cover"];
                } else {
                    photoUrl = @"";
                }
                createdAt = articleDic[@"date"];
                NSNumber *readCountNum = [articleDic objectForKey:@"views"];
                readCount = [readCountNum intValue];
                NSNumber *likeCountNum = [articleDic objectForKey:@"likes"];
                likeCount = [likeCountNum intValue];
                
                GPUser *user = nil;
                if([articleDic objectForKey:@"user"]) {
                    NSDictionary *userDic = [articleDic objectForKey:@"user"];
                    userId = [userDic objectForKey:@"id"];
                    username = [userDic objectForKey:@"username"];
                    clientId = [userDic objectForKey:@"clientId"];
                    if ([userDic objectForKey:@"photo"]) {
                        avatar = [[userDic objectForKey:@"photo"] objectForKey:@"url"];
                    } else {
                        avatar = @"";
                    }
                    
                    user = [[GPUser alloc] initWithId:userId imId:clientId name:username avatar:avatar extId:nil fields:nil];
                }
                
                GPArticle *article = [[GPArticle alloc] initWithId:articleId columnId:columnId columnName:columnName columnDescription:columnDescription columnPhotoUrl:columnPhotoUrl title:title descript:description url:url content:content photoUrl:photoUrl isLike:isLike createdAt:createdAt readCount:readCount likeCount:likeCount user:user];
                [articles addObject:article];
            }
        }
        
        if(success)
        {
            success(articles);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendSearchArticlesRequest:(id)params
                             url:(NSString*)url
                         success:(void (^)(NSArray *articles))success
                         failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleSearchArticlesResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleSearchArticlesResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleSearchArticlesResponse:(id)responseObject
                               error:(NSError *)error
                           isSuccess:(BOOL)isSuccess
                           operation:(ANAFHTTPRequestOperation *)operation
                             success:(void (^)(NSArray *articles))success
                             failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* articleId = nil;
        NSString* columnId = @"";
        NSString* columnName = @"";
        NSString* columnPhotoUrl = @"";
        NSString* columnDescription = @"";
        NSString* title = nil;
        NSString* description = nil;
        NSString* url = @"";
        NSString* content = @"";
        NSString* photoUrl = nil;
        NSNumber *createdAt = nil;
        bool isLike = NO;
        NSString *userId = nil;
        NSString *username = nil;
        NSString *clientId = nil;
        NSString *avatar = nil;
        NSMutableArray *articles = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([[res objectForKey:@"response"] objectForKey:@"results"])
        {
            NSArray *resultResponse = [[res objectForKey:@"response"] objectForKey:@"results"];
            for (int i=0; i<resultResponse.count; i++) {
                NSDictionary *dataDic = [resultResponse objectAtIndex:i];
                NSDictionary *articleDic = [dataDic objectForKey:@"data"];
                articleId = [articleDic objectForKey:@"id"];
                if ([articleDic objectForKey:@"wall_id"]) {
                    columnId = [articleDic objectForKey:@"wall_id"];
                } else {
                    columnId = @"";
                }
                title = [articleDic objectForKey:@"title"];
                description = [articleDic objectForKey:@"description"];
//                if([articleDic objectForKey:@"url"]) {
//                    url = [articleDic objectForKey:@"url"];
//                } else {
//                    url = @"";
//                }
//                if([articleDic objectForKey:@"content"]) {
//                    content = [articleDic objectForKey:@"content"];
//                } else {
//                    content = @"";
//                }
                photoUrl = @"";
                if([articleDic objectForKey:@"cover"]) {
                    photoUrl = [articleDic objectForKey:@"cover"];
                }
                createdAt = articleDic[@"date"];
                
                GPUser *user = nil;
                if([articleDic objectForKey:@"user"]) {
                    NSDictionary *userDic = [articleDic objectForKey:@"user"];
                    userId = [userDic objectForKey:@"id"];
                    username = [userDic objectForKey:@"username"];
                    clientId = [userDic objectForKey:@"clientId"];
                    if ([userDic objectForKey:@"photo"]) {
                        avatar = [[userDic objectForKey:@"photo"] objectForKey:@"url"];
                    } else {
                        avatar = @"";
                    }
                    
                    user = [[GPUser alloc] initWithId:userId imId:clientId name:username avatar:avatar extId:nil fields:nil];
                }
                
                GPArticle *article = [[GPArticle alloc] initWithId:articleId columnId:columnId columnName:columnName columnDescription:columnDescription columnPhotoUrl:columnPhotoUrl title:title descript:description url:url content:content photoUrl:photoUrl isLike:isLike createdAt:createdAt readCount:0 likeCount:0 user:user];
                [articles addObject:article];
            }
        }
        
        if(success)
        {
            success(articles);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetArticleByIdRequest:(id)params
                              url:(NSString*)url
                          success:(void (^)(GPArticle *article))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetArticleByIdResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetArticleByIdResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetArticleByIdResponse:(id)responseObject
                               error:(NSError *)error
                           isSuccess:(BOOL)isSuccess
                           operation:(ANAFHTTPRequestOperation *)operation
                             success:(void (^)(GPArticle *article))success
                             failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* articleId = nil;
        NSString* columnId = @"";
        NSString* columnName = @"";
        NSString* columnPhotoUrl = @"";
        NSString* columnDescription = @"";
        NSString* title = nil;
        NSString* description = nil;
        NSString* url = nil;
        NSString* content = nil;
        NSString* photoUrl = nil;
        NSNumber *createdAt = nil;
        bool isLike = NO;
        NSString *userId = nil;
        NSString *username = nil;
        NSString *clientId = nil;
        NSString *avatar = nil;
        GPArticle *article = nil;
        
        if([[res objectForKey:@"response"] objectForKey:@"article"])
        {
            NSDictionary *articleDic = [[res objectForKey:@"response"] objectForKey:@"article"];
            
            articleId = [articleDic objectForKey:@"id"];
            if([articleDic objectForKey:@"wall"])
            {
                NSDictionary *wallDic = [articleDic objectForKey:@"wall"];
                columnId = [wallDic objectForKey:@"id"];
                columnName = [wallDic objectForKey:@"name"];
                columnDescription = [wallDic objectForKey:@"description"];
                if([wallDic objectForKey:@"cover"]) {
                    columnPhotoUrl = [wallDic objectForKey:@"cover"];
                } else {
                    columnPhotoUrl = @"";
                }
            }
            title = [articleDic objectForKey:@"title"];
            description = [articleDic objectForKey:@"description"];
            if([articleDic objectForKey:@"url"]) {
                url = [articleDic objectForKey:@"url"];
            } else {
                url = @"";
            }
            if([articleDic objectForKey:@"content"]) {
                content = [articleDic objectForKey:@"content"];
            } else {
                content = @"";
            }
            if([articleDic objectForKey:@"cover"]) {
                photoUrl = [articleDic objectForKey:@"cover"];
            } else {
                photoUrl = @"";
            }
            
            NSNumber *readCountNum = [articleDic objectForKey:@"views"];
            int readCount = [readCountNum intValue];
            NSNumber *likeCountNum = [articleDic objectForKey:@"likes"];
            int likeCount = [likeCountNum intValue];
            NSNumber *isLikeNum = [articleDic objectForKey:@"isLiked"];
            int isLikeInt = [isLikeNum intValue];
            if (isLikeInt == 1) {
                isLike = true;
            }
            
            createdAt = articleDic[@"date"];
            
            GPUser *user = nil;
            if([articleDic objectForKey:@"user"]) {
                NSDictionary *userDic = [articleDic objectForKey:@"user"];
                userId = [userDic objectForKey:@"id"];
                username = [userDic objectForKey:@"username"];
                clientId = [userDic objectForKey:@"clientId"];
                if ([userDic objectForKey:@"photo"]) {
                    avatar = [[userDic objectForKey:@"photo"] objectForKey:@"url"];
                } else {
                    avatar = @"";
                }
                
                user = [[GPUser alloc] initWithId:userId imId:clientId name:username avatar:avatar extId:nil fields:nil];
            }
            
            article = [[GPArticle alloc] initWithId:articleId columnId:columnId columnName:columnName columnDescription:columnDescription columnPhotoUrl:columnPhotoUrl title:title descript:description url:url content:content photoUrl:photoUrl isLike:isLike createdAt:createdAt readCount:readCount likeCount:likeCount user:user];
            
            
        }
        if(success)
        {
            success(article);
        }
        
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetCommentsRequest:(id)params
                        isLinkUser:(BOOL)isLinkUser
                               url:(NSString*)url
                           success:(void (^)(NSArray *comments))success
                           failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetCommentsResponse:responseObject isLinkUser:isLinkUser error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetCommentsResponse:nil isLinkUser:isLinkUser error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetCommentsResponse:(id)responseObject
                       isLinkUser:(BOOL)isLinkUser
                            error:(NSError *)error
                        isSuccess:(BOOL)isSuccess
                        operation:(ANAFHTTPRequestOperation *)operation
                          success:(void (^)(NSArray *comments))success
                          failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* commentId = nil;
        NSString* content = nil;
        NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.zzz'Z'"];
        NSDate* createdTime = nil;
        NSNumber *createdAt = nil;
        NSString* userId = nil;
        NSString* imId = nil;
        NSString* name = nil;
        NSString* avatar = nil;
        NSString* extId = nil;
        NSMutableArray *comments = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([[res objectForKey:@"response"] objectForKey:@"comments"])
        {
            
            NSArray *commentResponse = [[res objectForKey:@"response"] objectForKey:@"comments"];
            for (int i=0; i<commentResponse.count; i++) {
                NSDictionary *commentDic = [commentResponse objectAtIndex:i];
                commentId = [commentDic objectForKey:@"id"];
                content = [commentDic objectForKey:@"content"];
                
                createdTime = [dateFormatter dateFromString:commentDic[@"created_at"]];
                createdAt = [NSNumber numberWithDouble:[createdTime timeIntervalSince1970]*1000];
                
                GPUser *user = nil;
                if([commentDic objectForKey:@"user"]) {
                    NSDictionary *userDic = [commentDic objectForKey:@"user"];
                    userId = [userDic objectForKey:@"id"];
                    imId = [userDic objectForKey:@"clientId"];
                    if (isLinkUser) {
                        user = [[GPUser alloc] initWithId:userId imId:imId name:nil avatar:nil extId:nil fields:userDic];
                    } else {
                        name = [userDic objectForKey:@"firstName"];
                        if (name == nil || name.length == 0) {
                            name = [userDic objectForKey:@"username"];
                        }
                        avatar = [userDic objectForKey:@"clientId"];
                        extId = [userDic objectForKey:@"extUserId"];
                    }
                    avatar = @"";
                    if ([userDic objectForKey:@"properties"]) {
                        avatar = [[userDic objectForKey:@"properties"] objectForKey:@"avatar"];
                    }
                    if (avatar == nil || avatar.length == 0) {
                        if ([userDic objectForKey:@"photo"]) {
                            avatar = [[userDic objectForKey:@"photo"] objectForKey:@"url"];
                        }
                    }
                    
                    user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:nil];
                } else if ([commentDic objectForKey:@"username"]) {
                    name = [commentDic objectForKey:@"username"];
                    user = [[GPUser alloc] initWithId:nil imId:nil name:name avatar:nil extId:nil fields:nil];
                } else {
                    user = [[GPUser alloc] initWithId:nil imId:nil name:nil avatar:nil extId:nil fields:nil];
                }
                
                GPComment *comment = [[GPComment alloc] initWithId:commentId content:content createdAt:createdAt user:user];
                [comments addObject:comment];
            }
        }
        
        if(success)
        {
            success(comments);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendCreateCommentRequest:(id)params
                          isLinkUser:(BOOL)isLinkUser
                                 url:(NSString*)url
                             success:(void (^)(GPComment *comment))success
                             failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"POST" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleCreateCommentResponse:responseObject isLinkUser:isLinkUser error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleCreateCommentResponse:nil isLinkUser:isLinkUser error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleCreateCommentResponse:(id)responseObject
                         isLinkUser:(BOOL)isLinkUser
                              error:(NSError *)error
                          isSuccess:(BOOL)isSuccess
                          operation:(ANAFHTTPRequestOperation *)operation
                            success:(void (^)(GPComment *comment))success
                            failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSString* commentId = nil;
        NSString* content = nil;
        NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.zzz'Z'"];
        NSDate* createdTime = nil;
        NSNumber *createdAt = nil;
        NSString* userId = nil;
        NSString* imId = nil;
        NSString* name = nil;
        NSString* avatar = nil;
        NSString* extId = nil;
        GPComment *comment = nil;
        
        if([[res objectForKey:@"response"] objectForKey:@"comment"])
        {
            
            NSDictionary *commentDic = [[res objectForKey:@"response"] objectForKey:@"comment"];
            commentId = [commentDic objectForKey:@"id"];
            content = [commentDic objectForKey:@"content"];
            
            createdTime = [dateFormatter dateFromString:commentDic[@"created_at"]];
            createdAt = [NSNumber numberWithDouble:[createdTime timeIntervalSince1970]*1000];
            
            GPUser *user = nil;
            if([commentDic objectForKey:@"user"]) {
                NSDictionary *userDic = [commentDic objectForKey:@"user"];
                userId = [userDic objectForKey:@"id"];
                imId = [userDic objectForKey:@"clientId"];
                if (isLinkUser) {
                    user = [[GPUser alloc] initWithId:userId imId:imId name:nil avatar:nil extId:nil fields:userDic];
                } else {
                    name = [userDic objectForKey:@"firstName"];
                    if (name == nil || name.length == 0) {
                        name = [userDic objectForKey:@"username"];
                    }
                    avatar = [userDic objectForKey:@"clientId"];
                    extId = [userDic objectForKey:@"extUserId"];
                }
                avatar = @"";
                if ([userDic objectForKey:@"properties"]) {
                    avatar = [[userDic objectForKey:@"properties"] objectForKey:@"avatar"];
                }
                user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:nil];
            }
            comment = [[GPComment alloc] initWithId:imId content:content createdAt:createdAt user:user];
        }
        
        if(success)
        {
            success(comment);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetTopicRequest:(id)params
                            url:(NSString*)url
                        success:(void (^)(GPTopic *topic, bool isJoin, NSArray *messages))success
                        failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetTopicResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetTopicResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetTopicResponse:(id)responseObject
                         error:(NSError *)error
                     isSuccess:(BOOL)isSuccess
                     operation:(ANAFHTTPRequestOperation *)operation
                       success:(void (^)(GPTopic *topic, bool isJoin, NSArray *messages))success
                       failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        
        NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.zzz'Z'"];
        NSDate* createdTime = nil;
        NSNumber *createdAt = nil;
        GPTopic *topic = nil;
        bool isJoin = NO;
        NSMutableArray *messages = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([res objectForKey:@"response"])
        {
            NSDictionary *topicDic = [res objectForKey:@"response"];
            NSString* topicId = [topicDic objectForKey:@"topic_id"];
            NSString* topicName = [topicDic objectForKey:@"topic_name"];
            
            createdTime = [dateFormatter dateFromString:topicDic[@"created_at"]];
            createdAt = [NSNumber numberWithDouble:[createdTime timeIntervalSince1970]*1000];
            
            NSNumber *membersNum = [topicDic objectForKey:@"members"];
            int members = [membersNum intValue];
            NSNumber *isJoinNum = [topicDic objectForKey:@"joined"];
            int isJoinInt = [isJoinNum intValue];
            if (isJoinInt == 1) {
                isJoin = YES;
            }
            topic = [[GPTopic alloc]initWithId:topicId name:topicName members:members];
            
            NSArray *messageResults = [topicDic objectForKey:@"messages"];
            for (int i=0; i<messageResults.count; i++) {
                NSDictionary *messageDic = [messageResults objectAtIndex:i];
                NSString *msgId = [messageDic objectForKey:@"msg_id"];
                NSString *message = [messageDic objectForKey:@"message"];
                NSNumber *timestamp = [messageDic objectForKey:@"timestamp"];
                NSDictionary *customData = [messageDic objectForKey:@"customData"];
                NSString* type = (NSString *)[messageDic objectForKey:@"content_type"];
                
                NSString *userId = [customData objectForKey:@"id"];
                NSString *imId = [messageDic objectForKey:@"from"];
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
                    name = [customData objectForKey:@"name"];
                    avatar = [customData objectForKey:@"avatar"];
                    extId = [customData objectForKey:@"ext_id"];
                }
                GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:fields];
                
                if([@"text" isEqualToString:type])
                {
                    if(message)
                    {
                        message = [ANEmojiUtil stringConvertToEmoji:message];
                    }
                    GPMessage *msg = [[GPMessage alloc] initWithType:AnGroupediaMessageText msgId:msgId topicId:topicId user:user message:message data:nil timestamp:timestamp];
                    [messages addObject:msg];
                }
                else if([@"binary" isEqualToString:type])
                {
                    NSData *data;
                    if(message)
                    {
                        data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                    }
                    NSString *fileType = [messageDic objectForKey:@"fileType"];
                    GPMessage *msg = nil;
                    if ([@"image" isEqualToString:fileType]) {
                        msg = [[GPMessage alloc] initWithType:AnGroupediaMessageImage msgId:msgId topicId:topicId user:user message:nil data:data timestamp:timestamp];
                    } else if ([@"audio" isEqualToString:fileType]){
                        msg = [[GPMessage alloc] initWithType:AnGroupediaMessageAudio msgId:msgId topicId:topicId user:user message:nil data:data timestamp:timestamp];
                    }
                    [messages addObject:msg];
                }
            }
        }
        
        if(success)
        {
            success(topic, isJoin, messages);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetTopicOfflineMessageRequest:(id)params
                                      url:(NSString*)url
                                  success:(void (^)(NSArray *messages, int count))success
                                  failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetTopicOfflineMessageResponse:responseObject error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetTopicOfflineMessageResponse:nil error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetTopicOfflineMessageResponse:(id)responseObject
                                       error:(NSError *)error
                                   isSuccess:(BOOL)isSuccess
                                   operation:(ANAFHTTPRequestOperation *)operation
                                     success:(void (^)(NSArray *messages, int count))success
                                     failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSMutableArray *messages = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([res objectForKey:@"response"] && [[res objectForKey:@"response"] objectForKey:@"messages"])
        {
            NSArray *messageResults = [[res objectForKey:@"response"] objectForKey:@"messages"];
            for (int i=0; i<messageResults.count; i++) {
                NSDictionary *messageDic = [messageResults objectAtIndex:i];
                NSString *msgId = [messageDic objectForKey:@"msg_id"];
                NSString *topicId = [messageDic objectForKey:@"topic_id"];
                NSString *message = [messageDic objectForKey:@"message"];
                NSNumber *timestamp = [messageDic objectForKey:@"timestamp"];
                NSDictionary *customData = [messageDic objectForKey:@"customData"];
                NSString* type = (NSString *)[messageDic objectForKey:@"content_type"];
                
                NSString *userId = [customData objectForKey:@"id"];
                NSString *imId = [messageDic objectForKey:@"from"];
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
                    name = [customData objectForKey:@"name"];
                    avatar = [customData objectForKey:@"avatar"];
                    extId = [customData objectForKey:@"ext_id"];
                }
                GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:fields];
                
                if([@"text" isEqualToString:type])
                {
                    if(message)
                    {
                        message = [ANEmojiUtil stringConvertToEmoji:message];
                    }
                    GPMessage *msg = [[GPMessage alloc] initWithType:AnGroupediaMessageText msgId:msgId topicId:topicId user:user message:message data:nil timestamp:timestamp];
                    [messages addObject:msg];
                }
                else if([@"binary" isEqualToString:type])
                {
                    NSData *data;
                    if(message)
                    {
                        data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                    }
                    NSString *fileType = [messageDic objectForKey:@"fileType"];
                    GPMessage *msg = nil;
                    if ([@"image" isEqualToString:fileType]) {
                        msg = [[GPMessage alloc] initWithType:AnGroupediaMessageImage msgId:msgId topicId:topicId user:user message:nil data:data timestamp:timestamp];
                    } else if ([@"audio" isEqualToString:fileType]){
                        msg = [[GPMessage alloc] initWithType:AnGroupediaMessageAudio msgId:msgId topicId:topicId user:user message:nil data:data timestamp:timestamp];
                    }
                    [messages addObject:msg];
                }
            }
        }
        int count = 0;
        if([res objectForKey:@"meta"] && [[res objectForKey:@"meta"] objectForKey:@"leftCount"])
        {
            count = [[[res objectForKey:@"meta"] objectForKey:@"leftCount"] integerValue];
        }
        if(!count)
        {
            count = 0;
        }
        
        if(success)
        {
            success(messages, count);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

- (void)sendGetTopicMessageRequest:(id)params
                           topicId:(NSString *)topicId
                               url:(NSString*)url
                           success:(void (^)(NSArray *messages))success
                           failure:(void (^)(ArrownockException* exception))failure
{
    NSMutableURLRequest *request = [self requestWithMethod:@"GET" path:url parameters:params];
    [request setTimeoutInterval:120];
    
    ANAFJSONRequestOperation *operation = [[ANAFJSONRequestOperation alloc] initWithRequest:request];
#ifdef SELF_SIGN
    [self setSSLHandler:operation];
#endif
    [operation setCompletionBlockWithSuccess:^(ANAFHTTPRequestOperation *operation, id responseObject) {
        [self handleGetTopicMessageResponse:responseObject topicId:topicId error:nil isSuccess:YES operation:operation success:success failure:failure];
    } failure:^(ANAFHTTPRequestOperation *operation, NSError *error) {
        [self handleGetTopicMessageResponse:nil topicId:topicId error:error isSuccess:NO operation:operation success:success failure:failure];
    }];
    [operation start];
}

- (void)handleGetTopicMessageResponse:(id)responseObject
                              topicId:(NSString *)topicId
                                error:(NSError *)error
                            isSuccess:(BOOL)isSuccess
                            operation:(ANAFHTTPRequestOperation *)operation
                              success:(void (^)(NSArray *messages))success
                              failure:(void (^)(ArrownockException* exception))failure
{
    if (isSuccess) {
        NSDictionary *res = (NSDictionary*) responseObject;
        NSMutableArray *messages = [[NSMutableArray alloc] initWithCapacity:10];
        
        if([res objectForKey:@"response"] && [[res objectForKey:@"response"] objectForKey:@"messages"])
        {
            NSArray *messageResults = [[res objectForKey:@"response"] objectForKey:@"messages"];
            for (int i=0; i<messageResults.count; i++) {
                NSDictionary *messageDic = [messageResults objectAtIndex:i];
                NSString *msgId = [messageDic objectForKey:@"msg_id"];
                NSString *message = [messageDic objectForKey:@"message"];
                NSNumber *timestamp = [messageDic objectForKey:@"timestamp"];
                NSDictionary *customData = [messageDic objectForKey:@"customData"];
                NSString* type = (NSString *)[messageDic objectForKey:@"content_type"];
                
                NSString *userId = [customData objectForKey:@"id"];
                NSString *imId = [messageDic objectForKey:@"from"];
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
                    name = [customData objectForKey:@"name"];
                    avatar = [customData objectForKey:@"avatar"];
                    extId = [customData objectForKey:@"ext_id"];
                }
                GPUser *user = [[GPUser alloc] initWithId:userId imId:imId name:name avatar:avatar extId:extId fields:fields];
                
                if([@"text" isEqualToString:type])
                {
                    if(message)
                    {
                        message = [ANEmojiUtil stringConvertToEmoji:message];
                    }
                    GPMessage *msg = [[GPMessage alloc] initWithType:AnGroupediaMessageText msgId:msgId topicId:topicId user:user message:message data:nil timestamp:timestamp];
                    [messages addObject:msg];
                }
                else if([@"binary" isEqualToString:type])
                {
                    NSData *data;
                    if(message)
                    {
                        data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                    }
                    NSString *fileType = [messageDic objectForKey:@"fileType"];
                    GPMessage *msg = nil;
                    if ([@"image" isEqualToString:fileType]) {
                        msg = [[GPMessage alloc] initWithType:AnGroupediaMessageImage msgId:msgId topicId:topicId user:user message:nil data:data timestamp:timestamp];
                    } else if ([@"audio" isEqualToString:fileType]){
                        msg = [[GPMessage alloc] initWithType:AnGroupediaMessageAudio msgId:msgId topicId:topicId user:user message:nil data:data timestamp:timestamp];
                    }
                    [messages addObject:msg];
                }
            }
        }
        
        if(success)
        {
            success(messages);
        }
    } else {
        [self processOnError:error failure:failure];
    }
}

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

-(void)processOnError:(NSError *)error failure:(void (^)(ArrownockException* exception))failure
{
    NSUInteger errCode = -1;
    NSString *errorString = nil;
    NSString *localizedRecoverySuggestion = [error localizedRecoverySuggestion];
    if (localizedRecoverySuggestion) {
        NSError *err = nil;
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[localizedRecoverySuggestion dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingMutableContainers error:&err];
        if (err == nil) {
            if ([dict objectForKey:@"meta"] != nil) {
                errorString = [[dict objectForKey:@"meta"] objectForKey:@"message"];
                if(failure)
                {
                    failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
                }
                return;
            }
        } else {
            errorString = localizedRecoverySuggestion;
            if(failure)
            {
                failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
            }
            return;
        }
    }
    else {
        errorString = [error localizedDescription];
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errCode message:errorString]);
        }
        return;
    }
}


#ifdef SELF_SIGN
- (void)setSSLHandler:(ANAFHTTPRequestOperation *)operation
{
    [operation setWillSendRequestForAuthenticationChallengeBlock:^(NSURLConnection *connection, NSURLAuthenticationChallenge *challenge) {
        [self connection:connection willSendRequestForAuthenticationChallenge:challenge];
    }];
}
#endif

#ifdef SELF_SIGN
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    SecTrustRef trust = [challenge.protectionSpace serverTrust];
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, 0);
    NSData* serverCertificateData = (__bridge NSData*)SecCertificateCopyData(certificate);
    NSString *serverCertificateDataHash = [self SHA256:[ANBase64Wrapper base64EncodedString:serverCertificateData]];
    
    NSData *certData = [ANBase64Wrapper dataWithBase64EncodedString:ARROWNOCK_SERVER_CERT];
    CFDataRef certDataRef = (__bridge_retained CFDataRef)certData;
    SecCertificateRef localcertificate = SecCertificateCreateWithData(NULL, certDataRef);
    NSData* localCertificateData = (__bridge NSData*)SecCertificateCopyData(localcertificate);
    NSString *localCertificateDataHash = [self SHA256:[ANBase64Wrapper base64EncodedString:localCertificateData]];
    
    CFRelease(certDataRef);
    
    // Check if the certificate returned from the server is identical to the saved certificate in local
    BOOL areCertificatesEqual = ([serverCertificateDataHash isEqualToString:localCertificateDataHash]);
    
    if (areCertificatesEqual)
    {
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
    }
    else
    {
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}

- (NSString*) SHA256:(NSString *)input {
    const char *cStr = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, strlen(cStr), result);
    NSString *s = [NSString  stringWithFormat:
                   @"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                   result[0], result[1], result[2], result[3], result[4],
                   result[5], result[6], result[7],
                   result[8], result[9], result[10], result[11], result[12],
                   result[13], result[14], result[15],
                   result[16], result[17], result[18], result[19],
                   result[20], result[21], result[22], result[23], result[24],
                   result[25], result[26], result[27],
                   result[28], result[29], result[30], result[31]
                   ];
    return [s lowercaseString];
}
#endif

@end
