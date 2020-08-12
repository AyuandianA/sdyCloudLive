//
//  OAuthCore.h
//
//  Created by Loren Brichter on 6/9/10.
//  Copyright 2010 Loren Brichter. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
    AnIMMethodGetToken,
    AnIMMethodGetHost,
    AnIMMethodCreateTopic,
    AnIMMethodUpdateTopic,
    AnIMMethodAddClients,
    AnIMMethodRemoveClients,
    AnIMMethodRemoveTopic,
    AnIMMethodBindService,
    AnIMMethodSendNoticeClient,
    AnIMMethodSendNoticeTopic,
    AnIMMethodUnbindService,
    AnIMMethodGetTopicInfo,
    AnIMMethodGetTopicLog,
    AnIMMethodGetTopicList,
    AnIMMethodGetClientsStatus,
    AnIMMethodGetSessionInfo,
    AnIMMethodCreateSession
} AnIMMethod;

extern NSString *AnIMOAuthorizationSignature(AnIMMethod method, NSString *appKey, NSString *topicId, NSString *clientIdsString, NSString *dateString, NSString *anid, NSString *service, NSString *type, NSString *pushKey, NSString *bind);

extern NSString *AnIMGetSignature(NSString* urlString, NSMutableDictionary* params);