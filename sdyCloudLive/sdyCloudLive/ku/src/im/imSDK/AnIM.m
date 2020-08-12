//
//  AnIM.m
//  AnIM
//
//  Copyright (c) 2014 arrownock. All rights reserved.
//

#import "AnIM.h"
#import "ArrownockConstants.h"
#import "ANMQTTClient.h"
#import "ANBase64Wrapper.h"
#import "AnIMOAuthCore.h"
#import "AnIMURLConnection.h"
#import "AnIMUtils.h"
#import "ArrownockExceptionUtils.h"
#import "DeviceManager.h"
#import "ANEmojiUtil.h"
#import "TokenHelper.h"
#import "AnIMHTTPClient.h"
#import "ANOAHMAC_SHA1SignatureProvider.h"
#import "ANKeychainItemWrapper.h"
#import "AnLiveProtocols.h"
#import "AnDeskProtocols.h"
#import "AnGroupediaProtocols.h"
#import "AnIMMessage.h"

#import <CommonCrypto/CommonDigest.h>

#define MQTT_HOST_KEY @"arrownock_mqtt_host_key"

#define createTopicWithClientsBodyFormat @"client=%@&name=%@"
#define createTopicWithClientsAndOwnerBodyFormat @"client=%@&name=%@&owner=%@"
#define addClientsBodyFormat @"client=%@&id=%@"
#define removeClientsBodyFormat @"client=%@&id=%@"
#define removeTopicWithIdFormat @"id=%@"
#define bindServiceBodyFormat @"bind=%@&service_id=%@&appkey=%@&client=%@&date=%@&service=%@&device_type=%@&signature=%@"
#define unbindServiceBodyFormat @"bind=%@&client=%@&date=%@&service=%@&device_type=%@&signature=%@"
#define noticeClientBodyFormat @"notice=%@&from=%@&client=%@&receive_ack=%@&msg_id=%@&signature=%@&date=%@"
#define noticeTopicBodyFormat @"notice=%@&from=%@&topic=%@&receive_ack=%@&msg_id=%@&signature=%@&date=%@"
#define noticeClientCustomDataBodyFormat @"notice=%@&custom_data=%@&from=%@&client=%@&receive_ack=%@&msg_id=%@&signature=%@&date=%@"
#define noticeTopicCustomDataBodyFormat @"notice=%@&custom_data=%@&from=%@&topic=%@&receive_ack=%@&msg_id=%@&signature=%@&date=%@"
#define createSessionWithClientsBodyFormat @"id=%@&client=%@"
#define createReportDeviceIdWithClientsBodyFormat @"id=%@&client_id=%@&device_id=%@&key=%@"

#define getTokenURLFormat @"/im/token.json?key=%@&id=%@&type=ios"
#define getHostURLFormat @"/im/server.json?token=%@"
#define createTopicWithClientsURLFormat @"/im/create_topic.json?key=%@"
#define createTopicEndPoint @"/im/create_topic.json"
#define updateTopicURLFormat @"/im/update_topic.json?key=%@"
#define updateTopicEndPoint @"/im/update_topic.json"
#define addClientsURLFormat @"/im/add_clients.json?key=%@"
#define addClientsEndPoint @"/im/add_clients.json"
#define removeClientsURLFormat @"/im/remove_clients.json?key=%@"
#define removeClientsEndPoint @"/im/remove_clients.json"
#define removeTopicURLFormat @"/im/remove_topic.json?key=%@"
#define removeTopicEndPoint @"/im/remove_topic.json"
#define bindServiceURLFormat @"/im/signed_bind_service.json?key=%@"
#define noticeURLFormat @"/im/notice.json?key=%@"
#define noticeEndPoint @"/im/notice.json"
#define topicInfoURLFormat @"/im/topic_info.json?key=%@&id=%@"
#define topicLogURLFormat @"/im/topic_log.json?key=%@&id=%@&start=%@&end=%@"
#define topicListAllURLFormat @"/im/topic_list.json?key=%@"
#define topicListMineURLFormat @"/im/topic_list.json?key=%@&client=%@"
#define clientsStatusURLFormat @"/im/client_status.json?key=%@&client=%@"
#define topicStatusURLFormat @"/im/client_status.json?key=%@&topic=%@"
#define sessionInfoURLFormat @"/im/session_info.json?key=%@&id=%@"
#define createSessionURLFormat @"/im/create_session.json?key=%@"
#define historyURLFormat @"/im/history.json"
#define topicHistoryURLFormat @"/im/topics/history.json"
#define syncHistoryURLFormat @"/im/sync_history.json"
#define pushNotificationSettingsURLFormat @"/im/signed_push_settings.json"
#define anLiveCreateSessionURLFormat @"/lives/create.json"
#define anLiveValidateSessionURLFormat @"/lives/validate.json"
#define anLiveTerminateSessionURLFormat @"/lives/terminate.json"
#define reportDeviceIdURLFormat @"/im/report_device_id.json?key=%@"
#define addBlacklistURLFormat @"/im/add_blacklist.json?key=%@"
#define removeBlacklistURLFormat @"/im/remove_blacklist.json?key=%@"
#define listBlacklistsURLFormat @"/im/blacklist.json?key=%@"
#define addBlacklistEndPoint @"/im/add_blacklist.json"
#define removeBlacklistEndPoint @"/im/remove_blacklist.json"

@interface AnIM () <ANMQTTSessionDelegate, NSURLConnectionDataDelegate, NSURLConnectionDelegate, AnLiveSignalController>

@end

@implementation AnIM {
    ANMQTTSession *_mClient;
    NSThread* clientThread;
    NSString *_clientId;
    id <AnIMDelegate> _delegate;
    AnDesk *_anDesk;
    NSString *_appKey;
    NSString *_userId;
    NSString *_getTokenURLFormat;
    NSString *_getHostURLFormat;
    NSString *_createTopicWithClientsURLFormat;
    NSString *_updateTopicURLFormat;
    NSString *_addClientsURLFormat;
    NSString *_removeClientsURLFormat;
    NSString *_removeTopicURLFormat;
    NSString *_bindServiceURLFormat;
    NSString *_noticeURLFormat;
    NSString *_topicInfoURLFormat;
    NSString *_topicLogURLFormat;
    NSString *_topicListAllURLFormat;
    NSString *_topicListMineURLFormat;
    NSString *_clientsStatusURLFormat;
    NSString *_topicStatusURLFormat;
    NSString *_sessionInfoURLFormat;
    NSString *_createSessionURLFormat;
    NSString *_historyURLFormat;
    NSString *_topicHistoryURLFormat;
    NSString *_syncHistoryURLFormat;
    NSString *_pushSettingsURLFormat;
    NSString *_anLiveCreateSessionURLFormat;
    NSString *_anLiveValidateSessionURLFormat;
    NSString *_anLiveTerminateSessionURLFormat;
    NSString *_reportDeviceIdURLFormat;
    NSString *_addBlacklistURLFormat;
    NSString *_removeBlacklistURLFormat;
    NSString *_listBlacklistsURLFormat;
    NSString *_apiURL;
    NSString *_dsURL;
    
    BOOL _secure;
    BOOL _willKickedOff;
    BOOL _status;
    BOOL _willReconnect;
    BOOL _noDisconnectCallback;
    AnIMHTTPClient *_httpClient;
    id <AnLiveSignalEventDelegate> _signalEventDelegate;
    id <AnDeskMessageDelegate> _deskMessageDelegate;
    id <AnGroupediaMessageDelegate> _groupediaMessageDelegate;
}

#pragma mark - internal methods

- (AnIM *)_initWithAppKey:(NSString *)appKey delegate:(id <AnIMDelegate>)delegate secure:(BOOL)secure reset:(BOOL)reset
{
    _appKey = appKey;
    _delegate = delegate;
    _secure = secure;
    _noDisconnectCallback = NO;
    
    if (reset) {
        [_mClient setDelegate:nil];
        _mClient = [ANMQTTSession alloc];
    } else {
        if (!_mClient) {
            _mClient = [ANMQTTSession alloc];
        }
    }
    
    [_mClient setDelegate:self];
    [self setHosts:ARROWNOCK_API_HOST dsHost:ARROWNOCK_IM_DISPATCH_HOST];
    
    _httpClient = [[AnIMHTTPClient alloc] setup];
    return self;
}

- (void)setHosts:(NSString *)apiHost dsHost:(NSString *)dsHost
{
    _dsURL = [NSString stringWithFormat:@"%@://%@/%@", _secure?@"https":@"http", dsHost, ARROWNOCK_IM_DISPATCH_VERSION];
    _getTokenURLFormat = [_dsURL stringByAppendingString:getTokenURLFormat];
    _getHostURLFormat = [_dsURL stringByAppendingString:getHostURLFormat];
    
    _apiURL = [NSString stringWithFormat:@"%@://%@/%@", _secure?@"https":@"http", apiHost, ARROWNOCK_API_VERSION];
    _createTopicWithClientsURLFormat = [_apiURL stringByAppendingString:createTopicWithClientsURLFormat];
    _updateTopicURLFormat = [_apiURL stringByAppendingString:updateTopicURLFormat];
    _addClientsURLFormat = [_apiURL stringByAppendingString:addClientsURLFormat];
    _removeClientsURLFormat = [_apiURL stringByAppendingString:removeClientsURLFormat];
    _removeTopicURLFormat = [_apiURL stringByAppendingString:removeTopicURLFormat];
    _bindServiceURLFormat = [_apiURL stringByAppendingString:bindServiceURLFormat];
    _noticeURLFormat = [_apiURL stringByAppendingString:noticeURLFormat];
    _topicInfoURLFormat = [_apiURL stringByAppendingString:topicInfoURLFormat];
    _topicLogURLFormat = [_apiURL stringByAppendingString:topicLogURLFormat];
    _topicListAllURLFormat = [_apiURL stringByAppendingString:topicListAllURLFormat];
    _topicListMineURLFormat = [_apiURL stringByAppendingString:topicListMineURLFormat];
    _clientsStatusURLFormat = [_apiURL stringByAppendingString:clientsStatusURLFormat];
    _topicStatusURLFormat = [_apiURL stringByAppendingString:topicStatusURLFormat];
    _sessionInfoURLFormat = [_apiURL stringByAppendingString:sessionInfoURLFormat];
    _createSessionURLFormat = [_apiURL stringByAppendingString:createSessionURLFormat];
    _historyURLFormat = [_apiURL stringByAppendingString:historyURLFormat];
    _topicHistoryURLFormat = [_apiURL stringByAppendingString:topicHistoryURLFormat];
    _syncHistoryURLFormat = [_apiURL stringByAppendingString:syncHistoryURLFormat];
    _pushSettingsURLFormat = [_apiURL stringByAppendingString:pushNotificationSettingsURLFormat];
    _anLiveCreateSessionURLFormat = [_apiURL stringByAppendingString:anLiveCreateSessionURLFormat];
    _anLiveValidateSessionURLFormat = [_apiURL stringByAppendingString:anLiveValidateSessionURLFormat];
    _anLiveTerminateSessionURLFormat = [_apiURL stringByAppendingString:anLiveTerminateSessionURLFormat];
    _reportDeviceIdURLFormat = [_apiURL stringByAppendingString:reportDeviceIdURLFormat];
    _addBlacklistURLFormat = [_apiURL stringByAppendingString:addBlacklistURLFormat];
    _removeBlacklistURLFormat = [_apiURL stringByAppendingString:removeBlacklistURLFormat];
    _listBlacklistsURLFormat = [_apiURL stringByAppendingString:listBlacklistsURLFormat];
}

- (NSString*) getAPIURL
{
    return _apiURL;
}

- (BOOL) isSecure
{
    return _secure;
}

- (NSString*) getDSURL
{
    return _dsURL;
}

- (void)_getCallbackConnection:(AnIMURLConnection *)connection data:(NSData *)data error:(NSError *)error
{
    NSString *resultString = nil;
    NSString *errorMessage = nil;
    NSDictionary *hostDict = nil;
    NSString *sessionId = @"";
    NSString *topicId = nil;
    NSString *topicName = nil;
    NSSet *parties = nil;
    NSDate *createdDate = nil;
    NSArray *logs = nil;
    NSArray *statusArray = nil;
    NSMutableDictionary *statusDict = nil;
    NSMutableArray *topicList = nil;
    NSNumber *timestamp = nil;
    if (error) {
        errorMessage = [error localizedDescription];
    }
    else if (data) {
        id jsonObjects = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&error];
        if (!error) {
            if (200 == connection.statusCode) {
                resultString = @"";
                if ([jsonObjects objectForKey:@"token"]) {
                    resultString = (NSString *)[jsonObjects objectForKey:@"token"];
                } else if ([jsonObjects objectForKey:@"host"]) {
                    hostDict = (NSDictionary *)jsonObjects;
                } else if ([[[jsonObjects objectForKey:@"response"] objectForKey:@"topic"] objectForKey:@"topic_id"]) {
                    resultString = (NSString *)[[[jsonObjects objectForKey:@"response"] objectForKey:@"topic"] objectForKey:@"topic_id"];
                } else if ([[jsonObjects objectForKey:@"response"] objectForKey:@"topic_id"]) {
                    resultString = (NSString *)[[jsonObjects objectForKey:@"response"] objectForKey:@"topic_id"];
                } else if ([[[jsonObjects objectForKey:@"meta"] objectForKey:@"method"] isEqualToString:@"GetTopicInfo"]) {
                    id topicJson = [[jsonObjects objectForKey:@"response"] objectForKey:@"topic"];
                    topicId = [topicJson objectForKey:@"id"];
                    topicName = [topicJson objectForKey:@"name"];
                    //                    parties = (NSSet *)[topicJson objectForKey:@"parties"];
                    parties = [NSSet setWithArray:[topicJson objectForKey:@"parties"]];
                    NSDateFormatter* df = [[NSDateFormatter alloc]init];
                    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
                    NSString *createdString = [topicJson objectForKey:@"created_at"];
                    createdDate = [df dateFromString:createdString];
                } else if ([[[jsonObjects objectForKey:@"meta"] objectForKey:@"method"] isEqualToString:@"GetTopicList"]) {
                    topicList = [[jsonObjects objectForKey:@"response"] objectForKey:@"list"];
                } else if ([[[jsonObjects objectForKey:@"meta"] objectForKey:@"method"] isEqualToString:@"GetTopicLog"]) {
                    logs = (NSArray *)[[jsonObjects objectForKey:@"response"] objectForKey:@"logs"];
                } else if ([[[jsonObjects objectForKey:@"meta"] objectForKey:@"method"] isEqualToString:@"GetClientStatus"]) {
                    statusArray = (NSArray *)[[jsonObjects objectForKey:@"response"] objectForKey:@"status"];
                    statusDict = [[NSMutableDictionary alloc] init];
                    for (NSDictionary *dict in statusArray) {
                        NSString *clientId = (NSString *)[[dict allKeys] objectAtIndex:0];
                        NSString *online = [[dict objectForKey:clientId] intValue] == 1 ? @"YES" : @"NO";
                        [statusDict setObject:online forKey:clientId];
                    }
                } else if ([[[jsonObjects objectForKey:@"meta"] objectForKey:@"method"] isEqualToString:@"GetSessionInfo"]) {
                    id sessionJson = [[jsonObjects objectForKey:@"response"] objectForKey:@"session"];
                    sessionId = [sessionJson objectForKey:@"id"];
                    //                    parties = (NSSet *)[sessionJson objectForKey:@"parties"];
                    parties = [NSSet setWithArray:[sessionJson objectForKey:@"parties"]];
                    NSDateFormatter* df = [[NSDateFormatter alloc]init];
                    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
                    NSString *createdString = [sessionJson objectForKey:@"created_at"];
                    createdDate = [df dateFromString:createdString];
                } else if ([[[jsonObjects objectForKey:@"meta"] objectForKey:@"method"] isEqualToString:@"Notice"]) {
                    timestamp = [[jsonObjects objectForKey:@"response"] objectForKey:@"timestamp"];
                }
            } else {
                if ([jsonObjects objectForKey:@"meta"]) {
                    errorMessage = [[jsonObjects objectForKey:@"meta"] objectForKey:@"message"];
                } else {
                    errorMessage = [jsonObjects objectForKey:@"message"];
                }
            }
        } else {
            errorMessage = [error localizedDescription];
        }
        
    } else {
        errorMessage = @"no response data";
    }
    
    BOOL success = (resultString != nil);
    ArrownockException *e = nil;
    if (connection.method == AnIMMethodGetToken) {
        if (success) {
            [AnIMUtils writeClientId:resultString toUserDefaultsKey:_userId];
        }
        if ([_delegate respondsToSelector:@selector(anIM:didGetClientId:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENT_ID message:errorMessage];
            }
            [_delegate anIM:self didGetClientId:resultString exception:e];
        }
    } else if (connection.method == AnIMMethodGetHost) {
        if (success) {
            [AnIMUtils writeHost:hostDict toUserDefaultsKey:MQTT_HOST_KEY];
            [self _connect:hostDict clientId:_clientId];
        } else {
            if ([_delegate respondsToSelector:@selector(anIM:didUpdateStatus:exception:)]) {
                [_delegate anIM:self didUpdateStatus:NO exception:nil];
            }
        }
    } else if (connection.method == AnIMMethodCreateTopic) {
        if ([_delegate respondsToSelector:@selector(anIM:didCreateTopic:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_CREATE_TOPIC message:errorMessage];
            }
            [_delegate anIM:self didCreateTopic:resultString exception:e];
        }
    } else if (connection.method == AnIMMethodUpdateTopic) {
        if ([_delegate respondsToSelector:@selector(anIM:didUpdateTopicWithException:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_UPDATE_TOPIC message:errorMessage];
            }
            [_delegate anIM:self didUpdateTopicWithException:e];
        }
    } else if (connection.method == AnIMMethodAddClients) {
        if ([_delegate respondsToSelector:@selector(anIM:didAddClientsWithException:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_ADD_CLIENTS message:errorMessage];
            }
            [_delegate anIM:self didAddClientsWithException:e];
        }
    } else if (connection.method == AnIMMethodRemoveClients) {
        if ([_delegate respondsToSelector:@selector(anIM:didRemoveClientsWithException:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_REMOVE_CLIENTS message:errorMessage];
            }
            [_delegate anIM:self didRemoveClientsWithException:e];
        }
    } else if (connection.method == AnIMMethodRemoveTopic) {
        if ([_delegate respondsToSelector:@selector(anIM:didRemoveTopic:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_REMOVE_TOPIC message:errorMessage];
            }
            [_delegate anIM:self didRemoveTopic:resultString exception:e];
        }
    } else if (connection.method == AnIMMethodBindService) {
        if ([_delegate respondsToSelector:@selector(anIM:didBindServiceWithException:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_BIND_SERVICE message:errorMessage];
            }
            [_delegate anIM:self didBindServiceWithException:e];
        }
    } else if (connection.method == AnIMMethodUnbindService) {
        if ([_delegate respondsToSelector:@selector(anIM:didUnbindServiceWithException:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_BIND_SERVICE message:errorMessage];
            }
            [_delegate anIM:self didUnbindServiceWithException:e];
        }
    } else if (connection.method == AnIMMethodSendNoticeClient) {
        if (success) {
            if ([_delegate respondsToSelector:@selector(anIM:messageSent:at:)]) {
                [_delegate anIM:self messageSent:connection.anMsgId at:timestamp];
            }
        } else {
            if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_SEND_NOTICE message:errorMessage];
                [_delegate anIM:self sendReturnedException:e messageId:connection.anMsgId];
            }
        }
    } else if (connection.method == AnIMMethodSendNoticeTopic) {
        if (success) {
            if ([_delegate respondsToSelector:@selector(anIM:messageSent:at:)]) {
                [_delegate anIM:self messageSent:connection.anMsgId at:timestamp];
            }
        } else {
            if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_SEND_NOTICE message:errorMessage];
                [_delegate anIM:self sendReturnedException:e messageId:connection.anMsgId];
            }
        }
    } else if (connection.method == AnIMMethodGetTopicInfo) {
        if ([_delegate respondsToSelector:@selector(anIM:didGetTopicInfo:name:parties:createdDate:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_INFO message:errorMessage];
            }
            [_delegate anIM:self didGetTopicInfo:topicId name:topicName parties:parties createdDate:createdDate exception:e];
        }
    } else if (connection.method == AnIMMethodGetTopicList) {
        if ([_delegate respondsToSelector:@selector(anIM:didGetTopicList:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LIST message:errorMessage];
            }
            [_delegate anIM:self didGetTopicList:topicList exception:e];
        }
    } else if (connection.method == AnIMMethodGetTopicLog) {
        if ([_delegate respondsToSelector:@selector(anIM:didGetTopicLog:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_TOPIC_LOG message:errorMessage];
            }
            [_delegate anIM:self didGetTopicLog:topicList exception:e];
        }
    } else if (connection.method == AnIMMethodGetClientsStatus) {
        if ([_delegate respondsToSelector:@selector(anIM:didGetClientsStatus:exception:)]) {
            if (!success) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_CLIENTS_STATUS message:errorMessage];
            }
            [_delegate anIM:self didGetClientsStatus:statusDict exception:e];
        }
    } else if (connection.method == AnIMMethodGetSessionInfo) {
        if (success) {
            [AnIMUtils writeParties:parties sessionKey:sessionId];
        }
        if (connection.stringMessage != nil) {
            // it is a incoming message, new session for the receiver
            if (success) {
                if(connection.stringMessage) {
                    [self newMessage:_mClient data:[connection.stringMessage dataUsingEncoding:NSUTF8StringEncoding] onTopic:nil qos:2 retained:YES mid:0];
                }
            } else {
//                [self _triggerCallbackWithNilParties:connection.stringMessage];
            }
            
        } else {
            // SDK getSessionInfo triggerred
            if ([_delegate respondsToSelector:@selector(anIM:didGetSessionInfo:parties:exception:)]) {
                if (!success) {
                    e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_GET_SESSION_INFO message:errorMessage];
                }
                [_delegate anIM:self didGetSessionInfo:connection.sessionKey parties:parties exception:e];
            }
        }
        
    } else if (connection.method == AnIMMethodCreateSession) {
        if (success) {
            NSString *str = nil;
            if (connection.binary != nil) {
                // sendBinary
                str = [self _sendBinary:connection.binary fileType:connection.fileType customData:connection.customData toSessionKey:connection.sessionKey needReceiveACK:connection.need messageId:connection.anMsgId];
            } else  if (connection.stringMessage != nil) {
                // sendMessage
                str = [self _sendMessage:connection.stringMessage customData:connection.customData toSessionKey:connection.sessionKey needReceiveACK:connection.need messageId:connection.anMsgId];
            } else {
                // sendReadACK
                str = [self _sendReadACK:connection.fileType toSessionKey:connection.sessionKey messageId:connection.anMsgId];
            }
            
            if (str == nil) {
                if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
                    e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_SEND message:@"connection error"];
                    [_delegate anIM:self sendReturnedException:e messageId:connection.anMsgId];
                }
            }
        } else {
            [AnIMUtils removeSession:connection.sessionKey];
            if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
                e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_SEND message:@"connection error"];
                [_delegate anIM:self sendReturnedException:e messageId:connection.anMsgId];
            }
        }
    }
}

- (void)_sendHTTPRequest:(NSString *)urlString method:(AnIMMethod)method clientIds:(NSSet *)clientIds topic:(NSString *)topic service:(NSString *)service anid:(NSString *)anid appKey:(NSString *)appKey deviceType:(NSString *)deviceType notice:(NSString *)notice customData:(NSDictionary *)customData pushKey:(NSString *)pushKey bind:(BOOL)bind start:(NSDate *)start end:(NSDate *)end anMsgId:(NSString *)anMsgId needReadACK:(BOOL)need sessionKey:(NSString *)sessionKey message:(NSString *)mosq_msg binary:(NSData *)binary owner:(NSString *)owner
{
    [self _sendHTTPRequest:urlString method:method clientIds:clientIds topic:topic service:service anid:anid appKey:appKey deviceType:deviceType notice:notice customData:customData pushKey:pushKey bind:bind start:start end:end anMsgId:anMsgId needReadACK:need sessionKey:sessionKey message:mosq_msg binary:binary owner:owner topicName:nil];
}

- (void)_sendHTTPRequest:(NSString *)urlString method:(AnIMMethod)method clientIds:(NSSet *)clientIds topic:(NSString *)topic service:(NSString *)service anid:(NSString *)anid appKey:(NSString *)appKey deviceType:(NSString *)deviceType notice:(NSString *)notice customData:(NSDictionary *)customData pushKey:(NSString *)pushKey bind:(BOOL)bind start:(NSDate *)start end:(NSDate *)end anMsgId:(NSString *)anMsgId needReadACK:(BOOL)need sessionKey:(NSString *)sessionKey message:(NSString *)mosq_msg binary:(NSData *)binary owner:(NSString *)owner topicName:(NSString *)name
{
    NSURL *url = [NSURL URLWithString:urlString];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    
    if (method == AnIMMethodBindService || method == AnIMMethodUnbindService) {
        
        NSString *bodyString = nil;
        //        NSString *clientIdsString = [clientIds componentsJoinedByString:@","];
        NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
        NSDateFormatter* df = [[NSDateFormatter alloc]init];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
        NSDate *date = [NSDate date];
        NSString *dateString = [df stringFromDate:date];
        NSString *bindString = bind==YES?@"true":@"false";
        NSString *signature = AnIMOAuthorizationSignature(method, appKey, topic, clientIdsString, dateString, anid, service, deviceType, pushKey, bindString);
        signature = [AnIMUtils encodeString:signature];
        dateString = [AnIMUtils encodeString:dateString];
        
        switch (method) {
            case AnIMMethodBindService:
                bodyString = [NSString stringWithFormat:bindServiceBodyFormat, bindString, anid, pushKey, clientIdsString, dateString, service, deviceType, signature];
                break;
            case AnIMMethodUnbindService:
                bodyString = [NSString stringWithFormat:unbindServiceBodyFormat, bindString, clientIdsString, dateString, service, deviceType, signature];
                break;
                
            default:
                break;
        }
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodCreateTopic) {
        //        NSString *clientIdsString = [clientIds componentsJoinedByString:@","];
        NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
        NSString *bodyString;
        if(owner == nil)
        {
            bodyString = [NSString stringWithFormat:createTopicWithClientsBodyFormat, clientIdsString, topic];
        }
        else
        {
            bodyString = [NSString stringWithFormat:createTopicWithClientsAndOwnerBodyFormat, clientIdsString, topic, owner];
        }
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodUpdateTopic) {
        NSString *bodyString;
        bodyString = [NSString stringWithFormat:@"id=%@", topic];
        if(owner != nil)
        {
            bodyString = [bodyString stringByAppendingString:[NSString stringWithFormat:@"&owner=%@", owner]];
        }
        if(name != nil)
        {
            bodyString = [bodyString stringByAppendingString:[NSString stringWithFormat:@"&name=%@", name]];
        }
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodAddClients) {
        //        NSString *clientIdsString = [clientIds componentsJoinedByString:@","];
        NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
        NSString *bodyString = [NSString stringWithFormat:addClientsBodyFormat, clientIdsString, topic];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodRemoveClients) {
        //        NSString *clientIdsString = [clientIds componentsJoinedByString:@","];
        NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
        NSString *bodyString = [NSString stringWithFormat:removeClientsBodyFormat, clientIdsString, topic];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodRemoveTopic) {
        NSString *bodyString = [NSString stringWithFormat:removeTopicWithIdFormat, topic];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodSendNoticeClient) {
        //        NSString *clientIdsString = [clientIds componentsJoinedByString:@","];
        NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
        NSString *bodyString;
        NSString *needString = need ? @"true" : @"false";
        
        NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
        notice = [notice stringByReplacingOccurrencesOfString:@"\\u" withString:@"\\u]"];
        NSDictionary *convertedCustomData = [self converCustomDataToString:customData];
        notice = [ANEmojiUtil emojiConvertToString:notice];
        [params setObject:notice forKey:@"notice"];
        [params setObject:_mClient.clientId forKey:@"from"];
        [params setObject:clientIdsString forKey:@"client"];
        [params setObject:needString forKey:@"receive_ack"];
        [params setObject:anMsgId forKey:@"msg_id"];
        NSDateFormatter* df = [[NSDateFormatter alloc]init];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
        NSDate *date = [NSDate date];
        NSString *dateString = [df stringFromDate:date];
        [params setObject:dateString forKey:@"date"];
        [params setObject:_appKey forKey:@"key"];
        dateString = [AnIMUtils encodeString:dateString];
        
        if (convertedCustomData) {
            [params setObject:[AnIMUtils getJsonStringFromDict:convertedCustomData] forKey:@"custom_data"];
            NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, noticeEndPoint], params);
            signature = [AnIMUtils encodeString:signature];
            bodyString = [NSString stringWithFormat:noticeClientCustomDataBodyFormat, notice, [AnIMUtils getJsonStringFromDict:convertedCustomData], _mClient.clientId, clientIdsString, needString, anMsgId, signature, dateString];
        } else {
            NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, noticeEndPoint], params);
            signature = [AnIMUtils encodeString:signature];
            bodyString = [NSString stringWithFormat:noticeClientBodyFormat, notice, _mClient.clientId, clientIdsString, needString, anMsgId, signature, dateString];
        }
        
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodSendNoticeTopic) {
        NSString *bodyString;
        NSString *needString = need ? @"true" : @"false";
        
        NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
        notice = [notice stringByReplacingOccurrencesOfString:@"\\u" withString:@"\\u]"];
        NSDictionary *convertedCustomData = [self converCustomDataToString:customData];
        notice = [ANEmojiUtil emojiConvertToString:notice];
        [params setObject:notice forKey:@"notice"];
        [params setObject:_mClient.clientId forKey:@"from"];
        [params setObject:topic forKey:@"topic"];
        [params setObject:needString forKey:@"receive_ack"];
        [params setObject:anMsgId forKey:@"msg_id"];
        NSDateFormatter* df = [[NSDateFormatter alloc]init];
        [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
        NSDate *date = [NSDate date];
        NSString *dateString = [df stringFromDate:date];
        [params setObject:dateString forKey:@"date"];
        [params setObject:_appKey forKey:@"key"];
        dateString = [AnIMUtils encodeString:dateString];
        
        if (convertedCustomData) {
            [params setObject:[AnIMUtils getJsonStringFromDict:convertedCustomData] forKey:@"custom_data"];
            NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, noticeEndPoint], params);
            signature = [AnIMUtils encodeString:signature];
            bodyString = [NSString stringWithFormat:noticeTopicCustomDataBodyFormat, notice, [AnIMUtils getJsonStringFromDict:convertedCustomData], _mClient.clientId, topic, needString, anMsgId, signature, dateString];
        } else {
            NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, noticeEndPoint], params);
            signature = [AnIMUtils encodeString:signature];
            bodyString = [NSString stringWithFormat:noticeTopicBodyFormat, notice, _mClient.clientId, topic, needString, anMsgId, signature, dateString];
        }
        
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    } else if (method == AnIMMethodCreateSession) {
        NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
        NSString *bodyString = [NSString stringWithFormat:createSessionWithClientsBodyFormat, sessionKey, clientIdsString];
        [request setHTTPMethod:@"POST"];
        [request setHTTPBody:[bodyString dataUsingEncoding:NSUTF8StringEncoding]];
    }
    
    AnIMURLConnection *connection = [[AnIMURLConnection alloc] initWithRequest:request delegate:self];
    connection.method = method;
    connection.anMsgId = anMsgId;
    connection.sessionKey = sessionKey;
    if (mosq_msg != nil) {
        connection.stringMessage = [NSString stringWithString:mosq_msg];
    }
    if (method == AnIMMethodCreateSession) {
        connection.sessionKey = sessionKey;
        connection.stringMessage = notice;
        connection.binary = binary;
        connection.customData = customData;
        connection.fileType = deviceType;
        connection.need = need;
    }
    
    [connection start];
}

- (void)_getClientId:(NSString *)userId __attribute__((deprecated))
{
    NSString *urlString = [NSString stringWithFormat:_getTokenURLFormat, _appKey, [AnIMUtils encodeString:userId]];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetToken clientIds:nil topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getHost:(NSString *)clientId
{
    NSString *urlString = [NSString stringWithFormat:_getHostURLFormat, clientId];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetHost clientIds:nil topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getSessionInfo:(NSString *)sessionKey message:(NSString *)mosq_msg
{
    NSString *urlString = [NSString stringWithFormat:_sessionInfoURLFormat, _appKey, sessionKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetSessionInfo clientIds:nil topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:sessionKey message:(NSString *)mosq_msg binary:nil owner:nil];
}

- (void)_createSession:(NSString *)sessionKey withClients:(NSSet *)clientIds stringMessage:(NSString *)stringMessage data:(NSData *)data customData:(NSDictionary *)customData fileType:(NSString *)fileType needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    NSString *urlString = [NSString stringWithFormat:_createSessionURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodCreateSession clientIds:clientIds topic:nil service:nil anid:nil appKey:_appKey deviceType:fileType notice:stringMessage customData:customData pushKey:nil bind:NO start:nil end:nil anMsgId:anMsgId needReadACK:need sessionKey:sessionKey message:nil binary:data owner:nil];
    
    [AnIMUtils writeParties:clientIds sessionKey:sessionKey];
}

- (void)_sendFirstMessage:(NSString *)message customData:(NSDictionary *)customData sessionKey:(NSString *)sessionKey toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    [self _createSession:sessionKey withClients:parties stringMessage:message data:nil customData:customData fileType:nil needReceiveACK:need messageId:anMsgId];
}

- (void)_sendFirstBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData sessionKey:(NSString *)sessionKey toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    [self _createSession:sessionKey withClients:parties stringMessage:nil data:data customData:customData fileType:fileType needReceiveACK:need messageId:anMsgId];
}

- (void)_sendFirstReadACK:(NSString *)messageId toClients:(NSSet *)clientIds sessionKey:(NSString *)sessionKey messageId:(NSString *)anMsgId
{
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    [self _createSession:sessionKey withClients:parties stringMessage:nil data:nil customData:nil fileType:messageId needReceiveACK:NO messageId:anMsgId];
}

- (NSString *)_sendMessage:(NSString *)message customData:(NSDictionary *)customData toSessionKey:(NSString *)sessionKey needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, message, @"1", anMsgId, [NSNumber numberWithBool:need]] forKeys:@[@"session_key", @"message", @"msg_type", @"msg_id", @"receiveACK"]];
    [dict setObject:_appKey forKey:@"app_key"];
    if (customData) {
        [dict setObject:customData forKey:@"customData"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (NSString *)_sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toSessionKey:(NSString *)sessionKey needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSString *base64String = [ANBase64Wrapper base64EncodedString:data];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, base64String, fileType, @"2", anMsgId, [NSNumber numberWithBool:need]] forKeys:@[@"session_key", @"message", @"fileType", @"msg_type", @"msg_id", @"receiveACK"]];
    [dict setObject:_appKey forKey:@"app_key"];
    if (customData) {
        [dict setObject:customData forKey:@"customData"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (NSString *)_sendReadACK:(NSString *)messageId toSessionKey:(NSString *)sessionKey messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, messageId, @"12"] forKeys:@[@"session_key", @"msg_id", @"msg_type"]];
    [dict setObject:_appKey forKey:@"app_key"];
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (NSString *)_sendMessage:(NSString *)message customData:(NSDictionary *)customData toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    message = [message stringByReplacingOccurrencesOfString:@"\\u" withString:@"\\u]"];
    message = [ANEmojiUtil emojiConvertToString:message];
    NSDictionary *convertedCustomData = [self converCustomDataToString:customData];
    
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    NSString *sessionKey = [AnIMUtils generateSessionKey:parties];
    if ([AnIMUtils readParties:sessionKey] == nil) {
        [self _sendFirstMessage:message customData:convertedCustomData sessionKey:sessionKey toClients:clientIds needReceiveACK:need messageId:anMsgId];
        return anMsgId;
    }
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, message, @"1", anMsgId, [NSNumber numberWithBool:need]] forKeys:@[@"session_key", @"message", @"msg_type", @"msg_id", @"receiveACK"]];
    [dict setObject:_appKey forKey:@"app_key"];
    if (convertedCustomData) {
        [dict setObject:convertedCustomData forKey:@"customData"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (NSString *)_sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    NSString *sessionKey = [AnIMUtils generateSessionKey:parties];
    if ([AnIMUtils readParties:sessionKey] == nil) {
        [self _sendFirstBinary:data fileType:fileType customData:customData sessionKey:sessionKey toClients:clientIds needReceiveACK:need messageId:anMsgId];
        return anMsgId;
    }
    
    NSString *base64String = [ANBase64Wrapper base64EncodedString:data];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, base64String, fileType, @"2", anMsgId, [NSNumber numberWithBool:need]] forKeys:@[@"session_key", @"message", @"fileType", @"msg_type", @"msg_id", @"receiveACK"]];
    [dict setObject:_appKey forKey:@"app_key"];
    if (customData) {
        [dict setObject:customData forKey:@"customData"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (void)_createTopic:(NSString *)topic withClients:(NSSet *)clientIds withOwner:(NSString *)owner __attribute__((deprecated))
{
    NSString *urlString = [NSString stringWithFormat:_createTopicWithClientsURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodCreateTopic clientIds:clientIds topic:topic service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:owner];
}

- (void)_updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner
{
    NSString *urlString = [NSString stringWithFormat:_updateTopicURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodUpdateTopic clientIds:nil topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:owner topicName:topicName];
}

- (void)_addClients:(NSSet *)clientIds toTopicId:(NSString *)topicId
{
    NSString *urlString = [NSString stringWithFormat:_addClientsURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodAddClients clientIds:clientIds topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_removeClients:(NSSet *)clientIds fromTopicId:(NSString *)topicId
{
    NSString *urlString = [NSString stringWithFormat:_removeClientsURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodRemoveClients clientIds:clientIds topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_removeTopic:(NSString *)topicId
{
    NSString *urlString = [NSString stringWithFormat:_removeTopicURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodRemoveTopic clientIds:nil topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (NSString *)_sendMessage:(NSString *)message customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId mentionedClientIds:(NSSet*)clientIds
{
    if(!_status)
    {
        return nil;
    }
    
    message = [message stringByReplacingOccurrencesOfString:@"\\u" withString:@"\\u]"];
    message = [ANEmojiUtil emojiConvertToString:message];
    NSDictionary *convertedCustomData = [self converCustomDataToString:customData];
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[topicId, message, @"3", anMsgId, [NSNumber numberWithBool:need]] forKeys:@[@"topic", @"message", @"msg_type", @"msg_id", @"receiveACK"]];
    [dict setObject:_appKey forKey:@"app_key"];
    if (convertedCustomData) {
        [dict setObject:convertedCustomData forKey:@"customData"];
    }
    if (clientIds) {
        [dict setObject:[clientIds allObjects] forKey:@"mlist"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (NSString *)_sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSString *base64String = [ANBase64Wrapper base64EncodedString:data];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[topicId, base64String, fileType, @"4", anMsgId, [NSNumber numberWithBool:need]] forKeys:@[@"topic", @"message", @"fileType", @"msg_type", @"msg_id", @"receiveACK"]];
    [dict setObject:_appKey forKey:@"app_key"];
    if (customData) {
        [dict setObject:customData forKey:@"customData"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (void)_bindAnPushService:(NSString *)anid appKey:(NSString *)appKey deviceType:(AnPushType)deviceType
{
    NSString *urlString = [NSString stringWithFormat:_bindServiceURLFormat, _appKey];
    NSString *deviceTypeString;
    switch (deviceType) {
        case AnPushTypeAndroid:
            deviceTypeString = @"android";
            break;
        case AnPushTypeiOS:
            deviceTypeString = @"ios";
            break;
        case AnPushTypeWP8:
            deviceTypeString = @"wp8";
            break;
            
        default:
            break;
    }
    //    [self _sendHTTPRequest:urlString method:AnIMMethodBindService clientIds:@[_mClient.clientId] topic:nil service:@"anpush" anid:anid appKey:_appKey deviceType:deviceTypeString notice:nil customData:nil pushKey:appKey bind:YES start:nil end:nil anMsgId:0 needReadACK:NO];
    [self _sendHTTPRequest:urlString method:AnIMMethodBindService clientIds:[NSSet setWithObject:_mClient.clientId] topic:nil service:@"anpush" anid:anid appKey:_appKey deviceType:deviceTypeString notice:nil customData:nil pushKey:appKey bind:YES start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_unbindAnPushService:(AnPushType)deviceType
{
    NSString *urlString = [NSString stringWithFormat:_bindServiceURLFormat, _appKey];
    NSString *deviceTypeString;
    switch (deviceType) {
        case AnPushTypeAndroid:
            deviceTypeString = @"android";
            break;
        case AnPushTypeiOS:
            deviceTypeString = @"ios";
            break;
        case AnPushTypeWP8:
            deviceTypeString = @"wp8";
            break;
            
        default:
            break;
    }
    //    [self _sendHTTPRequest:urlString method:AnIMMethodUnbindService clientIds:@[_mClient.clientId] topic:nil service:@"anpush" anid:nil appKey:_appKey deviceType:deviceTypeString notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO];
    [self _sendHTTPRequest:urlString method:AnIMMethodUnbindService clientIds:[NSSet setWithObject:_mClient.clientId] topic:nil service:@"anpush" anid:nil appKey:_appKey deviceType:deviceTypeString notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (NSString *)_sendNotice:(NSString *)notice customData:(NSDictionary *)customData toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    NSString *urlString = [NSString stringWithFormat:_noticeURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodSendNoticeClient clientIds:clientIds topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:notice customData:customData pushKey:nil bind:NO start:nil end:nil anMsgId:anMsgId needReadACK:need sessionKey:nil message:nil binary:nil owner:nil];
    return anMsgId;
}

- (NSString *)_sendNotice:(NSString *)notice customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need messageId:(NSString *)anMsgId
{
    NSString *urlString = [NSString stringWithFormat:_noticeURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodSendNoticeTopic clientIds:nil topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:notice customData:customData pushKey:nil bind:NO start:nil end:nil anMsgId:anMsgId needReadACK:need sessionKey:nil message:nil binary:nil owner:nil];
    return anMsgId;
}

- (void)_getTopicInfo:(NSString *)topicId
{
    NSString *urlString = [NSString stringWithFormat:_topicInfoURLFormat, _appKey, topicId];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetTopicInfo clientIds:nil topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getTopicLog:(NSString *)topicId start:(NSDate *)start end:(NSDate *)end
{
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSString *startString = [df stringFromDate:start];
    NSString *endString = [df stringFromDate:end];
    NSString *urlString = [NSString stringWithFormat:_topicLogURLFormat, _appKey, topicId, startString, endString];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetTopicLog clientIds:nil topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:start end:end anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getAllTopics
{
    NSString *urlString = [NSString stringWithFormat:_topicListAllURLFormat, _appKey];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetTopicList clientIds:nil topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getMyTopics
{
    NSString *urlString = [NSString stringWithFormat:_topicListMineURLFormat, _appKey, _mClient.clientId];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetTopicList clientIds:nil topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getClientsStatus:(NSSet *)clientIds
{
    //    NSString *urlString = [NSString stringWithFormat:_clientsStatusURLFormat, _appKey, [clientIds componentsJoinedByString:@","]];
    //    [self _sendHTTPRequest:urlString method:AnIMMethodGetClientsStatus clientIds:clientIds topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO];
    NSString *urlString = [NSString stringWithFormat:_clientsStatusURLFormat, _appKey, [[clientIds allObjects] componentsJoinedByString:@","]];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetClientsStatus clientIds:clientIds topic:nil service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_getClientsStatusOfTopic:(NSString *)topicId
{
    NSString *urlString = [NSString stringWithFormat:_topicStatusURLFormat, _appKey, topicId];
    [self _sendHTTPRequest:urlString method:AnIMMethodGetClientsStatus clientIds:nil topic:topicId service:nil anid:nil appKey:_appKey deviceType:nil notice:nil customData:nil pushKey:nil bind:NO start:nil end:nil anMsgId:0 needReadACK:NO sessionKey:nil message:nil binary:nil owner:nil];
}

- (void)_initializeMQTTClient:(NSString *)clientId
{
    if(!_mClient) {
        _mClient = [ANMQTTSession alloc];
    }
    
    _mClient.clientId = clientId;
    _mClient.keepAliveInterval = 60;
    _mClient.cleanSessionFlag = YES;
    _mClient.willFlag = NO;
    _mClient.willTopic = nil;
    _mClient.willMsg = nil;
    _mClient.willQoS = ANMQTTQosLevelAtMostOnce;
    _mClient.willRetainFlag = FALSE;
    _mClient.protocolLevel = 4;
    _mClient.runLoopMode = nil;
    _mClient.txMsgId = 1;
    _mClient.persistence = [[ANMQTTPersistence alloc] init];
    _mClient.delegate = self;
    _mClient.runLoop = [NSRunLoop currentRunLoop];
    
    NSString *deviceId = [self getDeviceId];
    if(deviceId) {
        _mClient.userName = deviceId;
        _mClient.password = _appKey;
    }
    
    if(_secure) {
//        ANMQTTSSLSecurityPolicy *securityPolicy = [ANMQTTSSLSecurityPolicy policyWithPinningMode:ANMQTTSSLPinningModeNone];
//        securityPolicy.pinnedCertificates = @[[ANBase64Wrapper dataWithBase64EncodedString:ARROWNOCK_SERVER_CERT]];
//        securityPolicy.allowInvalidCertificates = YES;
        
        ANMQTTSSLSecurityPolicy *securityPolicy = [ANMQTTSSLSecurityPolicy policyWithPinningMode:ANMQTTSSLPinningModeCertificate];
        securityPolicy.pinnedCertificates = @[[ANBase64Wrapper dataWithBase64EncodedString:ARROWNOCK_SERVER_CERT]];
        securityPolicy.allowInvalidCertificates = YES;
        
        NSData *pkcs12data = [ANBase64Wrapper dataWithBase64EncodedString:ARROWNOCK_CLIENT_P12];
        CFArrayRef keyref = NULL;
        OSStatus importStatus = SecPKCS12Import((__bridge CFDataRef)pkcs12data, (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:@"" forKey:(__bridge id)kSecImportExportPassphrase], &keyref);
        if (importStatus != noErr) {
            NSLog(@"Error while initilizing AnIM SSL [%d]", (int)importStatus);
            return;
        }
    
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(keyref, 0);
        if (!identityDict) {
            NSLog(@"Error while initilizing AnIM SSL");
            return;
        }
    
        SecIdentityRef identityRef = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        if (!identityRef) {
            NSLog(@"Error while initilizing AnIM SSL: could not CFDictionaryGetValue");
            return;
        };
    
        SecCertificateRef cert = NULL;
        OSStatus status = SecIdentityCopyCertificate(identityRef, &cert);
        if (status != noErr) {
            NSLog(@"Error while initilizing AnIM SSL: SecIdentityCopyCertificate failed [%d]", (int)status);
            return;
        }
        NSArray *clientCerts = [[NSArray alloc] initWithObjects:(__bridge id)identityRef, (__bridge id)cert, nil];
        
        _mClient.securityPolicy = securityPolicy;
        _mClient.certificates = clientCerts;
    }
}

- (void)_connect:(NSDictionary *)hostDict clientId:(NSString *)clientId
{
    if (_status == YES) {
        if (_delegate && [_delegate respondsToSelector:@selector(anIM:didUpdateStatus:exception:)]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [_delegate anIM:self didUpdateStatus:YES exception:nil];
            });
        }
        return;
    }
    
    NSString *host = [hostDict objectForKey:@"host"];
    NSString *port;
    
    if (_secure) {
        port = [hostDict objectForKey:@"secure_port"];
    } else {
        port = [hostDict objectForKey:@"port"];
    }
    
    if(!clientThread) {
        clientThread = [[NSThread alloc] initWithTarget:self selector:@selector(clientThreadLoop:) object:nil];
        [clientThread start];
    }
    [self performSelector:@selector(_doActualConnect:) onThread:clientThread withObject:@[clientId, host, port] waitUntilDone:NO];
}

- (void)clientThreadLoop:(id)unused {
    do {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
    } while (YES);
}

- (void)_doActualConnect:(id)connectInfo
{
    BOOL go = YES;
    if(_mClient) {
        NSLog(@"Do connection, current client status: %d", _mClient.status);
        if(_mClient.status == ANMQTTSessionStatusCreated ||
           _mClient.status == ANMQTTSessionStatusConnecting ||
           _mClient.status == ANMQTTSessionStatusConnected) {
            NSLog(@"Dulicated IM connect request detected. Ignoring...  status: %d", _mClient.status);
            go = NO;
        }
    }
    if(go) {
        NSArray *info = (NSArray *)connectInfo;
        [self _initializeMQTTClient:[connectInfo objectAtIndex:0]];
        [_mClient connectToHost:[info objectAtIndex:1] port:[[info objectAtIndex:2] intValue] usingSSL:_secure];
    }
}

- (void)_reconnect
{
    [self _initWithAppKey:_appKey delegate:_delegate secure:_secure reset:YES];
    [self connect:_clientId];
}

- (NSString *)_sendReadACK:(NSString *)messageId toClients:(NSSet *)clientIds messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    NSString *sessionKey = [AnIMUtils generateSessionKey:parties];
    if ([AnIMUtils readParties:sessionKey] == nil) {
        [self _sendFirstReadACK:messageId toClients:clientIds sessionKey:sessionKey messageId:anMsgId];
        return anMsgId;
    }
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, messageId, @"12"] forKeys:@[@"session_key", @"msg_id", @"msg_type"]];
    [dict setObject:_appKey forKey:@"app_key"];
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    return anMsgId;
}

- (NSString *)_sendReadACKBatch:(NSSet *)messageIds toClients:(NSSet *)clientIds messageId:(NSString *)anMsgId
{
    if(!_status)
    {
        return nil;
    }
    NSMutableSet *parties = [NSMutableSet setWithSet:clientIds];
    [parties addObject:_mClient.clientId];
    NSString *sessionKey = [AnIMUtils generateSessionKey:parties];
    if ([AnIMUtils readParties:sessionKey] == nil) {
        [self _sendFirstReadACK:@"" toClients:clientIds sessionKey:sessionKey messageId:anMsgId];
        return anMsgId;
    }
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[sessionKey, [messageIds allObjects], @"12"] forKeys:@[@"session_key", @"msg_id", @"msg_type"]];
    [dict setObject:_appKey forKey:@"app_key"];
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    [self _publishMessage:jsonString topic:[NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey] messageId:anMsgId];
    
    return anMsgId;
}

- (void)_triggerCallbackWithNilParties:(NSString *)payload
{
    /*
    NSDictionary *dict = [AnIMUtils getDictFromJsonString:payload];
    NSString *from = [dict objectForKey:@"from"];
    NSString *message = [dict objectForKey:@"message"];
    NSString *anMsgId = [dict objectForKey:@"msg_id"];
    NSString *fileType = [dict objectForKey:@"fileType"];
    NSDictionary *customData = [dict objectForKey:@"customData"];
    NSInteger type = [[dict objectForKey:@"msg_type"] intValue];
     */
    /*
    switch (type) {
        case 1:
            if ([_delegate respondsToSelector:@selector(anIM:didReceiveMessage:customData:from:parties:messageId:)]) {
                [_delegate anIM:self didReceiveMessage:message customData:customData from:from parties:nil messageId:anMsgId];
            }
            break;
        case 2:
            if ([_delegate respondsToSelector:@selector(anIM:didReceiveBinary:fileType:customData:from:parties:messageId:)]) {
                NSData *data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                [_delegate anIM:self didReceiveBinary:data fileType:fileType customData:customData from:from parties:nil messageId:anMsgId];
            }
            break;
            
        default:
            break;
    }
     */
}

- (void)_handleSendFailed:(NSString *)anMsgId {
    if ([anMsgId hasPrefix:@"D"]) {
        if ([_deskMessageDelegate respondsToSelector:@selector(sendReturnedException:messageId:)]) {
            double delayInSeconds = 0.1;
            dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
            dispatch_after(popTime, dispatch_get_main_queue(), ^(void) {
                ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_SEND message:@"failed to send"];
                [_deskMessageDelegate sendReturnedException:e messageId:anMsgId];
            });
        }
    } else {
        if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
            double delayInSeconds = 0.1;
            dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
            dispatch_after(popTime, dispatch_get_main_queue(), ^(void) {
                ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:IM_FAILED_SEND message:@"failed to send"];
                [_delegate anIM:self sendReturnedException:e messageId:anMsgId];
            });
        }
    }
}

- (void)_handleSendFailed:(NSString *)anMsgId code:(NSUInteger)code errorMessage:(NSString *)errorMessage {
    if ([anMsgId hasPrefix:@"D"]) {
        if ([_deskMessageDelegate respondsToSelector:@selector(sendReturnedException:messageId:)]) {
            double delayInSeconds = 0.1;
            dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
            dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
                ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:code message:errorMessage];
                [_deskMessageDelegate sendReturnedException:e messageId:anMsgId];
            });
        }
    } else {
        if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
            double delayInSeconds = 0.1;
            dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
            dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
                ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:code message:errorMessage];
                [_delegate anIM:self sendReturnedException:e messageId:anMsgId];
            });
        }
    }
    
}

- (void)_sendPushNotificationSettingsRequest:(NSString *)clientId type:(int)type isEnable:(BOOL)isEnable topicIds:(NSSet*)topicIds success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"anpush" forKey:@"service"];
    [params setObject:clientId forKey:@"client"];
    [params setObject:[[NSString alloc ]initWithFormat:@"%d", type] forKey:@"type"];
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    
    NSString *enableString = isEnable==YES?@"true":@"false";
    NSString* topicString = [[topicIds allObjects] componentsJoinedByString:@","];
    
    NSString *signatureBaseString;
    
    switch(type)
    {
        case 1:
        case 2:
        case 3:
        case 6:
            [params setObject:enableString forKey:@"value"];
            signatureBaseString = [NSString stringWithFormat:@"/%@/im/signed_push_settings.jsonclient=%@&date=%@&key=%@&service=%@&type=%d&value=%@",
                                   ARROWNOCK_API_VERSION,
                                   clientId,
                                   dateString,
                                   _appKey,
                                   @"anpush",
                                   type,
                                   enableString];
            break;
        case 4:
        case 5:
            [params setObject:topicString forKey:@"value"];
            signatureBaseString = [NSString stringWithFormat:@"/%@/im/signed_push_settings.jsonclient=%@&date=%@&key=%@&service=%@&type=%d&value=%@",
                                   ARROWNOCK_API_VERSION,
                                   clientId,
                                   dateString,
                                   _appKey,
                                   @"anpush",
                                   type,
                                   topicString];
            break;
    }
    
    NSString *signature = [[[ANOAHMAC_SHA1SignatureProvider alloc] init] signClearText:signatureBaseString withSecret:ARROWNOCK_API_SECRET];
    signature = [AnIMUtils encodeString:signature];
    [params setValue:signature forKey:@"signature"];
    
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
        
    if(_httpClient)
    {
        [_httpClient sendPushNotificationSettingsRequest:params url:_pushSettingsURLFormat success:success failure:failure];
    }
}

-(void) _publishMessage:(NSString *)json topic:(NSString *)topic messageId:(NSString *)messageId
{
    if(clientThread)
    {
        [self performSelector:@selector(_publishMessageInThread:) onThread:clientThread withObject:@[json, topic, messageId] waitUntilDone:NO];
    }
}

-(void) _publishMessageInThread:(id)data
{
    if(data) {
        NSArray *dataArray = (NSArray *)data;
        [_mClient publishData:[dataArray[0] dataUsingEncoding:NSUTF8StringEncoding] onTopic:dataArray[1] retain:YES qos:ANMQTTQosLevelExactlyOnce messageId:dataArray[2]];
    }
}

-(void) _publishMessageInThreadWithQoS1:(id)data
{
    if(data) {
        NSArray *dataArray = (NSArray *)data;
        [_mClient publishData:[dataArray[0] dataUsingEncoding:NSUTF8StringEncoding] onTopic:dataArray[1] retain:YES qos:ANMQTTQosLevelAtLeastOnce messageId:dataArray[2]];
    }
}

- (NSDictionary *) converCustomDataToString:(NSDictionary *)customData
{
    if (customData && ![customData isKindOfClass:[NSNull class]]) {
        NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
        for (NSString *key in customData) {
            id value = [customData objectForKey:key];
            if ([value isKindOfClass:[NSString class]]) {
                NSString *strValue = (NSString *)value;
                strValue = [strValue stringByReplacingOccurrencesOfString:@"\\u" withString:@"\\u]"];
                value = [ANEmojiUtil emojiConvertToString:strValue];
            }
            if(value) {
                [dict setObject:value forKey:key];
            } else {
                [dict setObject:[NSNull null] forKey:key];
            }
        }
        return dict;
    } else {
        return nil;
    }
}

- (NSDictionary *) converCustomDataToEmoji:(NSDictionary *)customData
{
    if (customData && ![customData isKindOfClass:[NSNull class]]) {
        NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
        for (NSString *key in customData) {
            id value = [customData objectForKey:key];
            if ([value isKindOfClass:[NSString class]]) {
                NSString *strValue = (NSString *)value;
                value = [ANEmojiUtil stringConvertToEmoji:strValue];
            }
            if(value) {
                [dict setObject:value forKey:key];
            } else {
                [dict setObject:[NSNull null] forKey:key];
            }
        }
        return dict;
    } else {
        return nil;
    }
}


#pragma mark - API Methods

- (AnIM *)initWithAppKey:(NSString *)appKey delegate:(id<AnIMDelegate>)delegate secure:(BOOL)secure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (appKey == nil) {
        message = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
#ifdef DM_ENABLED
    if (appKey != nil) {
        [ANDeviceManager initializeWithAppKey:appKey secure:secure];
    }
#endif
    return [self _initWithAppKey:appKey delegate:delegate secure:secure reset:NO];
}

- (void)setDeskMessageDelegate:(id <AnDeskMessageDelegate>)delegate
{
    _deskMessageDelegate = delegate;
}

- (void)setGroupediaMessageDelegate:(id <AnGroupediaMessageDelegate>)delegate
{
    _groupediaMessageDelegate = delegate;
}

- (NSString *)getCurrentClientId
{
    return _clientId;
}

- (void)getClientId:(NSString *)userId __attribute__((deprecated))
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (!userId) {
        message = @"invalid userId";
        errorCode = IM_INVALID_USER_ID;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
    }
    
    _userId = userId;
    [self _getClientId:userId];
}

- (void)getClientId:(NSString *)userId success:(void (^)(NSString *clientId))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (!userId) {
        message = @"invalid userId";
        errorCode = IM_INVALID_USER_ID;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:message]);
        }
        return;
    }
    
    _userId = userId;
    NSString *urlString = [NSString stringWithFormat:_getTokenURLFormat, _appKey, [AnIMUtils encodeString:userId]];
    
    if(_httpClient)
    {
        [_httpClient sendGetClientIdRequest:userId url:urlString success:success failure:failure];
    }
}

- (NSString *)getRemoteClientId:(NSString *)userId
{
    NSString * token = [ANTokenHelper getToken:userId appKey:_appKey odd:0 prefix:IM_TOKEN_PREFIX];
    return token;
}

- (void)connect:(NSString *)clientId
{
    NSString *message = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        message = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    }
    if (!clientId) {
        message = @"invalid clientId";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:errorCode message:message];
        dispatch_async(dispatch_get_main_queue(), ^{
            [_delegate anIM:self didUpdateStatus:NO exception:e];
        });
        return;
    }
    _clientId = clientId;
    
    NSDictionary *hostDict = [AnIMUtils readHost:MQTT_HOST_KEY];
    if (hostDict) {
        double expired = [[hostDict objectForKey:@"expiration"] doubleValue];
        double current = [[NSDate date] timeIntervalSince1970]*1000;
        if (expired > current) {
            [self _connect:hostDict clientId:clientId];
            return;
        } else {
            [AnIMUtils removeHost:MQTT_HOST_KEY];
        }
    }
    [self _getHost:clientId];
}

- (void)disconnect
{
    if (_mClient == nil) {
        [self handleEvent:_mClient event:ANMQTTSessionEventConnectionClosed error:nil];
    }
    
    if(clientThread) {
        [self performSelector:@selector(_doActualDisconnect) onThread:clientThread withObject:nil waitUntilDone:NO];
    } else {
        [_mClient close];
    }
}

- (void)_doActualDisconnect
{
    if(_mClient) {
        [_mClient close];
    }
}

- (NSString *)sendMessage:(NSString *)message toClient:(NSString *)clientId needReceiveACK:(BOOL)need
{
    NSSet *clientIds = [NSSet setWithObjects:clientId, nil];
    return [self sendMessage:message toClients:clientIds needReceiveACK:need];
}

- (NSString *)sendMessage:(NSString *)message toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need __attribute__((deprecated))
{
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!message) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendMessage:message customData:nil toClients:clientIds needReceiveACK:need messageId:anMsgId];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    
    return anMsgId;
}

- (NSString *)sendMessage:(NSString *)message customData:(NSDictionary *)customData toClient:(NSString *)clientId needReceiveACK:(BOOL)need
{
    NSSet *clientIds = [NSSet setWithObjects:clientId, nil];
    return [self sendMessage:message customData:customData toClients:clientIds needReceiveACK:need];
}

- (NSString *)sendMessage:(NSString *)message customData:(NSDictionary *)customData toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!message) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!customData) {
        msg = @"invalid customData";
        errorCode = IM_INVALID_CUSTOM_DATA;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendMessage:message customData:customData toClients:clientIds needReceiveACK:need messageId:anMsgId];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return anMsgId;
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType toClient:(NSString *)clientId needReceiveACK:(BOOL)need
{
    NSSet *clientIds = [NSSet setWithObjects:clientId, nil];
    return [self sendBinary:data fileType:fileType toClients:clientIds needReceiveACK:need];
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!data) {
        msg = @"invalid data";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!fileType) {
        msg = @"invalid fileType";
        errorCode = IM_INVALID_FILE_TYPE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendBinary:data fileType:fileType customData:nil toClients:clientIds needReceiveACK:need messageId:anMsgId];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    
    return anMsgId;
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toClient:(NSString *)clientId needReceiveACK:(BOOL)need
{
    NSSet *clientIds = [NSSet setWithObjects:clientId, nil];
    return [self sendBinary:data fileType:fileType customData:customData toClients:clientIds needReceiveACK:need];
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!data) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!fileType) {
        msg = @"invalid fileType";
        errorCode = IM_INVALID_FILE_TYPE;
    } else if (!customData) {
        msg = @"invalid customData";
        errorCode = IM_INVALID_CUSTOM_DATA;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendBinary:data fileType:fileType customData:customData toClients:clientIds needReceiveACK:need messageId:anMsgId];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return anMsgId;
}

- (void)createTopic:(NSString *)topicName __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _createTopic:topicName withClients:[[NSSet alloc] init] withOwner:nil];
}

- (void)createTopic:(NSString *)topicName success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:[[NSSet alloc] init] withOwner:nil customData:nil isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName customData:(NSDictionary *)customData success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:[[NSSet alloc] init] withOwner:nil customData:customData isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName withClients:(NSSet *)clientIds __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:nil];
}

- (void)createTopic:(NSString *)topicName withClients:(NSSet *)clientIds success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:nil customData:nil isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName withClients:(NSSet *)clientIds customData:(NSDictionary *)customData success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:nil customData:customData isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName withOwner:(NSString *)owner withClients:(NSSet *)clientIds __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!owner) {
        msg = @"invalid owner";
        errorCode = IM_INVALID_TOPIC_OWNER;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:owner];
}

- (void)createTopic:(NSString *)topicName withOwner:(NSString *)owner withClients:(NSSet *)clientIds success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!owner) {
        msg = @"invalid owner";
        errorCode = IM_INVALID_TOPIC_OWNER;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:owner customData:nil isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName withOwner:(NSString *)owner withClients:(NSSet *)clientIds customData:(NSDictionary *)customData success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!owner) {
        msg = @"invalid owner";
        errorCode = IM_INVALID_TOPIC_OWNER;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:owner customData:customData isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName withOwner:(NSString *)owner withClients:(NSSet *)clientIds isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!owner) {
        msg = @"invalid owner";
        errorCode = IM_INVALID_TOPIC_OWNER;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:owner customData:nil isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)createTopic:(NSString *)topicName withOwner:(NSString *)owner withClients:(NSSet *)clientIds customData:(NSDictionary *)customData isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicName) {
        msg = @"invalid topicName";
        errorCode = IM_INVALID_TOPIC_NAME;
    } else if (!owner) {
        msg = @"invalid owner";
        errorCode = IM_INVALID_TOPIC_OWNER;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    [self _createTopic:topicName withClients:clientIds withOwner:owner customData:customData isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)_createTopic:(NSString *)topic withClients:(NSSet *)clientIds withOwner:(NSString *)owner customData:(NSDictionary *)customData isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *urlString = [NSString stringWithFormat:_createTopicWithClientsURLFormat, _appKey];
    NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:clientIdsString forKey:@"client"];
    [params setObject:topic forKey:@"name"];
    if(owner != nil)
    {
        [params setObject:owner forKey:@"owner"];
    }
    if (customData) {
        [params setObject:[self dataTojsonString:customData] forKey:@"customData"];
    }
    if(isNeedNotice)
    {
        [params setObject:@"true" forKey:@"is_need_notice"];
        if(currentClientId != nil)
        {
            [params setObject:currentClientId forKey:@"current_client_id"];
        }
        NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
        [params setObject:anMsgId forKey:@"msg_id"];
    }
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, createTopicEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendCreateTopicRequest:params url:urlString success:success failure:failure];
    }
}

-(NSString*)dataTojsonString:(NSDictionary *)object
{
    NSString *jsonString = nil;
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:object
                                                       options:NSJSONWritingPrettyPrinted // Pass 0 if you don't care about the readability of the generated string
                                                         error:&error];
    if (! jsonData) {
        NSLog(@"Got an error: %@", error);
    } else {
        jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return jsonString;
}

- (void)updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if (!topicName && !owner) {
        msg = @"topicName and owner cannot both be empty";
        errorCode = IM_INVALID_TOPIC_NAME_OWNER;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _updateTopic:topicId withName:topicName withOwner:owner];
}

- (void)updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _updateTopic:topicId withName:topicName withOwner:owner customData:nil isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner customData:(NSDictionary *)customData success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _updateTopic:topicId withName:topicName withOwner:owner customData:customData isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _updateTopic:topicId withName:topicName withOwner:owner customData:nil isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner customData:(NSDictionary *)customData isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _updateTopic:topicId withName:topicName withOwner:owner customData:customData isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)_updateTopic:(NSString *)topicId withName:(NSString *)topicName withOwner:(NSString *)owner customData:(NSDictionary *)customData isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if (!topicName && !owner && !customData) {
        msg = @"topicName, owner and customData cannot both be empty";
        errorCode = IM_INVALID_TOPIC_NAME_OWNER;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_updateTopicURLFormat, _appKey];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:topicId forKey:@"id"];
    if(topicName != nil)
    {
        [params setObject:topicName forKey:@"name"];
    }
    if(owner != nil)
    {
        [params setObject:owner forKey:@"owner"];
    }
    if (customData) {
        [params setObject:[self dataTojsonString:customData] forKey:@"customData"];
    }
    if(isNeedNotice)
    {
        [params setObject:@"true" forKey:@"is_need_notice"];
        if(currentClientId != nil)
        {
            [params setObject:currentClientId forKey:@"current_client_id"];
        }
        NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
        [params setObject:anMsgId forKey:@"msg_id"];
    }
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, updateTopicEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendTopicOperationRequest:topicId type:1 params:params url:urlString success:success failure:failure];
    }
}

- (void)addClients:(NSSet *)clientIds toTopicId:(NSString *)topicId __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _addClients:clientIds toTopicId:topicId];
}

- (void)addClients:(NSSet *)clientIds toTopicId:(NSString *)topicId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _addClients:clientIds toTopicId:topicId isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)addClients:(NSSet *)clientIds toTopicId:(NSString *)topicId isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _addClients:clientIds toTopicId:topicId isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)_addClients:(NSSet *)clientIds toTopicId:(NSString *)topicId isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_addClientsURLFormat, _appKey];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:topicId forKey:@"id"];
    
    NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
    [params setObject:clientIdsString forKey:@"client"];
    if(isNeedNotice)
    {
        [params setObject:@"true" forKey:@"is_need_notice"];
        if(currentClientId != nil)
        {
            [params setObject:currentClientId forKey:@"current_client_id"];
        }
        NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
        [params setObject:anMsgId forKey:@"msg_id"];
    }
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, addClientsEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendTopicOperationRequest:topicId type:2 params:params url:urlString success:success failure:failure];
    }
}

- (void)removeClients:(NSSet *)clientIds fromTopicId:(NSString *)topicId __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    
    [self _removeClients:clientIds fromTopicId:topicId];
}

- (void)removeClients:(NSSet *)clientIds fromTopicId:(NSString *)topicId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _removeClients:clientIds fromTopicId:topicId isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)removeClients:(NSSet *)clientIds fromTopicId:(NSString *)topicId isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _removeClients:clientIds fromTopicId:topicId isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)_removeClients:(NSSet *)clientIds fromTopicId:(NSString *)topicId isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    
    NSString *urlString = [NSString stringWithFormat:_removeClientsURLFormat, _appKey];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:topicId forKey:@"id"];
    
    NSString *clientIdsString = [[clientIds allObjects] componentsJoinedByString:@","];
    [params setObject:clientIdsString forKey:@"client"];
    if(isNeedNotice)
    {
        [params setObject:@"true" forKey:@"is_need_notice"];
        if(currentClientId != nil)
        {
            [params setObject:currentClientId forKey:@"current_client_id"];
        }
        NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
        [params setObject:anMsgId forKey:@"msg_id"];
    }
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, removeClientsEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendTopicOperationRequest:topicId type:3 params:params url:urlString success:success failure:failure];
    }
}

- (void)removeTopic:(NSString *)topicId __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }     if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _removeTopic:topicId];
}

- (void)removeTopic:(NSString *)topicId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _removeTopic:topicId isNeedNotice:false currentClientId:nil success:success failure:failure];
}

- (void)removeTopic:(NSString *)topicId isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    [self _removeTopic:topicId isNeedNotice:isNeedNotice currentClientId:currentClientId success:success failure:failure];
}

- (void)_removeTopic:(NSString *)topicId isNeedNotice:(BOOL)isNeedNotice currentClientId:(NSString *)currentClientId success:(void (^)(NSString *topicId, NSNumber *createdTimestamp, NSNumber *updatedTimestamp))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_removeTopicURLFormat, _appKey];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:topicId forKey:@"id"];
    if(isNeedNotice)
    {
        [params setObject:@"true" forKey:@"is_need_notice"];
        if(currentClientId != nil)
        {
            [params setObject:currentClientId forKey:@"current_client_id"];
        }
        NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
        [params setObject:anMsgId forKey:@"msg_id"];
    }
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, removeTopicEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendTopicOperationRequest:topicId type:4 params:params url:urlString success:success failure:failure];
    }
}

- (NSString *)sendMessage:(NSString *)message toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need
{
    return [self sendMessage:message customData:nil toTopicId:topicId needReceiveACK:need mentionedClientIds:nil];
}

- (NSString *)sendMessage:(NSString *)message toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need mentionedClientIds:(NSSet*)clientIds
{
    return [self sendMessage:message customData:nil toTopicId:topicId needReceiveACK:need mentionedClientIds:clientIds];
}

- (NSString *)sendMessage:(NSString *)message customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need
{
    return [self sendMessage:message customData:customData toTopicId:topicId needReceiveACK:need mentionedClientIds:nil];
}

- (NSString *)sendMessage:(NSString *)message customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need mentionedClientIds:(NSSet*)clientIds
{
    return [self sendMessage:message customData:customData toTopicId:topicId needReceiveACK:need mentionedClientIds:clientIds msgIdPrefix:nil];
}

- (NSString *)sendMessage:(NSString *)message customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need mentionedClientIds:(NSSet*)clientIds msgIdPrefix:(NSString *)msgIdPrefix
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!message) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (msgIdPrefix) {
        anMsgId = [msgIdPrefix stringByAppendingString:anMsgId];
    }
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendMessage:message customData:customData toTopicId:topicId needReceiveACK:need messageId:anMsgId mentionedClientIds:clientIds];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return anMsgId;
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!data) {
        msg = @"invalid data";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!fileType) {
        msg = @"invalid fileType";
        errorCode = IM_INVALID_FILE_TYPE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendBinary:data fileType:fileType customData:nil toTopicId:topicId needReceiveACK:need messageId:anMsgId];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return anMsgId;
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need
{
    return [self sendBinary:data fileType:fileType customData:customData toTopicId:topicId needReceiveACK:need msgId:nil];
}

- (NSString *)sendBinary:(NSData *)data fileType:(NSString *)fileType customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need msgId:(NSString *)msgId
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!data) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!fileType) {
        msg = @"invalid fileType";
        errorCode = IM_INVALID_FILE_TYPE;
    } else if (!customData) {
        msg = @"invalid customData";
        errorCode = IM_INVALID_CUSTOM_DATA;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    
    NSString *anMsgId = @"";
    if (msgId) {
        anMsgId = msgId;
    } else {
        anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    }
    
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *messageId = [self _sendBinary:data fileType:fileType customData:customData toTopicId:topicId needReceiveACK:need messageId:anMsgId];
    if (messageId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return anMsgId;
}

- (void)bindAnPushService:(NSString *)anId appKey:(NSString *)appKey deviceType:(AnPushType)deviceType __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!anId) {
        msg = @"invalid anId";
        errorCode = IM_INVALID_ANID;
    } else if (!appKey) {
        msg = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _bindAnPushService:anId appKey:appKey deviceType:deviceType];
}

- (void)bindAnPushService:(NSString *)anId appKey:(NSString *)appKey clientId:(NSString *)clientId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (clientId == nil) {
        msg = @"invalid clientId";
        errorCode = IM_INVALID_CLIENT_ID;
    } else if (!anId) {
        msg = @"invalid anId";
        errorCode = IM_INVALID_ANID;
    } else if (!appKey) {
        msg = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_bindServiceURLFormat, _appKey];
    NSString *deviceTypeString = @"ios";
    
    NSString *clientIdsString = clientId;
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    NSString *bindString = @"true";
    NSString *signature = AnIMOAuthorizationSignature(AnIMMethodBindService, _appKey, nil, clientIdsString, dateString, anId, @"anpush", deviceTypeString, appKey, bindString);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:bindString forKey:@"bind"];
    [params setObject:clientIdsString forKey:@"client"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:@"anpush" forKey:@"service"];
    [params setObject:deviceTypeString forKey:@"device_type"];
    [params setObject:signature forKey:@"signature"];
    [params setObject:anId forKey:@"service_id"];
    [params setObject:appKey forKey:@"appkey"];
    
    if(_httpClient)
    {
        [_httpClient sendBindOrUnBindRequest:params url:urlString success:success failure:failure];
    }
}

- (void)unbindAnPushService:(AnPushType)deviceType __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _unbindAnPushService:deviceType];
}

- (void)unbindAnPushService:(AnPushType)deviceType success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_bindServiceURLFormat, _appKey];
    NSString *deviceTypeString;
    switch (deviceType) {
        case AnPushTypeAndroid:
            deviceTypeString = @"android";
            break;
        case AnPushTypeiOS:
            deviceTypeString = @"ios";
            break;
        case AnPushTypeWP8:
            deviceTypeString = @"wp8";
            break;
            
        default:
            break;
    }
    NSString *clientIdsString = _mClient.clientId;
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    NSString *bindString = @"false";
    NSString *signature = AnIMOAuthorizationSignature(AnIMMethodUnbindService, _appKey, nil, clientIdsString, dateString, nil, @"anpush", deviceTypeString, nil, bindString);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:bindString forKey:@"bind"];
    [params setObject:clientIdsString forKey:@"client"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:@"anpush" forKey:@"service"];
    [params setObject:deviceTypeString forKey:@"device_type"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendBindOrUnBindRequest:params url:urlString success:success failure:failure];
    }

}

- (void)unbindAnPushService:(NSString *)anId appKey:(NSString *)appKey clientId:(NSString *)clientId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (clientId == nil) {
        msg = @"invalid clientId";
        errorCode = IM_INVALID_CLIENT_ID;
    } else if (!anId) {
        msg = @"invalid anId";
        errorCode = IM_INVALID_ANID;
    } else if (!appKey) {
        msg = @"invalid appKey";
        errorCode = IM_INVALID_APP_KEY;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_bindServiceURLFormat, _appKey];
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    NSString *signature = AnIMOAuthorizationSignature(AnIMMethodUnbindService, _appKey, nil, clientId, dateString, nil, @"anpush", @"ios", nil, @"false");
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:@"false" forKey:@"bind"];
    [params setObject:clientId forKey:@"client"];
    [params setObject:dateString forKey:@"date"];
    [params setObject:@"anpush" forKey:@"service"];
    [params setObject:@"ios" forKey:@"device_type"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendBindOrUnBindRequest:params url:urlString success:success failure:failure];
    }
}

- (NSString *)sendNotice:(NSString *)notice toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    NSData *data = [notice dataUsingEncoding:NSUTF8StringEncoding];
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!notice) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    return [self _sendNotice:notice customData:nil toClients:clientIds needReceiveACK:need messageId:anMsgId];
}

- (NSString *)sendNotice:(NSString *)notice customData:(NSDictionary *)customData toClients:(NSSet *)clientIds needReceiveACK:(BOOL)need
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    NSData *data = [notice dataUsingEncoding:NSUTF8StringEncoding];
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!notice) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!customData) {
        msg = @"invalid customData";
        errorCode = IM_INVALID_CUSTOM_DATA;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    return [self _sendNotice:notice customData:customData toClients:clientIds needReceiveACK:need messageId:anMsgId];
}

- (NSString *)sendNotice:(NSString *)notice toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    NSData *data = [notice dataUsingEncoding:NSUTF8StringEncoding];
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!notice) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    return [self _sendNotice:notice customData:nil toTopicId:topicId needReceiveACK:need messageId:anMsgId];
}

- (NSString *)sendNotice:(NSString *)notice customData:(NSDictionary *)customData toTopicId:(NSString *)topicId needReceiveACK:(BOOL)need
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    NSData *data = [notice dataUsingEncoding:NSUTF8StringEncoding];
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!notice) {
        msg = @"invalid message";
        errorCode = IM_INVALID_MESSAGE;
    } else if (!customData) {
        msg = @"invalid customData";
        errorCode = IM_INVALID_CUSTOM_DATA;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    } else if ([data length] > 1024*1024*4) {
        msg = @"invalid message size";
        errorCode = IM_INVALID_MESSAGE_SIZE;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    return [self _sendNotice:notice customData:customData toTopicId:topicId needReceiveACK:need messageId:anMsgId];
}

- (void)getTopicInfo:(NSString *)topicId __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    
    [self _getTopicInfo:topicId];
}

- (void)getTopicInfo:(NSString *)topicId success:(void (^)(NSString *topicId, NSString *topicName, NSString *owner, NSSet *parties, NSDate *createdDate, NSDictionary *customData))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    
    NSString *urlString = [NSString stringWithFormat:_topicInfoURLFormat, _appKey, topicId];
    if(_httpClient)
    {
        [_httpClient sendGetTopicInfoRequest:urlString success:success failure:failure];
    }
}

- (void)getTopicHistory:(NSString *)topicId clientId:(NSString *)clientId limit:(int)limit timestamp:(NSNumber *)timestamp success:(void (^)(NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!topicId) {
        msg = @"topicId can not be empty.";
        errorCode = IM_INVALID_TOPIC;
    } else if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }

    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"topic" forKey:@"type"];
    [params setObject:topicId forKey:@"topic_id"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"mobile" forKey:@"device_type"];
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(timestamp != nil && timestamp > 0)
    {
        [params setObject:timestamp forKey:@"timestamp"];
    }
    
    if(_httpClient)
    {
        [_httpClient sendHistoryRequest:params url:_historyURLFormat success:success failure:failure];
    }
}

- (void)getFullTopicHistory:(NSString *)topicId limit:(int)limit timestamp:(NSNumber *)timestamp success:(void (^)(NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure
{
    [self getFullTopicHistory:topicId clientId:nil limit:limit timestamp:timestamp success:success failure:failure];
}

- (void)getFullTopicHistory:(NSString *)topicId clientId:(NSString *)clientId limit:(int)limit timestamp:(NSNumber *)timestamp success:(void (^)(NSArray *messages))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!topicId) {
        msg = @"topicId can not be empty.";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:topicId forKey:@"topic_id"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"mobile" forKey:@"device_type"];
    if(clientId)
    {
        [params setObject:clientId forKey:@"me"];
    }
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(timestamp != nil && timestamp > 0)
    {
        [params setObject:timestamp forKey:@"timestamp"];
    }
    if(_httpClient)
    {
        [_httpClient sendFullTopicHistoryRequest:params url:_topicHistoryURLFormat success:success failure:failure];
    }
}

- (void)getOfflineTopicHistory:(NSString *)topicId clientId:(NSString *)clientId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!topicId) {
        msg = @"topicId can not be empty.";
        errorCode = IM_INVALID_TOPIC;
    } else if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"topic" forKey:@"type"];
    [params setObject:topicId forKey:@"topic_id"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"offline"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"mobile" forKey:@"device_type"];
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(_httpClient)
    {
        [_httpClient sendOfflineHistoryRequest:params url:_historyURLFormat success:success failure:failure];
    }
}

- (void)getOfflineTopicHistory:(NSString *)clientId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"topic" forKey:@"type"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"offline"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"1" forKey:@"all"];
    [params setObject:@"mobile" forKey:@"device_type"];
    
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(_httpClient)
    {
        [_httpClient sendOfflineHistoryRequest:params url:_historyURLFormat success:success failure:failure];
    }
}

- (void)getHistory:(NSSet *)clientIds clientId:(NSString *)clientId limit:(int)limit timestamp:(NSNumber *)timestamp
           success:(void (^)(NSArray *messages))success
           failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!clientIds) {
        msg = @"clientIds can not be empty.";
        errorCode = IM_INVALID_CLIENTS;
    } else if(clientIds.count < 1) {
        msg = @"clientIds should contain at least one clientId.";
        errorCode = IM_INVALID_CLIENTS;
    } else if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    NSString* parties = [[clientIds allObjects] componentsJoinedByString:@","];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"private" forKey:@"type"];
    [params setObject:parties forKey:@"parties"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"mobile" forKey:@"device_type"];
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(timestamp != nil && timestamp > 0)
    {
        [params setObject:timestamp forKey:@"timestamp"];
    }
    if(_httpClient)
    {
        [_httpClient sendHistoryRequest:params url:_historyURLFormat success:success failure:failure];
    }
}

- (void)getOfflineHistory:(NSSet *)clientIds clientId:(NSString *)clientId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!clientIds) {
        msg = @"clientIds can not be empty.";
        errorCode = IM_INVALID_CLIENTS;
    } else if(clientIds.count < 1) {
        msg = @"clientIds should contain at least one clientId.";
        errorCode = IM_INVALID_CLIENTS;
    } else if (clientId == nil) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    NSString* parties = [[clientIds allObjects] componentsJoinedByString:@","];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"private" forKey:@"type"];
    [params setObject:parties forKey:@"parties"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"offline"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"mobile" forKey:@"device_type"];
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(_httpClient)
    {
        [_httpClient sendOfflineHistoryRequest:params url:_historyURLFormat success:success failure:failure];
    }
}

- (void)getOfflineHistory:(NSString *)clientId limit:(int)limit success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:@"private" forKey:@"type"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"offline"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"1" forKey:@"all"];
    [params setObject:@"mobile" forKey:@"device_type"];
    
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(_httpClient)
    {
        [_httpClient sendOfflineHistoryRequest:params url:_historyURLFormat success:success failure:failure];
    }
}

- (void)syncHistory:(NSString *)clientId limit:(int)limit timestamp:(NSNumber *)timestamp success:(void (^)(NSArray *messages, int count))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!clientId) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:clientId forKey:@"me"];
    [params setObject:@"1" forKey:@"b"];
    [params setObject:@"mobile" forKey:@"device_type"];
    if(limit > 0)
    {
        [params setObject:[NSString stringWithFormat:@"%i", limit] forKey:@"limit"];
    }
    if(timestamp != nil && timestamp > 0)
    {
        [params setObject:timestamp forKey:@"timestamp"];
    }
    if(_httpClient)
    {
        [_httpClient sendSyncHistoryRequest:params url:_syncHistoryURLFormat success:success failure:failure];
    }
}

- (void)getClientsStatus:(NSSet *)clientIds __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _getClientsStatus:clientIds];
}

- (void)getClientsStatus:(NSSet *)clientIds success:(void (^)(NSDictionary *clientsStatus))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
    }
    
    NSString *urlString = [NSString stringWithFormat:_clientsStatusURLFormat, _appKey, [[clientIds allObjects] componentsJoinedByString:@","]];
    if(_httpClient)
    {
        [_httpClient sendGetClientsStatusRequest:urlString success:success failure:failure];
    }
}

- (void)getClientsStatusOfTopic:(NSString *)topicId __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _getClientsStatusOfTopic:topicId];
}

- (void)getClientsStatusOfTopic:(NSString *)topicId success:(void (^)(NSDictionary *clientsStatus))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!topicId) {
        msg = @"invalid topicId";
        errorCode = IM_INVALID_TOPIC;
    }
    if (errorCode != 0) {
        if(failure)
        {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
    }
    
    NSString *urlString = [NSString stringWithFormat:_topicStatusURLFormat, _appKey, topicId];
    if(_httpClient)
    {
        [_httpClient sendGetClientsStatusRequest:urlString success:success failure:failure];
    }
}

- (void)getSessionInfo:(NSString *)sessionId
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (!sessionId) {
        msg = @"invalid sessionId";
        errorCode = IM_INVALID_SESSIONID;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    NSSet *parties = [AnIMUtils readParties:sessionId];
    
    if (parties != nil) {
        if ([_delegate respondsToSelector:@selector(anIM:didGetSessionInfo:parties:exception:)]) {
            [_delegate anIM:self didGetSessionInfo:sessionId parties:parties exception:nil];
        }
    } else {
        [self _getSessionInfo:sessionId message:nil];
    }
}

- (NSString *)sendReadACK:(NSString *)messageId toClients:(NSSet *)clientIds
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!messageId) {
        msg = @"invalid messageId";
        errorCode = IM_INVALID_MESSAGE_ID;
    } else if (!clientIds) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSString *msgId = [self _sendReadACK:messageId toClients:clientIds messageId:anMsgId];
    if (msgId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return msgId;
}

- (NSString *)sendReadACK:(NSString *)messageId toClient:(NSString *)clientId
{
    NSSet *toClients = [NSSet setWithObjects:clientId, nil];
    return [self sendReadACK:messageId toClients:toClients];
}

- (NSString *)sendReadACKBatch:(NSSet *)messageIds toClient:(NSString *)clientId
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    } else if (!messageIds) {
        msg = @"invalid messageId";
        errorCode = IM_INVALID_MESSAGE_ID;
    } else if (!clientId) {
        msg = @"invalid clientIds";
        errorCode = IM_INVALID_CLIENTS;
    }
    NSString *anMsgId = [AnIMUtils generateAnMsgId:_mClient.clientId];
    if (errorCode != 0) {
        [self _handleSendFailed:anMsgId code:errorCode errorMessage:msg];
        return anMsgId;
    }
    
    NSSet *toClients = [NSSet setWithObjects:clientId, nil];
    NSString *msgId = [self _sendReadACKBatch:messageIds toClients:toClients messageId:anMsgId];
    if (msgId == nil) {
        [self _handleSendFailed:anMsgId];
    }
    return msgId;
}

- (void)getAllTopics __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _getAllTopics];
}

- (void)getTopicList:(void (^)(NSMutableArray *topicList))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_topicListAllURLFormat, _appKey];
    if(_httpClient)
    {
        [_httpClient sendGetTopicListRequest:urlString success:success failure:failure];
    }
}

- (void)getMyTopics __attribute__((deprecated))
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (_mClient == nil) {
        msg = @"AnIM not initialized";
        errorCode = IM_FAILED_INITIALIZE;
    } else if (_mClient.clientId == nil) {
        msg = @"client not connected";
        errorCode = IM_FAILED_SEND;
    }
    if (errorCode != 0) {
        @throw [ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg];
    }
    
    [self _getMyTopics];
}

- (void)getTopicList:(NSString *)clientId success:(void (^)(NSMutableArray *topicList))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (clientId == nil) {
        msg = @"clientId can not be empty.";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if(failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_topicListMineURLFormat, _appKey, clientId];
    if(_httpClient)
    {
        [_httpClient sendGetTopicListRequest:urlString success:success failure:failure];
    }
}

- (void)setPushNotificationForChatSession:(NSString *)clientId isEnable:(BOOL)isEnable success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    [self _sendPushNotificationSettingsRequest:clientId type:1 isEnable:isEnable topicIds:nil success:success failure:failure];
}

- (void)setPushNotificationForTopic:(NSString *)clientId isEnable:(BOOL)isEnable success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    [self _sendPushNotificationSettingsRequest:clientId type:2 isEnable:isEnable topicIds:nil success:success failure:failure];
}

- (void)setPushNotificationForNotice:(NSString *)clientId isEnable:(BOOL)isEnable success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    [self _sendPushNotificationSettingsRequest:clientId type:3 isEnable:isEnable topicIds:nil success:success failure:failure];
}

- (void)disablePushNotificationForTopics:(NSString *)clientId topicIds:(NSSet *)topicIds success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    [self _sendPushNotificationSettingsRequest:clientId type:4 isEnable:NO topicIds:topicIds success:success failure:failure];
}

- (void)enablePushNotificationForTopics:(NSString *)clientId topicIds:(NSSet *)topicIds success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    [self _sendPushNotificationSettingsRequest:clientId type:5 isEnable:NO topicIds:topicIds success:success failure:failure];
}

- (void)setPushNotificationForMentioning:(NSString *)clientId isEnable:(BOOL)isEnable success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    [self _sendPushNotificationSettingsRequest:clientId type:6 isEnable:isEnable topicIds:nil success:success failure:failure];
}

#pragma mark - NSURLConnection Delegate
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    if (((AnIMURLConnection *)connection).gotData == NO) {
        ((AnIMURLConnection *)connection).data = [NSMutableData dataWithData:data];
        ((AnIMURLConnection *)connection).gotData = YES;
    } else {
        [((AnIMURLConnection *)connection).data appendData:data];
    }
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    ((AnIMURLConnection *)connection).statusCode = ((NSHTTPURLResponse *)response).statusCode;
    ((AnIMURLConnection *)connection).gotData = NO;
}

# pragma mark - Connection Delegate

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    [self _getCallbackConnection:(AnIMURLConnection *)connection data:((AnIMURLConnection *)connection).data error:nil];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    [self _getCallbackConnection:(AnIMURLConnection *)connection data:nil error:error];
}

#ifdef SELF_SIGN
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    SecTrustRef trust = [challenge.protectionSpace serverTrust];
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, 0);
    NSData* serverCertificateData = (__bridge NSData*)SecCertificateCopyData(certificate);
    NSString *serverCertificateDataHash = [AnIMUtils SHA256:[ANBase64Wrapper base64EncodedString:serverCertificateData]];
    
    NSData *certData = [ANBase64Wrapper dataWithBase64EncodedString:ARROWNOCK_SERVER_CERT];
    CFDataRef certDataRef = (__bridge_retained CFDataRef)certData;
    SecCertificateRef localcertificate = SecCertificateCreateWithData(NULL, certDataRef);
    NSData* localCertificateData = (__bridge NSData*)SecCertificateCopyData(localcertificate);
    NSString *localCertificateDataHash = [AnIMUtils SHA256:[ANBase64Wrapper base64EncodedString:localCertificateData]];
    
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
#endif

// MQTT Client event
- (void)handleEvent:(ANMQTTSession *)session event:(ANMQTTSessionEvent)eventCode error:(NSError *)error
{
    if(eventCode == ANMQTTSessionEventConnected) {
        // connected
#ifdef SIMPLE_CONNECTION
        _status = YES;
        if ([_delegate respondsToSelector:@selector(anIM:didUpdateStatus:exception:)]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [_delegate anIM:self didUpdateStatus:YES exception:nil];
            });
        }
#else
        [_mClient subscribeToTopic:[NSString stringWithFormat:@"AnIM/%@/%@", _clientId, _appKey] atLevel:ANMQTTQosLevelExactlyOnce];
#endif
#ifdef DM_ENABLED
        if (_clientId == nil) {
            return;
        }
        ANDeviceManager *manager = [ANDeviceManager shared];
        NSString *device_id = [manager getDeviceId];
        if (device_id == nil) {
            return;
        }
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self reportDeviceId:_clientId device_id:device_id];
        });
        
#endif
    } else if(eventCode == ANMQTTSessionEventConnectionClosed
              || eventCode == ANMQTTSessionEventConnectionRefused
              || eventCode == ANMQTTSessionEventConnectionError
              || eventCode == ANMQTTSessionEventProtocolError
              || eventCode == ANMQTTSessionEventConnectionClosedByBroker) {
        // disconnected
        _status = NO;
        if(_noDisconnectCallback)
        {
            _noDisconnectCallback = NO;
            _willKickedOff = NO;
            return;
        }
        
        ArrownockException *e = nil;
        if (error) {
            e = [ArrownockExceptionUtils generateWithErrorCode:error.code message:error.description];
        }
        if (_willKickedOff) {
            e = [ArrownockExceptionUtils generateWithErrorCode:IM_FORCE_CLOSED message:@"kicked off"];
        }
        if ([_delegate respondsToSelector:@selector(anIM:didUpdateStatus:exception:)]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [_delegate anIM:self didUpdateStatus:NO exception:e];
            });
        }
        _willKickedOff = NO;
    }
}

- (void)subAckReceived:(ANMQTTSession *)session msgID:(UInt16)msgID grantedQoss:(NSArray *)qoss{
    _status = YES;
    if ([_delegate respondsToSelector:@selector(anIM:didUpdateStatus:exception:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [_delegate anIM:self didUpdateStatus:YES exception:nil];
        });
    }
}

-(void)reportDeviceId:(NSString *) clientId device_id:(NSString*)device_id
{
    NSString *urlString = [NSString stringWithFormat:_reportDeviceIdURLFormat, _appKey];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:device_id forKey:@"device_id"];
    [params setObject:clientId forKey:@"client_id"];
    if(_httpClient) {
        [_httpClient reportDeviceId:params url:urlString success:nil failure:nil];
    }
}

- (void)messageDelivered:(ANMQTTSession *)session messageId:(NSString *)messageId extra:(NSString *)extra {
    if([messageId hasPrefix:@"-"]) {
        // anLive
    } else {
        NSNumber *timestamp = [NSNumber numberWithInt:-1];
        NSString *keyword = @"";
        bool isInBlacklist = NO;
        if(extra) {
            NSDictionary *dict = [AnIMUtils getDictFromJsonString:extra];
            if(dict) {
                NSString *mid = [dict objectForKey:@"msgId"];
                NSNumber *ts = [dict objectForKey:@"timestamp"];
                int tempIsInBlacklist = [[dict valueForKey:@"bl"] intValue];
                NSString *tempKeyword = [dict objectForKey:@"sk"];
                if(mid && [mid isKindOfClass:[NSString class]] && [mid isEqualToString:messageId] && ts) {
                    timestamp = ts;
                    isInBlacklist = tempIsInBlacklist == 1 ? YES : NO;
                    keyword = tempKeyword ? tempKeyword: @"";
                }
            }
        }
        
        if ([messageId hasPrefix:@"D"]) {
            if ([_deskMessageDelegate respondsToSelector:@selector(messageSent:at:)]) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [_deskMessageDelegate messageSent:messageId at:timestamp];
                });
            }
        } else {
            if (keyword && keyword.length > 0) {
                if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:IM_SENSITIVE message:keyword];
                        [_delegate anIM:self sendReturnedException:e messageId:messageId];
                    });
                }
            } else if (isInBlacklist) {
                if ([_delegate respondsToSelector:@selector(anIM:sendReturnedException:messageId:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        ArrownockException *e = [ArrownockExceptionUtils generateWithErrorCode:IM_IN_BLACKLIST message:@"The client is in blacklist"];
                        [_delegate anIM:self sendReturnedException:e messageId:messageId];
                    });
                }
            } else {
                if ([_delegate respondsToSelector:@selector(anIM:messageSent:at:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate anIM:self messageSent:messageId at:timestamp];
                    });
                }
            }
        }
    }
}

- (void)newMessage:(ANMQTTSession *)session data:(NSData *)data onTopic:(NSString *)topic qos:(ANMQTTQosLevel)qos retained:(BOOL)retained mid:(unsigned int)mid
{
    NSString *payload = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if(payload) {
        NSDictionary *dict = [AnIMUtils getDictFromJsonString:payload];
        NSString *from = [dict objectForKey:@"from"];
        NSString *sessionKey = [dict objectForKey:@"session_key"];
        NSSet *parties;

        if (sessionKey != nil) {
            parties = [AnIMUtils readParties:sessionKey];
            if (parties == nil) {
                NSString *messagePayload = [NSString stringWithString:payload];
                [self _getSessionInfo:sessionKey message:messagePayload];
                return;
            }
        }
        
        NSString *topicId = [dict objectForKey:@"topic"];
        NSString *message = [dict objectForKey:@"message"];
        NSString *anMsgId = [dict objectForKey:@"msg_id"];
        NSString *fileType = [dict objectForKey:@"fileType"];
        NSDictionary *cdata = [dict objectForKey:@"customData"];
        NSDictionary *customData = [self converCustomDataToEmoji:cdata];
        NSString *gpType = nil;
        NSInteger type = [[dict objectForKey:@"msg_type"] intValue];
        NSNumber *timestamp = [dict objectForKey:@"timestamp"];
        NSString *topicName = [dict objectForKey:@"topic_name"];
        NSString *owner = [dict objectForKey:@"owner"];
        NSArray *clientsArray = [dict objectForKey:@"clients"];
        NSString *fromType = [dict objectForKey:@"type"];
        NSMutableSet *clients = nil;
        if (clientsArray != nil){
            clients = [NSMutableSet setWithArray:clientsArray];
        }
        
        switch (type) {
            case 1:
                message = [ANEmojiUtil stringConvertToEmoji:message];
                if ([_delegate respondsToSelector:@selector(anIM:didReceiveMessage:customData:from:parties:messageId:at:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate anIM:self didReceiveMessage:message customData:customData from:from parties:parties messageId:anMsgId at:timestamp];
                    });
                }
                break;
            case 2:
                if ([_delegate respondsToSelector:@selector(anIM:didReceiveBinary:fileType:customData:from:parties:messageId:at:)]) {
                    NSData *data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate anIM:self didReceiveBinary:data fileType:fileType customData:customData from:from parties:parties messageId:anMsgId at:timestamp];
                    });
                }
                break;
            case 3:
                message = [ANEmojiUtil stringConvertToEmoji:message];
                if ([customData objectForKey:@"message_type"]) {
                    gpType = [customData objectForKey:@"message_type"];
                }
                if (gpType && [@"gp" isEqualToString:gpType]) {
                    if ([_groupediaMessageDelegate respondsToSelector:@selector(didReceiveMessage:customData:from:topicId:messageId:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_groupediaMessageDelegate didReceiveMessage:message customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                        });
                    }
                } else {
                    if ([anMsgId hasPrefix:@"D"]) {
                        if ([_deskMessageDelegate respondsToSelector:@selector(didReceiveMessage:customData:from:topicId:messageId:at:)]) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [_deskMessageDelegate didReceiveMessage:message customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                            });
                        }
                    } else {
                        if ([_delegate respondsToSelector:@selector(anIM:didReceiveMessage:customData:from:topicId:messageId:at:)]) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [_delegate anIM:self didReceiveMessage:message customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                            });
                        }
                    }
                }
                break;
            case 4:
                message = [ANEmojiUtil stringConvertToEmoji:message];
                if ([customData objectForKey:@"message_type"]) {
                    gpType = [customData objectForKey:@"message_type"];
                }
                if (gpType && [@"gp" isEqualToString:gpType]) {
                    if ([_groupediaMessageDelegate respondsToSelector:@selector(didReceiveBinary:fileType:customData:from:topicId:messageId:at:)]) {
                        NSData *data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_groupediaMessageDelegate didReceiveBinary:data fileType:fileType customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                        });
                    }
                } else {
                    if ([anMsgId hasPrefix:@"D"]) {
                        if ([_deskMessageDelegate respondsToSelector:@selector(didReceiveBinary:fileType:customData:from:topicId:messageId:at:)]) {
                            NSData *data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [_deskMessageDelegate didReceiveBinary:data fileType:fileType customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                            });
                        }
                    } else {
                        if ([_delegate respondsToSelector:@selector(anIM:didReceiveBinary:fileType:customData:from:topicId:messageId:at:)]) {
                            NSData *data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [_delegate anIM:self didReceiveBinary:data fileType:fileType customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                            });
                        }
                    }
                }
                break;
            case 5:
                message = [ANEmojiUtil stringConvertToEmoji:message];
                message = [message stringByReplacingOccurrencesOfString:@"\\u]" withString:@"\\u"];
                if ([_delegate respondsToSelector:@selector(anIM:didReceiveNotice:customData:from:topicId:messageId:at:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate anIM:self didReceiveNotice:message customData:customData from:from topicId:topicId messageId:anMsgId at:timestamp];
                    });
                }
                break;
            case 11:
                if ([_delegate respondsToSelector:@selector(anIM:messageReceived:from:type:)]) {
                    [_delegate anIM:self messageReceived:anMsgId from:from type:fromType];
                }
                if ([_delegate respondsToSelector:@selector(anIM:messageReceived:from:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate anIM:self messageReceived:anMsgId from:from];
                    });
                }
                break;
            case 12:
                if ([_delegate respondsToSelector:@selector(anIM:messageRead:from:type:)]) {
                    [_delegate anIM:self messageRead:anMsgId from:from type:fromType];
                }
                if ([_delegate respondsToSelector:@selector(anIM:messageRead:from:)]) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_delegate anIM:self messageRead:anMsgId from:from];
                    });
                }
                break;
            case 21:
                _willKickedOff = YES;
                [_mClient close];
                break;
            case 22:
                _noDisconnectCallback = YES;
                [_mClient close];
                break;
            case 31: // anLive invitation
                if([_signalEventDelegate respondsToSelector:@selector(onInvitationRecieved:)]) {
                    NSString* sessionId = [customData objectForKey:@"sid"];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [_signalEventDelegate onInvitationRecieved:sessionId];
                    });
                }
                break;
            case 32: // anLive offer
                if([_signalEventDelegate respondsToSelector:@selector(onOfferRecieved:offerJson:orientation:)]) {
                    NSString *o = [customData objectForKey:@"o"];
                    [_signalEventDelegate onOfferRecieved:from offerJson:message orientation:[o intValue]];
                }
                break;
            case 33: // anLive answer
                if([_signalEventDelegate respondsToSelector:@selector(onAnswerRecieved:answerJson:orientation:)]) {
                    NSString *o = [customData objectForKey:@"o"];
                    [_signalEventDelegate onAnswerRecieved:from answerJson:message orientation:[o intValue]];
                }
                break;
            case 34: // ice candidate
                if([_signalEventDelegate respondsToSelector:@selector(onICECandidate:candidateJson:)]) {
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        [_signalEventDelegate onICECandidate:from candidateJson:message];
                    });
                }
                break;
            case 35: // remote party hangup
                if([_signalEventDelegate respondsToSelector:@selector(onRemoteHangup:)]) {
                    [_signalEventDelegate onRemoteHangup:from];
                }
                break;
            case 51:// receive create topic message
                if ([anMsgId hasPrefix:@"D"]) {
                    
                } else {
                    if ([_delegate respondsToSelector:@selector(anIM:didReceiveCreateTopicEvent:from:topicId:owner:name:parties:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveCreateTopicEvent:anMsgId from:from topicId:topicId owner:owner name:topicName parties:clients at:timestamp];
                        });
                    } else if ([_delegate respondsToSelector:@selector(anIM:didReceiveCreateTopicEvent:from:topicId:owner:name:parties:at:customData:)]) {
                        NSDictionary *topicCustomData = [customData objectForKey:@"customData"];
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveCreateTopicEvent:anMsgId from:from topicId:topicId owner:owner name:topicName parties:clients at:timestamp customData:topicCustomData];
                        });
                    }
                }
                break;
            case 52:// receive update topic message
                if ([anMsgId hasPrefix:@"D"]) {
                    
                } else {
                    if ([_delegate respondsToSelector:@selector(anIM:didReceiveUpdateTopicEvent:from:topicId:owner:name:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveUpdateTopicEvent:anMsgId from:from topicId:topicId owner:owner name:topicName at:timestamp];
                        });
                    } else if ([_delegate respondsToSelector:@selector(anIM:didReceiveUpdateTopicEvent:from:topicId:owner:name:at:customData:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            NSDictionary *topicCustomData = [customData objectForKey:@"customData"];
                            [_delegate anIM:self didReceiveUpdateTopicEvent:anMsgId from:from topicId:topicId owner:owner name:topicName at:timestamp customData:topicCustomData];
                        });
                    }
                }
                break;
            case 53:// receive add clients to topic message
                if ([anMsgId hasPrefix:@"D"]) {
                    if ([_deskMessageDelegate respondsToSelector:@selector(accountAddedToSession:groupId:accountId:accountName:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_deskMessageDelegate accountAddedToSession:topicId groupId:[customData objectForKey:@"groupId"] accountId:[customData objectForKey:@"accId"] accountName:[customData objectForKey:@"name"] at:timestamp];
                        });
                    }
                } else {
                    if ([_delegate respondsToSelector:@selector(anIM:didReceiveAddClientsToTopicEvent:from:topicId:parties:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveAddClientsToTopicEvent:anMsgId from:from topicId:topicId parties:clients at:timestamp];
                        });
                    } else if ([_delegate respondsToSelector:@selector(anIM:didReceiveAddClientsToTopicEvent:from:topicId:parties:at:customData:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            NSDictionary *topicCustomData = [customData objectForKey:@"customData"];
                            [_delegate anIM:self didReceiveAddClientsToTopicEvent:anMsgId from:from topicId:topicId parties:clients at:timestamp customData:topicCustomData];
                        });
                    }
                }
                break;
            case 54:// receive remove clients from topic message
                if ([anMsgId hasPrefix:@"D"]) {
                    
                } else {
                    if ([_delegate respondsToSelector:@selector(anIM:didReceiveRemoveClientsFromTopicEvent:from:topicId:parties:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveRemoveClientsFromTopicEvent:anMsgId from:from topicId:topicId parties:clients at:timestamp];
                        });
                    } else if ([_delegate respondsToSelector:@selector(anIM:didReceiveRemoveClientsFromTopicEvent:from:topicId:parties:at:customData:)]) {
                        NSDictionary *topicCustomData = [customData objectForKey:@"customData"];
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveRemoveClientsFromTopicEvent:anMsgId from:from topicId:topicId parties:clients at:timestamp customData:topicCustomData];
                        });
                    }
                }
                break;
            case 55:// receive remove topic message
                if ([anMsgId hasPrefix:@"D"]) {
                    if ([_deskMessageDelegate respondsToSelector:@selector(sessionClosed:sessionId:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_deskMessageDelegate sessionClosed:[customData objectForKey:@"groupId"] sessionId:topicId at:timestamp];
                        });
                    }
                } else {
                    if ([_delegate respondsToSelector:@selector(anIM:didReceiveRemoveTopicEvent:from:topicId:at:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [_delegate anIM:self didReceiveRemoveTopicEvent:anMsgId from:from topicId:topicId at:timestamp];
                        });
                    } else if ([_delegate respondsToSelector:@selector(anIM:didReceiveRemoveTopicEvent:from:topicId:at:customData:)]) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            NSDictionary *topicCustomData = [customData objectForKey:@"customData"];
                            [_delegate anIM:self didReceiveRemoveTopicEvent:anMsgId from:from topicId:topicId at:timestamp customData:topicCustomData];
                        });
                    }
                }
                
                break;
            case 61:    // text message sent on other device
                if ([_delegate respondsToSelector:@selector(anIM:messageSentFromOtherDevice:)]) {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    if(message)
                    {
                        message = [ANEmojiUtil stringConvertToEmoji:message];
                    }
                    NSString *to = nil;
                    if(clients) {
                        [clients removeObject:from];
                        if([clients count] > 0) {
                            to = [[clients allObjects] objectAtIndex:0];
                        }
                    }
                    [mm initWithType:AnIMTextMessage msgId:anMsgId topicId:topicId message:message content:nil fileType:nil from:from to:to customData:customData timestamp:timestamp];
                    [_delegate anIM:self messageSentFromOtherDevice:mm];
                }
                break;
            case 62:    // binary message sent on other device
                if ([_delegate respondsToSelector:@selector(anIM:messageSentFromOtherDevice:)]) {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    NSData *data;
                    if(message)
                    {
                        data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                    }
                    NSString *to = nil;
                    if(clients) {
                        [clients removeObject:from];
                        if([clients count] > 0) {
                            to = [[clients allObjects] objectAtIndex:0];
                        }
                    }
                    [mm initWithType:AnIMBinaryMessage msgId:anMsgId topicId:nil message:nil content:data fileType:fileType from:from to:to customData:customData timestamp:timestamp];
                    [_delegate anIM:self messageSentFromOtherDevice:mm];
                }
                break;
            case 63:    // text topic message sent on other device
                if ([_delegate respondsToSelector:@selector(anIM:messageSentFromOtherDevice:)]) {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    if(message)
                    {
                        message = [ANEmojiUtil stringConvertToEmoji:message];
                    }
                    [mm initWithType:AnIMTextMessage msgId:anMsgId topicId:topicId message:message content:nil fileType:fileType from:from to:nil customData:customData timestamp:timestamp];
                    [_delegate anIM:self messageSentFromOtherDevice:mm];
                }
                break;
            case 64:    // binary topic message sent on other device
                if ([_delegate respondsToSelector:@selector(anIM:messageSentFromOtherDevice:)]) {
                    AnIMMessage* mm = [AnIMMessage alloc];
                    NSData *data;
                    if(message)
                    {
                        data = [ANBase64Wrapper dataWithBase64EncodedString:message];
                    }
                    [mm initWithType:AnIMBinaryMessage msgId:anMsgId topicId:topicId message:nil content:data fileType:fileType from:from to:nil customData:customData timestamp:timestamp];
                    [_delegate anIM:self messageSentFromOtherDevice:mm];
                }
                break;
            default:
                break;
        }
    }
}

- (NSString *)getDeviceId
{
    ANKeychainItemWrapper *keychainItem = [[ANKeychainItemWrapper alloc] initWithIdentifier:@"com.arrownock.ANIM_DEVICE_ID" accessGroup:nil];
    
    NSString *deviceId = [keychainItem objectForKey:(__bridge id)kSecAttrService];
    if (deviceId != nil && [deviceId length] != 0) {
        return deviceId;
    } else {
        deviceId = nil;
        if ([[[UIDevice currentDevice] systemVersion] hasPrefix:@"5"]) {
            CFUUIDRef cfuuid = CFUUIDCreate(kCFAllocatorDefault);
            deviceId = (NSString*)CFBridgingRelease(CFUUIDCreateString(kCFAllocatorDefault, cfuuid));
        } else {
            deviceId = [[NSUUID UUID] UUIDString];
        }
        deviceId = [NSString stringWithFormat:@"1%@", [self getMD5String:deviceId]];
        [keychainItem setObject:deviceId forKey:(__bridge id)kSecAttrService];
        return deviceId;
    }
}

- (NSString *)getMD5String:(NSString *)input
{
    // Create pointer to the string as UTF8
    const char *ptr = [input UTF8String];
    
    // Create byte array of unsigned chars
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
    // Create 16 byte MD5 hash value, store in buffer
    CC_MD5(ptr, strlen(ptr), md5Buffer);
    
    // Convert MD5 value in the buffer to NSString of hex values
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x",md5Buffer[i]];
    
    return output;
}


#pragma mark - AnLiveSignalController implementation
- (BOOL) isOnline
{
    return _status;
}

- (NSString*) getPartyId
{
    return _clientId;
}

- (void) createSession:(NSSet*)partyIds type:(NSString *)type
{
    NSString *partyIdsString = [[partyIds allObjects] componentsJoinedByString:@","];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:_clientId forKey:@"owner"];
    [params setObject:partyIdsString forKey:@"parties"];
    [params setObject:type forKey:@"type"];
    
    if(_httpClient)
    {
        [_httpClient sendAnLiveRequest:params url:_anLiveCreateSessionURLFormat method:@"POST" success:^(NSDictionary *response) {
            NSDictionary *session;
            if([response objectForKey:@"response"] != nil)
            {
                session = [[response objectForKey:@"response"] objectForKey:@"live_session"];
            }
            if(session)
            {
                NSString *sessionId = [session objectForKey:@"id"];
                NSArray *ids = [session objectForKey:@"parties"];
                NSSet *set = [NSSet setWithArray:ids];
                if(_signalEventDelegate)
                {
                    [_signalEventDelegate onSessionCreated:sessionId partyIds:set type:type error:nil];
                }
            }
            else
            {
                if(_signalEventDelegate)
                {
                    [_signalEventDelegate onSessionCreated:nil partyIds:nil type:nil error:[ArrownockExceptionUtils generateWithErrorCode:LIVE_FAILED_CREATE_SESSION message:@"Internal server error"]];
                }
            }
        } failure:^(NSDictionary *response, NSError *error) {
            if(_signalEventDelegate)
            {
                NSString *message;
                if(response && [response objectForKey:@"meta"])
                {
                    NSDictionary *meta = [response objectForKey:@"meta"];
                    if([meta objectForKey:@"message"])
                    {
                        message = [meta objectForKey:@"message"];
                    }
                }
                if(message)
                {
                    [_signalEventDelegate onSessionCreated:nil partyIds:nil type:nil error:[ArrownockExceptionUtils generateWithErrorCode:LIVE_FAILED_CREATE_SESSION message:message]];
                }
                else
                {
                    [_signalEventDelegate onSessionCreated:nil partyIds:nil type:nil error:[ArrownockExceptionUtils generateWithErrorCode:LIVE_FAILED_CREATE_SESSION message:@"Internal server error"]];
                }
            }
        }];
    }
}

- (void) validateSession:(NSString*)sessionId
{
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:sessionId forKey:@"id"];
    
    if(_httpClient)
    {
        [_httpClient sendAnLiveRequest:params url:_anLiveValidateSessionURLFormat method:@"GET" success:^(NSDictionary *response) {
            NSDictionary *session;
            if([response objectForKey:@"response"] != nil)
            {
                session = [[response objectForKey:@"response"] objectForKey:@"live_session"];
            }
            if(session)
            {
                NSString *sessionId = [session objectForKey:@"id"];
                NSString *type = [session objectForKey:@"type"];
                BOOL isExpired = [[session objectForKey:@"expired"] boolValue];
                NSString *date = [session objectForKey:@"created_at"];
                NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
                [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
                NSDate *createDate = [formatter dateFromString:date];
                NSArray *parties = [session objectForKey:@"parties"];

                NSMutableSet *partyIds = [[NSMutableSet alloc] init];
                for(NSString* party in parties) {
                    if(party && ![party isEqualToString:_clientId]) {
                        [partyIds addObject:party];
                    }
                }
                if(_signalEventDelegate)
                {
                    [_signalEventDelegate onSessionValidated:(!isExpired) sessionId:sessionId partyIds:partyIds type:type date:createDate];
                }
            }
            else
            {
                if(_signalEventDelegate)
                {
                    [_signalEventDelegate onSessionValidated:NO sessionId:nil partyIds:nil type:nil date:nil];
                }
            }
        } failure:^(NSDictionary *response, NSError *error) {
            if(_signalEventDelegate)
            {
                [_signalEventDelegate onSessionValidated:NO sessionId:nil partyIds:nil type:nil date:nil];
            }
        }];
    }
}

- (void) terminateSession:(NSString*)sessionId
{
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:_appKey forKey:@"key"];
    [params setObject:sessionId forKey:@"id"];
    
    if(_httpClient)
    {
        [_httpClient sendAnLiveRequest:params url:_anLiveTerminateSessionURLFormat method:@"POST" success:^(NSDictionary *response) {
            //NSLog(@"Session terminated");
        } failure:^(NSDictionary *response, NSError *error) {
            //NSLog(@"Session termination failed");
        }];
    }
}

- (void) sendInvitations:(NSString*)sessionId partyIds:(NSSet*) partyIds type:(NSString *)type notificationData:(NSDictionary*) data
{
    NSMutableDictionary *customData = [[NSMutableDictionary alloc] init];
    [customData setObject:sessionId forKey:@"sid"];
    [customData setObject:type forKey:@"st"];
    if(data && data.count > 0)
    {
        for(NSString *key in data)
        {
            if(![key isEqualToString:@"st"])
            {
                [customData setObject:data[key] forKey:key];
            }
        }
    }
    
    for(NSString* partyId in partyIds)
    {
        if(![partyId isEqualToString:_clientId]) {
            [self sendSignalData:partyId data:@"invitation" type:31 customData:customData QoS:2];
        }
    }
}

- (void) sendHangup:(NSSet*)partyIds
{
    for(NSString* partyId in partyIds)
    {
        [self sendSignalData:partyId data:@"hangup" type:35 customData:nil QoS:1];
    }
}

- (void) sendOffer:(NSString*)partyId sdp:(NSString*)sdp orientation:(int)orientation
{
    NSMutableDictionary *customData = [NSMutableDictionary dictionaryWithObjects:@[[NSString stringWithFormat:@"%d", orientation]] forKeys:@[@"o"]];
    [self sendSignalData:partyId data:sdp type:32 customData:customData QoS:1];
}

- (void) sendAnswer:(NSString*)partyId sdp:(NSString*)sdp orientation:(int)orientation
{
    NSMutableDictionary *customData = [NSMutableDictionary dictionaryWithObjects:@[[NSString stringWithFormat:@"%d", orientation]] forKeys:@[@"o"]];
    [self sendSignalData:partyId data:sdp type:33 customData:customData QoS:1];
}

- (void) sendICECandidate:(NSString*)partyId candidateJson:(NSString*)candidateJson
{
    [self sendSignalData:partyId data:candidateJson type:34 customData:nil QoS:1];
}

- (void) setSignalEventDelegate:(id <AnLiveSignalEventDelegate>)delegate
{
    _signalEventDelegate = delegate;
}

-(void) sendSignalData:(NSString*)partyId data:(NSString*)data type:(int)type customData:(NSDictionary*)customData QoS:(int)QoS
{
    NSString* msgId = [NSString stringWithFormat:@"-%d-%@", type, [AnIMUtils generateAnMsgId:_mClient.clientId]];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[data, msgId, [NSNumber numberWithInt:type], _appKey, partyId, _mClient.clientId] forKeys:@[@"message", @"msg_id", @"msg_type", @"app_key", @"party", @"from"]];
    if (customData)
    {
        [dict setObject:customData forKey:@"customData"];
    }
    NSString *jsonString = [AnIMUtils getJsonStringFromDict:dict];
    switch (QoS) {
        case 1:
            [self performSelector:@selector(_publishMessageInThreadWithQoS1:) onThread:clientThread withObject:@[jsonString, [NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey], msgId] waitUntilDone:NO];
            break;
        case 2:
            [self performSelector:@selector(_publishMessageInThread:) onThread:clientThread withObject:@[jsonString, [NSString stringWithFormat:@"AnIM/%@/%@", _mClient.clientId, _appKey], msgId] waitUntilDone:NO];
            break;
    }
}

- (void)addBlacklist:(NSString *)currentClientId targetClientId:(NSString *)targetClientId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!currentClientId) {
        msg = @"Invalid parameter: currentClientId";
        errorCode = IM_INVALID_CLIENT_ID;
    } else if (!targetClientId) {
        msg = @"Invalid parameter: targetClientId";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_addBlacklistURLFormat, _appKey];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:currentClientId forKey:@"current_client_id"];
    [params setObject:targetClientId forKey:@"target_client_id"];
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, addBlacklistEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendBlacklistOperationRequest:1 params:params url:urlString success:success failure:failure];
    }
}

- (void)removeBlacklist:(NSString *)currentClientId targetClientId:(NSString *)targetClientId success:(void (^)())success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!currentClientId) {
        msg = @"Invalid parameter: currentClientId";
        errorCode = IM_INVALID_CLIENT_ID;
    } else if (!targetClientId) {
        msg = @"Invalid parameter: targetClientId";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_removeBlacklistURLFormat, _appKey];
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:currentClientId forKey:@"current_client_id"];
    [params setObject:targetClientId forKey:@"target_client_id"];
    
    NSDateFormatter* df = [[NSDateFormatter alloc]init];
    [df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSZ"];
    NSDate *date = [NSDate date];
    NSString *dateString = [df stringFromDate:date];
    [params setObject:dateString forKey:@"date"];
    [params setObject:_appKey forKey:@"key"];
    
    NSString *signature = AnIMGetSignature([NSString stringWithFormat:@"/%@%@", ARROWNOCK_API_VERSION, removeBlacklistEndPoint], params);
    signature = [AnIMUtils encodeString:signature];
    dateString = [AnIMUtils encodeString:dateString];
    [params setObject:dateString forKey:@"date"];
    [params setObject:signature forKey:@"signature"];
    
    if(_httpClient)
    {
        [_httpClient sendBlacklistOperationRequest:1 params:params url:urlString success:success failure:failure];
    }
}

- (void)listBlacklists:(NSString *)currentClientId success:(void (^)(NSArray *clients))success failure:(void (^)(ArrownockException *exception))failure
{
    NSString *msg = nil;
    NSUInteger errorCode = 0;
    if (!currentClientId) {
        msg = @"Invalid parameter: currentClientId";
        errorCode = IM_INVALID_CLIENT_ID;
    }
    if (errorCode != 0) {
        if (failure) {
            failure([ArrownockExceptionUtils generateWithErrorCode:errorCode message:msg]);
        }
        return;
    }
    
    NSString *urlString = [NSString stringWithFormat:_listBlacklistsURLFormat, _appKey];
    
    NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
    [params setObject:currentClientId forKey:@"current_client_id"];
    
    if(_httpClient)
    {
        [_httpClient sendListBlacklistsRequest:params url:urlString success:success failure:failure];
    }
}

@end
