#import "AnPushOAuthCore.h"
#import "ArrownockConstants.h"
#import "ANOAHMAC_SHA1SignatureProvider.h"

NSString *AnPushOAuthorizationSignature(AnPushMethod method, NSDictionary *dict)
{
    NSString *signatureBaseString = [[NSString alloc] init];;
    NSString *anPushKey = ARROWNOCK_API_SECRET;
    NSString *version = ARROWNOCK_API_VERSION;
    NSString *base64Signature = [[NSString alloc] init];
    
    NSString *channel = [dict objectForKey:@"channel"];
    NSString *dateString = [dict objectForKey:@"date"];
    NSString *token = [dict objectForKey:@"token"];
    NSString *appKey = [dict objectForKey:@"appKey"];
    NSString *hourString = [dict objectForKey:@"hour"];
    NSString *minuteString = [dict objectForKey:@"minute"];
    NSString *durationString = [dict objectForKey:@"duration"];
    NSString *resendString = [dict objectForKey:@"resend"];
    NSString *deviceIdString = [dict objectForKey:@"id"];
    NSString *badge = [dict objectForKey:@"badge"];
#ifdef DM_ENABLED
    NSString *real_device_id = [dict objectForKey:@"real_device_id"];
#endif
    switch (method) {
        case AnPushMethodRegisterOverwrite:
#ifdef DM_ENABLED
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_register.jsonchannel=%@&date=%@&device_token=%@&id=%@&key=%@&overwrite=true&real_device_id=%@&type=ios",
                                   version,
                                   channel,
                                   dateString,
                                   token,
                                   deviceIdString,
                                   appKey,
                                   real_device_id];
            break;
#else
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_register.jsonchannel=%@&date=%@&device_token=%@&id=%@&key=%@&overwrite=true&type=ios",
                                   version,
                                   channel,
                                   dateString,
                                   token,
                                   deviceIdString,
                                   appKey];
            break;
#endif
        case AnPushMethodRegisterAppend:
#ifdef DM_ENABLED
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_register.jsonchannel=%@&date=%@&device_token=%@&id=%@&key=%@&real_device_id=%@&type=ios",
                                   version,
                                   channel,
                                   dateString,
                                   token,
                                   deviceIdString,
                                   appKey,
                                   real_device_id];
            break;
#else
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_register.jsonchannel=%@&date=%@&device_token=%@&id=%@&key=%@&type=ios",
                                   version,
                                   channel,
                                   dateString,
                                   token,
                                   deviceIdString,
                                   appKey];
            break;
#endif
        case AnPushMethodUnregisterAll:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_unregister.jsondate=%@&device_token=%@&key=%@&remove=true&type=ios",
                                   version,
                                   dateString,
                                   token,
                                   appKey];
            break;
        case AnPushMethodUnregisterSome:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_unregister.jsonchannel=%@&date=%@&device_token=%@&key=%@&type=ios",
                                   version,
                                   channel,
                                   dateString,
                                   token,
                                   appKey];
            break;
        case AnPushMethodSetMute:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_mute.jsondate=%@&device_token=%@&key=%@&mute=true&type=ios",
                                   version,
                                   dateString,
                                   token,
                                   appKey];
            break;
        case AnPushMethodSetMutePeriod:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_mute.jsondate=%@&device_token=%@&duration=%@&hour=%@&key=%@&minute=%@&mute=true&type=ios",
                                   version,
                                   dateString,
                                   token,
                                   durationString,
                                   hourString,
                                   appKey,
                                   minuteString];
            break;
        case AnPushMethodClearMute:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_mute.jsondate=%@&device_token=%@&key=%@&mute=false&type=ios",
                                   version,
                                   dateString,
                                   token,
                                   appKey];
            break;
        case AnPushMethodSetSilent:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_silent_period.jsondate=%@&device_token=%@&duration=%@&hour=%@&key=%@&minute=%@&resend=%@&set=true&type=ios",
                                   version,
                                   dateString,
                                   token,
                                   durationString,
                                   hourString,
                                   appKey,
                                   minuteString,
                                   resendString];
            break;
        case AnPushMethodClearSilent:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_silent_period.jsondate=%@&device_token=%@&key=%@&set=false&type=ios",
                                   version,
                                   dateString,
                                   token,
                                   appKey];
            break;
        case AnPushMethodSetBadge:
            signatureBaseString = [NSString stringWithFormat:@"/%@/push_notification/signed_set_badge.jsonbadge=%@&date=%@&device_token=%@&key=%@&type=ios",
                                   version,
                                   badge,
                                   dateString,
                                   token,
                                   appKey];
            break;
        default:
            break;
    }
    
    base64Signature = [[[ANOAHMAC_SHA1SignatureProvider alloc] init] signClearText:signatureBaseString withSecret:anPushKey];

    return base64Signature;
}
