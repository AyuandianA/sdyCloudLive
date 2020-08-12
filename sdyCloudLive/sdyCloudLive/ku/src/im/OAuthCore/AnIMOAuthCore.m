#import "AnIMOAuthCore.h"
#import "ArrownockConstants.h"
#import "ANOAHMAC_SHA1SignatureProvider.h"

NSString *AnIMOAuthorizationSignature(AnIMMethod method, NSString *appKey, NSString *topic, NSString *clientIdsString, NSString *dateString, NSString *anid, NSString *service, NSString *type, NSString *pushKey, NSString *bind)
{
    NSString *signatureBaseString = @"";
    NSString *AnIMKey = ARROWNOCK_API_SECRET;
    NSString *base64Signature;
    
    switch (method) {
        case AnIMMethodBindService:
            signatureBaseString = [NSString stringWithFormat:@"/%@/im/signed_bind_service.jsonappkey=%@&bind=%@&client=%@&date=%@&device_type=%@&key=%@&service=%@&service_id=%@",
                                   ARROWNOCK_API_VERSION,
                                   pushKey,
                                   bind,
                                   clientIdsString,
                                   dateString,
                                   type,
                                   appKey,
                                   service,
                                   anid];
            break;
        case AnIMMethodUnbindService:
            signatureBaseString = [NSString stringWithFormat:@"/%@/im/signed_bind_service.jsonbind=%@&client=%@&date=%@&device_type=%@&key=%@&service=%@",
                                   ARROWNOCK_API_VERSION,
                                   bind,
                                   clientIdsString,
                                   dateString,
                                   type,
                                   appKey,
                                   service];
            break;
        
            
        default:
            break;
    }
    
    base64Signature = [[[ANOAHMAC_SHA1SignatureProvider alloc] init] signClearText:signatureBaseString withSecret:AnIMKey];
    
    return base64Signature;
}

NSString *AnIMGetSignature(NSString* urlString, NSMutableDictionary* params)
{
    NSString *signatureBaseString = @"";
    NSString *AnIMKey = ARROWNOCK_API_SECRET;
    NSArray* keyArray = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (int i = 0; i < keyArray.count; i++) {
        signatureBaseString = [signatureBaseString stringByAppendingFormat:@"&%@=%@",[keyArray objectAtIndex: i], [params objectForKey:[keyArray objectAtIndex: i]]];
    }
    signatureBaseString = [urlString stringByAppendingString:[signatureBaseString substringFromIndex:1]];

    return [[[ANOAHMAC_SHA1SignatureProvider alloc] init] signClearText:signatureBaseString withSecret:AnIMKey];
}

