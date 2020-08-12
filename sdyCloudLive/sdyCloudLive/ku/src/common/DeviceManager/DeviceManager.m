#include <sys/types.h>
#include <sys/sysctl.h>

#import "DeviceManager.h"
#import "DeviceManagerURLConnection.h"
#import "ArrownockConstants.h"
#import "ANKeychainItemWrapper.h"
#import "ANReachability.h"
#import "ANBase64Wrapper.h"
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>

#define anSDKVersion ARROWNOCK_SDK_VERSION
#define uploadedTag ARROWNOCK_UPLOADED_TAG
#define uuidTag ARROWNOCK_UUID_TAG
#define apiURLFormatString @"%@://%@/%@"
#define metaDataURL @"devices/metadata"
#define locationURL @"devices/location"

static CLLocationManager *locManager;
static BOOL willKeepUpdatingLocation = NO;
static NSTimeInterval locationUpdatingInterval = -1.0f;
static ANDeviceManager *sharedInstance = nil;

@interface ANDeviceManager() <CLLocationManagerDelegate>
@property BOOL useSSL;
@property (nonatomic, strong) NSString *key;

@end

@implementation ANDeviceManager

+ (ANDeviceManager *)shared
{
    return sharedInstance;
}

+ (ANDeviceManager *)initializeWithAppKey:(NSString *)appKey secure:(BOOL)secure
{
    if (sharedInstance == nil) {
        sharedInstance = [[ANDeviceManager alloc] init];
    }
    sharedInstance.key = appKey;
    sharedInstance.useSSL = secure;
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [sharedInstance reportDeviceMetadata];
        [sharedInstance reportLocation];
    });
    
    return sharedInstance;
}

- (NSString *)getDeviceId
{
    return [self readUUID];
}

- (void)reportDeviceMetadata
{
#if TARGET_IPHONE_SIMULATOR
    return;
#endif
    
    if ([self checkIfEverUploaded]) {
        return;
    }
    
    NSString *metaDataURLString = [self getAPIURL:metaDataURL withAppKey:self.key];
    NSString *metaDataBodyString = [self getMetaDataBodyString];
    
    NSURL *url = [NSURL URLWithString:metaDataURLString];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"POST"];
    [request setHTTPBody:[metaDataBodyString dataUsingEncoding:NSUTF8StringEncoding]];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        ANDeviceManagerURLConnection *connection = [[ANDeviceManagerURLConnection alloc] initWithRequest:request delegate:self];
        connection.method = @"metadata";
        [connection start];
    });
}

- (void)reportLocation
{
#if TARGET_IPHONE_SIMULATOR
    return;
#endif
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSObject *last = [defaults objectForKey:@"com.arrownock.internal.device.LAST_LOCATION_REPORT"];
    if(last)
    {
        NSNumber *lastTS = (NSNumber*)last;
        NSNumber *now = @([[NSDate date] timeIntervalSince1970]);
        int interval = 60 * 60 * [ARROWNOCK_LOCATION_INTERVAL intValue];
        if(([now intValue] - [lastTS intValue]) < interval)
        {
            return;
        }
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        if (locManager == nil) {
            locManager = [[CLLocationManager alloc] init];
            locManager.delegate = sharedInstance;
            locManager.desiredAccuracy = kCLLocationAccuracyBest;
        }
    
        CLAuthorizationStatus status = [CLLocationManager authorizationStatus];
        if(status == kCLAuthorizationStatusNotDetermined || status == kCLAuthorizationStatusDenied || status == kCLAuthorizationStatusRestricted)
        {
            if ([locManager respondsToSelector:@selector(requestWhenInUseAuthorization)])
            {
                [locManager requestWhenInUseAuthorization];
            }
            if ([locManager respondsToSelector:@selector(requestAlwaysAuthorization)])
            {
                [locManager requestAlwaysAuthorization];
            }
        }
    
        if(status != kCLAuthorizationStatusRestricted && status != kCLAuthorizationStatusDenied)
        {
            [locManager startUpdatingLocation];
        }
    });
}

- (void)doUploadLocation:(CLLocation *)location withAppKey:(NSString *)appKey secure:(BOOL)secure
{
    [locManager stopUpdatingLocation];
    if (willKeepUpdatingLocation)
    {
        double delayInSeconds = locationUpdatingInterval;
        dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delayInSeconds * NSEC_PER_SEC));
        dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
            [locManager startUpdatingLocation];
        });
    }
    
    self.key = [NSString stringWithString:appKey];
    self.useSSL = secure;
    
    NSString *locationURLString = [self getAPIURL:locationURL withAppKey:self.key];
    NSString *locationBodyString = [self getLocationBodyString:location];
    
    NSURL *url = [NSURL URLWithString:locationURLString];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"POST"];
    [request setHTTPBody:[locationBodyString dataUsingEncoding:NSUTF8StringEncoding]];
    
    ANDeviceManagerURLConnection *connection = [[ANDeviceManagerURLConnection alloc] initWithRequest:request delegate:self];
    connection.method = @"location";
    [connection start];
}

- (BOOL)checkIfEverUploaded
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    BOOL flag = [[defaults objectForKey:uploadedTag] boolValue];
    return flag;
}

- (void)setHasUploaded:(BOOL)has
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:[NSNumber numberWithBool:has] forKey:uploadedTag];
    [defaults synchronize];
}

- (void)setLastLocationUploaded
{
    NSNumber *timestamp = @([[NSDate date] timeIntervalSince1970]);
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:timestamp forKey:@"com.arrownock.internal.device.LAST_LOCATION_REPORT"];
    [defaults synchronize];
}

- (NSString *)getAPIURL:(NSString *)endpoint withAppKey:(NSString *)key
{
    NSString *url = [NSString stringWithFormat:apiURLFormatString, self.useSSL?@"https":@"http", ARROWNOCK_DEVICE_HOST, endpoint];
    return url;
}

- (NSString *)getMetaDataBodyString
{
    NSMutableDictionary *telephonyInfo = [[self getTelephonyInfo] mutableCopy];
    NSMutableDictionary *deviceInfo = [[self getUIDeviceInfo] mutableCopy];
    NSMutableDictionary *hardwareInfo = [[self getHardwareInfo] mutableCopy];
    NSMutableDictionary *timeZoneInfo = [[self getTimezoneInfo] mutableCopy];
    
    NSMutableDictionary *allDict = [NSMutableDictionary dictionaryWithDictionary:telephonyInfo];
    [allDict addEntriesFromDictionary:deviceInfo];
    [allDict addEntriesFromDictionary:hardwareInfo];
    [allDict addEntriesFromDictionary:timeZoneInfo];
    
    [allDict setObject:self.key forKey:@"key"];
    [allDict setObject:[self readUUID] forKey:@"device_id"];
    [allDict setObject:anSDKVersion forKey:@"an_sdk"];
    [allDict setObject:@"ios" forKey:@"device_type"];
    
    NSString *extendedBodyString = [self serializeExtendedBody:allDict];
    NSString *bodyString = [NSString stringWithString:[self encodeString:extendedBodyString]];
    return bodyString;
}

- (NSString *)getLocationBodyString:(CLLocation *)location
{
    NSString *lat = [NSString stringWithFormat:@"%f", location.coordinate.latitude];
    NSString *lng = [NSString stringWithFormat:@"%f", location.coordinate.longitude];
    NSString *alt = [NSString stringWithFormat:@"%f", location.altitude];
    NSString *acc = [NSString stringWithFormat:@"%f", location.horizontalAccuracy];
    NSString *vAcc = [NSString stringWithFormat:@"%f", location.verticalAccuracy];
    NSString *speed = [NSString stringWithFormat:@"%f", location.speed];
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithObjects:@[
                                                                             lat,
                                                                             lng,
                                                                             alt,
                                                                             acc,
                                                                             vAcc,
                                                                             speed
                                                                             ]
                                                                   forKeys:@[
                                                                             @"lat",
                                                                             @"lng",
                                                                             @"alt",
                                                                             @"acc",
                                                                             @"vAcc",
                                                                             @"speed"
                                                                             ]
                                 ];
    [dict setObject:self.key forKey:@"key"];
    [dict setObject:[self readUUID] forKey:@"device_id"];
    [dict setObject:anSDKVersion forKey:@"an_sdk"];
    [dict setObject:@"ios" forKey:@"device_type"];
    
    NSString *extendedBodyString = [self serializeExtendedBody:dict];
    NSString *bodyString = [NSString stringWithString:[self encodeString:extendedBodyString]];
    
    return bodyString;
}

- (NSString *)serializeExtendedBody:(NSDictionary *)bodyDictionary
{
    NSString *bodyString = [[NSString alloc] init];
    
    for (NSString *key in [bodyDictionary allKeys]) {
        NSString *thisString = [NSString stringWithFormat:@"&%@=%@", key, [bodyDictionary objectForKey:key]];
        bodyString = [bodyString stringByAppendingString:thisString];
    }
    
    return bodyString;
}

- (NSString *)generateUUID
{
    NSString* deviceId = nil;
    if ([[[UIDevice currentDevice] systemVersion] hasPrefix:@"5"]) {
        CFUUIDRef cfuuid = CFUUIDCreate(kCFAllocatorDefault);
        deviceId = (NSString*)CFBridgingRelease(CFUUIDCreateString(kCFAllocatorDefault, cfuuid));
    } else {
        deviceId = [[NSUUID UUID] UUIDString];
    }
    
    const char *ptr = [deviceId UTF8String];
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    CC_MD5(ptr, strlen(ptr), md5Buffer);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x",md5Buffer[i]];
    
    return [NSString stringWithFormat:@"1%@", output];
}

- (NSString *)readUUID
{
    ANKeychainItemWrapper *keychainItem = [[ANKeychainItemWrapper alloc] initWithIdentifier:uuidTag accessGroup:nil];
    
    NSString *UUID = [keychainItem objectForKey:(__bridge id)kSecAttrService];
    if (UUID != nil && [UUID length] != 0) {
        return UUID;
    } else {
        [self writeUUID:[self generateUUID]];
        return [self readUUID];
    }
}

- (void)writeUUID:(NSString *)UUID
{
    ANKeychainItemWrapper *keychainItem = [[ANKeychainItemWrapper alloc] initWithIdentifier:uuidTag accessGroup:nil];
    [keychainItem setObject:UUID forKey:(__bridge id)kSecAttrService];
}

- (NSString *)encodeString:(NSString *)originalString
{
    return [originalString stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    
    originalString = [originalString stringByReplacingOccurrencesOfString:@"/" withString:@"-"];
    return [originalString stringByReplacingOccurrencesOfString:@" " withString:@"-"];
    
    NSString *encodedString = (__bridge NSString *)CFURLCreateStringByAddingPercentEscapes(NULL,
                                                                                           (CFStringRef)originalString,
                                                                                           NULL,
                                                                                           (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                                                           kCFStringEncodingUTF8);
    return encodedString;
}

- (NSString *)getCurrentNetworkStatus
{
    ANReachability *r = [ANReachability reachabilityWithHostName:ARROWNOCK_DEVICE_HOST];
    NetworkStatus status = r.currentANReachabilityStatus;
    
    NSString *network = nil;
    switch (status) {
        case ReachableViaWWAN:
            network = @"WWAN";
            break;
        case ReachableViaWiFi:
            network = @"WiFi";
            break;
            
        default:
            network = @"None";
            break;
    }
    
    return network;
}

#pragma mark CoreTelephony

- (NSDictionary *)getTelephonyInfo
{
    CTTelephonyNetworkInfo *netInfo = [[CTTelephonyNetworkInfo alloc] init];
    CTCarrier *carrier = [netInfo subscriberCellularProvider];
    NSString *carrierName = [carrier carrierName];
    NSString *mcc = [carrier mobileCountryCode];
    NSString *mnc = [carrier mobileNetworkCode];
    
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
    if([carrierName length] > 0)
    {
        [dict setValue:carrierName forKey:@"carrier_name"];
    }
    if([mcc length] > 0)
    {
        [dict setValue:mcc forKey:@"mcc"];
    }
    if([mnc length] > 0)
    {
        [dict setValue:mnc forKey:@"mnc"];
    }
    return dict;
}

#pragma mark UIDevice

- (NSString *)platform
{
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *machine = malloc(size);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    NSString *platform = [NSString stringWithCString:machine encoding:NSUTF8StringEncoding];
    free(machine);
    return platform;
}

- (NSDictionary *)getUIDeviceInfo
{
    UIDevice *device = [UIDevice currentDevice];
    NSString *systemName = device.systemName;
    NSString *systemVersion = device.systemVersion;
    NSString *name = device.name;
    //    NSString *model = device.model;
    //    NSString *localizedModel = device.localizedModel;
    NSString *model = [self platform];
    
    CGSize screenSize = [UIScreen mainScreen].bounds.size;
    CGFloat scale = [UIScreen mainScreen].scale;
    NSString *screenWidth = [NSString stringWithFormat:@"%d", (int)(screenSize.width * scale)];
    NSString *screenHeight = [NSString stringWithFormat:@"%d", (int)(screenSize.height * scale)];
    
    NSString *network = [self getCurrentNetworkStatus];
    
    NSDictionary *dict = [NSDictionary dictionaryWithObjects:@[
                                                               systemName,
                                                               systemVersion,
                                                               name,
                                                               model,
                                                               screenWidth,
                                                               screenHeight,
                                                               network
                                                               ]
                                                     forKeys:@[
                                                               @"system_name",
                                                               @"system_version",
                                                               @"device_name",
                                                               @"device_model",
                                                               @"screen_width",
                                                               @"screen_height",
                                                               @"network"
                                                               ]
                          ];
    
    return dict;
}

#pragma mark Hardware

- (NSDictionary *)getHardwareInfo
{
    NSProcessInfo *processInfo = [NSProcessInfo processInfo];
    NSString *cpu_core = [NSString stringWithFormat:@"%lu", (unsigned long)[processInfo processorCount]];
    NSString *physicalMemory = [NSString stringWithFormat:@"%llu", [processInfo physicalMemory]];
    
    NSDictionary *dict = [NSDictionary dictionaryWithObjects:@[
                                                               cpu_core,
                                                               physicalMemory
                                                               ]
                                                     forKeys:@[
                                                               @"cpu_core",
                                                               @"physical_memory"
                                                               ]
                          ];
    
    return dict;
}

#pragma mark Timezone

- (NSDictionary *)getTimezoneInfo
{
    NSLocale *locale = [NSLocale currentLocale];
    NSString *localeIdentifier = [locale localeIdentifier];
    
    NSTimeZone *systemTimeZone = [NSTimeZone systemTimeZone];
    NSString *timeZone = [systemTimeZone name];
    
    NSDictionary *dict = [NSDictionary dictionaryWithObjects:@[
                                                               localeIdentifier,
                                                               timeZone
                                                               ]
                                                     forKeys:@[
                                                               @"locale_identifier",
                                                               @"timezone"
                                                               ]
                          ];
    
    return dict;
}

# pragma mark - ConnectionData Delegate

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    NSHTTPURLResponse *res = (NSHTTPURLResponse *)response;
    NSString *method = ((ANDeviceManagerURLConnection *)connection).method;
    if (res.statusCode == 200)
    {
        if([@"location" isEqualToString:method])
        {
            [self setLastLocationUploaded];
        }
        else
        {
            [self setHasUploaded:YES];
        }
    }
    else
    {
        if([@"metadata" isEqualToString:method])
        {
            [self setHasUploaded:NO];
        }
    }
}

# pragma mark - Connection Delegate

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    [self setHasUploaded:NO];
}

# pragma mark - CLLocationManagerDelegate

- (void)locationManager:(CLLocationManager *)manager didUpdateLocations:(NSArray *)locations
{
    int count = [locations count];
    CLLocation *location = (CLLocation *)[locations objectAtIndex:count - 1];
    
    NSTimeInterval timeInterval = [location.timestamp timeIntervalSinceNow];
    if (timeInterval < -1.0) {
        return;
    }
    
    [self doUploadLocation:location withAppKey:self.key secure:self.useSSL];
}

- (void)locationManager:(CLLocationManager *)manager didChangeAuthorizationStatus:(CLAuthorizationStatus)status
{
    if(status == kCLAuthorizationStatusDenied || status == kCLAuthorizationStatusRestricted)
    {
        NSLog(@"[Arrownock] The location service has been disabled by user, no location data will be reported.");
    }
}

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
