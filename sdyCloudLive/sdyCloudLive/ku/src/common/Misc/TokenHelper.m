#import <CommonCrypto/CommonDigest.h>
#import <math.h>
#import "TokenHelper.h"

@implementation ANTokenHelper

+ (NSArray *)getSourceData
{
    static NSArray *_data;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _data = @[@"0",@"1",@"2",@"3",@"4",@"5",@"6",@"7",@"8",@"9",
                  @"A",@"B",@"C",@"D",@"E",@"F",@"G",@"H",@"I",@"J",@"K",@"L",@"M",
                  @"N",@"O",@"P",@"Q",@"R",@"S",@"T",@"U",@"V",@"W",@"X",@"Y",@"Z"];
    });
    return _data;
}

+ (NSString *) getToken:(NSString *)theId appKey:(NSString *)appKey odd:(int)odd prefix:(NSString *)prefix
{
    NSString * newId = theId;
    if(odd > 0)
    {
        newId = [NSString stringWithFormat:@"%@%d", newId, odd];
    }
    newId = [NSString stringWithFormat:@"%@%@", newId, appKey];
    
    NSString * hashedString = [ANTokenHelper encrypt:newId];
    hashedString = [NSString stringWithFormat:@"%@%@", prefix, hashedString];
    return hashedString;
}

+ (NSString *)encrypt:(NSString *)inputString
{
    NSData *data = [inputString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, data.length, digest);
    NSString * hashedString = [ANTokenHelper bytesToCharacters:digest withLength:CC_SHA1_DIGEST_LENGTH];
    return hashedString;
}

+ (NSString *)bytesToCharacters:(unsigned char *)digest withLength:(int)length
{
    NSMutableArray * results = [[NSMutableArray alloc] init];
    NSArray * sourceData = [[self class] getSourceData];
    
    for (int i = 0; i < length; i++)
    {
        NSString * result;
        int index = digest[i];
        index = (index > 127 ? 256 - index : index);
        int offset = index / 36;
        
        if( offset < 1 )
        {
            result = sourceData[index];
        }
        else
        {
            //result = const2[ val - position * 36 + position - 2];
            result = sourceData[ (index + offset) % 36 ];
        }
        [results addObject:result];
    }
    return [results componentsJoinedByString:@""];
}
@end