//
//  RequestHelper.m
//

#import "HashGenerator.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

@implementation HashGenerator

+(NSString *)getHashValue{

    NSString *hash = [[NSBundle mainBundle] bundleIdentifier];

    hash = [self getMD5FromSting:hash];
    
    NSData *nsdata = [hash dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Encoded = [nsdata base64EncodedStringWithOptions:0];
    return base64Encoded;
}


+(NSString *)getMD5FromSting:(NSString *)randomString
{
    // Create pointer to the string as UTF8
    const char *ptr = [randomString UTF8String];
    
    // Create byte array of unsigned chars
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
    // Create 16 bytes MD5 hash value, store in buffer
    CC_MD5(ptr, (CC_LONG)strlen(ptr), md5Buffer);
    
    // Convert unsigned char buffer to NSString of hex values
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x",md5Buffer[i]];
    
    return output;
    
}

@end
