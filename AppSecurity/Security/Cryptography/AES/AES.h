

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

@interface AES : NSObject

/* AES Encryption and Decryption */
+(NSData *)getAES128EncryptedStringForMessageData:(NSData *)messageData keyData:(NSData *)keyData;
+(NSData *)getAES128DecryptedStringForMessageData:(NSData *)messageData keyData:(NSData *)keyData;
+(NSData *)hexDataFromString:(NSString *)key;
+(NSString *)hexStringFromData:(NSData *)data;
+(NSString *)encryptMessage:(NSString *)message withKey:(NSString *)key;
+(id)decryptMessage:(NSString *)message withKey:(NSString *)key;

@end
