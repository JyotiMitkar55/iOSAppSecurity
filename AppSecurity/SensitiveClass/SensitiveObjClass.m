//
//  SensitiveObjClass.m
//  AppSecurity
//

#import "SensitiveObjClass.h"

@implementation SensitiveObjClass

+(NSString *)callCustomClassMethod{
    NSMutableData *data = [NSMutableData dataWithLength:16];
    int result = SecRandomCopyBytes(NULL, 16, data.mutableBytes);
    NSAssert(result == 0, @"Error generating random bytes: %d", errno);
    NSString *randomKey = [data base64EncodedStringWithOptions:0];
    return randomKey;
}

/* Random String of Length n */
-(NSString *)callInstanceMethodWithLength:(int)length{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(NULL, length, data.mutableBytes);
    NSAssert(result == 0, @"Error generating random bytes: %d", errno);
    NSString *base64EncodedData = [data base64EncodedStringWithOptions:0];
    return [base64EncodedData substringToIndex:26];
}

@end
