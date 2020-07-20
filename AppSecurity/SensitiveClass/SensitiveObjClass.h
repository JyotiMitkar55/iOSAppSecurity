//
//  SensitiveObjClass.h
//  AppSecurity
//

#import <Foundation/Foundation.h>

@interface SensitiveObjClass : NSObject

+(NSString *)callCustomClassMethod;
-(NSString *)callInstanceMethodWithLength:(int)length;

@end
