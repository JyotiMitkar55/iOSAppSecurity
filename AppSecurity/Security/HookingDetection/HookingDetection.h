//
//  HookingObjc.h
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface HookingDetection : NSObject

+(BOOL)isDebugged;
+(BOOL)isDylibInjected;
+(BOOL)isClassHookedWithClassList:(NSArray *)classList;
+(BOOL)isSensitiveFunctionHooked:(IMP)method;

@end
