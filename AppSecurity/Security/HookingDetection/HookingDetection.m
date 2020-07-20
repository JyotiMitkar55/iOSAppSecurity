//
//  HookingObjc.m
//

#import "SensitiveObjClass.h"

#import "HookingDetection.h"
#import <SystemConfiguration/SystemConfiguration.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import "AppSecurity-Swift.h"

//int isDebugged() __attribute__((always_inline));
//int checkDylibInjected() __attribute__((always_inline));
//int isClassHooked() __attribute__((always_inline));
//int checkSubstrateTrampoline() __attribute__((always_inline));

int isDebugged() {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    info.kp_proc.p_flag = 0;
    
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    if(sysctl(name, 4, &info, &info_size, NULL, 0) == -1)
    return 1; // bad sign
    
    return((info.kp_proc.p_flag & P_TRACED) != 0);
    // 0 is good - not being debugged
}

int checkDylibInjected() {
    
    uint32_t count = _dyld_image_count();
    char* blacklist[] = {"Substrate","cycript"}; // Examples of malicious dylibs
    
    for(uint32_t i = 0; i < count; i++) {
        
        const char *dyld = _dyld_get_image_name(i);
        int length = strlen(dyld);
        
        int j;
        for(j = length - 1; j >= 0; --j)
        if(dyld[j] == '/')
        break;
        
        char *name = strndup(dyld + ++j, length - j);
        
        for(int x=0; x<sizeof(blacklist)/sizeof(char*); x++){
            if(strstr(name, blacklist[x]) || strstr(dyld, blacklist[x])){
                // malicious dylib loaded!
                NSLog(@"malicious dylib loaded : %s",name);
                return YES;
            }
        }
        
        free(name);
    }
    return NO;
}

int isClassHooked(Class object) {
    
    const char * bundlePath = [[NSString stringWithFormat:@"%@/%@",[[NSBundle mainBundle] bundlePath],[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleName"]] cStringUsingEncoding:NSASCIIStringEncoding];
    
    char imagepath[512];
    unsigned int n;
    Dl_info info;
    
    Method *m = class_copyMethodList(object, &n);
    
    for (int i = 0; i < n; i++) {
        
        void *methodimp = (void *)method_getImplementation(m[i]);
        
        int d = dladdr((const void*)methodimp, &info);
        if(!d)
        return YES; // bad
        
        // check against known good locations
        memset(imagepath, 0x00, sizeof(imagepath));
        memcpy(imagepath, info.dli_fname, 9);
        if(strcmp(imagepath, "/usr/lib/") == 0)
        continue;
        
        memset(imagepath, 0x00, sizeof(imagepath));
        memcpy(imagepath, info.dli_fname, 27);
        if(strcmp(imagepath, "/System/Library/Frameworks/") == 0)
        continue;
        
        memset(imagepath, 0x00, sizeof(imagepath));
        memcpy(imagepath, info.dli_fname, 34);
        if(strcmp(imagepath, "/System/Library/PrivateFrameworks/") == 0)
        continue;
        
        memset(imagepath, 0x00, sizeof(imagepath));
        memcpy(imagepath, info.dli_fname, 29);
        if(strcmp(imagepath, "/System/Library/Accessibility") == 0)
        continue;
        
        memset(imagepath, 0x00, sizeof(imagepath));
        memcpy(imagepath, info.dli_fname, 25);
        if(strcmp(imagepath, "/System/Library/TextInput") == 0)
        continue;
        
        // check image name against the apps image location
        if(strcmp(info.dli_fname, bundlePath) == 0){
            NSLog(@"%s is called",info.dli_sname);
            continue;
        }
        return YES;// bad
    }
    free(m);
    return NO; // this is good
}

int isFunctionHooked(void * funcptr) {
    
    unsigned int *funcaddr = (unsigned int *)funcptr;
    
    if(funcptr)
    // assuming the first word is the trampoline
    if (funcaddr[0] == 0xe51ff004) // 0xe51ff004 = ldr pc, [pc-4]
    return 1; // bad
    
    return 0; // good
}

@implementation HookingDetection

+(BOOL)isDebugged{
    return isDebugged();
}
+(BOOL)isDylibInjected{
    return checkDylibInjected();
}
+(BOOL)isClassHookedWithClassList:(NSArray *)classList{
    
    for (int i = 0; i < [classList count]; i++) {
        NSLog(@"Class name: %s", class_getName(classList[i]));
        NSLog(@"isClassHooked instance method: %d", isClassHooked(classList[i]));
        NSLog(@"isClassHooked class method: %d", isClassHooked(object_getClass(classList[i])));
        
        /* Checking whether instance method is hooked or not */
        if (isClassHooked(classList[i]) == YES){
            return YES;
        }
        else{
            /* Checking whether class method is hooked or not */
            if (isClassHooked(object_getClass(classList[i])) == YES){
                return YES;
            }
        }
    }
    //classList = nil;
    return NO;
}
+(BOOL)isSensitiveFunctionHooked:(IMP)method{
    
    IMP methodIMP = method;
    void (*functionPointer)(id, SEL, NSString*) = (void (*)(id, SEL, NSString*))methodIMP;
    NSLog(@"function is hooked : %d",isFunctionHooked(functionPointer));
    if (isFunctionHooked(functionPointer) == YES)
        return YES;
    return NO;
}

@end
