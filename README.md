# AppSecurity

## JailBreak Detection:

We can detect if a device is jailBroken or not by checking the following:

1. Cydia is installed
2. Verify some of the system paths
3. Can perform a sandbox integrity check
4. Symbolic links check
5. Verify whether you create and write files outside your Sandbox
6. Verify whether you have access to inaccessible Files
7. Verify the exit status of fork() and the existence of certain known dylib’s.

### Installation

1. Copy the **JBDetection.swift** and put it in the source folder of your project.
2. Use **isJailBroken** function to check whether a device is jailbroken or not.

### Example

```
if JBDetection.isJailBroken() == true{
    self.displayAlertViewWith(title: JAIL_BREAK_IS_DETECTED_TITLE, message: "")
}
else{
    self.displayAlertViewWith(title: JAIL_BREAK_IS_NOT_DETECTED_TITLE, message: "")
}
```

```
func displayAlertViewWith(title :String, message :String){
    var alertController:UIAlertController? = UIAlertController(title: title, message: message, preferredStyle: UIAlertControllerStyle.alert)
    var okAction:UIAlertAction? = UIAlertAction(title: "OK", style: UIAlertActionStyle.default) { (action) in

    }
    alertController?.addAction(okAction!)
    self.present(alertController!, animated: true, completion: nil)
    alertController = nil
    okAction = nil
}
```


## Hooking Detection

**HookingDetection** class consists of utility methods to detect whether an Objective-C/Swift method is swizzled or overridden at runtime. We can detect if a function/class is hooked or not by checking the following:
1. Verify whether debug mode is enabled or not
2. Verify whether Suspicious dylibs Libraries are injected or not
3. Verify whether sensitive class is hooked or not by checking the source location of a method which is implemented in that class.
4. Verify whether a sensitive function is hooked or not by identifying signatures of common frameworks inside that function.


### Installation

1. Copy the **HookingDetection.h** and **HookingDetection.m** and put them in the source folder of your project.
2. Create **Objective-C Bridging Header** and add below import line to that bridging header file. You may refer step [here](https://stackoverflow.com/questions/39614899/objective-c-bridging-header-not-getting-created-with-xcode-8) for the same.
3. You may use the **IsClassFunctionHooked** function to check whether a particular class or method is hooked or not. In this function, classList and methodList are arrays in which you may add your custom sensitive classes and methods respectively to verify whether they are hooked. 

```
#import "HookingDetection.h"
```

### Example

```
func IsClassFunctionHooked(){

    var alertTitle:String? = nil;

    if HookingDetection.isDebugged() == false{
        alertTitle = DEBUG_MODE_IS_ENABLED;
    }
    else{
        if HookingDetection.isDylibInjected(){
            alertTitle = LIBRARIES_ARE_INJECTED;
        }
        else{

            /* You may add classes in classList Array to check whether they are hooked or not. In this method, all methods(Instance method, class method) of particular class will be checked. Please refer sample app for the same. */
            var classList:NSArray? = [SensitiveClass.self,SensitiveObjClass.self]

            if HookingDetection.isClassHooked(withClassList: classList as! [Any]){
                alertTitle = CLASS_IS_HOOKED;
            }
            else{

                /* You may add sensitive functions in method array to check whether they are hooked or not. Please refer sample app for the same.*/
                let methodList:[IMP] = [SensitiveObjClass.method(for: #selector(SensitiveObjClass.callInstanceMethod(withLength:))),SensitiveObjClass.method(for: #selector(SensitiveObjClass.callCustomClassMethod)),SensitiveClass.method(for: #selector(SensitiveClass.callStaticMethod)),SensitiveClass.method(for: #selector(SensitiveClass.callInstanceMethod))];

                for object in methodList{
                    if HookingDetection.isSensitiveFunctionHooked(object){
                        alertTitle = FUNCTION_IS_HOOKED
                        break
                    }
                    else{
                        alertTitle = CLASS_FUNCTION_IS_NOT_HOOKED
                        continue
                    }
                }

            }
            classList = nil
        }
    }
    if alertTitle != nil{
        self.displayAlertViewWith(title: alertTitle!, message: "")
    }
    alertTitle = nil
}
```


## Random Number Generator
The generation of random numbers is essential to cryptography. One of the most difficult aspect of cryptographic algorithms is in depending on or generating, true random information. By calling **generateRandomNumberWith** function, you may generate unique random number. 

If you pass 24 byte length in this function, it will generate string of 32 characters.

Where the Byte length is = (3/4) x (length of output string)

### Example
```
func generateRandomNumberWith(byteLength :Int){
    var keyData:Data? = Data(count: byteLength)
    var outputString:String? = nil
    let result = keyData?.withUnsafeMutableBytes {
        (mutableBytes: UnsafeMutablePointer<UInt8>) -> Int32 in
        SecRandomCopyBytes(kSecRandomDefault, byteLength, mutableBytes)
    }
    if result == errSecSuccess {
        outputString = (keyData?.base64EncodedString())!
        print(outputString!)
        displayAlertViewWith(title: "Random String", message: outputString!)
    } else {
        print("Problem generating random bytes")
    }
    keyData = nil
    outputString = nil
}
```
```
generateRandomNumberWith(byteLength: 24)//will generate string of 32 characters
```

## License
[MIT](https://thi.mit-license.org/)
