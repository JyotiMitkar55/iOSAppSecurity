//
//  ViewController.swift
//  AppSecurity
//

import UIKit

let JAIL_BREAK_IS_DETECTED_TITLE = "Device is Jail broken."
let JAIL_BREAK_IS_NOT_DETECTED_TITLE = "Device is not Jail broken."
let DEBUG_MODE_IS_ENABLED = "Debug mode is enabled.";
let CLASS_IS_HOOKED = "Class is hooked.";
let LIBRARIES_ARE_INJECTED = "Libraries are injected.";
let FUNCTION_IS_HOOKED = "Function is hooked.";
let CLASS_FUNCTION_IS_NOT_HOOKED = "Class/Function is not hooked.";

@objc class AppSecurityVC: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        self.navigationItem.title = "App Security"
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }
    //MARK: - IBOutlet methods
    @IBAction func jailBreakDetectionButtonClick(_ sender: Any) {
        if JBDetection.isJailBroken(){
            self.displayAlertViewWith(title: JAIL_BREAK_IS_DETECTED_TITLE, message: "")
        }
        else{
            self.displayAlertViewWith(title: JAIL_BREAK_IS_NOT_DETECTED_TITLE, message: "")
        }
    }
    
    @IBAction func hookingDetectionButtonClick(_ sender: Any) {
        IsClassFunctionHooked()
    }
    
    @IBAction func strongRandomNumberGenerator(_ sender: Any) {
        generateRandomNumberWith(byteLength: 24)
    }
    
    @IBAction func cryptographyButtonClick(_ sender: Any) {
        var controller:CryptographyVC? = UIStoryboard(name: "Main", bundle: nil).instantiateViewController(withIdentifier: "CryptographyVC") as? CryptographyVC
        self.navigationController?.pushViewController(controller!,animated: true)
        controller = nil
    }
    
    @IBAction func hashValueGenerator(_ sender: Any) {
        displayAlertViewWith(title: "Hash Value", message: HashGenerator.getHashValue())
    }
    
    //MARK: - Private Methods
    func displayAlertViewWith(title :String, message :String){
        
        DispatchQueue.main.async {
            var alertController:UIAlertController? = UIAlertController(title: title, message: message, preferredStyle: UIAlertControllerStyle.alert)
            var okAction:UIAlertAction? = UIAlertAction(title: "OK", style: UIAlertActionStyle.default) { (action) in
                
            }
            alertController?.addAction(okAction!)
            self.present(alertController!, animated: true, completion: nil)
            alertController = nil
            okAction = nil
        }
    }
    
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
    
    func IsClassFunctionHooked(){
        
        var alertTitle:String? = nil;
        
        if HookingDetection.isDebugged(){
            alertTitle = DEBUG_MODE_IS_ENABLED;
        }
        else{
            if HookingDetection.isDylibInjected(){
                alertTitle = LIBRARIES_ARE_INJECTED;
            }
            else{
                
                /* You may add classes in classList Array to check whether they are hooked or not. In this method, all methods(Instance method, class method) of particular class will be checked. Please refer sample app for the same. */
                var classList:NSArray? = [SensitiveClass.self,SensitiveObjClass.self]
                
                if HookingDetection.isClassHooked(withClassList: classList as? [Any]){
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
}

