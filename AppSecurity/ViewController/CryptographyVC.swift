//
//  CryptographyVC.swift
//  AppSecurity
//

import UIKit

class CryptographyVC: UIViewController {
    
    var encryptionKey:String = String()
    var rsaPublicKey:String = String()
    var rsaPrivateKey:String = String()
    
    override func viewDidLoad() {
        
        super.viewDidLoad()
        
        self.navigationItem.title = "Cryptography"
        encryptionKey = "30820270308201d9a003020102020458"
        rsaPublicKey = "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH6h8g3BkYJOjI6I1TqvGZqjJ7tc\nrS+Lj/x5TdV6jW31a/E4s3oc4EcqBfB/KZLpIKzifJpNHLN3o/Lu9mtlLqKC7TLR\nCu0fDEtyd159LJqhnzX6pZjA2Wy5sQRsTJz3AJJwtbCkL0MPcbkIv/Tyt9Vvycv2\nL+6FMNuCDTxmvTVTAgMBAAE=\n-----END PUBLIC KEY-----";
        rsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgH6h8g3BkYJOjI6I1TqvGZqjJ7tcrS+Lj/x5TdV6jW31a/E4s3oc\n4EcqBfB/KZLpIKzifJpNHLN3o/Lu9mtlLqKC7TLRCu0fDEtyd159LJqhnzX6pZjA\n2Wy5sQRsTJz3AJJwtbCkL0MPcbkIv/Tyt9Vvycv2L+6FMNuCDTxmvTVTAgMBAAEC\ngYB2T/pmTdcUhy0dssx+IsDqUMu7azBH/r4NZoyJCxJ+jNFIM/DEA5ysAKBB/Z0r\nLHMh9A304F0TdJGSVR+YYZW6V29Klo7aCy+1Cl84yVCcdlSa1IsqFm45hCgHjlFS\n2Mi9hZ0vf0a2Jn4AML9kxa7jgonqkoniR6wqvAb4GCZmwQJBAObky6FOX3L9Izot\nUcCTRd8fBTxpPdnoC0Oy97wlE52QCi3bgdMKeoyCQSaMDW8bd6TUpjXtjW+zNZEn\nvIubv6ECQQCMZuqIrc4Nrxq7ZHjpKVA/s4w6i9B9xofvn+wXqlbQhGca7zMiRvKb\npNLz6RoV9+ocKUY569b7kUNjZlQukiBzAkEAlnGRtOLqEnSaFXgeAopzRnRh5wDz\nyh4F6PCdtru50jpeR471Qltbil38sW8j+bc99+qO+ih0tclhJ9lqYtTywQJAINIO\nEVVPzbMZNKUP/rFBqSJ3rVfxrPUz4bgooH+ZO7U3xPwVn/Wl0Ox+w7XB+1Cw0VR0\nriWLY9NZRWsuUpSmMQJAQRMv+pSqkeTZC+Wb93xlD4JS5EWYAJNz8/fH7Swc9MP6\nGFjt5EYmrx1oXNfjmFFb1gqa6Fr52/lizPx3BnEE8A==\n-----END RSA PRIVATE KEY-----"
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }
    
    //MARK: - IBOutlet Methods
    @IBAction func encryptMessageWithAES(_ sender: Any) {
        print(AES.encryptMessage("TEST MESSAGE", withKey: encryptionKey))
        displayAlertViewWith(title: "Encrypted Message with AES", message: AES.encryptMessage("TEST MESSAGE", withKey: encryptionKey))
    }
    
    @IBAction func decryptMessageWithAES(_ sender: Any) {
        displayAlertViewWith(title: "Decrypted Message with AES", message: AES.decryptMessage("9B36948EB3C01371C3C0A384EE8E131C", withKey: encryptionKey) as! String)
    }
    
    @IBAction func encryptMessageWithRSA(_ sender: Any) {
        print(RSA.encryptString("TEST MESSAGE", publicKey: rsaPublicKey))
        displayAlertViewWith(title: "Encrypted Message with RSA", message: RSA.encryptString("TEST MESSAGE", publicKey: rsaPublicKey))
    }
    
    @IBAction func decryptMessageWithRSA(_ sender: Any) {
        displayAlertViewWith(title: "Decrypted Message with AES", message: RSA.decryptString("OJgfrrNB6ZGvr5Z1UAJf12DpOK++KJ547OQMM/QvoebP/BxVrM+SOsisJ6KYaIH2Mvd14AbCgCCojqXEQ+awKd0VDRWHfcOowiPKNlBZDMiuI/yFHmRfW2My7e9NooY7sjlWi7ZgaQlzSCTcIAIvarOxhw0LiZF4w0RgYbYTgMg=", privateKey: rsaPrivateKey))
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
}
