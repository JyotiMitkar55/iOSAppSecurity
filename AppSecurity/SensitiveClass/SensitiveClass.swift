//
//  SensitiveClass.swift
//  AppSecurity
//

import UIKit

@objc class SensitiveClass: NSObject {
    
    @objc class func callStaticMethod() -> String {
        return "87687998096455895467890987654"
    }
    @objc func callInstanceMethod() -> String {
        return "67898856789876546789987659"
    }
}
