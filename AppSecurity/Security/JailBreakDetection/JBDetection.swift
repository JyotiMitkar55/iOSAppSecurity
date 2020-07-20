//
//  JBDetection.swift
//  JBDetection
//

import Foundation
import UIKit
import MachO
import SystemConfiguration

let HIDDENFILES = ["/Applications/RockApp.app","/Applications/Icy.app","/usr/sbin/sshd","/usr/bin/sshd","/usr/libexec/sftp-server","/Applications/WinterBoard.app","/Applications/SBSettings.app","/Applications/MxTube.app","/Applications/IntelliScreen.app","/Library/MobileSubstrate/DynamicLibraries/Veency.plist","/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist","/private/var/lib/apt","/private/var/stash","/System/Library/LaunchDaemons/com.ikey.bbot.plist","/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist","/private/var/tmp/cydia.log","/private/var/lib/cydia", "/etc/clutch.conf", "/var/cache/clutch.plist", "/etc/clutch_cracked.plist", "/var/cache/clutch_cracked.plist", "/var/lib/clutch/overdrive.dylib", "/var/root/Documents/Cracked/"]

@objc public class JBDetection:NSObject{
    
    class func isJailBroken() -> Bool
    {
        if TARGET_OS_SIMULATOR != 1
        {
            if self.checkFileSysemBasedDetection() == false && self.checkAPIbasedDetection() == false && self.checkURLScheme() == false{
                return false
            }
            else{
                return true
            }
        }else{
            return false
        }
    }
    
    // MARK: Filesystem-based Detection
    class func checkFileSysemBasedDetection() -> Bool
    {
        if TARGET_OS_SIMULATOR != 1
        {
            if checkForFiles() || sandboxVoilationCheck() || symbolicLinkingCheck() || inaccessibleFilesCheck()
            {
                //Device is jailbroken
                return true
            }
            return false
        }
        else
        {
            return false
        }
    }
    
    //Check existance of file usually found on Jailbroken devices
    class func checkForFiles() -> Bool
    {
        if FileManager.default.fileExists(atPath: "/Applications/Cydia.app")
            || FileManager.default.fileExists(atPath: "/Applications/RockApp.app")
            || FileManager.default.fileExists(atPath: "/Applications/Icy.app")
            || FileManager.default.fileExists(atPath: "/Applications/WinterBoard.app")
            || FileManager.default.fileExists(atPath: "/Applications/SBSettings.app")
            || FileManager.default.fileExists(atPath: "/Applications/MxTube.app")
            || FileManager.default.fileExists(atPath: "/Applications/IntelliScreen.app")
            || FileManager.default.fileExists(atPath: "/Applications/FakeCarrier.app")
            || FileManager.default.fileExists(atPath: "/Applications/blackra1n.app")
            || FileManager.default.fileExists(atPath: "/private/var/stash")
            || FileManager.default.fileExists(atPath: "/var/cache/apt")
            || FileManager.default.fileExists(atPath: "/var/lib/apt")
            || FileManager.default.fileExists(atPath: "/var/lib/cydia")
            || FileManager.default.fileExists(atPath: "/var/log/syslog")
            || FileManager.default.fileExists(atPath: "/var/tmp/cydia.log")
            || FileManager.default.fileExists(atPath: "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist")
            || FileManager.default.fileExists(atPath: "/System/Library/LaunchDaemons/com.ikey.bbot.plist")
            || FileManager.default.fileExists(atPath: "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist")
            || FileManager.default.fileExists(atPath: "/Library/MobileSubstrate/DynamicLibraries/Veency.plist")
            || FileManager.default.fileExists(atPath: "/private/var/mobile/Library/SBSettings/Themes")
            || FileManager.default.fileExists(atPath: "/private/var/lib/cydia")
            || FileManager.default.fileExists(atPath: "/private/var/tmp/cydia.log")
            || FileManager.default.fileExists(atPath: "/Library/MobileSubstrate/MobileSubstrate.dylib")
            || FileManager.default.fileExists(atPath: "/bin/bash")
            || FileManager.default.fileExists(atPath: "/bin/sh")
            || FileManager.default.fileExists(atPath: "/usr/sbin/sshd")
            || FileManager.default.fileExists(atPath: "/usr/libexec/ssh-keysign")
            || FileManager.default.fileExists(atPath: "/usr/bin/sshd")
            || FileManager.default.fileExists(atPath: "/usr/libexec/sftp-server")
            || FileManager.default.fileExists(atPath: "/etc/apt")
            || FileManager.default.fileExists(atPath: "/etc/ssh/sshd_config")
            || FileManager.default.fileExists(atPath: "/private/var/lib/apt/")
        {
            //Device is jailbroken
            return true
        }
        else
        {
            return false
        }
    }
    
    //Standard framework check
    //***Don't consider this method for production as it always indicates a non-jailbroken device***
    /*class func checkForStandardFrameworks() -> Bool
    {
        if FileManager.default.fileExists(atPath: "/System/Library/Frameworks/Foundation.framework/")
        {
            // Presence indicates a non-jailbroken device
            return false
        }
        else
        {
            return true
        }
    }*/
    
    //Write access check outside of application's sandbox
    class func sandboxVoilationCheck() -> Bool{
        
        let stringToWrite = "Jailbreak Test"
        do{
            try stringToWrite.write(toFile:"/private/JailbreakTest.txt", atomically:true, encoding:String.Encoding.utf8)
            //Device is jailbroken
            return true
        }catch
        {
            return false
        }
    }
    
    //Symbolic links check
    class func symbolicLinkingCheck() -> Bool {
        var s : stat  = stat()
        if (lstat("/Applications", &s) == 0) {
            if (s.st_mode & S_IFMT == S_IFLNK) {
                return true
            }
        } else if (lstat("/Library/Ringtones", &s) == 0) {
            if s.st_mode & S_IFMT == S_IFLNK {
                return true
            }
        } else if (lstat("/Library/Wallpaper", &s) == 0) {
            if s.st_mode & S_IFMT == S_IFLNK {
                return true
            }
        } else if (lstat("/usr/arm-apple-darwin9", &s) == 0) {
            if s.st_mode & S_IFMT == S_IFLNK {
                return true
            }
        } else if (lstat("/usr/include", &s) == 0) {
            if s.st_mode & S_IFMT == S_IFLNK {
                return true
            }
        } else if (lstat("/usr/libexec", &s) == 0) {
            if s.st_mode & S_IFMT == S_IFLNK {
                return true
            }
        } else if (lstat("/usr/share", &s) == 0) {
            if s.st_mode & S_IFMT == S_IFLNK {
                return true
            }
        }
        return false
    }

    // Inaccessible Files Check
    class func inaccessibleFilesCheck() -> Bool {
        // Run through the array of files
        for key in HIDDENFILES {
            // Check if any of the files exist (should return no)
            if FileManager.default.fileExists(atPath: "\(key)") {
                //device is Jailbroken
                return true
            }
        }
        // No inaccessible files found, return NOT Jailbroken
        return false
    }
    
    // MARK: API-based Detection
    class func checkAPIbasedDetection() -> Bool
    {
        if TARGET_OS_SIMULATOR  != 1
        {
            if fork_check() || dyld_check()
            {
                //Device is jailbroken
                
                return true
            }
            else
            {
                return false
            }
        }
        else
        {
            return false
        }
    }
    
    //Forking
    class func fork_check() -> Bool
    {
        var pid = pid_t()
        posix_spawn(&pid, nil, nil, nil, nil, nil)
        if pid > 0
        {
            // device is jailbroken
            return true
        }
        else
        {
            return false
        }
    }
    
    class func dyld_check() -> Bool
    {
        //Get count of all currently loaded DYLD(Dynamic Link Editor)
        let count = _dyld_image_count()
        
        for i in (0..<count)
        {
            //Name of image (includes full path)
            let dyld = _dyld_get_image_name(i)
            if (strstr(dyld, "MobileSubstrate") == nil) {
                continue
            }
            else
            {
                return true
            }
        }
        return false
    }
    
    // MARK: Cydia Scheme Detection
    class func checkURLScheme() -> Bool
    {
        if UIApplication.shared.canOpenURL(URL(string:"cydia://package/com.example.package")!)
        {
            // Jailbroken
            return true
        }
        else
        {
            return false
        }
    }
}

