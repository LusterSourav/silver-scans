rule Pegasus_Spyware_Indicators {
    meta:
        description = "Pegasus spyware indicators"
        author = "Mobile Forensics Scanner"
        severity = "critical"
    strings:
        $pegasus1 = "com.pegasus" ascii wide
        $pegasus2 = "Pegasus" ascii wide
        $pegasus3 = "NSO Group" ascii wide
    condition:
        any of them
}

rule Predator_Spyware_Indicators {
    meta:
        description = "Predator spyware indicators"
        author = "Mobile Forensics Scanner"
        severity = "critical"
    strings:
        $predator1 = "Predator" ascii wide
        $predator2 = "Cytrox" ascii wide
    condition:
        any of them
}

rule Generic_Malware_Patterns {
    meta:
        description = "Generic mobile malware patterns"
        author = "Mobile Forensics Scanner"
        severity = "high"
    strings:
        $sms_intercept = "android.provider.Telephony.SMS_RECEIVED" ascii
        $device_admin = "android.app.admin.DeviceAdminReceiver" ascii
        $accessibility = "android.accessibilityservice.AccessibilityService" ascii
        $overlay = "SYSTEM_ALERT_WINDOW" ascii
        $root_check = "su" ascii
        $frida = "frida" ascii wide
        $xposed = "Xposed" ascii wide
        $magisk = "magisk" ascii wide
    condition:
        3 of them
}

rule Suspicious_Network_Indicators {
    meta:
        description = "Suspicious network communication patterns"
        author = "Mobile Forensics Scanner"
        severity = "medium"
    strings:
        $tor = ".onion" ascii
        $c2_pattern1 = "command" ascii
        $c2_pattern2 = "control" ascii
        $c2_pattern3 = "beacon" ascii
        $hardcoded_ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        2 of them
}

rule Data_Exfiltration_Indicators {
    meta:
        description = "Data exfiltration capabilities"
        author = "Mobile Forensics Scanner"
        severity = "high"
    strings:
        $contacts = "ContactsContract" ascii
        $call_log = "CallLog" ascii
        $sms = "SmsMessage" ascii
        $location = "LocationManager" ascii
        $camera = "Camera.open" ascii
        $mic = "MediaRecorder" ascii
        $upload = "HttpURLConnection" ascii
        $ftp = "FTPClient" ascii
    condition:
        4 of them
}