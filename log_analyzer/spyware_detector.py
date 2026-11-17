"""
Spyware Detection in Logs
Detects spyware, stalkerware, and surveillance software indicators in logs
"""
import asyncio
import re
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SpywareIndicator:
    name: str
    category: str
    severity: str
    indicators: List[str] = field(default_factory=list)
    description: str = ""
    mitre_technique: Optional[str] = None


class SpywareDetector:
    """
    Detects spyware, stalkerware, and surveillance software in logs
    Covers mobile spyware, stalkerware, RATs, keyloggers, and surveillance tools
    """
    
    # Known spyware/stalkerware package names and identifiers
    SPYWARE_PACKAGES = {
        # Commercial spyware
        "com.mspy.android.monitor": "mSpy",
        "com.flexispy.android": "FlexiSPY",
        "com.hoverwatch": "Hoverwatch",
        "com.spappmonitoring": "SPAPP",
        "com.cocospy.android": "Cocospy",
        "com.kidguard": "KidGuard",
        "com.phonespector": "PhoneSpector",
        "com.highster": "Highster Mobile",
        "com.autoforward": "Auto Forward",
        "com.exactspy": "ExactSpy",
        "com.spyic": "Spyic",
        "com.cocospy": "Cocospy",
        "com.mobistealth": "Mobistealth",
        "com.teensafe": "TeenSafe",
        "com.webwatcher": "WebWatcher",
        "com.norton.familypremier": "Norton Family Premier",
        "com.qustodio": "Qustodio",
        "com.netnanny": "Net Nanny",
        "com.bark": "Bark",
        "com.oursafety": "OurPact",
        "com.life360": "Life360",
        "com.findmykids": "Find My Kids",
        "com.kidslox": "Kidslox",
        "com.screentime": "Screen Time",
        
        # Stalkerware
        "com.letmetrack": "LetMeTrack",
        "com.gpswo": "GPSWO",
        "com.tracker": "Tracker",
        "com.locate": "Locate",
        "com.findmyphone": "Find My Phone",
        "com.findmyfriends": "Find My Friends",
        "com.familylocator": "Family Locator",
        "com.gpstracker": "GPS Tracker",
        "com.celltracker": "Cell Tracker",
        "com.phonetracker": "Phone Tracker",
        "com.spytracker": "Spy Tracker",
        "com.stealth": "Stealth",
        "com.hidden": "Hidden",
        "com.invisible": "Invisible",
        "com.secret": "Secret",
        "com.private": "Private",
        "com.hiddeneye": "Hidden Eye",
        "com.eyewitness": "Eye Witness",
        "com.spylog": "SpyLog",
        "com.keylogger": "Keylogger",
        "com.screenrecorder": "Screen Recorder",
        "com.callrecorder": "Call Recorder",
        "com.smsforwarder": "SMS Forwarder",
        "com.contactstealer": "Contacts Stealer",
        "com.locationtracker": "Location Tracker",
        "com.messagetracker": "Message Tracker",
        "com.whatsappmonitor": "WhatsApp Monitor",
        "com.facebookmonitor": "Facebook Monitor",
        "com.instagrammonitor": "Instagram Monitor",
        "com.snapchatmonitor": "Snapchat Monitor",
        "com.tiktokmonitor": "TikTok Monitor",
        
        # Malicious apps
        "com.android.system.update": "Fake System Update",
        "com.android.settings.security": "Fake Settings",
        "com.google.android.gms.location": "Fake Play Services",
        "com.google.android.gsf.login": "Fake Google Login",
        "com.android.vending.licensing": "Fake Licensing",
        "com.android.packageinstaller": "Fake Package Installer",
        "com.android.settings.bluetooth": "Fake Bluetooth",
        "com.android.settings.wifi": "Fake WiFi",
        "com.android.camera": "Fake Camera",
        "com.android.gallery": "Fake Gallery",
        "com.android.music": "Fake Music Player",
        "com.android.calculator": "Fake Calculator",
        "com.android.calendar": "Fake Calendar",
        "com.android.contacts": "Fake Contacts",
        "com.android.dialer": "Fake Dialer",
        "com.android.mms": "Fake Messages",
        "com.android.email": "Fake Email",
        "com.android.browser": "Fake Browser",
    }
    
    # Spyware behaviors and indicators
    SPYWARE_BEHAVIORS = {
        "location_tracking": [
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "ACCESS_BACKGROUND_LOCATION",
            "requestLocationUpdates",
            "LocationManager",
            "FusedLocationProviderClient",
            "Geofence",
            "GeofencingRequest",
            "LocationCallback",
            "LocationRequest",
            "FusedLocationProviderApi"
        ],
        "call_logging": [
            "READ_CALL_LOG",
            "READ_PHONE_STATE",
            "CALL_PHONE",
            "PROCESS_OUTGOING_CALLS",
            "CallLog",
            "TelephonyManager",
            "PhoneStateListener",
            "onCallStateChanged",
            "EXTRA_INCOMING_NUMBER",
            "EXTRA_STATE_RINGING",
            "EXTRA_STATE_OFFHOOK",
            "EXTRA_STATE_IDLE"
        ],
        "sms_monitoring": [
            "READ_SMS",
            "RECEIVE_SMS",
            "SEND_SMS",
            "RECEIVE_MMS",
            "SmsManager",
            "SmsMessage",
            "onReceive",
            "SMS_RECEIVED",
            "SMS_DELIVER_ACTION",
            "pdus",
            "getMessageBody",
            "getOriginatingAddress"
        ],
        "contact_theft": [
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "ContactsContract",
            "ContactsContract.Contacts",
            "ContactsContract.CommonDataKinds.Phone",
            "ContactsContract.CommonDataKinds.Email",
            "ContentResolver",
            "query",
            "DISPLAY_NAME",
            "HAS_PHONE_NUMBER",
            "NUMBER",
            "TYPE"
        ],
        "keylogging": [
            "INPUT_SERVICE",
            "BIND_INPUT_METHOD",
            "onStartInput",
            "onFinishInput",
            "onKeyDown",
            "onKeyUp",
            "sendKeyEvent",
            "InputConnection",
            "EditorInfo",
            "ExtractedText",
            "TextWatcher",
            "beforeTextChanged",
            "onTextChanged",
            "afterTextChanged"
        ],
        "screen_recording": [
            "MEDIA_PROJECTION",
            "createScreenCaptureIntent",
            "MediaProjectionManager",
            "MediaProjection",
            "createVirtualDisplay",
            "VirtualDisplay",
            "Surface",
            "SurfaceControl",
            "ScreenCapture",
            "MediaProjectionCallback"
        ],
        "audio_recording": [
            "RECORD_AUDIO",
            "AudioRecord",
            "MediaRecorder",
            "startRecording",
            "setAudioSource",
            "setOutputFormat",
            "setAudioEncoder",
            "setOutputFile",
            "prepare",
            "start",
            "stop",
            "release"
        ],
        "camera_access": [
            "CAMERA",
            "Camera",
            "Camera.open",
            "Camera.openCamera",
            "CameraDevice",
            "CameraManager",
            "openCamera",
            "createCaptureSession",
            "CaptureRequest",
            "ImageReader",
            "SurfaceTexture",
            "TextureView",
            "CameraPreview"
        ],
        "clipboard_monitoring": [
            "CLIPBOARD_SERVICE",
            "ClipboardManager",
            "getPrimaryClip",
            "getText",
            "setPrimaryClip",
            "OnPrimaryClipChangedListener",
            "addPrimaryClipChangedListener"
        ],
        "notification_access": [
            "BIND_NOTIFICATION_LISTENER_SERVICE",
            "NotificationListenerService",
            "onNotificationPosted",
            "onNotificationRemoved",
            "StatusBarNotification",
            "getNotification",
            "getPackageName",
            "getPostTime",
            "isClearable",
            "isOngoing"
        ],
        "accessibility_abuse": [
            "BIND_ACCESSIBILITY_SERVICE",
            "AccessibilityService",
            "onAccessibilityEvent",
            "onInterrupt",
            "TYPE_WINDOW_STATE_CHANGED",
            "TYPE_WINDOW_CONTENT_CHANGED",
            "TYPE_VIEW_CLICKED",
            "TYPE_VIEW_TEXT_CHANGED",
            "TYPE_VIEW_FOCUSED",
            "TYPE_VIEW_SCROLLED",
            "getText",
            "getClassName",
            "getPackageName",
            "getSource",
            "performAction",
            "ACTION_CLICK",
            "ACTION_LONG_CLICK",
            "ACTION_SCROLL_FORWARD",
            "ACTION_SCROLL_BACKWARD"
        ],
        "device_admin_abuse": [
            "BIND_DEVICE_ADMIN",
            "DeviceAdminReceiver",
            "DevicePolicyManager",
            "onEnabled",
            "onDisabled",
            "onPasswordChanged",
            "onPasswordFailed",
            "onPasswordSucceeded",
            "DEVICE_ADMIN_ENABLED",
            "DEVICE_ADMIN_DISABLED",
            "DEVICE_ADMIN_DISABLED",
            "ACTION_DEVICE_ADMIN_ENABLED",
            "ACTION_DEVICE_ADMIN_DISABLED",
            "DEVICE_ADMIN_DISABLE_REQUESTED"
        ],
        "data_exfiltration": [
            "INTERNET",
            "ACCESS_NETWORK_STATE",
            "ACCESS_WIFI_STATE",
            "HttpURLConnection",
            "HttpClient",
            "OkHttpClient",
            "Retrofit",
            "Volley",
            "POST",
            "GET",
            "PUT",
            "DELETE",
            "setRequestMethod",
            "setRequestProperty",
            "setDoOutput",
            "getOutputStream",
            "getInputStream",
            "getResponseCode",
            "Base64",
            "encode",
            "encodeToString",
            "AES",
            "Cipher",
            "SecretKeySpec",
            "IvParameterSpec",
            "Cipher.ENCRYPT_MODE",
            "Cipher.DECRYPT_MODE"
        ],
        "persistence": [
            "RECEIVE_BOOT_COMPLETED",
            "BOOT_COMPLETED",
            "QUICKBOOT_POWERON",
            "ACTION_BOOT_COMPLETED",
            "ACTION_LOCKED_BOOT_COMPLETED",
            "RECEIVE_BOOT_COMPLETED",
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.QUICKBOOT_POWERON",
            "android.intent.action.LOCKED_BOOT_COMPLETED",
            "SYSTEM_ALERT_WINDOW",
            "SYSTEM_OVERLAY_WINDOW",
            "TYPE_SYSTEM_ALERT",
            "TYPE_SYSTEM_OVERLAY",
            "TYPE_APPLICATION_OVERLAY",
            "SYSTEM_ALERT_WINDOW",
            "SYSTEM_OVERLAY_WINDOW",
            "android.permission.SYSTEM_ALERT_WINDOW"
        ]
    }
    
    # Suspicious network indicators
    C2_INDICATORS = [
        "c2.", "cmd.", "control.", "beacon", "heartbeat", "checkin",
        "register", "enroll", "enrollment", "provision", "provisioning",
        "agent", "bot", "implant", "implant", "payload", "dropper",
        "downloader", "loader", "injector", "inject", "reflective",
        "shellcode", "meterpreter", "cobaltstrike", "metasploit",
        "empire", "cobalt", "brute", "ratel", "njrat", "nanocore",
        "asyncrat", "quasar", "revenge", "lost", "darkcomet",
        "blackshades", "cybergate", "bifrost", "poison", "sub7",
        "netbus", "subseven", "backorifice", "beast", "netbus",
        "spy", "spyware", "stalker", "tracker", "monitor", "keylogger"
    ]
    
    # Suspicious file paths
    SUSPICIOUS_PATHS = [
        "/data/data/", "/data/user/", "/data/app/", "/system/app/",
        "/system/priv-app/", "/data/local/tmp/", "/data/local/",
        "/sdcard/", "/storage/emulated/", "/mnt/sdcard/",
        "/data/data/com.android.", "/data/data/com.google.",
        "/data/data/com.android.vending", "/data/data/com.google.android",
        "/data/data/com.android.chrome", "/data/data/com.android.browser"
    ]
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.alert_callbacks: List[Callable] = []
        self.stats = defaultdict(int)
        
    def add_alert_callback(self, callback: Callable):
        self.alert_callbacks.append(callback)
    
    async def analyze_apk(self, apk_path: str) -> Dict:
        """Analyze APK for spyware indicators"""
        results = {
            "package_name": None,
            "permissions": [],
            "spyware_score": 0,
            "detected_families": [],
            "detected_behaviors": [],
            "suspicious_strings": [],
            "network_indicators": [],
            "file_indicators": [],
            "risk_level": "LOW"
        }
        
        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # Check package name
                manifest_data = apk.read("AndroidManifest.xml")
                if manifest_data:
                    manifest_str = manifest_data.decode('utf-8', errors='ignore')
                    results["permissions"] = self._extract_permissions(manifest_str)
                    results["package_name"] = self._extract_package_name(manifest_str)
                    
                    # Check for known spyware packages
                    pkg_name = results["package_name"]
                    if pkg_name and pkg_name in self.SPYWARE_PACKAGES:
                        results["detected_families"].append({
                            "package": pkg_name,
                            "name": self.SPYWARE_PACKAGES[pkg_name],
                            "confidence": "HIGH"
                        })
                        results["spyware_score"] += 100
                    
                    # Check for spyware behaviors
                    for behavior, indicators in self.SPYWARE_BEHAVIORS.items():
                        detected = [ind for ind in indicators if ind in manifest_str]
                        if detected:
                            results["detected_behaviors"].append({
                                "behavior": behavior,
                                "indicators": detected,
                                "severity": self._get_behavior_severity(behavior)
                            })
                            results["spyware_score"] += len(detected) * 10
                    
                    # Check for C2 indicators
                    for c2 in self.C2_INDICATORS:
                        if c2.lower() in manifest_str.lower():
                            results["network_indicators"].append({
                                "indicator": c2,
                                "type": "C2_INDICATOR"
                            })
                            results["spyware_score"] += 20
                    
                    # Check for suspicious file paths
                    for path in self.SUSPICIOUS_PATHS:
                        if path in manifest_str:
                            results["file_indicators"].append({
                                "path": path,
                                "type": "SUSPICIOUS_PATH"
                            })
                            results["spyware_score"] += 5
                
                # Check all files in APK
                for file_info in apk.infolist():
                    if file_info.filename.endswith(('.dex', '.so', '.jar', '.xml')):
                        try:
                            content = apk.read(file_info.filename)
                            content_str = content.decode('utf-8', errors='ignore')
                            
                            # Check for C2 strings
                            for c2 in self.C2_INDICATORS:
                                if c2.lower() in content.lower():
                                    results["suspicious_strings"].append({
                                        "string": c2,
                                        "file": file_info.filename,
                                        "type": "C2_INDICATOR"
                                    })
                                    results["spyware_score"] += 15
                            
                            # Check for encoded payloads
                            if self._is_encoded(content):
                                results["suspicious_strings"].append({
                                    "file": file_info.filename,
                                    "type": "ENCODED_PAYLOAD",
                                    "reason": "Possible encoded payload"
                                })
                                results["spyware_score"] += 25
        except Exception as e:
            logger.error(f"APK analysis error: {e}")
        
        # Calculate risk level
        results["risk_level"] = self._calculate_risk_level(results["spyware_score"])
        return results
    
    def _extract_permissions(self, manifest: str) -> List[str]:
        """Extract permissions from AndroidManifest.xml"""
        perms = []
        import re
        pattern = r'android:name="android.permission.([^"]+)"'
        matches = re.findall(pattern, manifest)
        return matches
    
    def _extract_package_name(self, manifest: str) -> Optional[str]:
        import re
        pattern = r'package="([^"]+)"'
        match = re.search(pattern, manifest)
        return match.group(1) if match else None
    
    def _get_behavior_severity(self, behavior: str) -> str:
        severity_map = {
            "location_tracking": "HIGH",
            "call_logging": "HIGH",
            "sms_monitoring": "CRITICAL",
            "contact_theft": "CRITICAL",
            "keylogging": "CRITICAL",
            "screen_recording": "CRITICAL",
            "audio_recording": "CRITICAL",
            "camera_access": "CRITICAL",
            "clipboard_monitoring": "HIGH",
            "notification_access": "HIGH",
            "accessibility_abuse": "CRITICAL",
            "device_admin_abuse": "CRITICAL",
            "data_exfiltration": "CRITICAL",
            "persistence": "HIGH"
        }
        return severity_map.get(behavior, "MEDIUM")
    
    def _is_encoded(self, content: str) -> bool:
        """Check for encoded payloads"""
        import base64
        # Check for base64
        if re.search(r'[A-Za-z0-9+/]{100,}={0,2}', content):
            return True
        # Check for hex
        if re.search(r'[0-9a-fA-F]{100,}', content):
            return True
        return False
    
    def _calculate_risk_level(self, score: int) -> str:
        if score >= 100:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        return "LOW"