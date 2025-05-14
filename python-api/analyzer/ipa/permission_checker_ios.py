# analyzer/permission_checker_ios.py

PERMISSIONS_DB = {
    "NSPhotoLibraryAddUsageDescription": {
        "usage": "App adds photos to the user's photo library",
        "status": "normal"
    },
    "NSPhotoLibraryUsageDescription": {
        "usage": "App accesses the user's photo library",
        "status": "dangerous"
    },
    "NSCameraUsageDescription": {
        "usage": "App uses the device camera",
        "status": "dangerous"
    },
    "NSLocationAlwaysUsageDescription": {
        "usage": "App uses location services all the time",
        "status": "dangerous"
    },
    "NSLocationWhenInUseUsageDescription": {
        "usage": "App uses location services only when the app is running",
        "status": "dangerous"
    },
    "NSLocationUsageDescription": {
        "usage": "DEPRECATED: use other location permissions",
        "status": "dangerous"
    },
    "NSContactsUsageDescription": {
        "usage": "App uses the address book",
        "status": "dangerous"
    },
    "NSCalendarsUsageDescription": {
        "usage": "App uses or modifies the user's calendar",
        "status": "normal"
    },
    "NSRemindersUsageDescription": {
        "usage": "App creates reminders in the Reminders app",
        "status": "normal"
    },
    "NSHealthShareUsageDescription": {
        "usage": "App reads data from the Health app",
        "status": "dangerous"
    },
    "NSHealthUpdateUsageDescription": {
        "usage": "App writes data to the Health app",
        "status": "dangerous"
    },
    "NFCReaderUsageDescription": {
        "usage": "App uses the NFC reader",
        "status": "dangerous"
    },
    "NSBluetoothPeripheralUsageDescription": {
        "usage": "App works with Bluetooth devices",
        "status": "dangerous"
    },
    "NSMicrophoneUsageDescription": {
        "usage": "App uses the microphone",
        "status": "dangerous"
    },
    "NSSiriUsageDescription": {
        "usage": "App provides SiriKit Intent",
        "status": "normal"
    },
    "NSSpeechRecognitionUsageDescription": {
        "usage": "App uses speech recognition",
        "status": "dangerous"
    },
    "NSMotionUsageDescription": {
        "usage": "App uses motion tracking",
        "status": "normal"
    },
    "NSAppleMusicUsageDescription": {
        "usage": "App uses Apple Music integration",
        "status": "normal"
    },
    "NSFaceIDUsageDescription": {
        "usage": "App uses FaceID for authentication",
        "status": "normal"
    },
    "NSVideoSubscriberAccountUsageDescription": {
        "usage": "tvOS only: app uses video subscriber account",
        "status": "normal"
    }
}

def extract_ios_permissions(plist):
    results = []

    for key, value in plist.items():
        if key.endswith("UsageDescription"):
            entry = PERMISSIONS_DB.get(key, {
                "usage": "Unknown usage",
                "status": "normal"
            })
            results.append({
                "permission": key,
                "status": entry["status"],
                "usage": entry["usage"],
                "info": str(value)
            })

    return results
