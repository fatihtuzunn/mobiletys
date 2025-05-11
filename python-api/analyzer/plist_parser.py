# analyzer/plist_parser.py
import plistlib

def parse_info_plist(raw_data):
    plist = plistlib.loads(raw_data)

    # Hem kök hem de ATS altındaki NSAllowsArbitraryLoads’ı kontrol et
    ats_global = plist.get("NSAllowsArbitraryLoads", None)  # kökteyse bu çalışır
    ats = plist.get("NSAppTransportSecurity", {})

    ats_flags = {
        "NSAllowsArbitraryLoads": ats.get("NSAllowsArbitraryLoads", ats_global or False),
        "NSAllowsArbitraryLoadsInWebContent": ats.get("NSAllowsArbitraryLoadsInWebContent", False),
        "NSAllowsArbitraryLoadsForMedia": ats.get("NSAllowsArbitraryLoadsForMedia", False),
        "NSRequiresCertificateTransparency": ats.get("NSRequiresCertificateTransparency", False),
        "NSExceptionDomains": ats.get("NSExceptionDomains", {})
    }

    security_flags = {
        "get-task-allow": plist.get("get-task-allow", False),
        "UIFileSharingEnabled": plist.get("UIFileSharingEnabled", False),
        "UIApplicationExitsOnSuspend": plist.get("UIApplicationExitsOnSuspend", False),
        "UIBackgroundModes": plist.get("UIBackgroundModes", []),
        "LSApplicationQueriesSchemes": plist.get("LSApplicationQueriesSchemes", []),
        "NSAppTransportSecurity": ats_flags
    }

    return plist, security_flags
