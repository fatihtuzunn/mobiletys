import plistlib
import re
from datetime import datetime

def extract_mobileprovision(zipf):
    for name in zipf.namelist():
        if name.endswith("embedded.mobileprovision"):
            raw = zipf.read(name)
            # XML plist kısmını izole et
            match = re.search(b"<\?xml.*</plist>", raw, re.DOTALL)
            if match:
                try:
                    plist_data = plistlib.loads(match.group(0))
                    return {
                        "Name": plist_data.get("Name"),
                        "AppIDName": plist_data.get("AppIDName"),
                        "TeamName": plist_data.get("TeamName"),
                        "TeamIdentifier": plist_data.get("TeamIdentifier"),
                        "ExpirationDate": plist_data.get("ExpirationDate").isoformat() if isinstance(plist_data.get("ExpirationDate"), datetime) else str(plist_data.get("ExpirationDate")),
                        "ProvisionedDevices": plist_data.get("ProvisionedDevices", []),
                        "IsDeviceRestricted": bool(plist_data.get("ProvisionedDevices")),
                        "Entitlements": plist_data.get("Entitlements", {})
                    }
                except Exception:
                    return {"error": "mobileprovision parse edilemedi"}
    return None
