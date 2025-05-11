# analyzer/ipa_analyzer.py

import zipfile
from .file_info import get_file_info
from .plist_parser import parse_info_plist
from .provision_parser import extract_mobileprovision
from .permission_checker_ios import extract_ios_permissions
from .ios_string_scanner import scan_strings_in_ipa

def analyze_ipa(file_path):
    result = {
        "type": "ipa",
        "file_info": get_file_info(file_path),
        "info_plist": {},
        "security_flags": {},
        "provisioning_profile": {},
        "suspicious_files": [],
        "debug_info_plists": [],  # ⬅️ diğer plist’ler burada toplanacak
        "permissions": [],
        "suspicious_strings": []
    }

    with zipfile.ZipFile(file_path, "r") as zipf:
        for name in zipf.namelist():
            # ✅ Ana Info.plist sadece Payload/*.app içinde aranmalı
            result["suspicious_strings"] = scan_strings_in_ipa(file_path)
            if name.endswith(".app/Info.plist") and "Payload/" in name:
                try:
                    data = zipf.read(name)
                    plist, security_flags = parse_info_plist(data)
                    result["info_plist"] = plist
                    result["security_flags"] = security_flags
                    result["permissions"] = extract_ios_permissions(plist)
                except Exception:
                    continue
            


            # 🧪 Diğer Info.plist dosyalarını listele ama analiz etme
            elif name.endswith("Info.plist") and not name.endswith(".app/Info.plist"):
                try:
                    raw = zipf.read(name)
                    parsed = plistlib.loads(raw)
                    result["debug_info_plists"].append({
                        "path": name,
                        "plist": {k: str(v) for k, v in parsed.items()}
                    })
                except Exception:
                    continue

            elif name.endswith("embedded.mobileprovision"):
                profile_data = extract_mobileprovision(zipf)
                if profile_data:
                    result["provisioning_profile"] = profile_data

            elif any(s in name.lower() for s in ["keychain", "jailbreak", "cycript", "frida"]):
                result["suspicious_files"].append(name)

    return result
