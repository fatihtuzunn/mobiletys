import zipfile
import re

SUSPICIOUS_PATTERNS = {
    "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "URL": r"https?://[^\s\"']+",
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Firebase URL": r"https://[^\s\"']*firebaseio\.com[^\s\"']*",
    "API Key (Google)": r"AIza[0-9A-Za-z-_]{35}",
    "Client Secret": r"client_secret\s*[:=]\s*['\"][A-Za-z0-9\-_\.]+['\"]",
    "Push Token": r"\b[a-f0-9]{64}\b",
    "itms-services": r"itms-services://[^\s\"']+",
    "iCloud Reference": r"icloud[a-z\-\.]*",
}

def scan_strings_in_ipa(file_path):
    findings = []

    with zipfile.ZipFile(file_path, "r") as zipf:
        for name in zipf.namelist():
            if any(name.endswith(ext) for ext in [".plist", ".json", ".strings", ".xml", ".txt", ".conf"]):
                try:
                    content = zipf.read(name).decode("utf-8", errors="ignore")
                    for label, pattern in SUSPICIOUS_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            findings.append({
                                "file": name,
                                "type": label,
                                "matches": list(set(matches))
                            })
                except Exception:
                    continue

    return findings
