import zipfile
import re

VULN_PATTERNS = {
    "WebView - JS Enabled": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
    "WebView - JS Interface": r"addJavascriptInterface\s*\(",
    "DexClassLoader": r"DexClassLoader\s*\(",
    "PathClassLoader": r"PathClassLoader\s*\(",
    "Runtime.exec": r"Runtime\.getRuntime\(\)\.exec\s*\(",
    "Crypto - MD5": r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)",
    "Crypto - SHA1": r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-1[\"']\s*\)",
    "Crypto - DES": r"Cipher\.getInstance\s*\(\s*[\"']DES[\"']\s*\)",
    "Crypto - ECB Mode": r"Cipher\.getInstance\s*\(\s*[\"'].*ECB.*[\"']\s*\)",
    "Base64.decode": r"Base64\.decode\s*\("
}

def scan_vulnerabilities(apk_path):
    findings = []

    with zipfile.ZipFile(apk_path, "r") as zipf:
        for name in zipf.namelist():
            if name.endswith(".smali") or name.endswith(".java") or name.endswith(".txt") or name.endswith(".xml"):
                try:
                    data = zipf.read(name).decode("utf-8", errors="ignore")
                    for vuln_name, pattern in VULN_PATTERNS.items():
                        if re.search(pattern, data):
                            findings.append({
                                "file": name,
                                "issue": vuln_name
                            })
                except Exception:
                    continue

    return findings
