import zipfile
import re

SUSPICIOUS_PATTERNS = {
    "IP Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b",
    "URL": r"https?://[^\s\"']+",
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?:com|org|net|gov|edu|co|io|me|info|biz|app|dev)\b",
    "API Key (Google)": r"AIza[0-9A-Za-z-_]{35}",
    "Firebase URL": r"https?://[^\s\"']*firebase[^\s\"']*",
    "Crash Reporting API Key": r"google_crash_reporting_api_key\s*[:=]\s*['\"][A-Za-z0-9-_]{35}['\"]",
    "Google API Key": r"google_api_key\s*[:=]\s*['\"][A-Za-z0-9-_]{35}['\"]",
    "Facebook App ID": r"facebook_app_id\s*[:=]\s*['\"][0-9]{5,}['\"]",
    "Auth Token": r"(access_token|auth_token)\s*[:=]\s*['\"][A-Za-z0-9\-_\.]+['\"]",
    "Client Secret": r"client_secret\s*[:=]\s*['\"][A-Za-z0-9\-_\.]+['\"]"
}


KNOWN_DOMAINS = [
    "http://schemas.android.com",
    "https://schemas.android.com",

    "http://android.googlesource.com",
    "https://android.googlesource.com",

    "http://www.googleapis.com",
    "https://www.googleapis.com",

    "http://google.com",
    "https://google.com",
    "http://www.google.com",
    "https://www.google.com",


    "http://developers.google.com",
    "https://developers.google.com",

    "http://microsoft.com",
    "https://microsoft.com",
    "http://www.microsoft.com",
    "https://www.microsoft.com",

    "http://apache.org",
    "https://apache.org",
    "http://www.apache.org",
    "https://www.apache.org",

    "http://facebook.com",
    "https://facebook.com",
    "http://www.facebook.com",
    "https://www.facebook.com",

    "http://amazonaws.com",
    "https://amazonaws.com",
    "http://www.amazon.com",
    "https://www.amazon.com",

    "http://github.com",
    "https://github.com",
    "http://www.github.com",
    "https://www.github.com",
]

def is_known_domain(url):
    return any(url.startswith(domain) for domain in KNOWN_DOMAINS)

def is_binary_file(name):
    return any(name.lower().endswith(ext) for ext in [
        ".so", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".otf", ".ttf",
        ".mp3", ".mp4", ".zip", ".ogg", ".wav"
    ])

def clean_text(text):
    return re.sub(r'[\x00-\x1F\x7F]+', ' ', text)

def scan_strings(apk_path):
    results = []

    with zipfile.ZipFile(apk_path, "r") as zipf:
        for name in zipf.namelist():
            if is_binary_file(name):  # 👈 erken çık
                continue
            
            try:
                raw_data = zipf.read(name)
                text = raw_data.decode("utf-8", errors="ignore")
                lines = text.splitlines()

                for label, pattern in SUSPICIOUS_PATTERNS.items():
                    for match in re.finditer(pattern, text):
                        matched_raw = match.group()
                        matched_str = matched_raw.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
                        matched_str = re.sub(r'[\x00-\x1F\x7F]+', '', matched_str).strip()


                        if is_known_domain(matched_str):
                            continue
                        if len(matched_str) < 10 or '.' not in matched_str:
                            continue


                        offset = match.start()

                        # Satır hesaplaması
                        byte_offsets = []
                        total = 0
                        for line in lines:
                            byte_offsets.append(total)
                            total += len(line.encode("utf-8", errors="ignore")) + 1  # newline dahil

                        line_number = next((i for i, pos in enumerate(byte_offsets) if pos > offset), len(lines) - 1)

                        if is_binary_file(name):
                            snippet = f"...{matched_str[:50]}..."
                        else:
                            snippet_lines = lines[max(0, line_number - 2): line_number + 3]
                            snippet = clean_text("\n".join(snippet_lines))
                            if len(snippet) > 300:
                                snippet = snippet[:300] + "..."

                        results.append({
                            "file": name,
                            "type": label,
                            "matched": matched_str,
                            "line_number": line_number + 1,
                            "snippet": snippet
                        })

            except Exception as e:
                print(f"[!] Hata ({name}): {e}")
                continue

    return results

""" def scan_strings(apk_path):
    results = []

    with zipfile.ZipFile(apk_path, "r") as zipf:
        for name in zipf.namelist():
            "if name.endswith(".dex") or name.endswith(".xml") or name.endswith(".txt") or name.endswith(".properties"): "
            try:
                data = zipf.read(name).decode("utf-8", errors="ignore")
                for label, pattern in SUSPICIOUS_PATTERNS.items():
                    matches = re.findall(pattern, data)
                    if matches:
                        # Filtreden geçen eşleşmeleri al
                        filtered_matches = list(set(m for m in matches if not is_known_domain(m)))
                        if filtered_matches:
                            results.append({
                                "file": name,
                                "type": label,
                                "matches": filtered_matches
                            })
            except Exception:
                continue

    return results 
def scan_strings(apk_path):
    results = []

    with zipfile.ZipFile(apk_path, "r") as zipf:
        for name in zipf.namelist():
            try:
                raw_data = zipf.read(name)
                text = raw_data.decode("utf-8", errors="ignore")
                lines = text.splitlines()

                for label, pattern in SUSPICIOUS_PATTERNS.items():
                    for match in re.finditer(pattern, text):
                        matched_str = match.group()
                        if is_known_domain(matched_str):
                            continue

                        # offset → line_number
                        offset = match.start()
                        byte_offsets = []
                        total = 0
                        for line in lines:
                            byte_offsets.append(total)
                            total += len(line.encode("utf-8", errors="ignore")) + 1  # +1 for newline

                        line_number = next((i for i, pos in enumerate(byte_offsets) if pos > offset), len(lines) - 1)
                        snippet_lines = lines[max(0, line_number - 2): line_number + 3]
                        snippet = "\n".join(snippet_lines)
                        cleaned_snippet = re.sub(r"[\x00-\x1F\x7F]+", " ", snippet)

                        results.append({
                            "file": name,
                            "type": label,
                            "matched": matched_str,
                            "line_number": line_number + 1,
                            "snippet": cleaned_snippet
                        })

            except Exception as e:
                print(f"[!] Hata ({name}): {e}")
                continue

    return results"""