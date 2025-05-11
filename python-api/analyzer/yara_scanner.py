import yara
import zipfile
import os
import re

def load_yara_rules(rules_dir):
    rule_files = {}
    for filename in os.listdir(rules_dir):
        if filename.endswith(".yar") or filename.endswith(".yara"):
            rule_path = os.path.join(rules_dir, filename)
            rule_files[filename] = rule_path
    return yara.compile(filepaths=rule_files)
""" 
def scan_apk_with_yara(apk_path, rules_dir="yara_rules"):
    results = []
    rules = load_yara_rules(rules_dir)

    with zipfile.ZipFile(apk_path, 'r') as zipf:
        for name in zipf.namelist():
            if name.endswith(".dex") or name.endswith(".smali") or name.endswith(".xml"):
                try:
                    content = zipf.read(name)
                    text_content = content.decode("utf-8", errors="ignore")
                    matches = rules.match(data=content)
                    for match in matches:
                        results.append({
                            "file": name,
                            "rule": match.rule,
                            "meta": match.meta  # ⬅️ meta bilgisi de dahil edildi
                        }) 
                        
                except Exception:
                    continue

    return results
 """
 
""" def scan_apk_with_yara(apk_path, rules_dir="yara_rules"):
    results = []
    rules = load_yara_rules(rules_dir)

    with zipfile.ZipFile(apk_path, 'r') as zipf:
        for name in zipf.namelist():
            if name.endswith((".dex", ".smali", ".xml", ".txt", ".properties", ".rc", ".prop")):
                try:
                    raw_content = zipf.read(name)
                    decoded_content = raw_content.decode("utf-8", errors="ignore")
                    lines = decoded_content.splitlines()

                    matches = rules.match(data=raw_content)
                    for match in matches:
                        match_result = {
                            "file": name,
                            "rule": match.rule,
                            "meta": match.meta,
                            "matches": []
                        }

                        for s in match.strings:
                            try:
                                matched_str = s.data.decode("utf-8", errors="ignore")
                                for idx, line in enumerate(lines):
                                    if matched_str in line:
                                        snippet = "\n".join(lines[max(0, idx - 2): idx + 3])
                                        match_result["matches"].append({
                                            "string_id": s.identifier,
                                            "matched": matched_str,
                                            "line_number": idx + 1,
                                            "snippet": snippet
                                        })
                                        break
                            except Exception:
                                continue

                        if not match_result["matches"]:
                            match_result["matches"].append({
                                "string_id": "N/A",
                                "matched": "❓ Eşleşen string tespit edilemedi",
                                "line_number": -1,
                                "snippet": "-"
                            })

                        results.append(match_result)

                except Exception as e:
                    print(f"[!] {name} dosyasında hata: {e}")
                    continue

    return results
 """
def scan_apk_with_yara(apk_path, rules_dir="yara_rules"):
    import yara
    results = []
    rules = load_yara_rules(rules_dir)

    with zipfile.ZipFile(apk_path, 'r') as zipf:
        for name in zipf.namelist():
            if name.endswith((".dex", ".smali", ".xml", ".txt", ".properties", ".rc", ".prop")):
                try:
                    raw_content = zipf.read(name)
                    decoded_content = raw_content.decode("utf-8", errors="ignore")

                    # offset → satır numarası için ön hazırlık
                    byte_offsets = []
                    total = 0
                    for line in decoded_content.splitlines(keepends=True):
                        byte_offsets.append(total)
                        total += len(line.encode("utf-8", errors="ignore"))

                    lines = decoded_content.splitlines()
                    matches = rules.match(data=raw_content)

                    for match in matches:
                        match_result = {
                            "file": name,
                            "rule": match.rule,
                            "meta": match.meta,
                            "matches": []
                        }

                        for string_match in match.strings:
                            for instance in string_match.instances:
                                try:
                                    matched_str = instance.plaintext().decode("utf-8", errors="ignore")
                                    offset = instance.offset

                                    # offset → satır numarası
                                    line_number = next((i + 1 for i, pos in enumerate(byte_offsets) if pos > offset), len(byte_offsets))
                                    snippet = "\n".join(lines[max(0, line_number - 3): line_number + 2])
                                    clean_snippet = re.sub(r'[\x00-\x1F\x7F]+', ' ', snippet)  # Temizleme işlemi
                                    
                                    clean_snippet = re.sub(r'\s+', ' ', clean_snippet)  # Tekil boşlukları temizle
                                    clean_snippet = clean_snippet.strip()  # Baş ve sondaki boşlukları temizle
                                    
                                    match_result["matches"].append({
                                        "string_id": string_match.identifier,
                                        "matched": matched_str,
                                        "line_number": line_number,
                                        "snippet": clean_snippet
                                    })
                                except Exception as e:
                                    match_result["matches"].append({
                                        "string_id": string_match.identifier,
                                        "matched": "<decode hatası>",
                                        "line_number": -1,
                                        "snippet": str(e)
                                    })

                        results.append(match_result)

                except Exception as e:
                    print(f"[!] {name} dosyasında hata: {e}")
                    continue

    return results
