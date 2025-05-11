# analyzer/analyze.py
from .apk_analyzer import analyze_apk
from .ipa_analyzer import analyze_ipa

def analyze_file(file_path):
    if file_path.endswith(".apk"):
        return analyze_apk(file_path)
    elif file_path.endswith(".ipa"):
        return analyze_ipa(file_path)
    else:
        raise ValueError("Desteklenmeyen dosya formatı. Sadece .apk ve .ipa destekleniyor.")
