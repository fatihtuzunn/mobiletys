from ..yara_scanner import scan_apk_with_yara
from .manifest_parser import parse_manifest
from .permission_checker import check_permissions
from .string_scanner import scan_strings
from .vuln_scanner import scan_vulnerabilities
from ..file_info import get_file_info

def analyze_apk(analyzer_path):
    result = {
        "type": "apk",  # Dosya tipi belirtmek içlin kullanılıyor
    }

    manifest_info = parse_manifest(analyzer_path)
    result['manifest'] = manifest_info

    permissions = check_permissions(manifest_info.get("permissions", []))
    result['dangerous_permissions'] = permissions

    string_matches = scan_strings(analyzer_path)
    result['suspicious_strings'] = string_matches

    vuln_results = scan_vulnerabilities(analyzer_path)
    result['vulnerability_signatures'] = vuln_results

    yara_matches = scan_apk_with_yara(analyzer_path)
    result['yara_matches'] = yara_matches
    
    result["file_info"] = get_file_info(analyzer_path)
    


    return result