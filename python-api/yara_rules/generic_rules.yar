rule android_temp_file_creation {
    meta:
        group = "STORAGE"
        description = "Uygulama geçici dosya yaratıyor. Eğer bu dosyalar hassas veri içeriyorsa, saldırganlar tarafından okunabilir."
        severity = "Medium"
        reference = "https://cwe.mitre.org/data/definitions/276.html"
    strings:
        $tmp = ".createTempFile("
    condition:
        $tmp
}

rule reverse_shell_indicators {
    meta:
        group = "REVERSE_SHELL"
        description = "Reverse shell ya da command execution göstergeleri"
        severity = "High"
        reference = "https://attack.mitre.org/techniques/T1059/"
    strings:
        $sh = "/system/bin/sh"
        $nc = "nc -e"
        $bash = "bash -i"
    condition:
        any of them
}

rule missing_ssl_pinning {
    meta:
        group = "SSL_PINNING"
        description = "SSL pinning kontrolü uygulanmamış"
        severity = "Medium"
        reference = "https://owasp.org/www-project-mobile-top-10/"
    strings:
        $ssl = "TrustManager[]"
        $pin = "checkServerTrusted"
    condition:
        $ssl and not $pin
}

rule weak_crypto_usage {
    meta:
        group = "WEAK_CRYPTO"
        description = "MD5, DES, ECB gibi zayıf algoritmaların kullanımı"
        severity = "High"
        reference = "https://owasp.org/www-project-mobile-top-10/"
    strings:
        $md5 = "MessageDigest.getInstance(\"MD5\")"
        $des = "Cipher.getInstance(\"DES\")"
        $ecb = "AES/ECB/PKCS5Padding"
    condition:
        any of them
}

rule Detect_Base64_Encoded_URL {
    meta:
        group = "ENCODED_INDICATORS"
        description = "Base64 ile kodlanmış http/https URL'leri tespit eder"
        severity = "Low"
        reference = "-"
    strings:
        $b64url = /aHR0cDovL|aHR0cHM6Ly9/
    condition:
        $b64url
}

rule insecure_rng_java_random {
    meta:
        group = "INSECURE_RANDOM"
        description = "Uygulama güvenli olmayan java.util.Random sınıfını kullanıyor"
        severity = "Medium"
        reference = "https://cwe.mitre.org/data/definitions/338.html"
    strings:
        $random_class = "java/util/Random"
        $init_seed = ".<init>(J)V"
        $nextint = "nextInt"
        $nextbytes = "nextBytes"
    condition:
        $random_class and any of ($init_seed, $nextint, $nextbytes)
}

rule constant_seed_rng {
    meta:
        group = "INSECURE_RANDOM"
        description = "Random nesnesi sabit bir sayı ile başlatılmış"
        severity = "High"
        reference = "https://cwe.mitre.org/data/definitions/330.html"
    strings:
        $random = "new Random("
        $constant_seed = /new Random\s*\(\s*[0-9]{3,}\s*\)/
    condition:
        $random and $constant_seed
}

rule hardcoded_jwt {
    meta:
        group = "HARDCODED_TOKENS"
        description = "Hardcoded JWT token string"
        severity = "High"
        reference = "https://cwe.mitre.org/data/definitions/798.html"
    strings:
        $jwt = /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/
    condition:
        $jwt
}
