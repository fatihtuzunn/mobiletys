rule crypto_md5_in_messagedigest
{
    meta:
        description = "Uygulama, MessageDigest API ile MD5 algoritmasını kullanıyor. Bu algoritma kriptografik olarak kırılmıştır."
        group = "crypto"
        severity = "High"
        reference = "https://cwe.mitre.org/data/definitions/327.html"
    strings:
        $md5 = "MessageDigest.getInstance(\"MD5\")"
    condition:
        $md5
}

rule crypto_sha1_in_messagedigest
{
    meta:
        description = "Uygulama, MessageDigest API ile SHA-1 algoritmasını kullanıyor. SHA-1 artık güvenli kabul edilmemektedir."
        group = "crypto"
        severity = "High"
        reference = "https://cwe.mitre.org/data/definitions/328.html"
    strings:
        $sha1 = "MessageDigest.getInstance(\"SHA-1\")"
    condition:
        $sha1
}

rule crypto_aes_ecb_with_literal_key
{
    meta:
        description = "AES şifreleme ECB modunda ve sabit bir anahtar ile kullanılıyor. ECB modu tekrarlayan desenleri açığa çıkarır."
        group = "crypto"
        severity = "High"
        reference = "https://cwe.mitre.org/data/definitions/327.html"
    strings:
        $aes_ecb = "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"
        $key = /SecretKeySpec\s*\(\s*["'][A-Za-z0-9+\/=]{16,32}["']/
    condition:
        $aes_ecb and $key
}

rule crypto_des_cipher_usage
{
    meta:
        description = "DES algoritması çok kısa anahtar uzunluğuna sahiptir ve brute force ile kırılabilir. Güvenli kabul edilmez."
        group = "crypto"
        severity = "High"
    strings:
        $des = "Cipher.getInstance(\"DES\")"
    condition:
        $des
}

rule crypto_insecure_random_with_seed
{
    meta:
        description = "java.util.Random sınıfı sabit bir seed değeriyle başlatılmış. Bu, tahmin edilebilir şifreleme anahtarlarına neden olabilir."
        group = "crypto"
        severity = "High"
        reference = "https://cwe.mitre.org/data/definitions/330.html"
    strings:
        $rand = "new Random("
        $seeded = /new Random\s*\(\s*[0-9]{3,}\s*\)/
    condition:
        all of them
}

rule crypto_hardcoded_key_or_iv
{
    meta:
        description = "AES veya IV olarak sabit, base64 formatında bir 16/32 baytlık dize tespit edildi. Bu, kriptografik gizliliği tehlikeye atar."
        group = "crypto"
        severity = "High"
    strings:
        $b64key16 = /[A-Za-z0-9+\/]{22}==/
        $b64key32 = /[A-Za-z0-9+\/]{43}=/
    condition:
        any of ($b64key16, $b64key32)
}