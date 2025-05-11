rule Detect_Base64_Encoded_URL
{
    strings:
        $b64url = /aHR0cDovL|aHR0cHM6Ly9/  // base64 encoded 'http://' or 'https://'
    condition:
        $b64url
}

rule Suspicious_System_Exec
{
    strings:
        $s1 = "Runtime.getRuntime().exec"
        $s2 = "su -c"
    condition:
        any of them
}

rule weak_crypto_usage
{
    meta:
        description = "MD5, DES, ECB gibi zayıf algoritmaların kullanımı"
        owasp = "M5: Insufficient Cryptography"
        severity = "high"
    strings:
        $md5 = "MessageDigest.getInstance(\"MD5\")"
        $des = "Cipher.getInstance(\"DES\")"
        $ecb = "AES/ECB/PKCS5Padding"
    condition:
        any of them
}

rule missing_ssl_pinning
{
    meta:
        description = "SSL pinning kontrolü uygulanmamış"
        severity = "good"
    strings:
        $ssl = "TrustManager[]"
        $pin = "checkServerTrusted"
    condition:
        $ssl and not $pin
}

rule reverse_shell_indicators
{
    meta:
        description = "Reverse shell ya da command execution göstergeleri"
        severity = "high"
    strings:
        $sh = "/system/bin/sh"
        $nc = "nc -e"
        $bash = "bash -i"
    condition:
        any of them
}

rule hooking_tool_detection
{
    meta:
        description = "Xposed, Magisk gibi hooking framework’lerini tespit eder"
        group = "Hooking Detection"
        severity = "good"
    strings:
        $xposed = "de.robv.android.xposed"
        $magisk = "magisk"
        $substrate = "com.saurik.substrate"
    condition:
        any of them
}

rule android_dexguard_root_detection
{
    meta:
        description = "DexGuard root detection API kullanımı tespit edildi."
        group = "resilience"
        severity = "Info"
        masvs = "resilience-1"

    strings:
        $import = "import dexguard.util"
        $detect = "RootDetector.isDeviceRooted"

    condition:
        $import and $detect
}


rule emulator_detection
{
    meta:
        description = "Uygulama, emülatör ortamlarını tespit etmek için yaygın kullanılan sistem özelliklerini kontrol ediyor (ro.kernel.qemu, etc)."
        group = "Emulator Detection"
        severity = "info"
    strings:
        $qemu = "ro.kernel.qemu"
        $geny = "Genymotion"
        $debug = "ro.debuggable"
        $genymotion = "ro.genymotion.version"
        $emulator_check = "Build.FINGERPRINT.contains(\"generic\")"
        $file_qemu = "/dev/socket/qemud"
    condition:
        any of them
}

rule insecure_rng_java_random
{
    meta:
        description = "Uygulama güvenli olmayan java.util.Random sınıfını kullanıyor"
        author = "Lostar Security"
        reference = "OWASP Mobile M5 / CWE-338"
        severity = "Medium"

    strings:
        $random_class = "java/util/Random"
        $init_seed = ".<init>(J)V" // sabit seed ile başlatma
        $nextint = "nextInt"
        $nextbytes = "nextBytes"

    condition:
        $random_class and any of ($init_seed, $nextint, $nextbytes)
}

rule constant_seed_rng
{
    meta:
        description = "Random nesnesi sabit bir sayı ile başlatılmış"
        severity = "High"

    strings:
        $random = "new Random("
        $constant_seed = /new Random\s*\(\s*[0-9]{3,}\s*\)/

    condition:
        $random and $constant_seed
}

rule hardcoded_jwt
{
    meta:
        category = "MASTG-AUTH"
        description = "Hardcoded JWT token string"
        severity = "High"
    strings:
        $jwt = /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/
    condition:
        $jwt
}

rule network_insecure_trustmanager_class
{
    meta:
        description = "Uygulama, X509TrustManager sınıfını tüm sertifikaları kabul edecek şekilde override ediyor. Bu doğrudan TLS bypass'tır."
        group = "network"
        severity = "Critical"
        reference = "https://owasp.org/www-community/attacks/Man-in-the-middle"
    strings:
        $trust1 = "implements X509TrustManager"
        $trust2 = "checkServerTrusted"
        $trust3 = "return;"  // checkServerTrusted metodu içinde varsa
    condition:
        all of them
}

rule android_temp_file_creation
{
    meta:
        description = "Uygulama geçici dosya yaratıyor. Eğer bu dosyalar hassas veri içeriyorsa, saldırganlar tarafından okunabilir."
        group = "storage"
        severity = "Medium"
        cwe = "CWE-276"
        cvss = "5.5"
        masvs = "storage-2"
        owasp = "M2"

    strings:
        $tmp = ".createTempFile("
    condition:
        $tmp
}

rule android_frida_detection
{
    meta:
        description = "Uygulama fridaserver, LIBFRIDA veya benzeri Frida bileşenlerini tespit ediyor. Anti-analysis davranışı gösterebilir."
        group = "Hooking Detection"
        severity = "info"
        cvss = "0"
        masvs = "resilience-4"

    strings:
        $frida = "fridaserver"
        $lib = "LIBFRIDA"
        $port = "27047"

    condition:
        2 of them
}

rule iOS_CFBundleIdentifier_Exists
{
    meta:
        description = "Detects CFBundleIdentifier in Info.plist"
        author = "Lostar"
        group = "ios_test"
        severity = "info"

    strings:
        $identifier = "DTSDKName"

    condition:
        $identifier
}
