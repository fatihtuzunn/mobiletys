rule hooking_tool_detection {
    meta:
        group = "HOOKING_DETECTION"
        description = "Xposed, Magisk gibi hooking framework’lerini tespit eder"
        severity = "Medium"
        reference = "https://owasp.org/www-project-mobile-top-10/"
    strings:
        $xposed = "de.robv.android.xposed"
        $magisk = "magisk"
        $substrate = "com.saurik.substrate"
    condition:
        any of them
}

rule android_frida_detection {
    meta:
        group = "HOOKING_DETECTION"
        description = "Uygulama fridaserver, LIBFRIDA veya benzeri Frida bileşenlerini tespit ediyor. Anti-analysis davranışı gösterebilir."
        severity = "Info"
        reference = "https://owasp.org/www-project-mobile-top-10/"
    strings:
        $frida = "fridaserver"
        $lib = "LIBFRIDA"
        $port = "27047"
    condition:
        2 of them
}
