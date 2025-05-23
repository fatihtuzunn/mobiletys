rule obfuscator_proguard {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "ProGuard kullanımı tespit edildi"
        severity = "Medium"
        reference = "https://www.guardsquare.com/en/products/proguard"
    strings:
        $mapping_file = "proguard.map"
        $config_file = "proguard.cfg"
    condition:
        any of them
}

rule obfuscator_dexguard {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "DexGuard (ProGuard Premium) kullanımı"
        severity = "High"
        reference = "https://www.guardsquare.com/en/products/dexguard"
    strings:
        $stringguard = "com.guard.StringGuard"
        $runtime = "DexGuardRuntime"
        $lib = "libdexguard.so"
        
    condition:
        any of them
}

rule obfuscator_allatori {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "Allatori Obfuscator izleri"
        severity = "High"
        reference = "https://www.allatori.com/"
    strings:
        $copyright = "This software is protected by copyright law and international treaties. Unauthorized reproduction or distribution"
        $marker1 = "allatori.Obfuscator"
        $marker2 = "Powered by Allatori Obfuscator"
    condition:
        any of them
}

rule obfuscator_bangcle {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "Bangcle (apkprotect) kullanımı"
        severity = "High"
        reference = "https://www.bangcle.com/"
    strings:
        $lib1 = "libjiagu.so"
        $lib2 = "libsecmain.so"
        $pkg = "com.bangcle.protect"
    condition:
        any of them
}

rule obfuscator_qihoo360 {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "Qihoo 360 Jiagu tespiti"
        severity = "High"
        reference = "https://jiagu.360.cn/"
    strings:
        $pkg = "com.qihoo.util"
        $lib = "libjiagu.so"
        $tag = "360jiagu"
    condition:
        any of them
}

rule obfuscator_tencent_legu {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "Tencent Legu obfuscator tespiti"
        severity = "High"
        reference = "https://legu.tencent.com/"
    strings:
        $lib = "libshella.so"
        $stub = "Lcom/tencent/StubShell/"
        $key = "com.tencent.midas"
    condition:
        any of them
}

rule obfuscator_apkprotect {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "APKProtect kullanımı"
        severity = "Medium"
        reference = "https://apkprotect.com/"
    strings:
        $lib = "libAPKProtect.so"
        $class = "com.apkunion.defender"
    condition:
        any of them
}

rule obfuscator_nagoon {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "Nagoon obfuscator izleri"
        severity = "Low"
        reference = "-"
    strings:
        $lib = "libnagoon.so"
        $log = "nagonlog.txt"
    condition:
        any of them
}

rule obfuscator_secneo {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "SecNeo tespiti (Tencent iş ortakları için)"
        severity = "High"
        reference = "https://secneo.com/"
    strings:
        $lib = "libsecneo.so"
        $stub = "com.secneo.apkwrapper"
    condition:
        any of them
}

rule obfuscator_naga {
    meta:
        group = "OBFUSCATOR_ANALYSIS"
        description = "Naga obfuscator izleri"
        severity = "Medium"
        reference = "-"
    strings:
        $lib = "libnaga.so"
        $pkg = "com.nagasoft.protect"
    condition:
        any of them
}
