rule obfuscator_proguard
{
    meta:
        group = "Obfuscator Analizi"
        description = "ProGuard kullanımı tespit edildi"
        obfuscator = "ProGuard"
        confidence = "Medium"

    strings:
        $mapping_file = "proguard.map"
        $config_file = "proguard.cfg"

    condition:
        any of them
}

rule obfuscator_dexguard
{
    meta:
        group = "Obfuscator Analizi"
        description = "DexGuard (ProGuard Premium) kullanımı"
        obfuscator = "DexGuard"
        confidence = "High"

    strings:
        $stringguard = "com.guard.StringGuard"
        $runtime = "DexGuardRuntime"
        $lib = "libdexguard.so"

    condition:
        any of them
}

rule obfuscator_allatori
{
    meta:
        group = "Obfuscator Analizi"
        description = "Allatori Obfuscator izleri"
        obfuscator = "Allatori"
        confidence = "High"

    strings:
        $copyright = "This software is protected by copyright law and international treaties. Unauthorized reproduction or distribution"
        $marker1 = "allatori.Obfuscator"
        $marker2 = "Powered by Allatori Obfuscator"

    condition:
        any of them
}

rule obfuscator_bangcle
{
    meta:
        group = "Obfuscator Analizi"
        description = "Bangcle (apkprotect) kullanımı"
        obfuscator = "Bangcle / Jiagu"
        confidence = "High"

    strings:
        $lib1 = "libjiagu.so"
        $lib2 = "libsecmain.so"
        $pkg = "com.bangcle.protect"

    condition:
        any of them
}

rule obfuscator_qihoo360
{
    meta:
        group = "Obfuscator Analizi"
        description = "Qihoo 360 Jiagu tespiti"
        obfuscator = "Qihoo 360"
        confidence = "High"

    strings:
        $pkg = "com.qihoo.util"
        $lib = "libjiagu.so"
        $tag = "360jiagu"

    condition:
        any of them
}

rule obfuscator_tencent_legu
{
    meta:
        group = "Obfuscator Analizi"
        description = "Tencent Legu obfuscator tespiti"
        obfuscator = "Tencent Legu"
        confidence = "High"

    strings:
        $lib = "libshella.so"
        $stub = "Lcom/tencent/StubShell/"
        $key = "com.tencent.midas"

    condition:
        any of them
}

rule obfuscator_apkprotect
{
    meta:
        group = "Obfuscator Analizi"
        description = "APKProtect kullanımı"
        obfuscator = "APKProtect"
        confidence = "Medium"

    strings:
        $lib = "libAPKProtect.so"
        $class = "com.apkunion.defender"

    condition:
        any of them
}

rule obfuscator_nagoon
{
    meta:
        group = "Obfuscator Analizi"
        description = "Nagoon obfuscator izleri"
        obfuscator = "Nagoon"
        confidence = "Low"

    strings:
        $lib = "libnagoon.so"
        $log = "nagonlog.txt"

    condition:
        any of them
}

rule obfuscator_secneo
{
    meta:
        group = "Obfuscator Analizi"
        description = "SecNeo tespiti (Tencent iş ortakları için)"
        obfuscator = "SecNeo"
        confidence = "High"

    strings:
        $lib = "libsecneo.so"
        $stub = "com.secneo.apkwrapper"

    condition:
        any of them
}

rule obfuscator_naga
{
    meta:
        group = "Obfuscator Analizi"
        description = "Naga obfuscator izleri"
        obfuscator = "Naga"
        confidence = "Medium"

    strings:
        $lib = "libnaga.so"
        $pkg = "com.nagasoft.protect"

    condition:
        any of them
}
