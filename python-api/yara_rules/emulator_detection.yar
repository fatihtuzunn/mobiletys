rule emulator_detection {
    meta:
        group = "EMULATOR_DETECTION"
        description = "Uygulama, emülatör ortamlarını tespit etmek için yaygın kullanılan sistem özelliklerini kontrol ediyor (ro.kernel.qemu, Genymotion, vb.)."
        severity = "Info"
        reference = "https://developer.android.com/studio/run/emulator-commandline"
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
