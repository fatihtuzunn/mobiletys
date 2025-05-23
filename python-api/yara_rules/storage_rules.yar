rule insecure_sharedpreferences_usage {
    meta:
        group = "INSECURE_DATA_STORAGE"
        description = "Uygulama, SharedPreferences API'sini kritik veriler için kullanıyor. Eğer bu veriler şifrelenmeden yazılıyorsa, veri sızıntısı riski doğar."
        severity = "Medium"
        reference = "https://developer.android.com/training/data-storage/shared-preferences"
    strings:
        $getPrefs = "getSharedPreferences"
        $putString = "putString"
    condition:
        all of them
}

rule world_readable_file_mode {
    meta:
        group = "INSECURE_DATA_STORAGE"
        description = "Uygulama bir dosyayı MODE_WORLD_READABLE veya MODE_WORLD_WRITABLE ile açıyor. Bu, diğer uygulamaların verilere erişmesine olanak tanır."
        severity = "High"
        reference = "https://developer.android.com/reference/android/content/Context.html#MODE_WORLD_READABLE"
    strings:
        $readable = "MODE_WORLD_READABLE"
        $writable = "MODE_WORLD_WRITABLE"
    condition:
        any of them
}

rule hardcoded_credentials_found {
    meta:
        group = "INSECURE_DATA_STORAGE"
        description = "Kullanıcı adı, parola veya API anahtarı gibi hassas bilgiler uygulama içine sabitlenmiş. Sızdırıldığında hesap veya sistemlere yetkisiz erişim sağlanabilir."
        severity = "High"
        reference = "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage"
    strings:
        $username = "username=" ascii
        $password = "password=" ascii
        $apikey = /AIza[0-9A-Za-z\-_]{35}/
    condition:
        any of them
}

rule insecure_sqlite_usage_pattern {
    meta:
        group = "INSECURE_DATA_STORAGE"
        description = "Uygulama, SQLite API’sini string concatenation ile kullanıyor. Bu durum SQL injection açığına neden olabilir."
        severity = "High"
        reference = "https://owasp.org/www-community/attacks/SQL_Injection"
    strings:
        $query = "rawQuery("
        $exec = "execSQL("
        $concat = "\" +"
    condition:
        all of them
}

rule internal_storage_sensitive_file {
    meta:
        group = "INSECURE_DATA_STORAGE"
        description = "Uygulama, dahili bellekte kullanıcıya ait verileri korumasız bir dosyada saklıyor. Bu dosyalar rooted cihazlarda kolayca elde edilebilir."
        severity = "Medium"
        reference = "https://developer.android.com/training/data-storage"
    strings:
        $save = "openFileOutput"
        $file = "user_data.txt"
    condition:
        all of them
}
