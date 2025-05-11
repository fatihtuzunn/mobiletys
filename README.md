# 📱 Mobil Statik Analiz Aracı (APK & IPA)

Android ve iOS uygulama dosyaları (`.apk`, `.ipa`) üzerinde hızlı, hafif ve açıklayıcı statik analizler gerçekleştiren bir masaüstü güvenlik aracı.

## 🎯 Neden Bu Araç?

MobSF gibi araçlar güçlü olsalar da:
- Kurulumları karmaşık,
- Sonuçları fazla detaylı ve yorucu,
- iOS desteği oldukça sınırlı.

Bu araç:
- Docker veya emulator gerektirmez,
- Tek tıklamayla analiz başlatır,
- Hem iOS hem Android için sade ama anlamlı sonuçlar sunar.

## 🚀 Özellikler

### ✅ Android (APK)

- `AndroidManifest.xml` analizi (izinler, exported bileşenler, scheme’ler)
- Tehlikeli izinlerin tespiti ve renklendirilmiş tablo ile gösterimi
- Custom YARA kuralları ile `.dex`, `.smali` ve `.xml` içinde imza taraması
- Hardcoded API anahtarları, şüpheli stringler
- Zafiyet imzaları (ör. `Runtime.exec()`, `DexClassLoader`, `setJavaScriptEnabled(true)`)
- SHA1, SHA256, MD5 hash hesaplamaları

### 🍏 iOS (IPA)

- `Info.plist` analizi (ATS, debug flag, scheme, background modes)
- **iOS App Permissions (NSUsageDescription)** analizi, risk seviyelerine göre sınıflandırma
- `embedded.mobileprovision` dosyasından:
  - Profil tipi (App Store, Ad-Hoc vs.)
  - UDID tanımlı mı?
  - Sertifika bitiş tarihi
  - Entitlements içeriği
- `.entitlements` dosyasının ayrıştırılması ve analiz edilmesi
- `frida`, `cycript`, `.dylib` gibi şüpheli dosya tespiti

## 🧰 Teknoloji Yığını

- Python (Flask) → REST API
- Electron + Vanilla JavaScript → masaüstü GUI
- `zipfile`, `plistlib`, `re`, `yara-python` → dosya bazlı analiz
- Docker/emulator gerekmez, tüm analizler statik olarak çalışır

## 🖥️ Kurulum

```bash
git clone https://github.com/fatihtuzunn/mobiletys.git
cd mobiletys
```

### 1. Python API (Backend)

```bash
cd python-api
pip install -r requirements.txt
python app.py
```

### 2. Electron Uygulaması (Frontend)

```bash
cd electron-app
npm install
npm start
```

## 📸 

![mobiet](https://github.com/user-attachments/assets/dc040bf7-9bcd-4d2a-a985-bedbf1b5e1bd)


## ✍️ Katkı ve İletişim

İstek, katkı ya da geri bildirim için LinkedIn üzerinden bana ulaşabilirsiniz.  
Her türlü yapıcı geri bildirimi memnuniyetle karşılarım.

## ⚠️ Uyarı

Bu araç yalnızca **yasal testler**, eğitim amaçlı analizler ve kendi uygulamalarınızın güvenliğini denetlemek için geliştirilmiştir. Başkalarının uygulamalarını izinsiz analiz etmek **yasalara aykırıdır**.
