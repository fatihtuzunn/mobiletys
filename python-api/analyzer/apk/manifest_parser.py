import apkutils
from apkutils import APK
from lxml import etree
from io import BytesIO

ANDROID_NS = 'http://schemas.android.com/apk/res/android'

def parse_manifest(apk_path):
    apk = APK.from_file(apk_path)
    manifest_xml = apk.get_manifest()
    root = etree.parse(BytesIO(manifest_xml.encode('utf-8'))).getroot()

    def get_ns_attr(elem, attr):
        return elem.attrib.get(f"{{{ANDROID_NS}}}{attr}")

    # Versiyon & yapı bilgileri
    manifest_attrs = {
        "package_name": root.attrib.get("package", ""),
        "version_code": get_ns_attr(root, "versionCode") or root.attrib.get("versionCode", ""),
        "version_name": get_ns_attr(root, "versionName") or root.attrib.get("versionName", ""),
        "compile_sdk_version": root.attrib.get("android:compileSdkVersion", root.attrib.get("compileSdkVersion", "")),
        "compile_sdk_codename": root.attrib.get("android:compileSdkVersionCodename", root.attrib.get("compileSdkVersionCodename", "")),
        "platform_build_version_code": root.attrib.get("platformBuildVersionCode", ""),
        "platform_build_version_name": root.attrib.get("platformBuildVersionName", "")
    }

    # uses-sdk bilgileri
    uses_sdk = root.find("uses-sdk")
    manifest_attrs["min_sdk"] = get_ns_attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else ""
    manifest_attrs["target_sdk"] = get_ns_attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else ""

    # İzinler
    permissions = []
    for perm in root.findall("uses-permission"):
        name = get_ns_attr(perm, "name")
        if name:
            permissions.append(name)

    exported_components = []
    implicit_exported_components = []
    security_flags = {
        "allow_backup": None,
        "debuggable": None,
        "uses_cleartext_traffic": None,
        "network_security_config": None,
        "test_only": None,
        "direct_boot_aware": None,
        "task_affinities": [],
        "intent_filters": [],
        "protected_components": []
    }

    application = root.find("application")
    if application is not None:
        # Application düzeyindeki ayarlar
        security_flags["allow_backup"] = get_ns_attr(application, "allowBackup")
        security_flags["debuggable"] = get_ns_attr(application, "debuggable")
        security_flags["uses_cleartext_traffic"] = get_ns_attr(application, "usesCleartextTraffic")
        security_flags["network_security_config"] = get_ns_attr(application, "networkSecurityConfig")
        security_flags["test_only"] = get_ns_attr(application, "testOnly")
        security_flags["direct_boot_aware"] = get_ns_attr(application, "directBootAware")

        app_permission = get_ns_attr(application, "permission")

        # Component incelemesi
        for tag in ["activity", "receiver", "service", "provider"]:
            for item in application.findall(tag):
                name = get_ns_attr(item, "name")
                exported = get_ns_attr(item, "exported")
                permission = get_ns_attr(item, "permission")
                task_affinity = get_ns_attr(item, "taskAffinity")

                # Exported kontrolü
                if exported == "true":
                    exported_components.append({"type": tag, "name": name})
                elif exported is None:
                    # Eğer intent-filter varsa ve exported belirtilmemişse => implicit exported olabilir
                    if item.findall("intent-filter"):
                        implicit_exported_components.append({"type": tag, "name": name})

                # taskAffinity kontrolü
                if task_affinity and task_affinity != manifest_attrs["package_name"]:
                    security_flags["task_affinities"].append({
                        "component": name,
                        "affinity": task_affinity
                    })

                # intent-filter -> scheme kontrolü
                for intent_filter in item.findall("intent-filter"):
                    for data_tag in intent_filter.findall("data"):
                        scheme = get_ns_attr(data_tag, "scheme")
                        if scheme:
                            security_flags["intent_filters"].append({
                                "component": name,
                                "scheme": scheme
                            })

                # permission & protectionLevel analizi (geliştirme alanı)
                if permission:
                    security_flags["protected_components"].append({
                        "component": name,
                        "type": tag,
                        "permission": permission
                    })
                elif app_permission:
                    security_flags["protected_components"].append({
                        "component": name,
                        "type": tag,
                        "permission": app_permission + " (from application tag)"
                    })

    return {
        **manifest_attrs,
        "permissions": permissions,
        "exported_components": exported_components,
        "implicit_exported_components": implicit_exported_components,
        "security_flags": security_flags,
        "manifest_xml": manifest_xml
    }



""" def parse_manifest(apk_path):
    apk = APK.from_file(apk_path)
    manifest_xml = apk.get_manifest()
    root = etree.parse(BytesIO(manifest_xml.encode('utf-8'))).getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}

    # Versiyon & yapı bilgileri
    manifest_attrs = {
        "package_name": root.attrib.get("package", ""),
        "version_code": root.attrib.get("{http://schemas.android.com/apk/res/android}versionCode", ""),
        "version_name": root.attrib.get("{http://schemas.android.com/apk/res/android}versionName", ""),
        "compile_sdk_version": root.attrib.get("android:compileSdkVersion", root.attrib.get("compileSdkVersion", "")),
        "compile_sdk_codename": root.attrib.get("android:compileSdkVersionCodename", root.attrib.get("compileSdkVersionCodename", "")),
        "platform_build_version_code": root.attrib.get("platformBuildVersionCode", ""),
        "platform_build_version_name": root.attrib.get("platformBuildVersionName", "")
    }

    # İzinler
    permissions = []
    for perm in root.findall("uses-permission"):
        name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
        if name:
            permissions.append(name)

    exported_components = []
    security_flags = {
        "allow_backup": None,
        "debuggable": None,
        "uses_cleartext_traffic": None,
        "task_affinities": [],
        "intent_filters": []
    }

    application = root.find("application")
    if application is not None:
        # Ana application etiketinden alınan bayraklar
        security_flags["allow_backup"] = application.attrib.get("{http://schemas.android.com/apk/res/android}allowBackup")
        security_flags["debuggable"] = application.attrib.get("{http://schemas.android.com/apk/res/android}debuggable")
        security_flags["uses_cleartext_traffic"] = application.attrib.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")

        for tag in ["activity", "receiver", "service", "provider"]:
            for item in application.findall(tag):
                exported = item.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                name = item.attrib.get("{http://schemas.android.com/apk/res/android}name")

                if exported == "true":
                    exported_components.append({
                        "type": tag,
                        "name": name
                    })

                # taskAffinity sapması
                task_affinity = item.attrib.get("{http://schemas.android.com/apk/res/android}taskAffinity")
                if task_affinity and task_affinity != manifest_attrs["package_name"]:
                    security_flags["task_affinities"].append({
                        "component": name,
                        "affinity": task_affinity
                    })

                # intent-filter içinde scheme kontrolü
                for intent_filter in item.findall("intent-filter"):
                    for data_tag in intent_filter.findall("data"):
                        scheme = data_tag.attrib.get("{http://schemas.android.com/apk/res/android}scheme")
                        if scheme:
                            security_flags["intent_filters"].append({
                                "component": name,
                                "scheme": scheme
                            })

    return {
        **manifest_attrs,
        "permissions": permissions,
        "exported_components": exported_components,
        "security_flags": security_flags,
        "manifest_xml": manifest_xml
    }
 """