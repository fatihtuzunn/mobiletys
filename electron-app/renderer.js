const selectFileBtn = document.getElementById("selectFileBtn");
const selectedPathDiv = document.getElementById("selectedPath");
const resultsDiv = document.getElementById("results");
const downloadManifestBtn = document.getElementById("downloadManifestBtn");
const downloadPdfBtn = document.getElementById("downloadPdfBtn");
const downloadButtonsDiv = document.getElementById("downloadButtons");


selectFileBtn.addEventListener("click", async () => {
  const filePath = await window.electronAPI.openFileDialog();
  if (!filePath) {
    selectedPathDiv.textContent = "❌ Dosya seçilmedi.";
    return;
  }

  selectedPathDiv.textContent = `📁 Seçilen dosya: ${filePath}`;
  analyzeFile(filePath);

});


async function analyzeFile(filePath) {
  resultsDiv.textContent = "⏳ Analiz ediliyor...";

  try {
    const response = await fetch("http://127.0.0.1:5001/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apk_path: filePath }), // path her ikisi için kullanılıyor
    });

    const data = await response.json();
    window.lastAnalysisData = data;
    console.log("API yanıtı:", JSON.stringify(data, null, 2));
    if (!response.ok) {
      throw new Error(data.error || "Bilinmeyen hata");
    }

    downloadButtonsDiv.style.display = "block";

    let html = `<h4>📄 Dosya Türü: ${data.type?.toUpperCase() || "APK"}</h4>`;
    console.log(data.type)
    if (data.type === "ipa") {
      downloadManifestBtn.style.display = "none";
      html += renderIPAResult(data);
    } else if (data.type === "apk") {
      downloadManifestBtn.style.display = "inline";
      html += renderAPKResult(data);
    } else {
      html += `<p>❓ Tanınmayan analiz türü.</p>`;
    }

    resultsDiv.innerHTML = html;

  } catch (error) {
    resultsDiv.textContent = `❌ Hata: ${error.message}`;
  }
}

function renderAPKResult(data) {
  return `
    <h4>📁 Dosya Bilgileri</h4>    
    <div>${renderFileInfo(data.file_info)}</div>

    <h4>📦 Paket Bilgileri</h4>
    <div>${renderManifestDetails(data.manifest)}</div>

    ${renderSecurityFlags(data.manifest.security_flags)}

    <h4>🔐 İzinler:</h4>
    ${renderPermissions(data.manifest.permissions, data.dangerous_permissions)}

    <h4>🏁 Exported Bileşenler:</h4>
    ${renderExportedComponents(data.manifest.exported_components)}

    <h4>🟡 Implicit Exported Bileşenler</h4>
    ${renderExportedComponents(data.manifest.implicit_exported_components)}

    <h4>🧬 YARA Eşleşmeleri:</h4>
    ${renderYaraMatchesByGroup(data.yara_matches)}

    <h4>🧵 Şüpheli Stringler:</h4>
    ${renderSuspiciousStrings(data.suspicious_strings)}

    <h4>🚨 Zafiyet İmzaları:</h4>
    ${renderVulnerabilities(data.vulnerability_signatures)}
  `;
}

function renderIPAResult(data) {
  const plist = Object.entries(data.info_plist || {})
    .map(([k, v]) => `<li><strong>${k}</strong>: ${v}</li>`).join("");

  const susFiles = data.suspicious_files?.length
    ? `<ul>${data.suspicious_files.map(f => `<li>${f}</li>`).join("")}</ul>`
    : `<p>✅ Şüpheli dosya bulunamadı.</p>`;

  return `
    <h4>📁 Dosya Bilgileri</h4>    
    <div>${renderFileInfo(data.file_info)}</div>
        ${renderProvisioningProfile(data.provisioning_profile)}

    ${renderIOSPermissions(data.permissions)}
    <h4>🔐 Info.plist Güvenlik Ayarları</h4>
    ${renderIPASecurityTable(data.security_flags)}
    ${renderATSDetails(data.security_flags?.NSAppTransportSecurity || {})}
    <h4>📋 Info.plist İçeriği</h4>
    <ul>${plist}</ul>

    
    ${renderSuspiciousStringsIOS(data.suspicious_strings)}

    <h4>⚠️ Şüpheli Dosyalar</h4>
    ${susFiles}
  `;
}


function renderProvisioningProfile(profile) {
  if (!profile) return "<p>📄 embedded.mobileprovision bulunamadı.</p>";

  const devices = (profile.ProvisionedDevices || []).map(udid => `<li>${udid}</li>`).join("") || "-";
  const ent = profile.Entitlements || {};
  const isDebug = ent["get-task-allow"] === true;

  const riskColor = isDebug ? "#ff4d4d" : "#b3ffb3";

  return `
    <h4>🧾 Provisioning Profile</h4>
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%">
      <tr><th>Anahtar</th><th>Değer</th></tr>
      <tr><td>İsim</td><td>${profile.Name}</td></tr>
      <tr><td>Team</td><td>${profile.TeamName} (${(profile.TeamIdentifier || []).join(", ")})</td></tr>
      <tr><td>AppID</td><td>${profile.AppIDName}</td></tr>
      <tr><td>Sona Erme</td><td>${profile.ExpirationDate}</td></tr>
      <tr><td>Cihaz Sınırlı mı?</td><td>${profile.IsDeviceRestricted ? "✅ Evet (UDID bağlı)" : "❌ Hayır (Muhtemelen App Store)"}</td></tr>
    </table>

    <h5>📱 UDID Listesi</h5>
    <ul>${devices}</ul>

    <h5 style="margin-top:1em">🔐 Entitlements</h5>
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%">
      <tr style="background:${riskColor}"><td>get-task-allow</td><td>${ent["get-task-allow"]}</td></tr>
      <tr><td>aps-environment</td><td>${ent["aps-environment"] || "-"}</td></tr>
    </table>
  `;
}


function renderIOSPermissions(permissions = []) {
  if (!permissions.length) return "<p>ℹ️ İzin bilgisi bulunamadı.</p>";

  return `
    <h4>🔐 iOS Uygulama İzinleri</h4>
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%">
      <thead>
        <tr><th>PERMISSION</th><th>Durum</th><th>Kullanım</th><th>Bilgi (App)</th></tr>
      </thead>
      <tbody>
        ${permissions.map(p => {
          const color = p.status === "dangerous" ? "#ffcccc" : "#ffffcc";
          return `
            <tr style="background:${color}">
              <td>${p.permission}</td>
              <td>${p.status}</td>
              <td>${p.usage}</td>
              <td>${p.info}</td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
}


function renderATSDetails(ats = {}) {
  const getColor = (key, value) => {
    const riskyKeys = [
      "NSAllowsArbitraryLoads",
      "NSAllowsArbitraryLoadsInWebContent",
      "NSAllowsArbitraryLoadsForMedia"
    ];
    if (riskyKeys.includes(key) && value === true) return "#ff4d4d";
    if (key === "NSRequiresCertificateTransparency" && value === false) return "#ffd700";
    return "#b3ffb3";
  };

  const rows = Object.entries(ats).map(([key, value]) => {
    if (key === "NSExceptionDomains") {
      const domainDetails = Object.entries(value).map(([domain, config]) => {
        const configRows = Object.entries(config).map(
          ([k, v]) => `<li><strong>${k}</strong>: ${v}</li>`
        ).join("");
        return `<tr><td>${domain}</td><td><ul>${configRows}</ul></td></tr>`;
      }).join("");

      return `
        <tr style="background:#f2f2f2">
          <td>NSExceptionDomains</td>
          <td>
            <table border="1" cellpadding="4" cellspacing="0">
              <tr><th>Domain</th><th>Konfigürasyon</th></tr>
              ${domainDetails}
            </table>
          </td>
        </tr>
      `;
    } else {
      return `<tr style="background:${getColor(key, value)}">
                <td>${key}</td>
                <td>${value}</td>
              </tr>`;
    }
  });

  return `
    <h5>🔍 ATS Detayları (NSAppTransportSecurity)</h5>
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%">
      <tr><th>Anahtar</th><th>Değer</th></tr>
      ${rows.join("")}
    </table>
  `;
}


function renderIPASecurityTable(flags = {}) {
  const ats = flags["NSAppTransportSecurity"] || {};

  const rows = [
    {
      name: "get-task-allow",
      value: String(flags["get-task-allow"]),
      risk: flags["get-task-allow"] ? "Kritik" : "Güvenli",
      desc: "Debug mod aktifse kötü amaçlı analiz kolaylaşır."
    },
    {
      name: "UIFileSharingEnabled",
      value: String(flags["UIFileSharingEnabled"]),
      risk: flags["UIFileSharingEnabled"] ? "Orta" : "Güvenli",
      desc: "Kullanıcının iTunes/Finder ile uygulama dizinine erişmesine izin verir."
    },
    {
      name: "UIApplicationExitsOnSuspend",
      value: String(flags["UIApplicationExitsOnSuspend"]),
      risk: !flags["UIApplicationExitsOnSuspend"] ? "Orta" : "Güvenli",
      desc: "Arka planda çalışmasına izin verilmişse kötüye kullanılabilir."
    },
    {
      name: "UIBackgroundModes",
      value: (flags["UIBackgroundModes"] || []).join(", ") || "-",
      risk: (flags["UIBackgroundModes"] || []).length ? "Orta" : "Güvenli",
      desc: "Arka planda çalışan servisler güvenlik için risk olabilir."
    },
    {
      name: "LSApplicationQueriesSchemes",
      value: (flags["LSApplicationQueriesSchemes"] || []).join(", ") || "-",
      risk: (flags["LSApplicationQueriesSchemes"] || []).length ? "Orta" : "Güvenli",
      desc: "Uygulama diğer uygulamaları `canOpenURL` ile sorgulayabilir."
    },
    {
      name: "NSAppTransportSecurity.AllowArbitraryLoads",
      value: String(ats["NSAllowsArbitraryLoads"]),
      risk: ats["NSAllowsArbitraryLoads"] === true ? "Kritik" : "Güvenli",
      desc: "HTTP bağlantılarına izin verilmişse veri gizliliği riske girer."
    }
  ];

  const getColor = (risk) => {
    switch (risk) {
      case "Kritik": return "#ff4d4d";
      case "Orta": return "#ffd700";
      case "Güvenli": return "#b3ffb3";
      default: return "#ffffff";
    }
  };

  return `
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%">
      <thead>
        <tr>
          <th>Anahtar</th>
          <th>Değer</th>
          <th>Risk</th>
          <th>Açıklama</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(r => `
          <tr style="background:${getColor(r.risk)}">
            <td>${r.name}</td>
            <td>${r.value}</td>
            <td>${r.risk}</td>
            <td>${r.desc}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}



document.getElementById("printReportBtn").addEventListener("click", () => {
  const resultsElement = document.getElementById("results");
  const coverElement = document.getElementById("pdf-cover");

  // Geçici olarak görünür yap
  coverElement.style.display = "block";

  const originalContent = document.body.innerHTML;
  const printContent = coverElement.outerHTML + resultsElement.outerHTML;

  // Sadece analiz çıktısını yazdır
  document.body.innerHTML = printContent;
  window.print();

  // Sayfa içeriğini geri yükle
  document.body.innerHTML = originalContent;

  coverElement.style.display = "none"; // Kapağı gizle
});

downloadManifestBtn.addEventListener("click", () => {
  if (window.lastAnalysisData?.manifest?.manifest_xml) {
      downloadManifest(window.lastAnalysisData.manifest.manifest_xml, window.lastAnalysisData.manifest.package_name);
  }
});

downloadPdfBtn.addEventListener("click", () => {
  downloadPdfReport();
}); 



function downloadManifest(manifestXml, packageName = "manifest") {
  const blob = new Blob([manifestXml], { type: "text/xml" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${packageName}_AndroidManifest.xml`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

  function downloadPdfReport() {
    const resultsElement = document.getElementById("results");
    const coverElement = document.getElementById("pdf-cover");
  
    // PDF'e özel stil
    resultsElement.classList.add("pdf-export");
    coverElement.style.display = "block";
  
    // Kopya oluştur
    const clone = document.createElement("div");
    const clonedCover = coverElement.cloneNode(true);
    const clonedResults = resultsElement.cloneNode(true);
  
    // Tarih alanını güncelle
    const dateSpan = clonedCover.querySelector("#pdf-date");
    if (dateSpan) {
      dateSpan.textContent = new Date().toLocaleString();
    }
  
    // Yapıştır
    clone.appendChild(clonedCover);
    clone.appendChild(clonedResults);
  
    const opt = {
      margin: 0,
      filename: `${window.lastAnalysisData?.manifest?.package_name || "rapor"}.pdf`,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true },
      jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
    };
  
    html2pdf().set(opt).from(clone).save().then(() => {
      resultsElement.classList.remove("pdf-export");
      coverElement.style.display = "none";

    });
  }
  





function renderPermissions(permissions, dangerousList) {
  if (!permissions || permissions.length === 0) return "<p>❌ İzin bulunamadı.</p>";

  return `
      <table border="1" cellpadding="6" cellspacing="0">
        <tr><th>İzin</th><th>Risk</th></tr>
        ${permissions.map(p => {
    const isDangerous = dangerousList.includes(p);
    const color = isDangerous ? "#ff4d4d" : "#ffd700";
    const risk = isDangerous ? "Kritik" : "Uyarı";
    return `<tr style="background:${color}">
    <td style="width:70%">${p}</td>
    <td style="width:30%">${risk}</td>
    </tr>`;
  }).join("")}
      </table>
    `;
}

function renderExportedComponents(components) {
  if (!components || components.length === 0) return "<p>✅ Exported bileşen yok.</p>";

  return `
      <table border="1" cellpadding="6" cellspacing="0">
        <tr>
        <th style="width:10%">Tür</th>
        <th>İsim</th>
        </tr>
        ${components.map(c => `<tr><td>${c.type}</td><td>${c.name}</td></tr>`).join("")}
      </table>
    `;
}

function renderVulnerabilities(vulns) {
  if (!vulns || vulns.length === 0) return "<p>✅ Bilinen zafiyet bulunamadı.</p>";

  return `
      <table border="1" cellpadding="6" cellspacing="0">
        <tr><th>Dosya</th><th>Zafiyet</th></tr>
        ${vulns.map(v => `<tr style="background:#ffb347"><td>${v.file}</td><td>${v.issue}</td></tr>`).join("")}
      </table>
    `;
}


function renderManifestDetails(manifest) {
    let html = `
    <table border="1" cellpadding="6" cellspacing="0">
    <tr>
        <td>📦 Paket:</td><td> ${manifest.package_name}</td> </tr>
        <tr><td>📦 Sürüm:</td><td> ${manifest.version_name} (${manifest.version_code})</td> </tr>
        <tr><td>📦 Compile SDK:</td><td> ${manifest.compile_sdk_version || "-"} ${manifest.compile_sdk_codename || ""}</td> </tr>
        <tr><td>📦 Min SDK:</td><td> ${manifest.min_sdk || "-"}</td> </tr>
        <tr><td>📦 Target SDK:</td><td> ${manifest.target_sdk || "-"}</td> </tr>
        <tr><td>📦 platform_build_version_code:</td><td> ${manifest.platform_build_version_code}</td> </tr>
        <tr><td>📦 platform_build_version_name:</td><td> ${manifest.platform_build_version_name}</td> </tr>
      </table>
  
      <h4>⚠️ Task Affinity Uyuşmazlıkları</h4>
      ${manifest.security_flags.task_affinities.length > 0
        ? `<ul>${manifest.security_flags.task_affinities.map(t => `<li>${t.component} ➜ ${t.affinity}</li>`).join("")}</ul>`
        : `<p>✅ Uyuşmazlık bulunamadı.</p>`}

      <h4>🔐 Korunan Bileşenler</h4>
      ${manifest.security_flags.protected_components.length > 0
        ? `<ul>${manifest.security_flags.protected_components.map(c => `<li>${c.type}: ${c.component} ➜ ${c.permission}</li>`).join("")}</ul>`
        : `<p>ℹ️ Koruma bildirimi yapılmamış bileşen yok.</p>`}
  
      
    `;
    return html;
  }
  

function renderYaraMatchesByGroup(matches) {
  if (!matches || matches.length === 0) return "<p>✅ YARA eşleşmesi bulunamadı.</p>";

  const grouped = {};

  for (const match of matches) {
    const group = match.meta?.group || "Diğer";
    if (!grouped[group]) grouped[group] = [];
    grouped[group].push(match);
  }

  const getRowColor = (severity) => {
    switch ((severity || "").toLowerCase()) {
      case "critical": return "#ffcccc";
      case "high": return "#ffd9cc";
      case "medium": return "#fff3cd";
      case "low": return "#d1ecf1";
      case "info": return "#f8f9fa";
      case "good": return "#d4edda";
      default: return "#ffffff";
    }
  };

  let html = "";
  for (const group in grouped) {
    html += `<h5>🧩 ${group.toUpperCase()}:</h5>`;
    html += `
        <table border="1" cellpadding="6" cellspacing="0" style="table-layout:fixed; width:100%;">
          <thead>
            <tr>
              <th style="width:17%">📄 Dosya (Satır)</th>
              <th style="width:20%">🧪 Kural</th>
              
              <th style="width:30%">📝 Açıklama</th>
              <th style="width:8%">⚠️ Severity</th>
              <th class="snippet-column" style="width:25%">📋 Snippet</th>
            </tr>
          </thead>
          <tbody>
            ${grouped[group].flatMap(m =>
    (m.matches && m.matches.length > 0
      ? m.matches.map(match => `
                  <tr style="background:${getRowColor(m.meta?.severity)}">
                    <td>${m.file}${match.line_number ? ` <span style="color:gray;">(satır ${match.line_number})</span>` : ""}</td>
                    <td>${m.rule}</td>
                    
                    <td>${m.meta?.description || "-"}</td>
                    <td>${m.meta?.severity || "-"}</td>
                    <td class="snippet-cell">
                      <details>
                        <summary>Göster</summary>
                        <pre style="white-space:pre-wrap; font-size: 0.9em; max-height: 150px; overflow:auto;">${match.snippet || "-"}</pre>
                      </details>
                    </td>
                  </tr>
                `)
      : [`
                  <tr style="background:${getRowColor(m.meta?.severity)}">
                    <td>${m.file}</td>
                    <td>${m.rule}</td>
                    
                    <td>${m.meta?.description || "-"}</td>
                    <td>${m.meta?.severity || "-"}</td>
                    <td><i>Snippet yok</i></td>
                  </tr>
                `])
    ).join("")}
          </tbody>
        </table>
      `;
  }

  return html;
}



function showSnippet(file, line, content) {
  alert(`📄 Dosya: ${file}\n🔢 Satır: ${line}\n📎 İçerik:\n${content}`);
}


function renderFileInfo(file_info) {
  if (!file_info || Object.keys(file_info).length === 0) {
    return "<p>❌ Dosya bilgisi bulunamadı.</p>";
  }

  let html = `
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%;">
      <thead>
        <tr>
          <th style="width:25%;">Bilgi</th>
          <th>Değer</th>
        </tr>
      </thead>
      <tbody>
  `;

  for (const key in file_info) {
    html += `
      <tr>
        <td><strong>${key}</strong></td>
        <td>${file_info[key]}</td>
      </tr>
    `;
  }

  html += `
      </tbody>
    </table>
  `;

  return html;
}


function renderSuspiciousStrings(suspicious) {
  if (!suspicious || suspicious.length === 0) {
    return "<p>✅ Şüpheli string bulunamadı.</p>";
  }

  // Grupla: { matched + type => [entries] }
  const grouped = {};

  for (const entry of suspicious) {
    const key = `${entry.type}|||${entry.matched}`;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(entry);
  }

  return `
    <table border="1" cellpadding="2" cellspacing="0">
      <thead>
        <tr>
          <th style="width:10%">🚩 Tür</th>
            <th style="width:35%">🔍 İçerik</th>
            <th style="width:30%">📄 Dosya (Satır)</th>
            <th class="snippet-column" style="width:25%">📎 Kod Parçası</th>
        </tr>
      </thead>
      <tbody>
        ${Object.entries(grouped).map(([key, entries]) => {
          const [type, matched] = key.split("|||");
          const fileList = entries.map(e => `${e.file}${e.line_number ? ` (satır ${e.line_number})` : ""}`).join(", ");
          const snippet = entries[0].snippet ? `
            <details>
              <summary>Göster</summary>
              <pre style="white-space:pre-wrap; font-size:0.9em; max-height:120px; overflow:auto;">${entries[0].snippet}</pre>
            </details>` : "<i>Yok</i>";

          return `
            <tr>
              <td>${type}</td>
              <td><code>${matched}</code></td>
              <td>${fileList}</td>
              <td class="snippet-cell">${snippet}</td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
}

function renderSuspiciousStringsIOS(suspicious = []) {
  if (!suspicious || suspicious.length === 0) {
    return "<p>✅ Şüpheli string bulunamadı (iOS).</p>";
  }

  return `
    <h4>🧵 iOS Şüpheli Stringler</h4>
    <table border="1" cellpadding="6" cellspacing="0" style="width:100%">
      <thead>
        <tr><th>📄 Dosya</th><th>🔎 Tür</th><th>💬 Eşleşen Değerler</th></tr>
      </thead>
      <tbody>
        ${suspicious.map(item => `
          <tr>
            <td style="width:30%">${item.file}</td>
            <td style="width:20%">${item.type}</td>
            <td style="width:50%">
              <ul style="padding-left:1.2em;">
                ${(item.matches || []).map(m => `<li>${m}</li>`).join("")}
              </ul>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}


  function renderSecurityFlags(flags) {
    if (!flags) return "<p>⚠️ Güvenlik bayrakları tespit edilemedi.</p>";
  
    let html = `
      <h4>🔒 Uygulama Güvenlik Bayrakları</h4>
      <table border="1" cellpadding="6" cellspacing="0" style="width:100%;">
        <thead>
          <tr>
            <th style="width:30%;">Bayrak</th>
            <th style="width:30%;">Değer</th>
            <th style="width:40%;">Açıklama / Risk Seviyesi</th>
          </tr>
        </thead>
        <tbody>
          ${renderFlagRow("debuggable", flags.debuggable)}
          ${renderFlagRow("allowBackup", flags.allow_backup)}
          ${renderFlagRow("usesCleartextTraffic", flags.uses_cleartext_traffic)}
          ${renderFlagRow("testOnly", flags.test_only)}
          ${renderFlagRow("directBootAware", flags.direct_boot_aware)}
          ${renderFlagRow("NetworkSecurityConfig", flags.network_security_config)}
        </tbody>
      </table>
    `;
  
    if (flags.task_affinities?.length > 0) {
      html += `
        <h5>⚠️ Task Affinity Sapmaları</h5>
        <table border="1" cellpadding="6" cellspacing="0" style="width:100%;">
          <thead><tr><th>Bileşen</th><th>Affinity</th></tr></thead>
          <tbody>
            ${flags.task_affinities.map(t =>
              `<tr style="background:#ffd480"><td>${t.component}</td><td>${t.affinity}</td></tr>`
            ).join("")}
          </tbody>
        </table>
      `;
    }
  
    if (flags.intent_filters?.length > 0) {
      html += `
        <h5>🔗 Intent-Filter Scheme Eşleşmeleri</h5>
        <table border="1" cellpadding="6" cellspacing="0" style="width:100%;">
          <thead><tr><th>Bileşen</th><th>Scheme</th></tr></thead>
          <tbody>
            ${flags.intent_filters.map(i =>
              `<tr><td>${i.component}</td><td>${i.scheme}</td></tr>`
            ).join("")}
          </tbody>
        </table>
      `;
    }
  
    return html;
  }
  
  // 🎯 Her bayrak için açıklama + risk seviyesi
  function renderFlagRow(label, value) {
    if (value === undefined || value === null || value === "") {
      return `<tr style="background:#f0f0f0"><td>${label}</td><td>-</td><td>Bilinmiyor</td></tr>`;
    }
  
    // Açıklama + risk seviyesi tablosu
    const RISK_MAP = {
      debuggable: {
        desc: "Uygulama debug modda derlenmiş. Saldırgan kaynak kod çıkarımı ve dinleme yapabilir.",
        level: "Kritik", color: "#ff4d4d"
      },
      allowBackup: {
        desc: "Veriler adb ile yedeklenebilir. Kötü niyetli erişimle veri sızabilir.",
        level: "Orta", color: "#ffd480"
      },
      usesCleartextTraffic: {
        desc: "HTTP trafiğine izin veriliyor. MITM saldırılarına açıktır.",
        level: "Orta", color: "#ffd480"
      },
      testOnly: {
        desc: "Test amaçlı işaretlenmiş uygulama. Yanlışlıkla markete yüklenirse risklidir.",
        level: "Uyarı", color: "#fff3cd"
      },
      directBootAware: {
        desc: "Boot sonrası erken erişim izni. Güvenlik açısından doğrudan risk oluşturmaz.",
        level: "Güvenli", color: "#b3ffb3"
      },
      NetworkSecurityConfig: {
        desc: "TLS ayarları özelleştirilmiş. Dosya içeriği analiz edilmeden güvenlik düzeyi bilinemez.",
        level: "Bilinmiyor", color: "#e0e0e0"
      }
    };
  
    const key = label;
    const risk = RISK_MAP[key] || {
      desc: "Özel bayrak. Güvenlik etkisi analiz edilmedi.",
      level: "Bilinmiyor",
      color: "#e0e0e0"
    };
  
    return `
      <tr style="background:${risk.color}">
        <td>${label}</td>
        <td>${value}</td>
        <td><strong>${risk.level}</strong><br><small>${risk.desc}</small></td>
      </tr>
    `;
  }
  

/* function renderFlagRow(label, value) {
  const isRisk = value === "true";
  const bgColor = isRisk ? "#ff4d4d" : "#b3ffb3";
  const yorum = isRisk ? "Riskli" : "Güvenli";
  return `<tr style="background:${bgColor}"><td>${label}</td><td>${value || "-"}</td><td>${yorum}</td></tr>`;
}
 */
