# 🔍 Incident Investigation Report: Spear Phishing, Memory Forensics & Fileless Registry Persistence

**Case Reference:** IR-2023-0802-BG2  
**Target Organization:** Quick Logistics LLC  
**Incident Classification:** High (Severity 2 - P2)  
**Affected Hostnames / Users:** `WKSTN-2961` (Maxine Beck - Human Resources Specialist)  
**Date of Incident:** August 2023  
**Lead Investigator:** Ahmet Furkan Hüsmek (Junior SOC / DFIR Analyst)  

---

## 1. Executive Summary (Yönetici Özeti)

Quick Logistics LLC İnsan Kaynakları Uzmanı *Maxine Beck*, sahte bir iş başvurusu kılığında iletilen mızrak oltalama (Spear Phishing) e-postası almıştır. E-posta ekindeki kötü niyetli Microsoft Word belgesinin (`Resume_WesleyTaylor.doc`) açılması ve makroların etkinleştirilmesi neticesinde iş istasyonu ihlal edilmiştir.

Saldırgan; ağ düzeyindeki tespit mekanizmalarını atlatmak amacıyla ikinci aşama yükünü bir resim dosyası (`update.png`) kisvesi altında indirmiş, diske JavaScript betiği (`C:\ProgramData\update.js`) olarak kaydedip yerleşik Windows betik motoru `wscript.exe` ile çalıştırmıştır. Ardından C2 bağlantısını sağlayacak asıl ikili dosya (`update.exe`) indirilerek `C:\Windows\Tasks\updater.exe` yoluna bırakılmış ve aktif komuta kontrol kanalı açılmıştır. 

Kalıcılık (Persistence) amacıyla zamanlanmış görev (`schtasks`) oluşturulmuş, ancak antivirüs ve EDR taramalarını atlatmak adına zararlı kod doğrudan Kayıt Defteri (`HKCU:\Software\Microsoft\Windows\CurrentVersion\debug`) altına gizlenerek PowerShell üzerinden diske dokunmadan (fileless) bellekte yürütülmüştür.

Adli analiz ekibimiz, kurban makinenin uçucu bellek dökümü (`WKSTN-2961.raw`) üzerinde **Volatility 3** framework'ü ile derinlemesine inceleme yapmış; süreç hiyerarşisini, gizli ağ soketlerini, komut argümanlarını ve dosyasız kalıcılık mekanizmasını eksiksiz olarak ortaya çıkarmıştır.

---

## 2. Incident Timeline (Zaman Çizelgesi)

| Aşama / Zaman | Olay Yeri | Gerçekleşen Eylem / TTP | Tespit Edilen Süreç / Komut |
| :--- | :--- | :--- | :--- |
| **T0 (Delivery)** | Email Gateway | Sahte başvuru e-postası kurbanın posta kutusuna ulaştı. | Gönderen: `westaylor23@outlook.com` |
| **T1 (Initial Access)** | `WKSTN-2961` | Kurban Word belgesini açtı ve VBA makroları tetiklendi. | `Resume_WesleyTaylor.doc` (MD5: `52c4384a0b9e248b95804352ebec6c5b`) |
| **T2 (Staging)** | Network / Web | Resim görünümlü JS yükü WebClient ile diske çekildi. | `update.png` ──► `C:\ProgramData\update.js` |
| **T3 (Execution)** | `WKSTN-2961` | JavaScript yükü Windows betik motoru ile yürütüldü. | `wscript.exe` (PID: 4260, PPID: 1124) |
| **T4 (C2 Drop)** | `WKSTN-2961` | Asıl C2 ikili dosyası indirilip görev dizinine bırakıldı. | `C:\Windows\Tasks\updater.exe` (PID: 6216) |
| **T5 (C2 Callback)** | Network / Socket| Dış ağdaki C2 sunucusuna soket bağlantısı açıldı. | `updater.exe` ──► `128.199.95.189:8080` |
| **T6 (Persistence)** | `WKSTN-2961` | Registry'deki payload'u tetikleyen günlük görev kuruldu. | `schtasks /Create /TN Updater` (PowerShell IEX) |

---

## 3. Detailed Technical Analysis (Derinlemesine Teknik Analiz)

### 3.1 Initial Access & VBA Macro Extraction (Olevba Analizi)
- **Vektör:** `Resume_WesleyTaylor.doc` (Outlook önbellek yolu: `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc`).
- **Analiz Yöntemi:** Oletools paketine ait `olevba` aracı kullanılarak belgenin arka planındaki makro kodları ayrıştırılmıştır:
  ```bash
  olevba Resume_WesleyTaylor.doc

```

* **Bulgular:** Makro kodunun bir HTTP GET isteği ile `https://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` adresinden veri çektiği ve bu içeriği yerel sisteme `C:\ProgramData\update.js` adıyla kaydettiği tespit edilmiştir. Resim formatı süsü verilmesi içerik filtreleme çözümlerini atlatmaya yöneliktir.

### 3.2 Memory Forensics via Volatility 3

Uçucu bellek dökümü (`WKSTN-2961.raw`) üzerinde Volatility 3 eklentileri çalıştırılarak saldırının uç nokta üzerindeki izleri doğrulanmıştır:

1. **Süreç Taraması (`windows.psscan.PsScan`):**
Zararlı betiğin `wscript.exe` tarafından **PID 4260** ve **PPID 1124** ile yürütüldüğü saptanmıştır:
```bash
vol -f WKSTN-2961.raw windows.psscan.PsScan | grep "wscript.exe"

```


2. **Süreç Hiyerarşisi (`windows.pstree.PsTree`):**
`wscript.exe` sürecinin başlattığı alt süreç incelendiğinde, **PID 6216** ile `updater.exe` sürecinin dallandığı görülmüştür:
```bash
vol -f WKSTN-2961.raw windows.pstree.PsTree | grep "4260"

```


3. **Komut Satırı Argümanları (`windows.cmdline.CmdLine --pid 6216`):**
Zararlı ikili dosyanın çalışma yolu `C:\Windows\Tasks\updater.exe` olarak doğrulanmıştır:
```bash
vol -f WKSTN-2961.raw windows.cmdline.CmdLine --pid 6216

```


4. **Ağ Soketleri (`windows.netscan.NetScan`):**
PID 6216'nın dış ağda yer alan **`128.199.95.189:8080`** IP adresine aktif TCP bağlantısı kurduğu belirlenmiştir:
```bash
vol -f WKSTN-2961.raw windows.netscan.NetScan | grep "6216"

```


5. **Dosya Nesnesi Taraması (`windows.filescan.FileScan`):**
Word belgesinin Outlook tarafından açıldığı yerel geçici dizin haritalanmıştır:
```bash
vol -f WKSTN-2961.raw windows.filescan.FileScan | grep -i "Resume_WesleyTaylor"

```



### 3.3 Fileless Registry-Based Persistence (Dosyasız Kalıcılık İncelemesi)

Bellek üzerinde ham metin taraması (`strings WKSTN-2961.raw | grep "schtasks"`) yapıldığında şu kalıcılık komutu yakalanmıştır:

```cmd
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"'

```

* **Teknik Mekanizma:** Saldırgan zamanlanmış göreve doğrudan bir dosya yolu tanımlamamıştır. Bunun yerine zararlı yükü Kayıt Defteri'nde `HKCU:\Software\Microsoft\Windows\CurrentVersion` yolu altında `debug` isimli bir anahtara Base64 formatında gizlemiştir.
* Görev tetiklendiğinde PowerShell bu değeri okumakta (`gp` = `Get-ItemProperty`), Base64'ten Unicode metne dönüştürmekte ve `IEX` (`Invoke-Expression`) ile diske dosya yazmadan doğrudan RAM üzerinde çalıştırmaktadır.

---

## 4. MITRE ATT&CK Mapping

| Taktik | Teknik ID | Teknik Adı | Gözlemlenen Eylem |
| --- | --- | --- | --- |
| **Initial Access** | `T1566.001` | Spearphishing Attachment | Sahte özgeçmiş temalı makro içeren Word belgesi. |
| **Execution** | `T1059.005` / `T1059.001` | Visual Basic / PowerShell | Makro tetiklemesi ve dosyasız PowerShell çalıştırma. |
| **Defense Evasion** | `T1027` / `T1036` | Obfuscated Files / Masquerading | `.png` uzantısı altında JS teslimatı, `IEX` Base64 çözümleme. |
| **Persistence** | `T1053.005` | Scheduled Task | Her gün 09:00'da çalışan `Updater` isimli görev. |
| **Persistence** | `T1112` | Modify Registry | Zararlı kodun `HKCU:\...\CurrentVersion\debug` içine gömülmesi. |
| **Command & Control** | `T1071.001` | Web Protocols (HTTP) | `128.199.95.189:8080` üzerinden kurulan C2 kanalı. |

---

## 5. Indicators of Compromise (IOCs)

Güvenlik duvarı (Firewall), SIEM ve EDR sistemlerinde derhal bloklanması gereken göstergeler:

### Network Indicators (Defanged)

* `https://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` (Stager Payload)
* `https://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe` (Malicious Binary)
* `128.199.95[.]189:8080` (C2 IP & Port)

### Host & File Artifacts

* `Resume_WesleyTaylor.doc` (MD5: `52c4384a0b9e248b95804352ebec6c5b`)
* `C:\ProgramData\update.js`
* `C:\Windows\Tasks\updater.exe`
* Scheduled Task: `Updater`
* Registry Key: `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug`

---

## 6. Remediation & Detection Engineering (İyileştirme & Tespit Önerileri)

### 6.1 Acil Müdahale Adımları (Immediate Containment)

1. **İzolasyon:** `WKSTN-2961` iş istasyonu ağdan izole edilmeli, bellek analizi tamamlandıktan sonra yeniden kurulmalıdır.
2. **Kalıcılık Temizliği:** Sistemde `Updater` zamanlanmış görevi silinmeli ve `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug` kayıt defteri anahtarı kaldırılmalıdır.
3. **C2 Engelleme:** `128.199.95[.]189` IP adresi ve `boogeymanisback[.]lol` domaini kurumsal güvenlik duvarında bloklanmalıdır.

### 6.2 Örnek Tespit Kuralı: Şüpheli Registry Değeri Okuyan PowerShell Görevleri (Sigma Kuralı)

```yaml
title: Suspicious PowerShell Reading Registry for IEX Execution
id: 5a4f7811-92b1-4c12-8862-316279f01833
status: experimental
description: Detects scheduled tasks or command-lines where PowerShell reads a registry property and invokes expression directly.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - 'FromBase64String'
      - 'IEX'
      - 'HKCU:\Software\Microsoft\Windows\CurrentVersion'
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.persistence
  - attack.t1059.001
  - attack.t1112
