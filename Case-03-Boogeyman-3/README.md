# 🔍 Incident Investigation Report: Enterprise Compromise, DCSync & Ransomware Deployment

**Case Reference:** IR-2023-0829-BG3  
**Target Organization:** Quick Logistics LLC  
**Incident Classification:** Critical (Severity 1 - P1)  
**Affected Hostnames:** `WKSTN-0051.quicklogistics.org` (CEO Workstation), `WKSTN-1327` (IT Admin Workstation), `DC01.quicklogistics.org` (Domain Controller)  
**Date of Incident:** August 29, 2023 – August 30, 2023  
**Lead Investigator:** Ahmet Furkan Hüsmek (Junior SOC / DFIR Analyst)  

---

## 1. Executive Summary (Yönetici Özeti)

29-30 Ağustos 2023 tarihleri arasında Quick Logistics LLC altyapısına yönelik çok aşamalı, gelişmiş bir siber saldırı tespit edilmiştir. Tehdit aktörü, daha önce ele geçirilmiş bir iç çalışan hesabından CEO *Evan Hutchinson*'a oltalama e-postası ileterek ilk erişimi sağlamıştır. 

Saldırgan; sanal disk imajı (`.iso`) içerisine gizlenmiş HTA yükü ile uç nokta savunma mekanizmalarını (Mark of the Web - MoTW) atlatmış, yerleşik Windows ikililerini (LOLBINs: `mshta.exe`, `rundll32.exe`) kullanarak zararlı DLL yürütmüştür. Yerel yönetici haklarına sahip olan aktör, `fodhelper.exe` aracılığıyla UAC korumasını atlatmış, `Mimikatz` kullanarak bellekten kimlik bilgisi çalmış ve açıkta bulunan ağ paylaşımları üzerinden keşif yapmıştır. Elde edilen yetkili hesapla WinRM (`wsmprovhost.exe`) üzerinden yanal hareket (Lateral Movement) gerçekleştirilerek Domain Controller (`DC01`) hedef alınmış, **DCSync** atağı ile etki alanı düzeyinde tam yetki sağlanmış ve fidye yazılımı (`ransomboogey.exe`) indirilerek dağıtım aşamasına geçilmiştir.

Analiz ekibimiz saldırı zincirini uçtan uca aydınlatmış, tüm kalıcılık mekanizmalarını ve IOC'leri temizlemiş, domain düzeyinde parola sıfırlama ve sıkılaştırma önerilerini devreye almıştır.

---

## 2. Incident Timeline (Zaman Çizelgesi)

| Tarih / Saat (UTC) | Etkilenen Sistem | Gerçekleşen Eylem / TTP | Tespit Edilen Komut / Süreç |
| :--- | :--- | :--- | :--- |
| **2023-08-29 14:15** | `WKSTN-0051` | Kurban tarafından ISO eklentisi bağlandı ve HTA tetiklendi. | `mshta.exe` (PID: 6392) |
| **2023-08-29 14:17** | `WKSTN-0051` | Zararlı kütüphane gizli yoldan geçici dizine kopyalandı. | `xcopy.exe /s /i /e /h D:\review.dat %TEMP%\review.dat` |
| **2023-08-29 14:18** | `WKSTN-0051` | DLL kaydı süsü verilerek payload çalıştırıldı. | `rundll32.exe D:\review.dat,DllRegisterServer` |
| **2023-08-29 14:20** | `WKSTN-0051` | Kalıcılık (Persistence) amacıyla zamanlanmış görev eklendi. | Task Name: `Review` (PowerShell script trigger) |
| **2023-08-29 14:22** | `WKSTN-0051` | C2 komuta kontrol sunucusu ile oturum kuruldu. | PowerShell ──► `165.232.170.151:80` |
| **2023-08-29 15:05** | `WKSTN-0051` | UAC Bypass yapılarak yüksek yetkili oturum elde edildi. | `fodhelper.exe` (Registry hijacking) |
| **2023-08-29 15:12** | `WKSTN-0051` | GitHub üzerinden Mimikatz indirildi ve LSASS dump edildi. | `itadmin:F84769D250EB95EB2D7D8B4A1C5613F2` |
| **2023-08-29 16:30** | `WKSTN-0051` | Kurumsal paylaşım taramasıyla açık metin parola bulundu. | `IT_Automation.ps1` (`allan.smith:Tr!ckyP@ssw0rd987`) |
| **2023-08-29 17:10** | `WKSTN-1327` | WinRM protokolü üzerinden hedef iş istasyonuna yanal sıçrama. | Parent: `wsmprovhost.exe` |
| **2023-08-29 17:45** | `WKSTN-1327` | İkinci makinede yerel yönetici hash'i dump edildi. | `administrator:00f80f2538dcb54e7adc715c0e7091ec` |
| **2023-08-30 08:30** | `DC01` | Active Directory senkronizasyon protokolü istismarı (DCSync). | `backupda` hesabı ve Domain Admin hash'leri çalındı. |
| **2023-08-30 09:15** | `DC01` | Kurum geneline dağıtılacak Ransomware ikilisi indirildi. | `http://ff.sillytechninja.io/ransomboogey.exe` |

---

## 3. Detailed Technical Analysis (Derinlemesine Teknik Analiz)

### 3.1 Initial Access & Defense Evasion (İlk Erişim & Savunma Atlatma)
* **Vektör:** E-posta ekindeki `ProjectFinancialSummary_Q3.pdf.iso` dosyası.
* **Mekanizma:** Windows 10/11'in yerel ISO bağlama kabiliyeti suistimal edilmiştir. İnternetten indirilen dosyalara atanan `Zone.Identifier` (Mark of the Web - MoTW) bayrağı ISO içindeki alt dosyalara geçmediği için SmartScreen uyarıları baypas edilmiştir.
* **Yürütme:** HTML Application (`.hta`) dosyası Windows'un meşru ikilisi `mshta.exe` (PID: 6392) ile çalıştırılmıştır.

### 3.2 Stage 1 Execution & Persistence (Yürütme & Kalıcılık)
* `mshta.exe`, `xcopy.exe` aracını tetikleyerek `review.dat` dosyasını `C:\Users\EVAN~1.HUT\AppData\Local\Temp\` dizinine gizlice taşımıştır.
* Gizlenen `.dat` dosyası aslında bir PE/DLL kütüphanesidir ve `rundll32.exe D:\review.dat,DllRegisterServer` komutuyla yürütülmüştür.
* Sistem yeniden başlatıldığında bile erişimi korumak amacıyla `Review` isimli günlük bir **Scheduled Task (Zamanlanmış Görev)** oluşturulmuştur.
* `powershell.exe` süreci, dış ağda yer alan `165.232.170.151:80` C2 soketine geri bağlantı (reverse shell) açmıştır (Sysmon EID 3).

### 3.3 Privilege Escalation & Credential Harvesting (Yetki Yükseltme & Kimlik Hırsızlığı)
* Kurban hesabın yerel yönetici grubunda olduğu belirlendikten sonra UAC engelini aşmak için Windows Ayarlar arayüzü ikilisi `fodhelper.exe` kullanılmıştır. `HKCU:\Software\Classes\ms-settings\Shell\Open\command` kaydı manipüle edilerek yüksek yetkili oturum açılmıştır.
* GitHub'dan resmi Mimikatz paketi indirilmiş (`mimikatz_trunk.zip`) ve yerel `LSASS` sürecinden `itadmin` kullanıcısına ait NTLM hash'i (`F84769D250EB95EB2D7D8B4A1C5613F2`) ele geçirilmiştir.

### 3.4 Reconnaissance & Lateral Movement (Keşif & Yanal Hareket)
* Saldırgan kurumsal ağ paylaşımlarında `ShareFinder` taraması gerçekleştirmiş ve `IT_Automation.ps1` dosyasında açık unutulmuş servis hesabı parolasını (`QUICKLOGISTICS\allan.smith : Tr!ckyP@ssw0rd987`) ele geçirmiştir.
* Bu kimlik bilgileriyle `WKSTN-1327` makinesine **WinRM (Windows Remote Management - TCP 5985)** üzerinden bağlanılmıştır. Olay günlüğü incelemesinde komutların ebeveyn sürecinin **`wsmprovhost.exe`** olduğu doğrulanmıştır (Sysmon EID 1).

### 3.5 Domain Dominance & Impact (Domain Ele Geçirme & Etki)
* `WKSTN-1327` üzerinden yerel yönetici hash'i (`administrator:00f80f2538dcb54e7adc715c0e7091ec`) elde edilerek Etki Alanı Denetleyicisi (`DC01`) hedeflenmiştir.
* Saldırgan `lsadump::dcsync` metodunu kullanarak `backupda` ve etki alanı yöneticisi hesaplarının kimlik bilgilerini uzaktan çekmiştir.
* Nihai aşamada sistemleri şifrelemek amacıyla `http://ff.sillytechninja.io/ransomboogey.exe` adresinden fidye yazılımı indirilmiştir.

---

## 4. MITRE ATT&CK Mapping

| Taktik | Teknik ID | Teknik Adı | Gözlemlenen Eylem |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1566.001` | Spearphishing Attachment | Sahte finansal rapor temalı ISO eklentisi. |
| **Execution** | `T1218.005` / `T1218.011` | Mshta / Rundll32 | `mshta.exe` ve `rundll32.exe` LOLBIN istismarı. |
| **Persistence** | `T1053.005` | Scheduled Task | Günlük tetiklenen `Review` adlı zamanlanmış görev. |
| **Privilege Escalation**| `T1548.002` | Bypass User Account Control | `fodhelper.exe` kayıt defteri manipülasyonu. |
| **Defense Evasion** | `T1553.005` | Mark-of-the-Web Bypass | ISO konteyneri içinde HTA teslimatı. |
| **Credential Access** | `T1003.001` / `T1003.006` | LSASS Memory / DCSync | Mimikatz ile bellekten hash çekme ve uzaktan DCSync. |
| **Lateral Movement** | `T1021.006` | Windows Remote Management | `wsmprovhost.exe` ile uzak PowerShell oturumu açılması. |
| **Command & Control** | `T1071.001` | Web Protocols (HTTP) | `165.232.170.151:80` üzerinden C2 beaconing. |
| **Impact** | `T1486` | Data Encrypted for Impact | `ransomboogey.exe` indirme girişimi. |

---

## 5. Indicators of Compromise (IOCs)

Güvenlik duvarı (Firewall), SIEM ve EDR sistemlerinde derhal bloklanması gereken göstergeler:

### Network Indicators (Defanged)
* `165.232.170[.]151:80` (C2 Server IP)
* `http://ff.sillytechninja[.]io/ransomboogey.exe` (Ransomware Download URL)
* `https://github[.]com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`

### Host & File Artifacts
* `review.dat` (Path: `C:\Users\<User>\AppData\Local\Temp\review.dat`)
* `ransomboogey.exe` (Malicious Ransomware Binary)
* `IT_Automation.ps1` (Compromised script with hardcoded credentials)
* Scheduled Task Name: `Review`

### Compromised Credentials
* `itadmin` : `F84769D250EB95EB2D7D8B4A1C5613F2` (NTLM)
* `administrator` : `00f80f2538dcb54e7adc715c0e7091ec` (NTLM)
* `QUICKLOGISTICS\allan.smith` : `Tr!ckyP@ssw0rd987` (Plaintext)
* `backupda` (Compromised via DCSync)

---

## 6. Remediation & Detection Engineering (İyileştirme & Tespit Önerileri)

### 6.1 Acil Müdahale Adımları (Immediate Containment)
1. **İzolasyon:** `WKSTN-0051` ve `WKSTN-1327` iş istasyonları ağ seviyesinde karantinaya alınmalı, adli bellek imajları alındıktan sonra yeniden kurulmalıdır.
2. **Kimlik Sıfırlaması:** Etki alanı genelinde `krbtgt` hesabı (2 kez aralıklı olarak), `administrator`, `itadmin`, `allan.smith` ve `backupda` hesaplarının parolaları derhal sızma testleri ve güvenlik prosedürlerine uygun olarak sıfırlanmalıdır.
3. **Kalıcılık Temizliği:** Tüm istemcilerde `Review` zamanlanmış görevi ve ilgili Kayıt Defteri (`HKCU:\Software\Classes\ms-settings`) anahtarları merkezi olarak taranıp silinmelidir.

### 6.2 Örnek Tespit Kuralı: Sysmon Üzerinden Fodhelper UAC Bypass Yakalama (Sigma Kuralı)

```yaml
title: UAC Bypass via Fodhelper Registry Hijacking
id: e4b23dfb-4687-4b13-9118-a62174ef8799
status: production
description: Detects registry modifications to ms-settings protocol handler commonly used by fodhelper.exe to bypass UAC.
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - 'Software\Classes\ms-settings\Shell\Open\command'
  condition: selection
falsepositives:
  - Rare legitimate Windows settings interactions.
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.002
