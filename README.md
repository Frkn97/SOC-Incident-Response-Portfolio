# 🛡️ SOC Incident Response & DFIR Portfolio

Welcome to my **Security Operations Center (SOC) & Digital Forensics and Incident Response (DFIR)** portfolio. 

This repository documents end-to-end, technical investigation reports of enterprise-level cyber incident simulations. Each case study covers the complete cyber kill chain: from initial compromise and privilege escalation to lateral movement, detection engineering, and remediation.

---

## 🔬 Core Competencies & Toolset

- **Log Analysis & SIEM:** Splunk (SPL), Elastic / Kibana (KQL), Windows Event Logs, Sysmon (EID 1, 3, 7, 8, 11, 22).
- **Network Traffic & C2 Analysis:** Wireshark, Tshark, NetworkMiner (PCAP inspection, protocol anomaly analysis, DNS tunneling).
- **Endpoint & Memory Forensics:** Volatility 3 Framework (Process injection, hidden DLLs, network artifacts), Eric Zimmerman Tools (EvtxECmd, Timeline Explorer), Olevba (VBA Macro extraction).
- **Threat Detection & TTPs:** MITRE ATT&CK mapping, LOLBIN exploitation (`mshta`, `rundll32`, `xcopy`), UAC Bypass techniques (`fodhelper`), WinRM-based lateral movement, and Active Directory credential dumping (DCSync).

---

## 📁 Incident Case Studies

| Case ID | Incident Title | Primary TTPs & Vectors | Key Tools Utilized | Report Link |
| :--- | :--- | :--- | :--- | :--- |
| **CASE-01** | **The Boogeyman I:** Phishing & DNS Exfiltration | Malicious `.lnk`, Obfuscated PowerShell, Sticky Notes DB Compromise, DNS Tunneling (`nslookup`) | `jq`, `Wireshark`, `Tshark`, `LNKParse3`, `KeePass` | [View Case Study](./Case-01-Boogeyman-1/) |
| **CASE-02** | **The Boogeyman II:** Memory Forensics & Fileless Persistence | Spear Phishing, Malicious VBA Macro, Process Injection, Registry-based Scheduled Task | `Volatility 3`, `Olevba`, `strings`, `NetScan` | [View Case Study](./Case-02-Boogeyman-2/) |
| **CASE-03** | **The Boogeyman III:** Enterprise Domain Compromise & Ransomware | ISO/HTA Delivery, UAC Bypass (`fodhelper`), WinRM Lateral Movement, DCSync, Ransomware Deployment | `Elasticsearch (KQL)`, `Sysmon`, `Mimikatz`, `WinRM` | [View Case Study](./Case-03-Boogeyman-3/) |
| **CASE-04** | **Operation Tempest:** Web Exploit to Domain Admin | Public Vulnerability Exploitation, Follina (CVE-2022-30190), SOCKS Tunneling (`chisel`), Named Pipe Impersonation (`PrintSpoofer`) | `Splunk`, `PowerShell`, `Chisel`, `Sysmon` | [View Case Study](./Case-04-Tempest/) |

---

## 🎯 Investigation Methodology

Every case in this portfolio adheres to standard incident response frameworks (**NIST SP 800-61 Rev. 2** / **SANS PICERL**):

1. **Identification & Initial Triage:** Scoping artifacts (Email headers, network captures, memory images, event logs).
2. **Containment & Scoping:** Mapping out compromised endpoints, persistent backdoors, and lateral hops.
3. **Root Cause Analysis (RCA):** Uncovering attacker tradecraft and extracting Indicators of Compromise (IOCs).
4. **Remediation & Detection Engineering:** Formulating actionable Sigma rules, EDR prevention policies, and hardening recommendations.

---

## 📬 Contact & Profiles

- **LinkedIn:** [www.linkedin.com/in/afhusmek](https://www.linkedin.com/)
- **TryHackMe:** [tryhackme.com/p/Frkn04](https://tryhackme.com/p/Frkn04) (SOC Level 1 - Certified)
