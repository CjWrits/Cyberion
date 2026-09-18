# Cyberion Defense Labs — Indicators of Compromise (IOC) Research & Correlation

**Document Code:** `CDL-IOC-RES-V2`  
**Classification:** Threat Intelligence & Security Operations  
**Engagement:** Detection Engineering & Threat Hunting (CDL-DET-V2)  
**Author:** Threat Intelligence Office  
**Status:** Validated & Active  

---

## 1. Executive Intelligence Overview

This document catalogues all verified Indicators of Compromise (IOCs) identified across the **Mordor APT29 Day 1** adversary simulation and the **EVTX-ATTACK-SAMPLES** forensic repository. Every indicator documented herein has been empirically extracted from raw log records and correlated against published open-source threat intelligence (OSINT), vendor research publications, and MITRE ATT&CK evaluation frameworks.

### IOC Quality & Operationalization Policy
Cyberion Defense Labs adheres to the **Pyramid of Pain** framework. While atomic indicators (IP addresses, domains, file hashes) provide immediate tactical containment value, they have short half-lives. Therefore, each IOC documented below includes actionable instructions for operationalizing it into:
* **High-confidence watchlists** (SIEM dynamic lookup tables / threat intel feeds).
* **Behavioral detection rules** (Sigma rules targeting underlying techniques).
* **Forensic hunting pivots** (Incident response triage indicators).

---

## 2. Master IOC Catalog

| IOC Type | IOC Value / Indicator | Dataset Location & Channel | Related Host / Process / User Context | Threat Intelligence Context | Operationalization Method |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **IPv4 Address** | `192.168.0.4` | Mordor Zeek `conn.log`, `ssl.log`, Sysmon EID 3 | Destination for `powershell.exe` (PID 6120) on host `10.0.1.6` (`DMEVALS\pbeesly`) | Emulated external Command and Control (C2) server used by APT29 (Cozy Bear) in MITRE ATT&CK Evaluation Round 2. | Ingest into perimeter firewall blocklist; configure SIEM alert for any internal RFC1918 asset routing traffic to this external node. |
| **Domain (FQDN)** | `rempel.group.net` | Mordor Zeek `ssl.log` (`server_name`, `subject`) | Outbound TLS connection from host `10.0.1.6` to `192.168.0.4:8443` | Fictitious adversary infrastructure domain imitating a legitimate corporate entity. Used in X.509 certificate subject. | Ingest into DNS sinkhole and web proxy categorization blocklists (categorized as Malicious C2). |
| **Email / Cert CN** | `synthesize@rempel.group.net` | Mordor Zeek `ssl.log` (`subject`, `issuer`) | X.509 certificate metadata in TLS handshake to `192.168.0.4` | Self-signed adversary certificate contact email generated for ad-hoc HTTPS listener encryption. | Deploy Zeek / Suricata signature alerting on X.509 certificate subject containing `@rempel.group.net`. |
| **TLS Cert SHA1** | `d9105746ea023ecdc6a47e7b4d026d5308525b8c` | Mordor Zeek `ssl.log` (`resp_certificate_sha1`) | Server certificate presented during TLS handshake | Unique cryptographic thumbprint of the adversary's self-signed C2 TLS certificate. | Configure Network Security Monitor (Zeek / Suricata) to drop any TLS handshake returning this certificate SHA1. |
| **JA3 Fingerprint** | `e0fe397a5edfba9a6facc7c7b341f4eb` | Mordor Zeek `ssl.log` (`ja3`) | Client TLS handshake initiated by `powershell.exe` | Cryptographic profile of the TLS client stack utilized by the PowerShell C2 payload. | Add to SIEM JA3 watchlist; alert when this JA3 hash connects to non-Microsoft or non-standard external ports. |
| **JA3S Fingerprint**| `e35df3e00ca4ef31d42b34bebaa2f86e` | Mordor Zeek `ssl.log` (`ja3s`) | Server TLS response from `192.168.0.4` listener | Cryptographic profile of the adversary's OpenSSL / C2 server listener configuration. | Correlate with client JA3 to detect C2 pairing regardless of server IP reassignment. |
| **Port / Protocol** | `TCP 8443` / TLSv12 | Mordor Zeek `conn.log`, `ssl.log` | Listening port on `192.168.0.4` | Non-standard alternative HTTPS port used for adversary C2 to bypass default port 443 inspection. | Restrict outbound perimeter firewall egress policy; mandate proxy mediation for all TCP 8443 traffic. |
| **File / RLO Path** | `C:\ProgramData\victim\‮cod.3aka3.scr` | Mordor Sysmon EID 1 (Line 372), EID 11 | Spawned by `C:\Windows\Explorer.EXE` under user `pbeesly` | Initial execution payload disguised with Unicode Right-to-Left Override (`\u202e`) to appear as `.3aka3.doc`. | Deploy Sigma rule `057de226-ae47-4d2e-9fc3-47935bcfe860`; add regex scan to EDR sensor blocking filenames containing `\u202e`. |
| **File Path** | `C:\Users\pbeesly\Downloads\monkey.png` | Mordor Sysmon EID 1, PowerShell EID 4104 | Accessed by `powershell.exe` via `System.Drawing.Bitmap` | Steganographic carrier file holding encrypted shellcode embedded within image pixels. | Search enterprise endpoints for `monkey.png` in user profile directories; quarantine for forensic steganography extraction. |
| **Registry Key** | `HKCU:\Software\Classes\Folder\shell\open\command` | Mordor Sysmon EID 13, PowerShell EID 4104 | Created by PowerShell; triggered by `sdclt.exe` | Target of UAC bypass via Registry Shell Open Command hijack with `DelegateExecute` value. | Deploy Sigma rule `7cb39dc7-ae81-47a1-b36c-2581534b9a17` and correlation rule `fbf66860-6faf-4c5f-babb-5ed0417f6836`. |
| **Registry Value**| `DelegateExecute` | Mordor Sysmon EID 13 | Value under `Folder\shell\open\command` | Triggers elevated execution of default handler command without triggering UAC elevation prompt. | Baseline HKCU registry keys; alert immediately upon creation of any `DelegateExecute` value in user hive. |
| **AD Extended Right** | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | EVTX `CA_DCSync_4662.evtx` | Object: Active Directory Domain Head, Access: 4662 | `DS-Replication-Get-Changes-All` extended access right GUID required to dump password hashes via DCSync. | Deploy Sigma rule `6b9079cd-604b-420a-a248-8e636962235d`; alert whenever requested by non-domain-controller account. |
| **AD Extended Right** | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | EVTX `CA_DCSync_4662.evtx` | Object: Active Directory Domain Head, Access: 4662 | `DS-Replication-Get-Changes` extended access right GUID used during directory synchronization. | Correlate with `Get-Changes-All` to confirm directory replication privilege abuse. |
| **Registry Key** | `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` | EVTX `4794_DSRM_password_change_t1098.evtx` | Domain Controller Local Security Authority | Setting value to `2` allows DSRM administrator account to log on to DC remotely via network. | Monitor registry key on all Domain Controllers; alert on any modification deviating from value `0` (disabled). |

---

## 3. Threat Intelligence Context & Campaign Alignment

### The APT29 (Cozy Bear) MITRE ATT&CK Evaluation Context
The indicators observed in the Mordor APT29 dataset originate from the adversary emulation of the threat group tracked as **APT29** (also known as *Cozy Bear*, *The Dukes*, *Nobelium*). APT29 is an advanced cyber espionage group attributed to Russia's Foreign Intelligence Service (SVR). 

Key campaign behaviors reflected in the dataset:
1. **Stealthy Execution & Evasion:** The adversary avoids loud exploitation on endpoints, instead leveraging living-off-the-land techniques, Right-to-Left Override Unicode deception, steganography embedded in benign image media (`monkey.png`), and user-hive registry manipulation (`DelegateExecute`).
2. **Asymmetric C2 Infrastructure:** Communication is staged through custom HTTPS listeners utilizing self-signed certificates and non-standard high ports (TCP 8443). The C2 protocol mimics legitimate web traffic while maintaining encrypted encapsulation.
3. **Lateral Proliferation:** Once elevated, the adversary extracts credentials using LSASS handle operations and pivots through remote administrative shares (`ADMIN$`, `C$`) to move laterally to secondary workstations (`10.0.1.4`, `10.0.1.5`).

---

## 4. Operationalization in SIEM & EDR Systems

To operationalize these indicators immediately within Cyberion Defense Labs client environments, the following rules and automated watchlists are established:

### A. SIEM Dynamic Watchlist Definition
```
Watchlist Name: CDL_APT29_IOC_Watchlist
TTL: 90 Days
Contents:
  - 192.168.0.4 (IP)
  - rempel.group.net (Domain)
  - d9105746ea023ecdc6a47e7b4d026d5308525b8c (Cert SHA1)
  - e0fe397a5edfba9a6facc7c7b341f4eb (JA3)
Correlation Query:
  index=network OR index=sysmon
  [ search watchlist="CDL_APT29_IOC_Watchlist" | fields ip, domain, hash, ja3 ]
  | eval AlertName = "Threat Intel Match: APT29 Campaign Indicator Observed"
  | eval Severity = "Critical"
```

### B. EDR File & Registry Prevention Rules
* **YARA / EDR Rule:** Quarantine any file dropped in user directories containing Unicode character `\u202e`.
* **Registry Guard Rule:** Block non-SYSTEM write operations to `HKCU\Software\Classes\Folder\shell\open\command` across all Windows workstations.
