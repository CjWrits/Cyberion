# Incident Case Report 01: Multi-Stage Endpoint Compromise, UAC Bypass, and Encrypted C2 Beaconing

**Case Identifier:** `IR-CASE-2026-001`  
**Classification:** Incident Response Investigation Report  
**Severity:** Critical  
**Lead Investigator:** Detection Engineering & IR Practice  
**Investigation Trigger:** Threat Hunt `TH-2026-001` & Sigma Rule `057de226-ae47-4d2e-9fc3-47935bcfe860`  
**Target Environment:** Simulated Enterprise Domain (`DMEVALS.LOCAL`)  
**Primary Compromised Host:** `10.0.1.6` (`NASHUA.dmevals.local`)  
**Primary Compromised Account:** `DMEVALS\pbeesly`  
**Adversary Attribution:** APT29 (Cozy Bear) Tradecraft Emulation  
**Closure Classification:** **TRUE POSITIVE**  

---

## 1. Executive Incident Summary

On September 16, 2026, security analysts investigating alerts from the newly deployed Cyberion Defense Labs detection library identified an end-to-end multi-stage intrusion on workstation `10.0.1.6` (`NASHUA`). Initial execution was initiated when user `pbeesly` launched a disguised screensaver binary (`cod.3aka3.scr`) leveraging Unicode Right-to-Left Override (RLO) control characters to disguise the executable extension.

Following execution, the payload established a local shell, executed a fileless User Account Control (UAC) bypass by hijacking `HKCU:\Software\Classes\Folder\shell\open\command` via `sdclt.exe`, and spawned an elevated, hidden PowerShell process. The elevated shell extracted secondary shellcode from a steganographic image file (`monkey.png`), compiled bypass wrappers using `csc.exe`, and established persistent, encrypted command-and-control (C2) communication across port 8443 to external infrastructure (`192.168.0.4`) using an ad-hoc, self-signed TLS certificate.

Corroborating evidence was successfully verified across three independent telemetry sources: Windows Sysmon, Windows Security Auditing, and Zeek Network Security Monitoring.

---

## 2. Evidence Sources & Telemetry Corroboration

This investigation relies on direct log evidence extracted from the Mordor APT29 Day 1 dataset:

| Evidence Layer | Log Source / Dataset | Monitored Telemetry | Observed Event Types |
| :--- | :--- | :--- | :--- |
| **Endpoint Kernel Telemetry** | `mordor_apt29/apt29_evals_day1_manual.zip` | Sysmon Operational | Event ID 1 (Process Creation), Event ID 3 (Network Connection), Event ID 13 (Registry Set) |
| **Operating System Auditing** | `mordor_apt29/apt29_evals_day1_manual.zip` | Windows Security | Event ID 4688 (Process Creation with Elevated Token), Event ID 4624 (Logon Session) |
| **Script Execution Telemetry** | `mordor_apt29/apt29_evals_day1_manual.zip` | PowerShell Operational | Event ID 4104 (Script Block Logging) |
| **Network Wire Telemetry** | `mordor_apt29/zeek/ssl.log` & `conn.log` | Zeek Network Engine | SSL/TLS Handshake parameters, Certificate Subject/Issuer, Transport state |

---

## 3. Reconstructed Incident Timeline (Raw Telemetry Trace)

All events have been chronologically reconstructed from raw timestamps recorded during the intrusion:

```
+--------------------------------------------------------------------------------------------------+
| INTRUSION TIMELINE: HOST 10.0.1.6 (NASHUA)                                                       |
+--------------------------------------------------------------------------------------------------+
| 02:55:56.157 UTC | Sysmon EID 1   | Explorer.exe spawns "C:\ProgramData\victim\cod.3aka3.scr" /S |
| 02:56:04.510 UTC | Sysmon EID 1   | Malicious .scr spawns "C:\windows\system32\cmd.exe"          |
| 02:56:14.894 UTC | Sysmon EID 1   | cmd.exe launches interactive powershell.exe                  |
| 02:58:42.401 UTC | Sysmon EID 13  | PowerShell writes DelegateExecute to Folder\shell\open...    |
| 02:58:42.855 UTC | Sysmon EID 1   | cmd.exe invokes C:\windows\system32\sdclt.exe (UAC Bypass)   |
| 02:58:43.212 UTC | Sysmon EID 1   | sdclt.exe invokes control.exe /name BackupAndRestoreCenter   |
| 02:58:44.325 UTC | Sysmon EID 1   | control.exe launches High-Integrity powershell.exe -hidden   |
| 02:58:45.297 UTC | Sysmon EID 1   | Elevated PowerShell invokes csc.exe to compile payload       |
| 02:58:46.100 UTC | PS EID 4104    | PowerShell extracts stego byte array from monkey.png         |
| 03:20:44.736 UTC | Zeek ssl.log   | First outbound TLS session to 192.168.0.4:8443 (Rempel Group)|
| 03:21:30.387 UTC | Sysmon EID 3   | Host powershell.exe connects socket to 192.168.0.4:8443      |
| 03:24:44.752 UTC | Zeek ssl.log   | 376th TLS C2 session completed; active beaconing sustained   |
+--------------------------------------------------------------------------------------------------+
```

---

## 4. Root Cause Analysis

The root cause of this incident consists of three compounding vulnerabilities:
1. **Human Factor & Visual Deception:** The user `pbeesly` executed an untrusted file placed in `C:\ProgramData\victim\`. The attacker exploited Windows shell font rendering using the Unicode Right-to-Left Override character (`U+202E`), causing the executable `cod.3aka3.scr` to appear visually as a benign document (`cod.rcs.3aka3.doc`).
2. **Flawed Elevation Logic in Operating System (UAC Bypass):** The Windows binary `sdclt.exe` (Backup and Restore) is configured to auto-elevate (`high` integrity) while reading shell open registry handlers from the user-writable registry hive (`HKCU`). This architectural flaw allows an unprivileged local attacker to achieve High integrity without displaying a User Account Control prompt.
3. **Unrestricted Egress Filtering:** The enterprise perimeter firewall allowed direct outbound TCP connections from internal client subnets to external non-standard ports (TCP 8443) without mandatory TLS decryption or web proxy authentication.

---

## 5. MITRE ATT&CK Mapping

| Attack Phase | Technique ID | Technique Name | Observed Telemetry Artifact |
| :--- | :--- | :--- | :--- |
| **Initial Execution** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | `Explorer.EXE` launching `.scr` binary |
| **Defense Evasion** | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Masquerading: Right-to-Left Override | Filename contains Unicode `\u202e` |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | `powershell.exe -noni -noexit -ep bypass` |
| **Privilege Escalation**| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Registry hijack of `Folder\shell\open\command` via `sdclt.exe` |
| **Defense Evasion** | [T1027.003](https://attack.mitre.org/techniques/T1027/003/) | Steganography | `System.Drawing.Bitmap('...monkey.png')` pixel extraction |
| **Defense Evasion** | [T1027.004](https://attack.mitre.org/techniques/T1027/004/) | Compile After Delivery | `csc.exe /noconfig /fullpaths` child of PowerShell |
| **Command and Control**| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols: HTTPS | 376 outbound TLS sessions to `192.168.0.4:8443` |
| **Command and Control**| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Encrypted Channel: Asymmetric Cryptography | Self-signed certificate for `CN=rempel.group.net` |

---

## 6. Impact Assessment

* **Confidentiality:** **HIGH.** Workstation memory, local files, and user credentials accessible under High integrity. Active C2 channel established for data exfiltration.
* **Integrity:** **HIGH.** Operating system registry altered; unauthorized code compiled and executed in-memory.
* **Availability:** **LOW.** No destructive wiping or ransomware encryption observed.
* **Blast Radius:** Contained to single endpoint `10.0.1.6` during Day 1 window; however, elevated privileges position the adversary for immediate Active Directory lateral movement across domain subnets.

---

## 7. Recommended Containment & Response Actions

Refer to Response Playbooks: `playbooks/c2-beaconing.md` and `playbooks/credential-compromise.md`.

1. **Immediate Host Isolation:** Issue network isolation command via EDR to disconnect host `10.0.1.6` from the corporate network, retaining only EDR management connectivity.
2. **Process Termination:** Terminate elevated process trees rooted at `sdclt.exe` (PID 3060), `control.exe`, and `powershell.exe` (PID 6120).
3. **Perimeter Firewall Blocking:** Add IP `192.168.0.4` and domain `rempel.group.net` to perimeter edge firewalls and DNS sinkholes.
4. **Registry Remediation:** Delete the malicious registry tree under `HKCU:\Software\Classes\Folder\shell\open\command`.
5. **Credential Invalidation:** Force an immediate Kerberos ticket purge and Active Directory password reset for user `pbeesly`.
6. **Forensic Imaging:** Collect physical memory dump and triage image (KAPE / CyLR) from `10.0.1.6` for offline timeline analysis.

---

## 8. Detection Gaps Identified

* **Email Attachment Inspection Gap:** The initial arrival of `cod.3aka3.scr` was not detected at the network perimeter because endpoint email client download telemetry was absent.
* **Steganography Analysis Gap:** Antivirus static scanning failed to flag `monkey.png` because the malicious byte sequence was distributed across RGB pixel values rather than executable file headers.

---

## 9. Closure Classification & Justification

* **Final Classification:** **TRUE POSITIVE**
* **Justification:**  
  The investigation verified an authentic, multi-stage adversary execution chain confirmed across three independent telemetry tiers (Sysmon, Windows Security Auditing, and Zeek). The adversary actively achieved elevated code execution via a confirmed UAC bypass and maintained active, bidirectional encrypted C2 communication with external infrastructure (`192.168.0.4:8443`). No benign business activity accounts for these events.
