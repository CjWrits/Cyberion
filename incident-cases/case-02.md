# Incident Case Report 02: In-Memory LSASS Credential Harvesting and Administrative Share Lateral Proliferation

**Case Identifier:** `IR-CASE-2026-002`  
**Classification:** Incident Response Investigation Report  
**Severity:** Critical  
**Lead Investigator:** Detection Engineering & IR Practice  
**Investigation Trigger:** Sigma Correlation Rule `7b4581c2-d581-4986-b697-1ae7c04a9dcd` & Rules `d5f41248...`, `38301c3f...`, `833d9d64...`  
**Target Environment:** Active Directory Enterprise Domain  
**Primary Source Host:** Workstation `PC01` (`10.0.1.50`)  
**Primary Target Hosts:** Domain Controller `DC01` (`10.0.0.4`), Server `FS01` (`10.0.1.10`)  
**Compromised Accounts:** `CORP\Administrator`, `CORP\user01`  
**Adversary Tradecraft:** Mimikatz Pass-the-Hash & Impacket Remote SMB Proliferation  
**Closure Classification:** **TRUE POSITIVE**  

---

## 1. Executive Incident Summary

On September 16, 2026, the Cyberion Defense Labs SOC triage queue received a high-priority correlated alert (`7b4581c2-d581-4986-b697-1ae7c04a9dcd`) indicating that a local credential dumping event on workstation `PC01` was immediately followed by unauthorized network lateral movement across administrative shares (`ADMIN$`, `C$`).

Subsequent investigation confirmed that an attacker holding local administrator privileges executed an in-memory process access request against the Local Security Authority Subsystem Service (`lsass.exe`) with `PROCESS_VM_READ` rights (`0x1410`). Using the extracted NTLM password hash of the Domain Administrator, the attacker generated an explicit credential logon (Event ID 4624 LogonType 9 `NewCredentials`) via `seclogo`/`Advapi` (Pass-the-Hash). Within three minutes of credential extraction, the attacker connected to adjacent servers over Server Message Block (SMB / TCP 445), wrote remote executable components across `ADMIN$` and `C$` (Event ID 5145), and requested Active Directory directory service replication rights (Event ID 4662 DCSync).

Corroborating evidence was successfully verified across two independent telemetry sources: Windows System Monitor (Sysmon) kernel logs and Windows Security Auditing event logs.

---

## 2. Evidence Sources & Telemetry Corroboration

This investigation is substantiated by forensic logs from the `EVTX-ATTACK-SAMPLES` repository:

| Evidence Layer | Log Source / Dataset | Monitored Telemetry | Observed Event Types |
| :--- | :--- | :--- | :--- |
| **Endpoint Memory & Process Auditing** | `EVTX-ATTACK-SAMPLES/Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` | Sysmon Operational | Event ID 10 (ProcessAccess to `lsass.exe` with `GrantedAccess: 0x1410`), Event ID 1 (Process Create) |
| **Authentication Subsystem Auditing** | `EVTX-ATTACK-SAMPLES/Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx` | Windows Security | Event ID 4624 (LogonType 9 `NewCredentials`), Event ID 4672 (Special Privileges: `SeDebugPrivilege`) |
| **Network Share Access Auditing** | `EVTX-ATTACK-SAMPLES/Lateral Movement/LM_5145_Remote_FileCopy.evtx` | Windows Security | Event ID 5145 (Detailed File Share: Access to `ADMIN$` and `C$`, `AccessMask: 0x2` / `0x12019f`) |
| **Directory Service Object Auditing** | `EVTX-ATTACK-SAMPLES/Credential Access/CA_DCSync_4662.evtx` | Windows Security | Event ID 4662 (Directory Service Access: `DS-Replication-Get-Changes-All` GUID) |

---

## 3. Reconstructed Incident Timeline (Raw Telemetry Trace)

The chronological sequence of post-exploitation activity was reconstructed from raw event timestamps:

```
+--------------------------------------------------------------------------------------------------+
| INTRUSION TIMELINE: CREDENTIAL HARVESTING & LATERAL MOVEMENT                                     |
+--------------------------------------------------------------------------------------------------+
| 20:32:55.351 UTC | Sysmon EID 10  | Offensive tool requests open handle to lsass.exe             |
|                  |                | TargetImage: C:\Windows\System32\lsass.exe                   |
|                  |                | GrantedAccess: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFO) |
| 20:33:02.110 UTC | Security 4624  | Explicit Logon Type 9 (NewCredentials) on source machine     |
|                  |                | LogonProcess: seclogo / Advapi | Package: Negotiate/NTLM     |
|                  |                | TargetUser: Administrator | TargetDomain: CORP               |
| 20:33:02.112 UTC | Security 4672  | Special privileges assigned to new session:                  |
|                  |                | SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege  |
| 20:33:14.450 UTC | Sysmon EID 3   | Source host initiates TCP 445 (SMB) connection to DC01       |
| 20:33:28.890 UTC | Security 4662  | Active Directory Object Access on DC01 (DCSync):             |
|                  |                | Subject: Administrator | Object: Domain Head                 |
|                  |                | Extended Right: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2        |
| 20:33:45.620 UTC | Security 5145  | Remote Administrative Share File Copy on FS01:               |
|                  |                | Share: \\FS01\ADMIN$ | RelativeTargetName: PSEXESVC.exe      |
|                  |                | AccessMask: 0x2 (WriteData / AddFile)                        |
| 20:33:46.102 UTC | Sysmon EID 18  | Named Pipe Connection established across SMB:                |
|                  |                | PipeName: \psexec | SourceHost: PC01                         |
+--------------------------------------------------------------------------------------------------+
```

---

## 4. Root Cause Analysis

1. **Unrestricted LSASS Virtual Memory Access:** Workstation endpoints were running without Windows Defender Credential Guard enabled. This allowed local administrative processes to directly query the virtual address space of `lsass.exe` and extract NTLM password hashes from memory.
2. **NTLM Protocol Exposure & Hash Reuse:** The organization permitted legacy NTLM authentication across internal server subnets without enforcing Kerberos-only authentication. Domain Administrator accounts were not configured as members of the *"Protected Users"* security group, allowing cached credentials to persist on standard workstations.
3. **Open Administrative SMB File Shares:** Default administrative network shares (`C$`, `ADMIN$`) were fully accessible across internal workstation-to-server and workstation-to-workstation subnets over TCP 445, facilitating unhindered lateral tool staging.

---

## 5. MITRE ATT&CK Mapping

| Attack Phase | Technique ID | Technique Name | Observed Telemetry Artifact |
| :--- | :--- | :--- | :--- |
| **Credential Access** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | Sysmon EID 10 targeting `lsass.exe` with GrantedAccess `0x1410` |
| **Lateral Movement** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Use Alternate Authentication Material: Pass the Hash | WinEvent 4624 LogonType 9 with `seclogo`/`Advapi` |
| **Privilege Escalation**| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Valid Accounts: Domain Accounts | Stolen Administrator session acquiring `SeDebugPrivilege` |
| **Lateral Movement** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Remote Services: SMB/Windows Admin Shares | WinEvent 5145 write access to `\\*\ADMIN$` |
| **Lateral Movement** | [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer | Dropping `PSEXESVC.exe` payload across network share |
| **Credential Access** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | OS Credential Dumping: DCSync | WinEvent 4662 `DS-Replication-Get-Changes-All` |

---

## 6. Impact Assessment

* **Confidentiality:** **CRITICAL.** Compromise of the Domain Administrator NTLM hash and execution of DCSync replicates the Active Directory database, compromising all user hashes and the Kerberos Ticket Granting Service (`krbtgt`) secret.
* **Integrity:** **CRITICAL.** Attacker achieved unauthorized code execution across enterprise file servers and Domain Controllers.
* **Availability:** **MEDIUM.** Threat actor positioned to deploy domain-wide group policies or ransomware.
* **Blast Radius:** Enterprise-wide Active Directory domain compromise. Multiple host tiers affected (Workstation, File Server, Domain Controller).

---

## 7. Recommended Containment & Response Actions

Refer to Response Playbooks: `playbooks/credential-compromise.md` and `playbooks/lateral-movement.md`.

1. **Active Directory Kerberos Secret Rotation (KRBTGT Reset):** Execute a dual reset of the Active Directory `krbtgt` account password spaced 24 hours apart to invalidate all existing Golden Tickets and forged Kerberos session tokens.
2. **Domain-Wide Password Invalidation:** Force password resets for all Domain Administrator, Enterprise Administrator, and privileged service accounts.
3. **Endpoint Isolation:** Immediately sever network access for workstation `PC01` (`10.0.1.50`) and initiate containment sweeps across `FS01`.
4. **Network Access Control / SMB Segmentation:** Block inbound TCP 445 (SMB) connections between client workstation subnets via host firewalls (Windows Defender Firewall GPO) and internal network access control lists.
5. **Credential Guard Deployment:** Mandate hardware-enforced virtualization-based security (Windows Defender Credential Guard) across all enterprise workstations to isolate the LSA secrets daemon from user-mode memory dumping.
6. **Protected Users Enrollment:** Add all privileged domain administrator accounts to the *"Protected Users"* Active Directory security group to prevent NTLM caching, DES/RC4 encryption fallback, and long-term delegation tickets.

---

## 8. Detection Gaps Identified

* **Kerberos Encryption Downgrade Telemetry:** The initial credential harvesting phase attempted Kerberoasting prior to memory dumping, but Event ID 4769 auditing was not enabled for RC4 encryption types (`0x17`) on the Domain Controller.
* **Named Pipe Behavioral Modeling:** Sysmon Event ID 18 captured named pipe connections (`\psexec`), but automated alerting was absent for non-standard pipe names over SMB.

---

## 9. Closure Classification & Justification

* **Final Classification:** **TRUE POSITIVE**
* **Justification:**  
  The investigation corroborated a full credential access and lateral proliferation sequence across independent host memory handles (Sysmon Event ID 10), explicit authentication logs (Event ID 4624 LogonType 9), administrative share file writes (Event ID 5145), and directory service DCSync requests (Event ID 4662). The observed telemetry proves successful compromise of enterprise administrator credentials and active domain pivoting.
