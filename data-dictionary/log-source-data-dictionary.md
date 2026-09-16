# Cyberion Defense Labs — Telemetry Source Data Dictionary

**Document Code:** `CDL-TEL-DICT-V2`  
**Classification:** Internal Security Operations & Engineering  
**Engagement:** Detection Engineering & Threat Hunting Engagement (CDL-DET-V2)  
**Author:** Detection Engineering & Threat Intelligence Practice  
**Status:** Approved / Production  

---

## 1. Executive Telemetry Overview

This data dictionary formalizes the schema, semantics, detection utility, and attacker mapping for all telemetry sources ingested during the **Cyberion Defense Labs** detection engineering and threat hunting engagement. Telemetry has been sourced exclusively from real-world adversary emulation datasets and documented attack event logs:

1. **Microsoft Windows System Monitor (Sysmon)** — Deep host-level kernel and user-space instrumentation capturing process execution lineages, inter-process memory handles, network sockets, file system writes, and registry modifications.
2. **Microsoft Windows Security Auditing (WinEventLog:Security)** — Authoritative operating system security audit events tracking security principals, logon session types, credential authentication protocols, Active Directory directory service object operations, privilege delegations, and security event log state changes.
3. **Zeek Network Security Monitoring (Zeek / Bro)** — Passive wire-speed network protocol analysis generating structured transaction logs for transport connections (`conn.log`), domain name resolutions (`dns.log`), transport layer security sessions (`ssl.log`), DCE/RPC interfaces (`dce_rpc.log`), Kerberos exchanges (`kerberos.log`), and SMB file operations (`smb_files.log`).

### Telemetry Baseline & Dataset Provenance

| Telemetry Source Type | Provider / Channel | Origin Dataset | Dataset Source & Identifier | Time Range (UTC) |
| :--- | :--- | :--- | :--- | :--- |
| **Windows Sysmon Telemetry** | `Microsoft-Windows-Sysmon/Operational` | Mordor Project: APT29 Day 1 Manual Emulation | [OTRF Security-Datasets / Mordor](https://github.com/OTRF/Security-Datasets) (`apt29_evals_day1_manual.zip`) | 2020-05-02 02:55:00 to 2020-05-02 04:30:00 |
| **Windows Security Auditing** | `Microsoft-Windows-Security-Auditing` / `Security` | EVTX-ATTACK-SAMPLES & Mordor APT29 | [EVTX-ATTACK-SAMPLES (SBousseaden)](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | 2019-02-16 to 2021-04-20 (technique-specific) |
| **Zeek Network Telemetry** | Zeek Network Engine (JSON Streams) | Mordor Project: APT29 Day 1 Zeek Network Artifacts | [OTRF Mordor APT29 Day 1 Zeek](https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/zeek/) (`NASHUA-zeek_logs.zip`, `combined_zeek.log`) | 2020-05-02 02:46:39 to 2020-05-02 04:26:40 |

---

## 2. Telemetry Source Type 1: Windows System Monitor (Sysmon)

Sysmon is an operating system service and kernel driver that remains resident across system reboots to monitor and log system activity to the Windows event log. It provides granular visibility into process creation chains, inter-process memory access, raw disk access, network connections initiated by host binaries, driver loads, and registry modifications.

### Key Monitored Event IDs

* **Event ID 1:** Process creation (process lineage, full command line, hashes, parent details).
* **Event ID 3:** Network connection detected (process-to-socket mapping, remote IP, destination port).
* **Event ID 7:** Image loaded (DLL modules, signatures, hashes).
* **Event ID 8:** CreateRemoteThread detected (cross-process thread injection).
* **Event ID 10:** ProcessAccess (process handle creation, desired access mask, target process).
* **Event ID 11:** FileCreate (file system writes, creation time, target path).
* **Event ID 12 / 13 / 14:** RegistryEvent (Object create/delete, Value Set, Key/Value rename).
* **Event ID 22:** DNSEvent (DNS query name, query status, results).

### Sysmon Field Dictionary

| Field Name | Type | Event IDs | Meaning & Semantic Definition | Detection Utility | Associated Attacker Behaviors (MITRE ATT&CK) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ProcessGuid` | GUID string | All | Unique operating system identifier assigned to a specific process instance by Sysmon to prevent PID reuse collisions. | Correlates multiple independent actions (network connects, registry writes, image loads) taken by a single process across its lifetime. | Campaign attribution, multi-stage attacks (T1059, T1071) |
| `ProcessId` | Integer | All | Operating system Process ID (PID) at runtime. | Immediate triage and memory analysis on a running host. | Execution analysis |
| `Image` | String | 1, 3, 7, 8, 10, 11 | Fully qualified filesystem path to the executable image executing the action. | Identifies suspicious execution directories (e.g., `C:\Users\Public`, `C:\ProgramData`, `AppData\Local\Temp`), renamed system binaries, and unauthorized binaries. | Masquerading (T1036), Execution (T1059), Defense Evasion (T1218) |
| `CommandLine` | String | 1 | Complete argument string passed to the process at launch, including flags, parameters, encoded scripts, and target paths. | Unveils obfuscated PowerShell, LOLBAS abuse (`rundll32.exe`, `certutil.exe`, `mshta.exe`), hidden windows, execution bypass switches (`-ep bypass`, `-window hidden`), and masqueraded characters. | Command and Scripting Interpreter (T1059), Obfuscated Files (T1027), Defense Evasion (T1564) |
| `ParentImage` | String | 1 | Full filesystem path of the parent process that spawned this process. | Establishes abnormal process parent-child relationships (e.g., `word.exe` spawning `cmd.exe` or `w3wp.exe` spawning `powershell.exe`). | Phishing (T1566), Web Shell Execution (T1505.003), Exploitation for Client Execution (T1203) |
| `ParentCommandLine` | String | 1 | Complete argument string of the parent process. | Provides upstream contextual execution intent leading to the child process spawning. | Execution Chain Analysis, UAC Bypass (T1548.002) |
| `User` | String | 1, 3, 10, 11 | Account context under which the process was executed (Format: `DOMAIN\Username` or `NT AUTHORITY\SYSTEM`). | Detects abnormal user context (e.g., service accounts launching interactive shells, unprivileged users executing elevated utilities). | Privilege Escalation (T1068), Valid Accounts (T1078) |
| `Hashes` | String | 1, 7 | Cryptographic hash strings (SHA256, MD5, IMPHASH) of the binary image computed at execution time. | Allows direct threat intelligence lookups against known malware repositories and detection of modified standard binaries. | Masquerading (T1036), Ingress Tool Transfer (T1105) |
| `SourceImage` | String | 8, 10 | The executable initiating a cross-process thread or requesting an open handle to another process. | Pinpoints offensive injection tools, memory dumping utilities (e.g., Mimikatz, Procdump), or Cobalt Strike beacons. | Process Injection (T1055), LSASS Memory Access (T1003.001) |
| `TargetImage` | String | 8, 10 | The target process whose virtual memory or execution flow is being accessed or altered. | Critical when `TargetImage` is `lsass.exe`, `explorer.exe`, or security software processes. | Credential Dumping (T1003), Process Hollowing (T1055.012) |
| `GrantedAccess` | Hex String | 10 | The hexadecimal bitmask representing the specific access permissions granted to the calling process. | Differentiates benign queries from memory dumping operations (`0x10` `PROCESS_VM_READ`, `0x1F0FFF` full control, `0x1410` minidump access). | Credential Access (T1003.001), Defense Evasion (T1562) |
| `DestinationIp` | IP String | 3 | IPv4 or IPv6 address to which the process initiated a TCP/UDP socket connection. | Identifies command-and-control IP destinations, proxy hops, and lateral movement target hosts. | Command and Control (T1071), Lateral Movement (T1021) |
| `DestinationPort` | Integer | 3 | Port number of the remote target endpoint. | Detects non-standard service ports (e.g., PowerShell connecting to port 8443, 4444, 8080) and protocol anomalies. | Non-Standard Port (T1571), Protocol Tunneling (T1572) |
| `TargetFilename` | String | 11 | Complete path of the file created or overwritten on disk. | Detects drops of secondary payloads, script drop directories, ransomware file extension modifications, and DLL drops. | Ingress Tool Transfer (T1105), Persistence (T1547) |
| `TargetObject` | String | 12, 13, 14 | Full Windows Registry key and value path being queried, created, modified, or deleted. | Unveils persistence hooks (`CurrentVersion\Run`, Startup, Services), security tampering (`DisableRealtimeMonitoring`), and UAC bypass hijacks. | Boot or Logon Autostart Execution (T1547.001), Impair Defenses (T1562.001), UAC Bypass (T1548.002) |
| `Details` | String | 13 | The new data value written to the registry key specified in `TargetObject`. | Reveals malicious payload commands stored in registry values for fileless execution. | Fileless Storage (T1027), Hijack Execution Flow (T1574) |

---

## 3. Telemetry Source Type 2: Windows Security Auditing (WinEventLog:Security)

Windows Security Auditing generates auditable logs for security-relevant system operations governed by the Local Security Authority Subsystem Service (LSASS). It captures authentication transactions, authorization checks, Active Directory directory service object manipulation, privilege escalation, and log tampering.

### Key Monitored Event IDs

* **Event ID 4624:** An account was successfully logged on (logon types, authentication package, source IP, elevated status).
* **Event ID 4625:** An account failed to log on (failure status code, target account, caller workstation).
* **Event ID 4662:** An operation was performed on an object (Active Directory object access, extended rights GUIDs).
* **Event ID 4672:** Special privileges assigned to new logon (Administrator/SYSTEM privilege delegation).
* **Event ID 4688:** A new process has been created (OS process auditing with token elevation flags and command line).
* **Event ID 4720:** A user account was created (local or Active Directory account creation).
* **Event ID 4738:** A user account was modified (password changes, account flags).
* **Event ID 4794:** An attempt was made to set the Directory Services Restore Mode (DSRM) administrator password.
* **Event ID 5145:** A network share object was checked to see whether client can be granted desired access.
* **Event ID 1102 / 104:** The audit log was cleared (Security Log / System Log erasure).

### Windows Security Field Dictionary

| Field Name | Type | Event IDs | Meaning & Semantic Definition | Detection Utility | Associated Attacker Behaviors (MITRE ATT&CK) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `EventID` | Integer | All | Unique numerical identifier of the security audit event assigned by Microsoft. | Core filtering predicate to isolate specific transaction categories. | Baseline triage across all tactics |
| `LogonType` | Integer | 4624, 4625 | Numeric code specifying the method of logon: `2` (Interactive), `3` (Network/SMB), `4` (Batch), `5` (Service), `7` (Unlock), `8` (NetworkCleartext), `9` (NewCredentials/RunAs), `10` (RemoteInteractive/RDP). | Essential for identifying lateral movement (Type 3), Pass-the-Hash (Type 9), unauthorized RDP (Type 10), and anomalous service spawns (Type 5). | Lateral Movement (T1021.001, T1021.002), Pass the Hash (T1550.002), Remote Services (T1021) |
| `TargetUserName` | String | 4624, 4625, 4720, 4738 | Identity of the account for whom the logon or modification was attempted. | Identifies brute-force targets, targeted administrator accounts, and newly created rogue accounts. | Brute Force (T1110), Account Creation (T1136) |
| `TargetDomainName` | String | 4624, 4625, 4720 | Domain name or computer name where the target account resides. | Differentiates local machine credential usage from Active Directory domain-level compromise. | Domain Account Discovery (T1087.002) |
| `LogonProcessName` | String | 4624, 4625 | Subsystem that registered and submitted the authentication request (e.g., `User32`, `Advapi`, `Kerberos`, `NtLmSsp`, `seclogo`). | Detects abnormal authentication brokers (e.g., third-party tools submitting synthetic logons). | Credential Access (T1110, T1550) |
| `IpAddress` | IP String | 4624, 4625, 5145 | Network IP address of the remote host requesting the session. | Identifies the pivot source in lateral movement chains and malicious remote workstations. | Remote Services (T1021), Pass the Hash (T1550.002) |
| `IpPort` | Integer | 4624, 4625 | Ephemeral source port on the remote client initiating the connection. | Distinguishes programmatic scripts from interactive desktop logons; tracks network flows. | Lateral Movement (T1021) |
| `ElevatedToken` | String | 4624 | Flag indicating whether the logon session token is split and elevated (`%%1842` = Yes, `%%1843` = No). | Identifies whether the logon acquired full administrative UAC token context. | Privilege Escalation (T1548), Valid Accounts (T1078) |
| `Properties` / `AccessMask` | Hex String | 4662, 5145 | Rights and permissions requested during the object access. In 4662, contains Extended Rights GUIDs; in 5145, contains file permission flags (`0x2` WriteData). | Vital for detecting DCSync attacks (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` - DS-Replication-Get-Changes-All) and remote administrative share tampering. | OS Credential Dumping: DCSync (T1003.006), Lateral Tool Transfer (T1570) |
| `RelativeTargetName` | String | 5145 | The relative filename or pipe name accessed across an SMB share (`\ADMIN$`, `\C$`, `\IPC$`). | Detects remote executable drops (e.g., `PSEXESVC.exe`, `.bat`), remote service tampering, and named pipe exploitation. | Remote Services: SMB (T1021.002), Lateral Tool Transfer (T1570) |
| `ShareName` | String | 5145 | Name of the shared folder accessed (e.g., `\\*\ADMIN$`, `\\*\C$`, `\\*\IPC$`). | Identifies default administrative share abuse common in lateral movement frameworks. | SMB/Windows Admin Shares (T1021.002) |
| `PrivilegeList` | String | 4672 | List of sensitive user rights granted to the session at logon (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`). | Flags immediate assignment of high-risk operating system privileges capable of token theft and LSASS access. | Privilege Escalation (T1078), Token Impersonation (T1134) |

---

## 4. Telemetry Source Type 3: Zeek Network Security Monitoring (Zeek)

Zeek is an open-source, passive network traffic analyzer that converts raw network packets into compact, highly structured, protocol-specific transaction logs. Unlike traditional signature-based packet inspectors, Zeek performs deep semantic protocol dissection, stateful session reassembly, and metadata extraction.

### Monitored Zeek Log Types

* **`conn.log`:** Comprehensive transport-layer connection summaries (TCP/UDP/ICMP), durations, state flags, and packet/byte metrics.
* **`dns.log`:** DNS request/response transactions, query domains, transaction IDs, return codes, and resolved IPs.
* **`ssl.log`:** Transport Layer Security handshakes, TLS protocol versions, negotiated cipher suites, SNI server names, and X.509 certificate metadata.
* **`dce_rpc.log`:** Distributed Computing Environment / Remote Procedure Calls, endpoint interfaces, and operation calls.
* **`kerberos.log`:** Kerberos protocol exchanges, request types (AS-REQ, TGS-REQ), client realms, and service principal names (SPNs).
* **`smb_files.log`:** File transactions conducted over Server Message Block (SMB), filenames, paths, and byte counts.

### Zeek Field Dictionary

| Field Name | Type | Log Source | Meaning & Semantic Definition | Detection Utility | Associated Attacker Behaviors (MITRE ATT&CK) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ts` | Float (Epoch) | All | Precise floating-point timestamp of the start of the network connection or protocol event. | High-fidelity temporal sequencing and calculation of beaconing intervals (delta time analysis). | C2 Beaconing (T1071.001), Data Exfiltration (T1041) |
| `uid` | String | All | Unique 18-character alphanumeric string generated by Zeek to globally identify a single network session across all protocol logs. | Allows instant cross-protocol joins (e.g., linking a `conn.log` summary with its corresponding `ssl.log` handshake and `dns.log` resolution). | Multi-stage network investigation (T1071, T1573) |
| `id.orig_h` | IP String | All | IP address of the session initiator (originating client host). | Identifies internal compromised hosts initiating outbound egress traffic or internal lateral pivots. | Internal Reconnaissance (T1046), Lateral Movement (T1021) |
| `id.orig_p` | Integer | All | Source port used by the initiating client endpoint. | Identifies client port exhaustion, anomalous source port selections, and tracks ephemeral connections. | Network Communication |
| `id.resp_h` | IP String | All | IP address of the responding endpoint (remote server or target host). | Pinpoints external Command-and-Control infrastructure, adversary redirectors, and internal pivot targets. | Application Layer Protocol (T1071), Remote Services (T1021) |
| `id.resp_p` | Integer | All | Destination port hosted by the responding server. | Detects non-standard service ports (e.g., HTTPS running on 8443 or DNS on 5353) and unauthorized service access. | Non-Standard Port (T1571) |
| `proto` | String | `conn.log` | Transport-layer protocol used (`tcp`, `udp`, `icmp`). | Isolates protocol tunneling and baseline deviations. | Non-Application Protocol (T1095) |
| `service` | String | `conn.log` | Protocol dynamically identified by Zeek's protocol analysis engine (e.g., `ssl`, `dns`, `http`, `smb`, `dce_rpc`). | Detects port-protocol mismatches (e.g., TLS traffic masquerading across TCP port 80 or unencrypted HTTP over port 443). | Protocol Tunneling (T1572) |
| `duration` | Float | `conn.log` | Total duration of the connection session in seconds. | Long-lived persistent connections indicate interactive C2 reverse shells, SOCKS proxies, or large exfiltration streams. | C2 Persistence (T1573), Exfiltration Over C2 (T1041) |
| `orig_bytes` | Integer | `conn.log` | Number of payload bytes sent from client to server (originator to responder). | Detects outbound data exfiltration volume and command execution payloads. | Automated Exfiltration (T1020), Data Exfiltration (T1041) |
| `resp_bytes` | Integer | `conn.log` | Number of payload bytes sent from server to client (responder to originator). | Detects staging and binary tool downloads over C2 channels. | Ingress Tool Transfer (T1105) |
| `conn_state` | String | `conn.log` | Zeek state tracking flag string summarizing connection termination state: `SF` (Normal SYN/FIN completion), `S0` (SYN seen, no reply / port scan), `REJ` (Connection rejected), `RSTO` (Reset by originator). | Identifies port scanning activity (`S0`), blocked connections (`REJ`), and clean adversary C2 terminations (`SF`). | Network Service Discovery (T1046) |
| `query` | String | `dns.log` | The domain name requested in the DNS question section. | Detects Dynamic DNS (DDNS) providers, newly registered domains (NRDs), high-entropy DNS tunneling queries, and C2 domains. | Application Layer Protocol: DNS (T1071.004) |
| `answers` | Array[String]| `dns.log` | List of resource records returned in the DNS response (IP addresses, CNAMEs, TXT records). | Flags fast-flux IP resolution, sinkholed domains, and base64-encoded payloads transmitted via TXT records. | Dynamic Resolution: Fast Flux (T1568.001) |
| `server_name` | String | `ssl.log` | Server Name Indication (SNI) extension value sent in the client TLS handshake. | Detects discrepancies between the requested SNI and the resolved IP or certificate subject; detects direct IP-based TLS connections. | Asymmetric Cryptography (T1573.002) |
| `subject` | String | `ssl.log` | X.509 Distinguished Name (DN) identifying the entity to whom the server certificate is issued. | Reveals spoofed or fictitious organization names, ad-hoc self-signed adversary certs, and default tool certificates (e.g., Metasploit/Cobalt Strike). | Digital Certificates (T1588.004), Encrypted Channel (T1573) |
| `issuer` | String | `ssl.log` | X.509 Distinguished Name (DN) identifying the Certificate Authority (CA) that signed the certificate. | Pinpoints self-signed certificates where `subject == issuer` and detects non-public/untrusted CAs. | Subvert Trust Controls (T1553) |
| `validation_status`| String | `ssl.log` | Result of certificate path validation performed by Zeek (e.g., `ok`, `self signed certificate`, `certificate has expired`). | High-precision indicator for untrusted CAs and self-signed adversary C2 infrastructure. | Encrypted Channel (T1573.002) |
| `ja3` / `ja3s` | String | `ssl.log` | MD5 hash of the client (JA3) and server (JA3S) TLS handshake parameters (ciphers, extensions, curves). | Enables cryptographic client profiling to identify malicious agents (Cobalt Strike, PowerShell, Meterpreter) regardless of destination IP. | Encrypted Channel (T1573.002) |

---

## 5. Cross-Telemetry Correlation Map

The true strength of detection engineering lies in correlating across these distinct telemetry layers. An adversary's action on an endpoint leaves simultaneous traces across process memory, audit subsystems, and the network wire:

```
+-------------------------------------------------------------------------------+
|                           ADVERSARY ACTION                                    |
|   Adversary delivers disguised malicious payload (.scr with RLO character)    |
+-------------------------------------------------------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------------------+
| Telemetry Layer 1: Windows Sysmon                                             |
| • EID 1: Image = "C:\ProgramData\victim\cod.3aka3.scr", Cmd = /S              |
| • EID 13: Sets HKCU\Software\Classes\Folder\shell\open\command (UAC Bypass)   |
| • EID 1: sdclt.exe -> control.exe -> powershell.exe -window hidden            |
+---------------------------------+---------------------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------------------+
| Telemetry Layer 2: Windows Security Auditing                                  |
| • EID 4688: Process creation with ElevatedToken = %%1842 (Admin Context)      |
| • EID 4624: LogonType 2 (Interactive session with Administrator privileges)   |
| • EID 4672: SeDebugPrivilege, SeImpersonatePrivilege assigned                 |
+---------------------------------+---------------------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------------------+
| Telemetry Layer 3: Zeek Network Security Monitoring                           |
| • conn.log: Initiates outbound TCP connection to 192.168.0.4:8443 (SF state)  |
| • ssl.log: TLSv12, validation_status="self signed certificate"                |
|            subject/issuer: "CN=rempel.group.net, O=Rempel Group"              |
| • Sysmon EID 3: Correlates socket to powershell.exe (PID 6120)                |
+-------------------------------------------------------------------------------+
```

This multi-dimensional visibility ensures that evasion at one telemetry layer (e.g., unhooking user-mode API calls or clearing local event logs) is caught by adjacent kernel or network instrumentation.
