# Cyberion Defense Labs — Incident Response Playbook: Lateral Movement via Remote Services

**Playbook Code:** `IR-PB-002`  
**Classification:** Operational Cybersecurity Standard Operating Procedure  
**Version:** 2.0  
**Owner:** Director, Security Operations  
**Scope:** Windows Workstations, Member Servers, Remote Services (SMB, RDP, WMI, WinRM)  
**Mode:** Procedural Analyst Response (Non-Automated / Human-in-the-Loop)  

---

## 1. Purpose & Scope

This standard operating procedure guides SOC analysts and incident responders in detecting, containing, and remediating unauthorized adversary movement across internal network endpoints using legitimate remote administration protocols and services.

Scope includes:
* Server Message Block (SMB) administrative share abuse (`ADMIN$`, `C$`, `IPC$`).
* Remote service execution and service installation (PsExec, remote service controllers).
* Windows Management Instrumentation (WMI) and PowerShell Remoting (WinRM / PSRemoting).
* Remote Desktop Protocol (RDP) sessions, tunneling, and session hijacking.
* In-memory authentication token and hash replay (Pass-the-Hash / Pass-the-Ticket).

---

## 2. Trigger Conditions

This playbook is activated upon any of the following triggers:
* **Detection Rule Triggers:**
  * `833d9d64-5164-42f3-879b-b7b5e8e135cf` — Remote Administrative Share File Write Operation via SMB (Event ID 5145).
  * `38301c3f-4ba5-4217-9339-c27ff47e3944` — Explicit Credential Logon with NewCredentials via Pass-the-Hash (Event ID 4624 LogonType 9).
  * `7b4581c2-d581-4986-b697-1ae7c04a9dcd` — Correlation: Credential Dumping Preceding Remote Share Lateral Movement.
* **Telemetry Triggers:** Multiple simultaneous Event ID 4624 LogonType 3 (Network) or LogonType 10 (RemoteInteractive) connections from a single client workstation across multiple servers within a 5-minute interval.

---

## 3. Initial Triage & Verification (0 – 15 Minutes)

1. **Confirm Source and Destination Endpoints:**
   * Extract calling IP address (`IpAddress`), caller workstation name, and target host.
   * Verify if the source IP belongs to an authorized IT management station, SCCM server, vulnerability scanner, or an unprivileged user desktop.
2. **Verify User Authorization:**
   * Contact the user/administrator whose account was used: verify if they are actively conducting maintenance.
   * If activity is unconfirmed, immediately escalate to Severity **HIGH** or **CRITICAL**.
3. **Establish Incident Boundary:** Identify how many secondary endpoints have received inbound network logons from the offending source IP.

---

## 4. Investigative Procedures

```
+-------------------------------------------------------------------------------+
|                             INVESTIGATION FLOW                                |
+-------------------------------------------------------------------------------+
  1. Isolate Pivot Source Host       -> 2. Trace Inbound Network Logons (Type 3/10)
               |                                            |
               v                                            v
  3. Inspect File Drops on Shares    -> 4. Trace Remote Process Spawns (WMI/Service)
+-------------------------------------------------------------------------------+
```

1. **Map Inbound Authentication Across Enterprise (SIEM Query):**
   * Query all Windows Security logs for network logons originating from the suspect host IP:
     ```
     EventID=4624 AND IpAddress="<source_ip>" AND LogonType IN (3, 10)
     | stats count by TargetUserName, ComputerName, LogonProcessName
     ```
2. **Inspect Network Share File Operations (Event ID 5145):**
   * Query target systems for Event ID 5145 where `ShareName` ends with `ADMIN$` or `C$`:
     * Look for executable or script drops in `RelativeTargetName` (e.g., `PSEXESVC.exe`, `*.bat`, `*.ps1`, `*.dll`).
     * Inspect access masks (`0x2` WriteData, `0x12019f` Full Control).
3. **Trace Remote Process Execution (Target Endpoints):**
   * On destination machines, check Sysmon Event ID 1 / Security Event ID 4688 for processes spawned shortly after the inbound logon:
     * `services.exe` -> `cmd.exe` or dropped service binary (indicative of PsExec / sc.exe).
     * `wmiprvse.exe` -> `powershell.exe` or `cmd.exe` (indicative of WMI execution / wmiexec).
     * `wsmprovhost.exe` (indicative of PowerShell Remoting / WinRM).
4. **Inspect Named Pipes (Sysmon Event ID 18):**
   * Check for communication across common lateral movement named pipes: `\psexec`, `\paexec`, `\remcom`, `\winexe`.

---

## 5. Forensic Evidence to Collect

* **Target Systems Forensic Triage:**
  * Windows Event Logs: `Security.evtx`, `System.evtx`, `Sysmon.evtx`, `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`.
  * Prefetch files (`C:\Windows\Prefetch\*.pf`) on target systems to prove binary execution timing.
  * Shimcache and Amcache (`C:\Windows\appcompat\Programs\Amcache.hve`).
* **Source System Triage:**
  * Active network sockets and connections (`netstat -ano`).
  * Process memory of active shell interpreters (`powershell.exe`, `cmd.exe`).
  * PowerShell command history (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`).

---

## 6. Containment Procedures

1. **Source Host Network Isolation:**
   * Immediately issue an EDR network isolation command against the initial pivot workstation to stop outbound lateral propagation.
2. **Target Host Containment:**
   * Isolate secondary hosts where remote file writes or unauthorized process executions have occurred.
3. **Account Revocation:**
   * Disable the user account utilized for lateral traversal in Active Directory; terminate all active Kerberos ticket-granting sessions.
4. **Network Access Control (Emergency SMB Blocking):**
   * If automated lateral proliferation (worm or ransomware) is suspected, deploy emergency GPO or core switch ACL blocking TCP 445 (SMB) and TCP 3389 (RDP) between workstation subnets.

---

## 7. Eradication & Recovery Procedures

1. **Payload Removal Across Staged Shares:**
   * Scan and delete dropped executable binaries from `C:\Windows\`, `C:\Windows\System32\`, and root `C:\` on all affected systems.
2. **Service Deletion:**
   * Identify and remove rogue services created by lateral execution:
     `sc.exe stop <service_name>` -> `sc.exe delete <service_name>`.
3. **System Rebuilding / Image Restoration:**
   * Re-image all systems where unauthorized elevated payloads achieved execution.
4. **Host-Based Firewall Hardening:**
   * Enforce Windows Defender Firewall rules blocking workstation-to-workstation SMB (TCP 445) and WinRM (TCP 5985/5986). Workstations must only communicate administrative ports to authorized jump boxes.

---

## 8. Validation Steps (Ensuring Threat Is Neutralized)

1. **Authentication Sweep:** Verify zero Event ID 4624 (LogonType 3 or 10) initiated from the isolated IP range over a 24-hour observation window.
2. **File Integrity Verification:** Scan administrative network shares (`C$`, `ADMIN$`) to ensure zero unexplained executable files exist.
3. **Service Audit:** Execute PowerShell script across all domain endpoints auditing newly installed system services within the past 7 days (`Get-CimInstance Win32_Service`).

---

## 9. Required Stakeholder Communications

* **SOC Lead & Incident Commander:** Continuous updates on compromised host count and blast radius.
* **Network Infrastructure Team:** Coordinate internal VLAN / subnet isolation if workstation-to-workstation traffic must be severed.
* **Server Administration / Application Owners:** Notify system owners before restarting or isolating production servers.
* **Executive Leadership:** Provide high-level briefing on containment status and operational impact.

---

## 10. Incident Closure Criteria

* Pivot source host identified, isolated, and triaged.
* All compromised target hosts inventoried, cleaned, or re-imaged.
* Lateral movement accounts revoked, passwords reset, and Kerberos tickets cleared.
* Host firewall rules restricting lateral SMB/RDP verified across the domain.

---

## 11. Relevant MITRE ATT&CK Mapping

* [T1021.002](https://attack.mitre.org/techniques/T1021/002/) — Remote Services: SMB/Windows Admin Shares
* [T1021.001](https://attack.mitre.org/techniques/T1021/001/) — Remote Services: Remote Desktop Protocol
* [T1570](https://attack.mitre.org/techniques/T1570/) — Lateral Tool Transfer
* [T1550.002](https://attack.mitre.org/techniques/T1550/002/) — Use Alternate Authentication Material: Pass the Hash
* [T1047](https://attack.mitre.org/techniques/T1047/) — Windows Management Instrumentation
