# Cyberion Defense Labs — Incident Response Playbook: Credential Compromise

**Playbook Code:** `IR-PB-001`  
**Classification:** Operational Cybersecurity Standard Operating Procedure  
**Version:** 2.0  
**Owner:** Director, Security Operations  
**Scope:** Enterprise Workstations, Domain Controllers, Active Directory Infrastructure, Cloud Identifiers  
**Mode:** Procedural Analyst Response (Non-Automated / Human-in-the-Loop)  

---

## 1. Purpose & Scope

This standard operating procedure guides Tier 1 to Tier 3 SOC analysts and incident responders through the systematic triage, containment, investigation, eradication, and recovery phases following a suspected or confirmed credential compromise incident.

Scope includes:
* In-memory credential extraction (e.g., LSASS memory dumping, SAM hive extraction).
* Stolen credential material usage (Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash).
* Active Directory replication abuse (DCSync, Golden/Silver Ticket generation).
* Unauthorized privileged account manipulation (DSRM backdoors, administrative group alterations).

---

## 2. Trigger Conditions

This playbook is activated upon any of the following alerts or hunting findings:
* **Detection Rule Triggers:**
  * `6b9079cd-604b-420a-a248-8e636962235d` — Active Directory DCSync Replication Request by Non-Machine Account.
  * `d5f41248-645d-49da-a048-6f1b6f0f0496` — Suspicious Process Handle Access to LSASS Memory.
  * `01753072-e2ec-4d43-a3f8-1edf1ab511f0` — Directory Services Restore Mode Admin Password Reset Attempt.
  * `7b4581c2-d581-4986-b697-1ae7c04a9dcd` — Correlated Credential Dumping Preceding Remote Share Write.
* **External Triggers:** User report of unexplained multi-factor authentication (MFA) prompts, anomalous geographically impossible logons, or dark web credential breach notifications.

---

## 3. Initial Triage & Verification (0 – 15 Minutes)

1. **Verify Alert Fidelity:**
   * Review source process image, command line, and calling security principal.
   * Cross-check whether the calling process is a known enterprise security agent (e.g., Microsoft Defender `MsMpEng.exe` or licensed vulnerability scanner). If verified change-ticket exists, mark as Benign Positive and document exception.
2. **Determine Compromise Tier:**
   * **Tier 1 (Domain-Level Impact):** Alert involves Domain Controller, DCSync extended rights, `krbtgt` ticket requests, or Enterprise/Domain Admin accounts. Escalate immediately to Severity **CRITICAL**.
   * **Tier 2 (Workstation/Local Impact):** Alert involves non-domain local accounts or unprivileged user workstations without domain replication. Escalate to Severity **HIGH**.
3. **Establish Incident Bridge:** Open incident ticket in ITSM; notify Incident Response Lead and initiate unified investigation log.

---

## 4. Investigative Procedures

```
+-------------------------------------------------------------------------------+
|                             INVESTIGATION FLOW                                |
+-------------------------------------------------------------------------------+
  1. Determine Scope of Dumped Process -> 2. Query Global Authentication Logs
               |                                            |
               v                                            v
  3. Inspect Kerberos Ticket Requests  -> 4. Reconstruct Attacker Blast Radius
+-------------------------------------------------------------------------------+
```

1. **Identify Memory Dumping Origin:**
   * Ingest Sysmon Event ID 10 on source host: examine `SourceImage`, `TargetImage` (`lsass.exe`), and `GrantedAccess` bitmask.
   * Look for companion process launches (Sysmon EID 1): `procdump.exe`, `mimikatz.exe`, `dumpert.exe`, `rundll32.exe comsvcs.dll #24`.
2. **Track Stolen Credential Utilization (Global Auth Sweep):**
   * Execute SIEM search across Windows Security Event ID 4624 (Logon) and Event ID 4625 (Failed Logon) for the compromised username across all endpoints:
     ```
     EventID=4624 AND TargetUserName="<compromised_user>" AND LogonType IN (2, 3, 9, 10)
     ```
   * Flag any LogonType 9 (`NewCredentials`) initiated via `seclogo` or `Advapi` indicative of Pass-the-Hash.
3. **Audit Active Directory Replication & Privilege Changes:**
   * Query Domain Controller security event logs for Event ID 4662 where `Properties` contains extended rights GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`.
   * Check for unexpected additions to privileged groups (Event ID 4728 / 4732 / 4756: Member added to security group).
4. **Check Cloud Identity Sync (Entra ID / Azure AD):**
   * Inspect Azure AD sign-in logs for non-compliant device connections, unfamiliar user agents, or bypass of Conditional Access policies.

---

## 5. Forensic Evidence to Collect

* **Volatile Memory:** Execute live RAM acquisition on source host using WinPmem / LiME prior to rebooting or isolating.
* **Disk Triage Artifacts:** Collect master triage bundle (KAPE / CyLR) targeting:
  * `$MFT`, `$LogFile`, `$UsnJrnl` (Filesystem timeline).
  * LNK files and Shellbags (`%APPDATA%\Microsoft\Windows\Recent`).
  * Registry hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`).
  * Windows Event Logs (`Security.evtx`, `System.evtx`, `Sysmon.evtx`, `PowerShell.evtx`).
* **Active Directory State Capture:** Export snapshot of compromised account attributes, group memberships, and Kerberos SPN mappings.

---

## 6. Containment Procedures

1. **Host Isolation:**
   * Issue host network isolation via EDR agent to prevent lateral movement while preserving SOC analysis tunnel.
2. **Account Invalidation (Immediate Revocation):**
   * Disable compromised user account in Active Directory and revoke active Azure AD refresh tokens (`Revoke-AzureADUserAllRefreshToken`).
   * Reset the account password to a randomly generated 25+ character string.
3. **Active Directory Kerberos Secret Rotation (For Domain-Level Compromise):**
   * If DCSync or Domain Admin compromise is confirmed, execute a dual reset of the Active Directory `krbtgt` account password spaced 24 hours apart using Microsoft's `New-KrbtgtKeys.ps1` script to invalidate Golden Tickets.
4. **Session Termination:**
   * Force disconnect of all active interactive and remote desktop sessions:
     `qwinsta` -> `rwinsta <session_id>`.

---

## 7. Eradication & Recovery Procedures

1. **Credential Sanitization:**
   * Reset passwords for all systems, service accounts, and administrators that logged into the compromised workstation within the past 30 days.
2. **Malware Removal:**
   * Delete dropped memory dumping binaries, scripts, or DLLs identified during investigation.
   * Clear user-hive persistence keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
3. **Workstation Re-Imaging:**
   * If root-level or SYSTEM persistence is suspected, wipe the host storage media and restore from a certified golden corporate image.
4. **Infrastructure Hardening:**
   * Deploy Windows Defender Credential Guard via GPO.
   * Place all Enterprise and Domain Administrators into the *"Protected Users"* security group.

---

## 8. Validation Steps (Ensuring Threat Is Neutralized)

1. **Verify Authentication Silence:** Monitor SIEM for Event ID 4625 (Failed Logon) or Event ID 4624 using the old credentials; verify zero unauthorized logins.
2. **Verify Ticket Invalidation:** Confirm that pre-existing Kerberos TGTs fail authentication across domain controllers.
3. **Confirm EDR Clean State:** Run comprehensive full-disk and memory antimalware scan; confirm zero active alerts for 48 consecutive hours.

---

## 9. Required Stakeholder Communications

* **Incident Commander / CISO:** Bi-hourly situational briefing for Tier 1 compromise; immediate notification if DCSync or domain dominance is confirmed.
* **Enterprise Identity Team:** Immediate notification to coordinate `krbtgt` password resets and service account changes.
* **Legal & Compliance:** Notify if compromised account had access to regulated customer PII, HIPAA records, or financial data requiring breach disclosure.
* **Affected User:** Coordinate with HR/Manager to issue new credentials and review recent user activity for phishing confirmation.

---

## 10. Incident Closure Criteria

* Root cause of initial credential theft identified and documented.
* All compromised accounts reset, active sessions terminated, and `krbtgt` rotated (if applicable).
* Host either sanitized, restored, or re-imaged, with EDR reporting healthy telemetry.
* Post-incident review meeting completed and documented detection rule improvements scheduled.

---

## 11. Relevant MITRE ATT&CK Mapping

* [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — OS Credential Dumping: LSASS Memory
* [T1003.006](https://attack.mitre.org/techniques/T1003/006/) — OS Credential Dumping: DCSync
* [T1550.002](https://attack.mitre.org/techniques/T1550/002/) — Use Alternate Authentication Material: Pass the Hash
* [T1558](https://attack.mitre.org/techniques/T1558/) — Steal or Forge Kerberos Tickets
* [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts
