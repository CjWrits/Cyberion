# Cyberion Defense Labs — Detection Rule Library

**Library Code:** `CDL-SIGMA-LIB-V2`  
**Standard:** Sigma Generic Detection Format (pySigma Compliant)  
**Total Rules Delivered:** 17  
**Correlation-Style Rules:** 3  
**Classification:** Internal Engineering & SOC Content  

---

## 1. Architecture & Organizational Taxonomy

The **Cyberion Defense Labs** Detection Rule Library provides standardized, vendor-neutral detection content formatted according to the official Sigma open specification. The library is categorized into three primary functional domains to mirror enterprise telemetry segregation and analyst operational workflows:

```
sigma-rules/
├── windows/                # Host endpoint execution, registry manipulation, memory access, and log tampering
├── authentication/         # Credential harvesting, Kerberos/NTLM authentication, Active Directory replication, and SMB shares
└── network/                # Perimeter and network security monitoring telemetry (Zeek/Bro, socket telemetry)
```

Each rule is uniquely identified by a UUID v4 identifier, version-controlled, and mapped to specific **MITRE ATT&CK® Enterprise** techniques and tactics.

---

## 2. Rule Catalog & ATT&CK Matrix Alignment

| Rule ID | Rule Title | Subdirectory | Target MITRE Technique | Tactic | Severity | Type |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `057de226-ae47-4d2e-9fc3-47935bcfe860` | Masquerading Process Command Line via Right-to-Left Override Character | `windows/` | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) (Right-to-Left Override) | Defense Evasion | **High** | Atomic |
| `7d5fb47e-fea1-4173-b030-520a167c2bd5` | UAC Bypass via Sdclt DelegateExecute Hijacking | `windows/` | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Bypass User Account Control) | Privilege Escalation | **High** | Atomic |
| `d14d6b0c-8349-44c8-a5f8-2fc89299cb9e` | PowerShell Steganographic Payload Extraction via System.Drawing.Bitmap | `windows/` | [T1027.003](https://attack.mitre.org/techniques/T1027/003/) (Steganography) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Defense Evasion, Execution | **High** | Atomic |
| `7cb39dc7-ae81-47a1-b36c-2581534b9a17` | UAC Bypass Registry Hijack in Folder Shell Open Command | `windows/` | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Bypass User Account Control) | Privilege Escalation | **High** | Atomic |
| `ab9c4e58-f323-4524-b02c-44d8ef3d6e02` | C# Compiler Invoked by PowerShell for On-The-Fly Compilation | `windows/` | [T1027.004](https://attack.mitre.org/techniques/T1027/004/) (Compile After Delivery) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Defense Evasion, Execution | **Medium** | Atomic |
| `d5f41248-645d-49da-a048-6f1b6f0f0496` | Suspicious Process Handle Access to LSASS Memory | `windows/` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (LSASS Memory Dumping) | Credential Access | **High** | Atomic |
| `cacaf252-f706-446a-8b88-0516e962cfb4` | Windows Security or System Audit Log Cleared | `windows/` | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) (Clear Windows Event Logs) | Defense Evasion | **High** | Atomic |
| `f4c1fd22-9035-4b9d-88ed-54184d9480e1` | Suspicious Persistence Registry Run Key Modification | `windows/` | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Registry Run Keys / Startup Folder) | Persistence | **High** | Atomic |
| `fbf66860-6faf-4c5f-babb-5ed0417f6836` | Correlation: UAC Registry Bypass Preceding High-Integrity Shell Launch | `windows/` | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Privilege Escalation, Execution | **Critical** | **Correlation** |
| `38301c3f-4ba5-4217-9339-c27ff47e3944` | Explicit Credential Logon with NewCredentials via Pass-the-Hash | `authentication/` | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Pass the Hash) / [T1078](https://attack.mitre.org/techniques/T1078/) | Lateral Movement | **High** | Atomic |
| `6b9079cd-604b-420a-a248-8e636962235d` | Active Directory DCSync Replication Request by Non-Machine Account | `authentication/` | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (DCSync) | Credential Access | **Critical** | Atomic |
| `01753072-e2ec-4d43-a3f8-1edf1ab511f0` | Directory Services Restore Mode Admin Password Reset Attempt | `authentication/` | [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation) | Persistence, Credential Access | **High** | Atomic |
| `833d9d64-5164-42f3-879b-b7b5e8e135cf` | Remote Administrative Share File Write Operation via SMB | `authentication/` | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (SMB Shares) / [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Movement | **Medium** | Atomic |
| `7b4581c2-d581-4986-b697-1ae7c04a9dcd` | Correlation: Credential Dumping Preceding Remote Share Lateral Movement | `authentication/` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) / [T1021.002](https://attack.mitre.org/techniques/T1021/002/) / [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Credential Access, Lateral Movement | **Critical** | **Correlation** |
| `67e22644-d440-4b97-b1bd-7216bd270178` | Outbound Encrypted C2 Session Using Self-Signed SSL/TLS Certificate | `network/` | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Web Protocols) / [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Command and Control | **High** | Atomic |
| `f62006ac-158a-4162-a48f-6547c0768b43` | PowerShell Direct Outbound Network Socket to External IP | `network/` | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Control, Execution | **High** | Atomic |
| `bc5f23b7-7515-42b3-af7e-ae53aaa6ce4c` | Correlation: Endpoint PowerShell Socket Correlated with Network TLS Beaconing | `network/` | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) / [T1071.001](https://attack.mitre.org/techniques/T1071/001/) / [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Execution, Command and Control | **Critical** | **Correlation** |

---

## 3. Severity Rating Scheme & Rationale Standards

Every rule in the library incorporates a defined severity rating (`low`, `medium`, `high`, `critical`) along with an explicit documented rationale:

* **Critical:** Confirmed exploit execution, domain-level credential harvesting (e.g., DCSync), multi-stage correlated attack sequences, or unconstrained administrative compromise. Requires immediate 24/7 on-call paging and rapid host isolation.
* **High:** High-confidence malicious intent with low probability of benign explanation (e.g., Right-to-Left Override character injection, event log clearing, self-signed external C2 TLS session). Requires SOC tier-2 investigation within 15 minutes.
* **Medium:** Potentially dual-use activity observed outside standard baselines (e.g., C# compiler invocation via PowerShell, remote file copy to administrative share). Requires contextual enrichment and user verification within 1 hour.
* **Low / Informational:** Baseline anomalies, policy deviations, or telemetry breadcrumbs used primarily to enrich higher-order correlations.

---

## 4. Rule Validation & Testing Protocol

All 17 rules have been strictly validated against the official Sigma specification using `pySigma` and tested against real attack datasets (`mordor_apt29_day1` and `EVTX-ATTACK-SAMPLES`). Validation results and raw matching evidence records are published in:
* `rule-validation/validation-results.md`
* `rule-validation/rule-test-evidence/`
