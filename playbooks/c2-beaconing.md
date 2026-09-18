# Cyberion Defense Labs — Incident Response Playbook: Command-and-Control (C2) Beaconing

**Playbook Code:** `IR-PB-003`  
**Classification:** Operational Cybersecurity Standard Operating Procedure  
**Version:** 2.0  
**Owner:** Director, Security Operations  
**Scope:** Network Egress Sensors, Perimeter Firewalls, Endpoint Process-to-Socket Instrumentation  
**Mode:** Procedural Analyst Response (Non-Automated / Human-in-the-Loop)  

---

## 1. Purpose & Scope

This standard operating procedure directs SOC analysts and incident response personnel in identifying, analyzing, severing, and remediating unauthorized outbound command-and-control (C2) communication channels between internal network assets and external adversary infrastructure.

Scope includes:
* HTTP/HTTPS/TLS beaconing over standard (80, 443) and non-standard ports (8443, 8080, 4443).
* Encrypted channels utilizing self-signed or untrusted SSL/TLS certificates.
* Script interpreters (PowerShell, MSHTA, cscript) initiating direct outbound sockets.
* In-memory reverse shells and C2 agents (Cobalt Strike, Mythic, Empire, POSHSPY).
* DNS-based command-and-control or data exfiltration tunneling.

---

## 2. Trigger Conditions

This playbook is activated upon any of the following triggers:
* **Detection Rule Triggers:**
  * `67e22644-d440-4b97-b1bd-7216bd270178` — Outbound Encrypted C2 Session Using Self-Signed SSL/TLS Certificate.
  * `f62006ac-158a-4162-a48f-6547c0768b43` — PowerShell Direct Outbound Network Socket to External IP.
  * `bc5f23b7-7515-42b3-af7e-ae53aaa6ce4c` — Correlation: Endpoint PowerShell Socket Correlated with Network TLS Beaconing.
* **Threat Hunting Triggers:** Statistical timing anomaly detection (low jitter coefficient of variation) or high-frequency external connection bursts from threat hunting operations (`TH-2026-001`).

---

## 3. Initial Triage & Verification (0 – 15 Minutes)

1. **Classify External Infrastructure:**
   * Query WHOIS, reverse DNS, and threat intelligence feeds (VirusTotal, AlienVault OTX) for destination IP and domain.
   * Determine if the remote endpoint belongs to a known Content Delivery Network (Cloudflare, Akamai), Microsoft Azure/AWS infrastructure, or an unclassified VPS provider (DigitalOcean, Linode, OVH).
2. **Examine SSL Certificate Telemetry:**
   * Inspect Zeek `ssl.log` for certificate validation status, subject DN, issuer DN, and JA3/JA3S fingerprints.
   * If `validation_status` is `self signed certificate` or subject contains fictitious organizations, elevate immediately to Severity **HIGH** or **CRITICAL**.
3. **Map Socket to Host Process:**
   * Query Sysmon Event ID 3 or EDR telemetry: identify the initiating binary path, command line, process GUID, and user account.

---

## 4. Investigative Procedures

```
+-------------------------------------------------------------------------------+
|                             INVESTIGATION FLOW                                |
+-------------------------------------------------------------------------------+
  1. Profile C2 Timing & Jitter      -> 2. Attribute Socket to Host Process
               |                                            |
               v                                            v
  3. Inspect Transferred Byte Volume -> 4. Sweep Fleet for Identical Indicators
+-------------------------------------------------------------------------------+
```

1. **Statistical Beacon Timing & Jitter Analysis:**
   * Extract all connection timestamps between the internal host and destination IP from Zeek `conn.log` or proxy logs.
   * Calculate inter-arrival deltas ($\Delta t = t_i - t_{i-1}$).
   * Compute Mean, Standard Deviation, and Coefficient of Variation ($CoV = \sigma / \mu$):
     * $CoV < 0.5$: High-regularity automated beaconing (hardcoded sleep interval).
     * $0.5 \le CoV \le 1.5$: Automated beacon with standard jitter (e.g., 20%–50% sleep jitter).
     * Burst activity: Interactive operator shell executing live commands.
2. **Process Memory & Parent Lineage Inspection:**
   * On the endpoint, inspect the process tree (Sysmon EID 1):
     * Was PowerShell spawned by `control.exe`, `sdclt.exe`, `word.exe`, or `w3wp.exe`?
     * Does the command line contain encoded commands (`-enc`, `-e`), bypass switches (`-ep bypass -w hidden`), or steganography?
   * Check for injected threads (Sysmon Event ID 8 `CreateRemoteThread`) or process hollowing into legitimate system binaries (`explorer.exe`, `svchost.exe`).
3. **Data Exfiltration & Volume Assessment:**
   * Analyze `orig_bytes` (client to server) and `resp_bytes` (server to client) in `conn.log`:
     * High `orig_bytes` indicates potential data exfiltration or reconnaissance output.
     * High `resp_bytes` indicates secondary payload staging or tool downloads.
4. **Enterprise-Wide Fleet Sweep:**
   * Search perimeter firewall and proxy logs for any other internal workstation or server communicating with the destination IP, domain, certificate SHA1, or JA3 hash within the past 30 days.

---

## 5. Forensic Evidence to Collect

* **Live Volatile Memory:** Capture complete RAM image of the host before terminating processes to preserve unencrypted C2 memory buffers, decrypted shellcode, and sleep masks.
* **Network Packet Captures:** Export full PCAP of active session traffic from perimeter taps or Zeek packet buffers.
* **Endpoint Forensic Artifacts:**
  * Network socket state (`netstat -ano -b`).
  * Process memory dump of the offending PID (using ProcDump: `procdump.exe -ma <pid>`).
  * PowerShell Operational event logs (`Microsoft-Windows-PowerShell%4Operational.evtx`).
  * DNS client cache records (`ipconfig /displaydns`).

---

## 6. Containment Procedures

1. **Immediate Endpoint Network Isolation:**
   * Issue host network isolation command via EDR to instantly sever the C2 socket while maintaining EDR telemetry.
2. **Perimeter Firewall Egress Drop:**
   * Add destination IP address and port to the perimeter firewall egress blocklist (Drop with logging).
3. **DNS Sinkholing:**
   * Redirect the C2 domain to internal loopback (`127.0.0.1`) or sinkhole appliance across all internal DNS resolvers to prevent failover beacons.
4. **Process Termination:**
   * Kill the process tree hosting the C2 agent (`powershell.exe`, injected host) after volatile memory acquisition is confirmed.

---

## 7. Eradication & Recovery Procedures

1. **Payload & Staging Removal:**
   * Delete local dropper files, masqueraded binaries (e.g., files with Unicode RLO), and steganographic images (`*.png`, `*.bmp`).
2. **Persistence Neutralization:**
   * Inspect and clean scheduled tasks (`schtasks /query`), service entries (`Get-Service`), and Registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
3. **OS Rebuilding:**
   * If rootkit activity, kernel driver injection, or deep memory hollowing occurred, re-image the host operating system from verified media.
4. **Proxy & Egress Architecture Hardening:**
   * Enforce strict egress proxy filtering: block direct outbound connections on non-standard ports (8443, 8080, 4443).
   * Mandate SSL/TLS inspection on web proxies; configure proxy to drop any TLS connection where certificate validation fails.

---

## 8. Validation Steps (Ensuring Threat Is Neutralized)

1. **Egress Verification Sweep:** Monitor perimeter network sensors for 48 hours for any retry connections to the blocked C2 IP/domain; confirm zero outbound packets.
2. **EDR Behavioral Monitoring:** Verify that newly spawned script engines on the affected host exhibit no anomalous network socket bindings.
3. **Sinkhole Telemetry Review:** Inspect DNS sinkhole logs to verify whether other previously dormant internal hosts attempt resolution of the blocked C2 domain.

---

## 9. Required Stakeholder Communications

* **Incident Commander & CISO:** Brief within 30 minutes of confirmed C2 channel establishment; present data exfiltration volume assessment.
* **Network Security / Firewall Engineering:** Coordinate emergency perimeter blocking rules and proxy configuration updates.
* **Threat Intelligence Team:** Share extracted IOCs (IP, domain, certificate SHA1, JA3) with external ISACs and threat intelligence sharing platforms.
* **Legal & Regulatory Counsel:** Notify if forensic analysis confirms exfiltration of sensitive corporate IP or regulated customer personal information.

---

## 10. Incident Closure Criteria

* Active C2 network channel completely severed and verified via perimeter traffic analysis.
* Offending process and host-side persistence mechanisms fully identified and eradicated.
* Memory forensics and volume metrics confirm whether data exfiltration occurred.
* Egress firewall policies and proxy TLS decryption policies updated to prevent recurrence.

---

## 11. Relevant MITRE ATT&CK Mapping

* [T1071.001](https://attack.mitre.org/techniques/T1071/001/) — Application Layer Protocol: Web Protocols
* [T1573.002](https://attack.mitre.org/techniques/T1573/002/) — Encrypted Channel: Asymmetric Cryptography
* [T1571](https://attack.mitre.org/techniques/T1571/) — Non-Standard Port
* [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — Command and Scripting Interpreter: PowerShell
* [T1041](https://attack.mitre.org/techniques/T1041/) — Exfiltration Over C2 Channel
