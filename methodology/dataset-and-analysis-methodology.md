# Cyberion Defense Labs — Dataset Acquisition, Analysis, & Reproducibility Methodology

**Document Code:** `CDL-METH-REP-V2`  
**Classification:** Internal Engineering Standard  
**Engagement:** Detection Engineering & Threat Hunting Engagement (CDL-DET-V2)  
**Author:** Detection Engineering & Threat Intelligence Practice  
**Status:** Approved / Production  

---

## 1. Overview & Reproducibility Standard

A fundamental tenet of detection engineering at **Cyberion Defense Labs** is absolute analytical reproducibility. Any independent security analyst, SOC engineer, or external auditor must be able to follow this methodology document, acquire the public datasets, execute the analysis scripts, validate the detection rules, and replicate 100% of the findings, matches, and correlation results reported in this project.

No synthetic data, fabricated logs, or simulated matches were introduced. Every finding is traceable to raw, publicly verifiable telemetry.

---

## 2. Environment & Tooling Specifications

The analysis and testing environment utilizes simple, vendor-neutral open-source tools:

| Component | Tool / Library | Minimum Version | Installation / Acquisition |
| :--- | :--- | :--- | :--- |
| **Operating System** | Microsoft Windows / Linux | Windows 10/11 or Ubuntu 22.04 LTS | Standard OS environment |
| **Runtime Environment** | Python | 3.11+ (Tested on Python 3.13.14) | [python.org](https://www.python.org/) |
| **Data Analysis** | `pandas`, `numpy` | `pandas >= 2.0.0`, `numpy >= 1.24.0` | `pip install pandas numpy` |
| **Excel Generation** | `openpyxl` | `openpyxl >= 3.1.2` | `pip install openpyxl` |
| **EVTX Parser** | `python-evtx` | `python-evtx >= 0.8.1` | `pip install python-evtx` |
| **Sigma Rule Engine** | `pySigma`, `sigma-cli` | `pysigma >= 1.5.0`, `sigma-cli >= 3.1.0` | `pip install pySigma sigma-cli` |
| **YAML Processing** | `PyYAML` | `pyyaml >= 6.0.0` | `pip install pyyaml` |
| **Version Control** | Git | 2.40+ | `git --version` |

### Environment Setup Command
Execute the following command in a terminal to install all required dependencies:
```bash
pip install pandas numpy openpyxl python-evtx pySigma sigma-cli pyyaml requests
```

---

## 3. Dataset Sources & Acquisition Procedures

Two primary public repositories provide the telemetry for this engagement. Follow the exact commands below to acquire the raw data:

### Dataset 1: Mordor Project — APT29 Day 1 Adversary Emulation
* **Publisher:** Open Threat Research Forge (OTRF) / Roberto Rodriguez (@Cyb3rWard0g)
* **Repository:** [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
* **Dataset Scope:** Full endpoint telemetry (Sysmon, Windows Security, System, PowerShell Operational) and passive wire network monitoring (Zeek protocol logs).
* **Time Range:** 2020-05-02 02:46:00 UTC to 2020-05-02 04:30:00 UTC.

#### Acquisition Commands:
```bash
# Create target dataset directory
mkdir -p datasets/mordor_apt29/zeek

# 1. Download Host Endpoint Telemetry (Sysmon, Security, PowerShell) [13.9 MB compressed, 385 MB JSON]
curl -L -o datasets/mordor_apt29/apt29_evals_day1_manual.zip \
  https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip

# 2. Download Zeek Network Protocol Artifacts [Combined & Structured Zip]
curl -L -o datasets/mordor_apt29/combined_zeek.log \
  https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/zeek/combined_zeek.log

curl -L -o datasets/mordor_apt29/NASHUA-zeek_logs.zip \
  https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/zeek/NASHUA-zeek_logs.zip

# 3. Unzip Zeek protocol logs into datasets/mordor_apt29/zeek/
python -c "import zipfile; zipfile.ZipFile('datasets/mordor_apt29/NASHUA-zeek_logs.zip').extractall('datasets/mordor_apt29/zeek/')"
```

### Dataset 2: EVTX-ATTACK-SAMPLES Repository
* **Publisher:** Samir Bousseaden (@SBousseaden)
* **Repository:** [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
* **Dataset Scope:** 278 real-world Windows Event Log (`.evtx`) samples organized by MITRE ATT&CK tactics (Credential Access, Lateral Movement, Defense Evasion, Persistence, Discovery, Privilege Escalation).

#### Acquisition Command:
```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git datasets/EVTX-ATTACK-SAMPLES
```

---

## 4. Telemetry Preparation & Field Mapping

1. **Host Endpoint Telemetry (JSON Streams):**  
   The Mordor dataset `apt29_evals_day1_manual_2020-05-01225525.json` is a newline-delimited JSON (JSONL) file. Each line represents a distinct Windows Event Log structure serialized with Sysmon or Security Auditing schemas.
   * *Key Channels Parsed:* `Microsoft-Windows-Sysmon/Operational`, `Security`, `Microsoft-Windows-PowerShell/Operational`.
2. **Binary EVTX Logs:**  
   The EVTX samples are native binary XML event logs. The `python-evtx` library transforms binary chunks into structured XML trees, from which `EventID`, `Provider`, and `EventData` elements are extracted dynamically.
3. **Zeek Protocol Logs:**  
   The Zeek logs (`conn.log`, `ssl.log`, `dns.log`, `dce_rpc.log`) are structured as JSON Lines. Each record contains typed protocol fields (e.g., `ts`, `uid`, `id_orig_h`, `id_resp_h`, `id_resp_p`, `validation_status`, `subject`).

---

## 5. Sigma Rule Validation & Testing Protocol

The repository includes an automated testing harness (`analysis/rule_tester.py`) that systematically executes the two-phase validation:

### Phase 1: Syntactic & Metadata Validation
* Uses `pySigma`'s `SigmaRule.from_yaml()` to parse every YAML file in `sigma-rules/`.
* Confirms mandatory fields: `title`, `id` (UUID v4), `status`, `description`, `references`, `tags`, `falsepositives`, `level`, and severity rationale.
* Verifies condition logic (boolean combinations, modifiers like `|contains`, `|endswith`).

### Phase 2: Telemetry Replay & Evidence Collection
* Evaluates rule selection logic directly against raw events in `datasets/mordor_apt29` and `datasets/EVTX-ATTACK-SAMPLES`.
* Records matched record IDs, timestamps, image paths, user accounts, and network sockets.
* Automatically serializes match evidence into individual JSON artifacts in `rule-validation/rule-test-evidence/evidence_<rule_id>.json`.

### Replication Command:
```bash
python analysis/rule_tester.py
```
*Expected Result:*  
`Total rules validated: 17 | Passed: 17`  
All 17 rules display `[PASSED (MATCHES CONFIRMED)]`.

---

## 6. Threat Hunting Methodology & Execution

The threat hunting practice followed a structured, hypothesis-driven loop:
1. **Hypothesis Formulation:** Stating testable attacker behaviors derived from threat intelligence.
2. **Telemetry Identification:** Identifying required fields across host and network wire logs.
3. **Statistical & Behavioral Querying:** Computing inter-arrival intervals, delta timing, and clustering.
4. **Negative Control Verification:** Analyzing benign traffic to confirm true anomalies and reporting negative/inconclusive findings honestly.

### Replication Command for Threat Hunts:
```bash
python analysis/threat_hunt_analysis.py
```
*Expected Output:*
* **Hunt 01:** 376 C2 SSL sessions identified to `192.168.0.4:8443`; Mean delta = 0.64s; Certificate subject `CN=rempel.group.net`; Negative control IPs ruled out.
* **Hunt 02:** 63 records in `dicovery_4661_net_group_domain_admins_target.evtx` identified targeting `SAM_DOMAIN`, `SAM_GROUP`, and `SAM_USER`; Negative results for BloodHound in APT29 confirmed.

---

## 7. Evidence Storage & Artifact Hierarchy

All project deliverables are stored in clean, version-controlled directories:

```
cyberion-defense-labs/
├── README.md                                # Master project documentation
├── methodology/
│   └── dataset-and-analysis-methodology.md  # Reproducibility instructions (this document)
├── data-dictionary/
│   └── log-source-data-dictionary.md        # Telemetry fields, types, and detection utility
├── sigma-rules/
│   ├── windows/                             # Host endpoint Sigma detection rules
│   ├── network/                             # Network wire & socket Sigma detection rules
│   ├── authentication/                      # Auth, AD replication, & lateral movement rules
│   └── README.md                            # Rule library architecture and catalog
├── rule-validation/
│   ├── validation-results.md                # Validation report & 3 false-positive tuning passes
│   └── rule-test-evidence/                  # 17 raw JSON empirical test evidence artifacts
├── threat-hunts/
│   ├── hunt-01.md                           # Encrypted C2 Beaconing hunt report
│   └── hunt-02.md                           # Active Directory Discovery hunt report
├── incident-cases/
│   ├── case-01.md                           # APT29 Multi-Stage Endpoint Breach investigation
│   └── case-02.md                           # LSASS Dumping & Lateral Proliferation investigation
├── playbooks/
│   ├── credential-compromise.md             # Credential compromise response playbook
│   ├── lateral-movement.md                  # Lateral movement response playbook
│   └── c2-beaconing.md                      # C2 beaconing response playbook
├── ioc-research/
│   └── ioc-notes.md                         # Indicators of Compromise & operationalization
├── coverage/
│   ├── mitre-coverage-matrix.xlsx           # Excel coverage matrix (30 techniques, formatted)
│   ├── coverage-summary.md                  # Comprehensive coverage report
│   └── attack-navigator-layer.json          # MITRE ATT&CK Navigator layer JSON
├── executive-summary/
│   └── executive-summary.md                 # CISO executive briefing
├── presentation/
│   └── final-presentation-outline.md        # Technical & executive slide outline
└── analysis/
    ├── inspect_apt29.py                     # Initial dataset inspection script
    ├── extract_apt29_timeline.py            # Chronological attack timeline extractor
    ├── inspect_evtx.py                      # Fast EVTX triage utility
    ├── rule_tester.py                       # Automated rule validation & test engine
    ├── threat_hunt_analysis.py              # Statistical hunting engine (C2 & AD discovery)
    ├── generate_coverage_matrix.py          # Matrix generator (Excel, Navigator, Markdown)
    └── cyberion_analysis_notebook.ipynb     # Jupyter analysis notebook
```

---

## 8. Known Analytical Limitations

1. **Pre-Recorded Telemetry Fixed Timeframes:**  
   The analysis was performed against historical recorded adversary emulations. Dynamic response interactions (e.g., active firewall throttling or live honeypot pivoting) cannot be executed against static datasets.
2. **Network Decryption Boundary:**  
   Payload inspection for SSL sessions was limited to Zeek's TLS metadata (handshake SNI, validation status, certificates, JA3 hashes). Full plaintext HTTP payload reassembly was unavailable because the adversary used non-intercepted TLSv12 encryption.
3. **Domain Controller Event Subcategory Auditing:**  
   Certain Active Directory events (e.g., Event ID 4661) require specific non-default audit policy subcategories enabled in Group Policy. In environments where advanced auditing is unconfigured, detection reliance shifts downstream to endpoint process and share access telemetry.
