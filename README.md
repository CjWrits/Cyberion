# CYBERION DEFENSE LABS
## Managed Security Services | Detection Engineering & Threat Hunting Practice
### Product Requirements Document Implementation: Detection Engineering & Threat Hunting Engagement (CDL-DET-V2)

[![Detection Content: Sigma](https://img.shields.io/badge/Detection%20Format-Sigma%20Standard-blue.svg)](https://github.com/SigmaHQ/sigma)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20v14-orange.svg)](https://attack.mitre.org/)
[![Validation: pySigma](https://img.shields.io/badge/Validation-pySigma%20100%25-brightgreen.svg)](https://github.com/SigmaHQ/pySigma)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Classification: Internal SOC / Engineering](https://img.shields.io/badge/Classification-Engineering%20Program-red.svg)]()

---

## 1. Project Overview & Business Mandate

**Cyberion Defense Labs** is a Managed Security Service Provider (MSSP) supporting enterprise clients across financial services, healthcare, and e-commerce. Prior to this engagement, security detection content was maintained informally, without central documentation, version control, or mapping to recognized adversary attack frameworks.

This repository represents the complete, production-ready deliverables of a **four-week individual Detection Engineering and Threat Hunting sprint (CDL-DET-V2)**. It establishes an evidence-based, framework-aligned detection library, tests every rule against real attack telemetry, performs structured hypothesis-driven threat hunting, investigates confirmed findings through to root cause and closure, and authors standardized response playbooks.

### Critical Engagement Restriction
In strict accordance with the PRD specification, **no software application, backend service, web portal, live database, or automated SOAR execution playbooks were built**. The deliverables consist strictly of **detection content, empirical log analysis, threat hunting reports, incident investigation case reports, response procedures, and professional documentation**—reflecting the daily work product of a Detection Engineer and Threat Hunter in a modern SOC.

---

## 2. Key Deliverables Summary & Verification Metrics

| Category | PRD Requirement | Delivered Count | Verification & Status |
| :--- | :--- | :--- | :--- |
| **Telemetry Data Dictionary** | $\ge 3$ log source types documented | **3 Source Types** (Sysmon, Windows Security, Zeek NSM) | [Data Dictionary](data-dictionary/log-source-data-dictionary.md) complete with field semantics & detection utility. |
| **Sigma Detection Rules** | $\ge 15$ valid Sigma rules | **17 Production Rules** | [Rule Library](sigma-rules/README.md): 100% pySigma valid; 100% tested against real attack data. |
| **Correlation-Style Rules** | $\ge 3$ correlation-style rules | **3 Correlation Rules** | Host temporal sequence, host-to-lateral pivot, endpoint-to-wire network correlation. |
| **ATT&CK Coverage Matrix** | $\ge 20$ techniques across $\ge 4$ tactics | **30 Techniques across 8 Tactics** | [Excel Matrix](coverage/mitre-coverage-matrix.xlsx) (`.xlsx`), [Navigator Layer](coverage/attack-navigator-layer.json), [Summary Report](coverage/coverage-summary.md). |
| **Threat Hunt Reports** | $\ge 2$ structured hunts (1 unmonitored tech) | **2 Full Hunt Reports** | [Hunt 01 (C2 Beaconing)](threat-hunts/hunt-01.md) & [Hunt 02 (AD Discovery - T1087/T1069)](threat-hunts/hunt-02.md). |
| **Incident Case Reports** | $\ge 2$ confirmed investigations | **2 Full Case Reports** | [Case 01 (Multi-Stage Breach)](incident-cases/case-01.md) & [Case 02 (LSASS Dump & Lateral Spread)](incident-cases/case-02.md). |
| **Incident Response Playbooks**| $\ge 3$ written procedural playbooks | **3 Standard Playbooks** | [Credential Compromise](playbooks/credential-compromise.md), [Lateral Movement](playbooks/lateral-movement.md), [C2 Beaconing](playbooks/c2-beaconing.md). |
| **Rule Tuning Passes** | $\ge 3$ documented tuning passes | **3 Detailed Passes** | [Validation Report](rule-validation/validation-results.md) detailing noise analysis, logic changes, and accepted risks. |
| **Empirical Test Evidence** | 100% of submitted rules tested | **17 Evidence Files** | [Evidence Directory](rule-validation/rule-test-evidence/) containing raw JSON event matches. |
| **Methodology & Reproducibility**| Reproducible from written instructions | **100% Reproducible** | [Methodology Guide](methodology/dataset-and-analysis-methodology.md) with exact commands and analysis scripts. |
| **Executive Summary** | Non-technical CISO briefing | **Complete Briefing** | [Executive Summary](executive-summary/executive-summary.md). |
| **Final Presentation** | Executive & technical deck outline | **14-Slide Outline** | [Presentation Outline](presentation/final-presentation-outline.md). |

---

## 3. Telemetry Sources & Dataset Provenance

All analysis and validation were performed on verified, publicly documented security datasets:

1. **Mordor Project (Open Threat Research Forge):**
   * *Dataset:* `apt29_evals_day1_manual.zip` (385 MB JSONL endpoint logs) & `zeek/` (JSONL network logs).
   * *Adversary Tradecraft:* Pre-recorded emulation of **APT29 (Cozy Bear)** covering spearphishing execution, Right-to-Left Override masquerading, UAC bypasses, in-memory steganography decoding, C# compilation, and encrypted C2 beaconing.
2. **EVTX-ATTACK-SAMPLES Repository:**
   * *Dataset:* 278 real-world Windows event log samples (`.evtx`) mapped to MITRE ATT&CK techniques.
   * *Coverage:* Active Directory replication (DCSync), Mimikatz Pass-the-Hash, Event Log clearing, remote share manipulation, and DSRM password resets.

---

## 4. Final Repository Structure

```
cyberion-defense-labs/
├── README.md                                # Master documentation & project guide (this file)
├── methodology/
│   └── dataset-and-analysis-methodology.md  # Complete reproducibility guide, tools, and commands
├── data-dictionary/
│   └── log-source-data-dictionary.md        # Comprehensive data dictionary for Sysmon, Security, & Zeek
├── sigma-rules/
│   ├── windows/                             # Host execution, registry, memory, & log tampering rules
│   │   ├── proc_creation_win_masquerading_rlo.yml
│   │   ├── proc_creation_win_uac_bypass_sdclt.yml
│   │   ├── proc_creation_win_powershell_steganography_bitmap.yml
│   │   ├── registry_set_win_uac_bypass_folder_command.yml
│   │   ├── proc_creation_win_csc_compilation_from_powershell.yml
│   │   ├── proc_access_win_lsass_suspicious_access.yml
│   │   ├── security_event_win_audit_log_cleared.yml
│   │   ├── registry_set_win_persistence_hidden_run_key.yml
│   │   └── correlation_win_uac_bypass_to_elevated_shell.yml
│   ├── authentication/                      # Credential harvesting, AD replication, & share access rules
│   │   ├── security_event_win_pth_logon_type_9.yml
│   │   ├── security_event_win_dcsync_replication_access.yml
│   │   ├── security_event_win_dsrm_password_reset.yml
│   │   ├── security_event_win_remote_share_file_write.yml
│   │   └── correlation_win_credential_dump_to_lateral_pivot.yml
│   ├── network/                             # Network wire & socket communication rules
│   │   ├── net_zeek_ssl_self_signed_cert_c2.yml
│   │   ├── net_sysmon_powershell_external_socket.yml
│   │   └── correlation_win_endpoint_powershell_to_zeek_c2_burst.yml
│   └── README.md                            # Rule catalog, UUID mapping, and severity standards
├── rule-validation/
│   ├── validation-results.md                # Automated test results & 3 documented false-positive tuning passes
│   └── rule-test-evidence/                  # 17 raw JSON empirical test match evidence artifacts
│       ├── evidence_01753072-e2ec-4d43-a3f8-1edf1ab511f0.json
│       ├── evidence_057de226-ae47-4d2e-9fc3-47935bcfe860.json
│       ├── evidence_38301c3f-4ba5-4217-9339-c27ff47e3944.json
│       ├── evidence_67e22644-d440-4b97-b1bd-7216bd270178.json
│       ├── evidence_6b9079cd-604b-420a-a248-8e636962235d.json
│       ├── evidence_7b4581c2-d581-4986-b697-1ae7c04a9dcd.json
│       ├── evidence_7cb39dc7-ae81-47a1-b36c-2581534b9a17.json
│       ├── evidence_7d5fb47e-fea1-4173-b030-520a167c2bd5.json
│       ├── evidence_833d9d64-5164-42f3-879b-b7b5e8e135cf.json
│       ├── evidence_ab9c4e58-f323-4524-b02c-44d8ef3d6e02.json
│       ├── evidence_bc5f23b7-7515-42b3-af7e-ae53aaa6ce4c.json
│       ├── evidence_cacaf252-f706-446a-8b88-0516e962cfb4.json
│       ├── evidence_d14d6b0c-8349-44c8-a5f8-2fc89299cb9e.json
│       ├── evidence_d5f41248-645d-49da-a048-6f1b6f0f0496.json
│       ├── evidence_f4c1fd22-9035-4b9d-88ed-54184d9480e1.json
│       ├── evidence_f62006ac-158a-4162-a48f-6547c0768b43.json
│       └── evidence_fbf66860-6faf-4c5f-babb-5ed0417f6836.json
├── threat-hunts/
│   ├── hunt-01.md                           # Hunt 01: Encrypted C2 Beaconing via Untrusted TLS (Confirmed C2)
│   └── hunt-02.md                           # Hunt 02: Active Directory Discovery (Uncovered Technique Gap)
├── incident-cases/
│   ├── case-01.md                           # Case 01: Multi-Stage APT29 Breach (Timeline, Root Cause, TP)
│   └── case-02.md                           # Case 02: LSASS Credential Theft & Lateral Proliferation (TP)
├── playbooks/
│   ├── credential-compromise.md             # Standard Operating Procedure for Credential Compromise
│   ├── lateral-movement.md                  # Standard Operating Procedure for Lateral Movement
│   └── c2-beaconing.md                      # Standard Operating Procedure for C2 Beaconing
├── ioc-research/
│   └── ioc-notes.md                         # Extracted Indicators of Compromise & operationalization
├── coverage/
│   ├── mitre-coverage-matrix.xlsx           # Excel Coverage Matrix (30 techniques, professionally styled)
│   ├── coverage-summary.md                  # Coverage report, tactical heatmap, and gap analysis
│   └── attack-navigator-layer.json          # MITRE ATT&CK Navigator layer export
├── executive-summary/
│   └── executive-summary.md                 # CISO executive briefing & strategic recommendations
├── presentation/
│   └── final-presentation-outline.md        # 14-slide technical & executive presentation deck outline
└── analysis/
    ├── inspect_apt29.py                     # Raw dataset inspection script
    ├── extract_apt29_timeline.py            # Chronological attack timeline extractor
    ├── inspect_evtx.py                      # Fast EVTX log triage utility
    ├── rule_tester.py                       # Automated rule validation & dataset testing engine
    ├── threat_hunt_analysis.py              # Statistical hunting engine (inter-arrival deltas, CoV)
    ├── generate_coverage_matrix.py          # Matrix generator (Excel, Navigator JSON, Markdown)
    ├── create_notebook.py                   # Analysis notebook generator
    └── cyberion_analysis_notebook.ipynb     # Jupyter analysis notebook
```

---

## 5. Quick-Start & Verification Instructions

Follow these steps to reproduce the entire project verification on any workstation:

### Step 1: Install Dependencies
```bash
pip install pandas numpy openpyxl python-evtx pySigma sigma-cli pyyaml requests
```

### Step 2: Run Automated Sigma Validation & Telemetry Testing
```bash
python analysis/rule_tester.py
```
*Outputs:* Validates all 17 rules with `pySigma`, replays datasets, confirms true-positive matches, and generates evidence in `rule-validation/rule-test-evidence/`.

### Step 3: Run Threat Hunting Statistical Calculations
```bash
python analysis/threat_hunt_analysis.py
```
*Outputs:* Computes inter-arrival delta times, jitter coefficients of variation, and Active Directory object queries for Hunt 01 and Hunt 02.

### Step 4: Regenerate Coverage Matrix & Navigator Layer
```bash
python analysis/generate_coverage_matrix.py
```
*Outputs:* Refreshes `coverage/mitre-coverage-matrix.xlsx`, `coverage/attack-navigator-layer.json`, and `coverage/coverage-summary.md`.

---

## 6. Project Milestone Timeline (4-Week Implementation)

This project was developed strictly following the 4-week structured sprint plan:
* **Week 1 (Data Familiarization & Baseline):** Datasets selected; 3 telemetry source types analyzed; data dictionary completed; 5 target techniques justified; Git initialized.
* **Week 2 (Detection Engineering & Validation):** 17 Sigma rules authored (including 3 correlations); automated testing engine built; 100% telemetry verification achieved; rule tuning passes documented.
* **Week 3 (Threat Hunting & Incident Investigations):** 2 hypothesis-driven threat hunts executed; confirmed findings escalated; Case 01 and Case 02 investigated with raw log timelines; 3 incident response playbooks authored.
* **Week 4 (Finalization & Governance):** 30-technique coverage matrix completed in Excel and Navigator formats; IOC research notes finalized; executive summary and presentation deck outline delivered; documentation internally reviewed for traceability.

---

## 7. License & Compliance

All detection rules and analytical scripts are published under the **MIT License**. Telemetry samples originate from publicly released research datasets by the Open Threat Research Forge (OTRF) and Samir Bousseaden under standard open-access licenses. No confidential client data or intellectual property is contained within this repository.
