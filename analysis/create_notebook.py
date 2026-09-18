"""
Helper script to generate cyberion_analysis_notebook.ipynb cleanly.
"""
import json
import os

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
NB_PATH = os.path.join(WORKSPACE_ROOT, 'analysis', 'cyberion_analysis_notebook.ipynb')

notebook = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# CYBERION DEFENSE LABS — Detection Engineering & Threat Hunting Analysis Notebook\n",
                "\n",
                "**Engagement Reference:** `CDL-DET-V2`  \n",
                "**Author:** Detection Engineering & Threat Intelligence Practice  \n",
                "**Target Datasets:** Mordor APT29 Day 1 (`apt29_evals_day1_manual.zip`, Zeek network logs) & EVTX-ATTACK-SAMPLES (278 files)  \n",
                "\n",
                "This notebook documents the programmatic data analysis, statistical threat hunting calculations, and automated Sigma rule validation results."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import os\n",
                "import json\n",
                "import zipfile\n",
                "import pandas as pd\n",
                "import numpy as np\n",
                "import yaml\n",
                "from sigma.rule import SigmaRule\n",
                "\n",
                "print('All analytical libraries successfully imported.')"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 1. Threat Hunt 01: Zeek TLS C2 Beaconing Telemetry Analysis\n",
                "Parsing `datasets/mordor_apt29/zeek/ssl.log` to analyze encrypted sessions to external destination `192.168.0.4:8443`."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "ssl_log_path = os.path.join('..', 'datasets', 'mordor_apt29', 'zeek', 'ssl.log')\n",
                "c2_sessions = []\n",
                "\n",
                "with open(ssl_log_path, 'r', encoding='utf-8') as f:\n",
                "    for line in f:\n",
                "        ev = json.loads(line)\n",
                "        if ev.get('id_resp_h') == '192.168.0.4' and ev.get('id_resp_p') == 8443:\n",
                "            c2_sessions.append(ev)\n",
                "\n",
                "df_c2 = pd.DataFrame(c2_sessions)\n",
                "print(f'Total C2 Sessions Identified: {len(df_c2)}')\n",
                "print('Validation Status Breakdown:\\n', df_c2['validation_status'].value_counts())\n",
                "print('Server Subject:', df_c2['subject'].iloc[0] if len(df_c2) > 0 else 'N/A')\n",
                "print('Client JA3 Hash:', df_c2['ja3'].iloc[0] if len(df_c2) > 0 else 'N/A')"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "### Beaconing Timing Regularity & Delta Calculation\n",
                "Computing inter-arrival times between consecutive TLS sessions to evaluate jitter and beacon automation."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "timestamps = df_c2['ts'].astype(float).sort_values().values\n",
                "deltas = np.diff(timestamps)\n",
                "\n",
                "mean_delta = float(np.mean(deltas))\n",
                "std_delta = float(np.std(deltas))\n",
                "cov = std_delta / mean_delta if mean_delta > 0 else 0\n",
                "\n",
                "print(f'Mean Inter-Arrival Delta: {mean_delta:.2f} seconds')\n",
                "print(f'Standard Deviation:       {std_delta:.2f} seconds')\n",
                "print(f'Coefficient of Variation: {cov:.3f}')"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 2. Automated Rule Validation & Empirical Match Summary\n",
                "Ingesting test results from `rule-validation/rule-test-evidence/` to verify empirical dataset matches."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "evidence_dir = os.path.join('..', 'rule-validation', 'rule-test-evidence')\n",
                "summary_records = []\n",
                "\n",
                "for fname in sorted(os.listdir(evidence_dir)):\n",
                "    if fname.endswith('.json'):\n",
                "        with open(os.path.join(evidence_dir, fname), 'r', encoding='utf-8') as ef:\n",
                "            data = json.load(ef)\n",
                "            summary_records.append({\n",
                "                'Rule ID': data['rule_id'],\n",
                "                'Rule Title': data['title'],\n",
                "                'Severity': data['severity'],\n",
                "                'Matches Recorded': data['total_matches_recorded']\n",
                "            })\n",
                "\n",
                "df_rules = pd.DataFrame(summary_records)\n",
                "print(f'Total Validated Sigma Rules: {len(df_rules)}')\n",
                "df_rules"
            ]
        }
    ],
    "metadata": {
        "language_info": {
            "name": "python",
            "version": "3.13"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

with open(NB_PATH, 'w', encoding='utf-8') as f:
    json.dump(notebook, f, indent=2)

print(f"Generated {NB_PATH} successfully.")
