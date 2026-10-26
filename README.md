# SOC Alert Tuning & False-Positive Optimizer (CLI Engine)

A lightweight security automation utility engineered to tackle alert fatigue in Security Operations Centers (SOC). The tool correlates ingested SIEM alerts against an approved benign baseline, isolates recurring noise, and automatically generates query exclusion filters for Splunk and Elastic (KQL).

## 🎯 The Problem
SOC analysts spend significant triage time manually investigating recurring, benign events caused by internal vulnerability scanners and approved administrative service accounts. Without automated feedback loops, alert queues become clogged, increasing Mean Time to Detect (MTTD) for real threats.

## 🚀 The Solution
This tool provides an automated tuning workflow:
1. **Contextual Evaluation:** Cross-references incoming alert metadata against baseline assets (vulnerability scanners, authorized service tasks, trusted subnets).
2. **Noise Classification:** Segregates actionable True Positives (escalated for incident response) from Benign Tuning Candidates.
3. **Automated SIEM Exclusions:** Generates production-ready exclusion syntax for:
   - **Splunk (SPL):** `| search NOT (...)`
   - **Elasticsearch (KQL):** `NOT (...)`

## 🛠️ Installation & Execution
```bash
pip install rich
python tuner.py
