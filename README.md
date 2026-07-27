# 🛡️ OT-Guard: PLC Logic Drift & Unauthorized Change Detection

**Built for the Adani Cyber Sanjeevni Hackathon 2026 (Track 2)**

OT-Guard is an enterprise-grade, secure-by-design microservice built to detect silent configuration drift and unauthorized logic modifications in Programmable Logic Controllers (PLCs).

## 🏭 The Problem: Silent Ladder Logic Changes
In Operational Technology (OT) environments, unauthorized modifications to PLC logic (e.g., changing a safety interlock from a Normally Open contact to a Normally Closed contact) can cause catastrophic physical impact. Traditional IT security tools fail to detect this because they lack context into industrial configurations and often trigger false positives due to normal PLC operations.

## 🏗️ The OT-Guard Architecture (Pitch-Ready)
OT-Guard is designed to operate as a passive, zero-impact edge node, solving the exact problem statement with OT-specific reality in mind.

1. **Stateless AST Parsing Engine:** Unlike naive File Integrity Monitors (FIM) that trigger false positives on volatile data (like PLC timestamps, export dates, or runtime counters), OT-Guard utilizes an `lxml` Abstract Syntax Tree (AST) parser. It strips away volatile metadata and isolates strictly the structural logic tags (e.g., `<Rung>`, `<Instruction>`).
2. **Cryptographic Baselines:** The "known good" state is mathematically locked using an HMAC-SHA256 signature. If an attacker tries to overwrite the baseline file to hide their tracks, the signature breaks.
3. **Continuous Monitoring:** Utilizing Python's `watchdog`, the engine hooks directly into the host OS to detect PLC project file updates in real-time with sub-second latency.
4. **SIEM Integration (MITRE ATT&CK for ICS):** Alerts are written to an append-only JSON Lines (`.jsonl`) ledger. Every alert is context-rich, tagging the event with **MITRE ICS Tactic T0836 (Modify Control Logic)**, making it instantly consumable by Splunk, Wazuh, or Elastic.
5. **Decoupled Microservice Deployment:** Fully containerized via Docker. The engine can be deployed on a hardened gateway next to the Engineering Workstation without touching or scanning the fragile PLCs themselves, ensuring zero latency impact on industrial processes.

## 🚀 Quickstart & Live Simulation

You can simulate an insider threat modifying a PLC configuration right on your local machine using Docker.

### 1. Start the Environment
```bash
docker-compose up -d --build
```
This boots the headless Drift Engine and the UI Dashboard.
Navigate to **http://localhost:8501** to view the live "known good" state.

### 2. Run the Cyber Attack Simulation
```bash
docker-compose run --rm attacker
```
This boots a temporary script that reaches into the shared `/plc_config` volume and maliciously alters the `active.xml` file. It simulates an attacker changing an `XIC` logic gate to an `XIO` logic gate, and modifying a safety pressure threshold from `1000` to `5000`.

### 3. Observe the Detection
Check the dashboard at **http://localhost:8501**. The engine instantly detects the drift, generates a GitHub-style visual diff of the exact ladder logic anomaly, and logs a CRITICAL SIEM alert.

## 📦 Repository Structure
- `/engine`: The core AST parsing and continuous monitoring backend.
- `/ui`: The Streamlit-based visual diff dashboard.
- `/tools`: The attacker simulation scripts for live demos.
- `/plc_config`: The mounted volume holding the dummy `baseline.xml` and `active.xml` configurations.
- `/logs`: The output directory for the SIEM-ready `drift_alerts.jsonl`.
