# 🛡️ NexusSec — Enterprise Cybersecurity Analytics Platform
## Complete Technical Documentation

**Version:** 1.0  
**Classification:** Internal  
**Generated:** June 24, 2026  

---

## 1. Executive Summary
NexusSec is a production-ready, enterprise-grade Security Operations Center (SOC) analytics platform designed to continuously ingest, analyse, and respond to cybersecurity threats in real time. Built on Python/Flask with a modular architecture, it integrates machine-learning threat detection, Gemini AI-powered analysis, automated data ingestion from Grafana/Loki/Prometheus, and a modern dark-mode web dashboard — all backed by a persistent SQLite database.

The platform replaces simple proof-of-concept (POC) log scanning with a scalable pipeline capable of detecting 40+ attack categories, providing real-time alerts, vulnerability assessments, predictive risk forecasting, and one-click Excel report exports.

---

## 2. System Architecture
NexusSec follows the Flask Application Factory pattern with clearly separated concerns across modules. The high-level data flow is:

`Mock Grafana/Loki/Prometheus APIs` ➔ `Log Ingestor (APScheduler)` ➔ `Parser` ➔ `Feature Engineering` ➔ `Threat Detection Engine (ML + Signatures)` ➔ `SQLite Database` ➔ `REST API` ➔ `Dashboard Frontend`

### 2.1 Component Diagram

| Component | Technology | Responsibility |
|---|---|---|
| **Frontend (Browser)** | HTML / CSS / Vanilla JS | Polls `/api/dashboard` every 3s, renders charts and threat tables. |
| **Flask Web Server** | Python 3.13 / Flask 3.x | Serves static files, API endpoints, and the main template. |
| **REST API Layer** | `cybersec_platform/api.py` | 5 endpoints: dashboard, scan, export, start/stop-ingestion. |
| **Background Scheduler** | APScheduler 3.x | Polls mock APIs every 10–15 s, saves data to DB. |
| **Threat Detection** | Scikit-learn + RegEx | 40+ MITRE-mapped signatures + Isolation Forest + Random Forest. |
| **Gemini AI** | google-genai SDK 2.10+ | Analyses high/critical alerts & manual log scans. |
| **Database** | SQLAlchemy + SQLite | Stores logs, alerts, metrics, vulnerabilities, system health. |

---

## 3. Repository File Structure
```text
Cybersecurity POC/
├── run.py                          # Application entry point
├── main.py                         # Legacy CLI entry (retained for reference)
├── requirements.txt                # Python dependencies
├── cybersec.db                     # SQLite data store (auto-created)
├── generate_docs.py                # Script that generated the Word Document
├── NexusSec_Documentation.docx     # Word Document (binary format)
├── NexusSec_Documentation.md       # Markdown Document (plain text format)
├── cybersec_platform/              # Core application package
│   ├── __init__.py
│   ├── app.py                      # Flask app factory
│   ├── api.py                      # REST endpoints
│   ├── config.py                   # Configuration dataclass
│   ├── database.py                 # SQLAlchemy ORM models
│   ├── ingestion.py                # Background polling & pipeline
│   ├── integrations.py             # Mock Grafana/Loki/Prometheus clients
│   ├── parsing.py                  # Multi-format log parser
│   ├── feature_engineering.py      # Feature extraction & normalisation
│   ├── models.py                   # ML model wrappers (IsoForest, RF)
│   ├── threat_detection.py         # Unified detection engine
│   ├── vulnerability_assessment.py # CVE risk scoring
│   ├── predictive_analytics.py     # Trend forecasting
│   ├── gemini_client.py            # Google Gemini AI integration
│   └── utils.py                    # Shared helpers
├── static/
│   ├── dashboard.css               # Dark-mode stylesheet
│   └── dashboard.js                # Frontend logic & API polling
├── templates/
│   └── index.html                  # Main SPA template
└── tests/
    ├── test_feature_engineering.py
    └── test_parsing.py
```

---

## 4. Module Documentation

### 4.1 `database.py` — Data Persistence Layer
Defines all SQLAlchemy ORM models and initialises the SQLite database. The global `SessionLocal` factory is imported by all modules needing database access.

| Model | Table | Purpose |
|---|---|---|
| `LogEntry` | `log_entries` | Raw ingested log messages from Loki/manual scan. |
| `Alert` | `alerts` | Detected threats with severity, MITRE tactic, and Gemini AI summary. |
| `Metric` | `metrics` | Time-series Prometheus metrics (CPU, memory, network). |
| `Vulnerability` | `vulnerabilities` | Known CVEs with CVSS scores and mitigations. |
| `SystemHealth` | `system_health` | Aggregated system resource snapshots. |

### 4.2 `ingestion.py` — Background Pipeline
Implements the `LogIngestor` singleton that manages an `APScheduler` instance. Two recurring jobs run in background threads:
- **`poll_loki()`** (runs every 10s): Fetches 20 log lines from `LokiClient`, extracts features, runs `ThreatDetector`, optionally calls Gemini for High/Critical alerts, and saves results to DB.
- **`poll_prometheus()`** (runs every 15s): Fetches system metrics from `PrometheusClient`, and saves a `SystemHealth` snapshot to DB.

### 4.3 `integrations.py` — Mock API Clients
Provides realistic mock implementations of `GrafanaClient`, `LokiClient`, and `PrometheusClient`. 
- The `LokiClient` generates logs from a library of 50+ attack templates (12% attack rate) and 10 benign templates.
- The `PrometheusClient` simulates CPU/memory spikes (8% chance) and network exfiltration anomalies (3% chance).
- *To connect to a live Grafana/Loki/Prometheus stack, replace these classes with real HTTP calls.*

### 4.4 `threat_detection.py` — Detection Engine
The `ThreatDetector` class is the core of the platform. It combines two detection strategies:
- **Rule-Based Signatures:** 40+ compiled RegEx patterns mapped to MITRE ATT&CK technique IDs.
- **Machine Learning:** Isolation Forest for anomaly detection + Random Forest for multi-class threat classification.

| Attack Category | Detected Threats |
|---|---|
| **Web Application** | SQL Injection, XSS, Path Traversal, RCE, SSRF, XXE, SSTI, Deserialization, HTTP Smuggling |
| **Authentication** | Brute-Force, Password Spraying, Credential Dumping, Credential Exposure, Token Theft |
| **Privilege Escalation** | sudo/root Escalation, Container Escape, Kernel Exploits |
| **Network** | Port Scanning, DDoS/SYN Flood, MitM/ARP Poisoning, DNS Tunneling, Lateral Movement |
| **Malware** | Ransomware, Cryptominer, C2 Beacon, Fileless/LOLBins, Persistence |
| **Cloud/Infrastructure** | IMDS Abuse, K8s API Abuse, IAM Escalation, S3 Exposure |
| **Exfiltration** | Data Exfiltration, Database Dump |
| **Defense Evasion** | Log Tampering, Firewall Disable, Process Injection, SSH Tampering |
| **Initial Access** | Log4Shell/CVE Exploitation, Supply Chain Attack, Tor/Proxy, Zero-Day |
| **Discovery/Recon** | API Abuse/Scraping, VPN Abuse |

### 4.5 `gemini_client.py` — Gemini AI Integration
Uses the official `google-genai` Python SDK to call the `gemini-2.5-flash` model for two use cases:
- **`analyze_log(log_text)`** ➔ `{probability: int, reason: str}`: Used by the Manual Scan POC endpoint. Returns a 0–100 threat probability and a 1-sentence explanation.
- **`analyze_alert(threat_type, severity, raw_message)`** ➔ `str`: Called automatically by the ingestion pipeline for High/Critical alerts only. Returns a 2–3 sentence incident summary with impact assessment and mitigation recommendation.
- *Includes graceful handling of 429 quota errors from the Free Tier API.*

### 4.6 `api.py` — REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/start-ingestion` | Start the background APScheduler ingestion loop. |
| `POST` | `/api/stop-ingestion` | Stop the background APScheduler ingestion loop. |
| `GET` | `/api/dashboard` | Returns JSON: `live_threats`, `system_health`, `attack_timeline`, `vulnerability_summary`, `predictive_risk`. |
| `POST` | `/api/scan` | Manual log scan: body `{log_text}`. Returns detections, assessment, and `gemini_analysis`. |
| `GET` | `/api/export/excel` | Generates and downloads all alerts as `security_alerts_export.xlsx`. |

### 4.7 `parsing.py` — Log Parsing
Auto-detects the format of incoming log lines using heuristic probing and regex. Supported formats: JSON (structured), Apache/Nginx Combined Log, Syslog (RFC 5424 & 3164), Key=Value pairs, and plain text. Normalises all formats into a common Python dict with fields: `timestamp`, `level`, `source_ip`, `message`, `raw`.

### 4.8 `feature_engineering.py` — Feature Extraction
Converts parsed log dicts into numerical feature vectors for the ML pipeline. Extracted features include: `message_length`, `status_code`, `bytes_sent`, `cpu`, `memory`, `network_tx`, `network_rx`, `source_ip` (encoded), `log_level` (encoded), `hour_of_day`, `day_of_week`.

### 4.9 `models.py` — Machine Learning Models

| Class | Algorithm | Role |
|---|---|---|
| `AnomalyDetector` | IsolationForest (scikit-learn) | Unsupervised anomaly detection. Flags statistical outliers. |
| `ThreatClassifier` | RandomForestClassifier | Multi-class supervised. Classifies threat type. |
| `XGBoostClassifier` | XGBoost | Stub for future integration. |
| `LightGBMClassifier`| LightGBM | Stub for future integration. |
| `LSTMDetector` | PyTorch LSTM | Stub for sequence-based detection. |

### 4.10 `vulnerability_assessment.py` — Vulnerability Assessment
Analyses incoming feature batches to identify known-vulnerable software versions (e.g. Apache 2.4.49, Log4j 2.14.1) from a local CVE database. Computes a global 0–100 Organisational Risk Score based on the CVSS scores of matched CVEs.

### 4.11 `predictive_analytics.py` — Predictive Analytics
Analyses recent database trends (CPU spikes, failed login rates, alert volumes over the last hour) to forecast the probability and category of future attacks. Provides actionable mitigation recommendations.

---

## 5. Database Schema

| Table | Column | Type | Description |
|---|---|---|---|
| **`alerts`** | `id` | INTEGER | Primary Key. |
| | `timestamp` | DATETIME | Indexed; when the alert was generated. |
| | `alert_type` | VARCHAR(100) | e.g. 'SQL Injection', 'Ransomware Activity'. |
| | `severity` | VARCHAR(20) | low \| medium \| high \| critical. |
| | `description` | TEXT | Human-readable description of the threat. |
| | `source_ip` | VARCHAR(50) | Originating IP address. |
| | `confidence` | FLOAT | 0.0–1.0 ML confidence score. |
| | `mitre_tactic` | VARCHAR(100) | Comma-separated MITRE ATT&CK technique IDs. |
| | `gemini_summary` | TEXT | AI-generated incident summary (nullable). |
| **`log_entries`** | `id` | INTEGER | Primary Key. |
| | `timestamp` | DATETIME | When the log was ingested. |
| | `source` | VARCHAR(50) | e.g. 'loki', 'manual'. |
| | `level` | VARCHAR(20) | INFO \| WARN \| ERROR \| CRITICAL. |
| | `message` | TEXT | Raw log message text. |
| | `raw_data` | JSON | Parsed structured metadata. |
| **`system_health`** | `id` | INTEGER | Primary Key. |
| | `cpu_usage` | FLOAT | CPU utilisation % (0–100). |
| | `memory_usage` | FLOAT | RAM utilisation % (0–100). |
| | `network_tx` | FLOAT | Outbound bytes. |
| | `network_rx` | FLOAT | Inbound bytes. |
| | `active_connections`| INTEGER | Open TCP connections. |

---

## 6. Frontend Dashboard
The frontend is a single-page application (SPA) built with vanilla HTML, CSS, and JavaScript. It auto-polls `/api/dashboard` every 3 seconds for live data updates.

- **POC Dashboard:** Main landing tab showing live metrics, charts, alerts, and the Manual Scan form.
- **Metric Cards:** 4 live metrics: Total Threats (1h), High Severity, Critical Severity, and Org Risk Score.
- **Attack Timeline:** Chart.js bar chart showing attacks per minute over the last 60 minutes.
- **Manual Log Analysis:** Paste raw logs ➔ click 'Scan with Gemini AI' ➔ view threat probability & raw classifications.
- **Live Threat Alerts:** Table of latest 15 detected threats. High/Critical severity rows display the Gemini AI analysis inline.
- **Vulnerability Feed:** List of detected CVEs matched against incoming logs.
- **Predictive Risk:** AI forecast of the next likely attack type and mitigation recommendation.
- **Export Excel Button:** Downloads all alerts as `security_alerts_export.xlsx` via `/api/export/excel`.

---

## 7. API Reference

### 7.1 GET `/api/dashboard`
Returns live JSON data for dashboard rendering:
```json
{
  "live_threats": [
    {
      "id": 1,
      "timestamp": "2026-06-24T14:30:00Z",
      "type": "SQL Injection",
      "severity": "high",
      "description": "SQL Injection attempt detected in query parameter.",
      "source_ip": "192.168.1.45",
      "mitre": "T1190",
      "gemini_summary": "AI summary details..."
    }
  ],
  "system_health": {
    "cpu_usage": 14.5,
    "memory_usage": 62.1,
    "active_connections": 12
  },
  "attack_timeline": [
    { "time": "14:30", "count": 1 }
  ],
  "vulnerability_summary": {
    "risk_score": 45,
    "cves": []
  },
  "predictive_risk": {
    "probability": 75,
    "category": "Authentication Attack",
    "target": "Login Endpoint",
    "mitigation": "Enable rate limiting on authentication routes."
  }
}
```

### 7.2 POST `/api/scan`
Request Body:
```json
{
  "log_text": "192.168.1.1 - - [24/Jun/2026] \"GET /index.php?id=1 UNION SELECT... HTTP/1.1\" 200 4500"
}
```
Response Body:
```json
{
  "detections": [
    {
      "threat_type": "SQL Injection",
      "severity": "high",
      "confidence": 0.98,
      "mitre_tactics": "T1190",
      "signatures": ["SQLi Pattern Detected"]
    }
  ],
  "assessment": {
    "risk_score": 85,
    "cves": []
  },
  "aggregate": {},
  "gemini_analysis": {
    "probability": 95,
    "reason": "SQL injection pattern matched in query URI."
  }
}
```

### 7.3 GET `/api/export/excel`
Returns a binary Excel `.xlsx` spreadsheet download containing all logged threat alerts with their timestamps, severities, classifications, source IPs, confidence levels, MITRE Tactics, raw messages, and the detailed Gemini AI analysis summaries.

---

## 8. Dependencies
All required Python packages are specified in `requirements.txt`:
- `flask>=3.0` (Web Server Framework)
- `scikit-learn>=1.4` (Unsupervised & Supervised ML models)
- `joblib>=1.3` (Model Persistence)
- `numpy>=1.26` (Data Operations)
- `SQLAlchemy>=2.0` (Object Relational Mapper)
- `APScheduler>=3.10` (Background Jobs)
- `xgboost>=2.0` & `lightgbm>=4.0` (Future-proofing stubs)
- `google-genai>=0.1` (Official Google Gemini API SDK)
- `pandas>=2.0` (Dataframe manipulation)
- `openpyxl>=3.1` (Excel Writer Engine)
- `python-docx` (Word generation library)

---

## 9. Setup & Running the Platform

### 9.1 Prerequisites
- Python 3.11 or later
- pip (Python package manager)
- A valid Google Gemini API key

### 9.2 Installation
```bash
# 1. Navigate to the project directory
cd "Cybersecurity POC"

# 2. Install all dependencies
pip install -r requirements.txt

# 3. Run the server
python run.py

# 4. Open in browser
# Navigate to: http://127.0.0.1:5000
```

### 9.3 Configuration
The Gemini API key is configured in `cybersec_platform/gemini_client.py`. For production use, configure it via environment variables:
```python
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "your-api-key-here")
```

---

## 10. Complete Attack Detection Catalogue

| Attack Name | Severity | MITRE ID | Category |
|---|---|---|---|
| SQL Injection | High | T1190 | Web Application Attack |
| Cross-Site Scripting (XSS) | High | T1059.007 | Web Application Attack |
| Directory / Path Traversal | High | T1083 | Web Application Attack |
| Command Injection / RCE | Critical | T1059 | Remote Code Execution |
| SSRF | High | T1190 | Web Application Attack |
| XXE Injection | High | T1190 | Web Application Attack |
| SSTI | Critical | T1190 | Web Application Attack |
| Insecure Deserialization | Critical | T1211 | Web Application Attack |
| HTTP Request Smuggling | High | T1190 | Web Application Attack |
| Brute-Force Authentication | Medium | T1110 | Authentication Attack |
| Password Spraying | High | T1110.003 | Authentication Attack |
| Credential Dumping | Critical | T1003 | Credential Access |
| Credential Exposure in Logs | High | T1552 | Credential Access |
| OAuth / JWT Token Theft | High | T1528 | Credential Access |
| Privilege Escalation (sudo) | Critical | T1068 | Privilege Escalation |
| Container Escape | Critical | T1611 | Privilege Escalation |
| Kernel Exploit Attempt | Critical | T1068 | Privilege Escalation |
| Port Scanning / Recon | Medium | T1046 | Reconnaissance |
| DDoS / Volumetric Attack | High | T1498 | Network Attack |
| Man-in-the-Middle (MitM) | High | T1557 | Network Attack |
| DNS Tunneling / Exfiltration | High | T1048.003 | Exfiltration |
| Lateral Movement / PtH | Critical | T1550.002 | Lateral Movement |
| Ransomware Activity | Critical | T1486 | Malware |
| Cryptominer / Coin Miner | High | T1496 | Malware |
| Malware Download / C2 Beacon | Critical | T1105 | Malware |
| Fileless Malware / LOLBins | Critical | T1059.001 | Malware |
| Persistence Mechanism | High | T1053 | Persistence |
| Data Exfiltration | Critical | T1041 | Exfiltration |
| Database Exfiltration / Dump | Critical | T1005 | Exfiltration |
| Cloud Metadata Abuse (IMDS) | Critical | T1552.005 | Cloud Attack |
| Kubernetes API Server Abuse | Critical | T1610 | Cloud Attack |
| IAM / Permissions Abuse | High | T1078.004 | Cloud Attack |
| S3 / Cloud Storage Exposure | High | T1530 | Cloud Attack |
| Anomalous Process Execution | High | T1055 | Defense Evasion |
| Log Tampering / Anti-Forensics | Critical | T1070 | Defense Evasion |
| Firewall / Security Disabled | Critical | T1562 | Defense Evasion |
| SSH Key Tampering | High | T1098.004 | Persistence |
| VPN / Tunneling Abuse | Medium | T1133 | Initial Access |
| Tor / Anonymous Proxy | Medium | T1090.003 | Command & Control |
| Log4Shell / Known CVE Exploit | Critical | T1190 | Initial Access |
| Supply Chain / Third-Party | Critical | T1195 | Initial Access |
| API Abuse / Scraping | Medium | T1190 | Discovery |
| Zero-Day / Unknown Exploit | Critical | T1203 | Initial Access |

---

## 11. Future Roadmap

| Feature | Description |
|---|---|
| **Replace Mock Clients** | Connect `GrafanaClient`, `LokiClient`, and `PrometheusClient` to actual production endpoints. |
| **PostgreSQL Migration** | Migrate from SQLite to PostgreSQL via SQLAlchemy connection strings for production volume. |
| **LSTM / BERT Models** | Train sequence models on historical logs for advanced sequential/behavioural anomaly detection. |
| **NVD / CISA Feed Sync** | Automate vulnerability updates via scheduled syncing with NVD, MITRE ATT&CK, and CISA feeds. |
| **SOAR Integration** | Add real-time alerting integrations via webhooks for Slack, Microsoft Teams, JIRA, and PagerDuty. |
| **Multi-Tenant Support** | Implement secure multi-user role-based access control (RBAC). |
| **Custom Alert Rules UI** | Add an interactive dashboard tab allowing security analysts to write custom detection rules live. |
| **Threat Intel Enrichment** | Enrich threat alerts automatically with Geo-IP and reputation feeds (e.g. VirusTotal, IPQS, AbuseIPDB). |
| **Geo-IP Visualisation** | Render map widgets displaying spatial heatmaps of incoming alerts based on geographic source IPs. |
| **Kubernetes Deployment** | Deploy as a standard K8s application using Helm charts. |

---

## 12. Known Limitations
- **Gemini Quota Limitations:** The Free Tier key has daily limits; requests are queued and throttled gracefully.
- **Mock Integration Dependencies:** Ingestion modules currently rely on mock server simulation components.
- **Uncalibrated ML Weights:** Unsupervised models start training with seed data; precision requires real historic datasets.
- **Concurrency Bottlenecks:** SQLite might run into write lockups under heavy simultaneous requests; PostgreSQL is recommended.
- **Credential Storage:** The Gemini key in `gemini_client.py` is configured statically; use environment variables in production.
