# Hybrid Phishing URL Trap: Integrating Machine Learning and Honeypots for Cybersecurity

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0+](https://img.shields.io/badge/flask-3.0%2B-green.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-orange.svg)](https://scikit-learn.org/)
[![Security Hardened](https://img.shields.io/badge/security-hardened-red.svg)](#security-guarantees--defensive-design)
[![Tests Passing](https://img.shields.io/badge/tests-44%20passed-brightgreen.svg)](#testing)

An integrated cybersecurity defense system combining **Machine Learning lexical feature classification** with an **isolated, deceptive honeypot environment** to detect malicious phishing lures and capture threat actor interaction telemetry safely.

---

## Architecture & Data Flow

```text
Phishing URL Data / Feeds
          │
          ▼
 Lexical Feature Extraction (20 indicators)
          │
          ▼
 Machine Learning Classifier (Random Forest)
          │
          ▼
 Phishing / Suspicious / Legitimate Decision
     │                             │
     ▼ (Suspicious/Phishing)        ▼ (Legitimate)
 Controlled Honeypot Trap        Allowed / Verified
     │
     ▼
 Attacker Interaction Logging (SHA-256 Redacted)
     │
     ▼
 Behavior & Scanner Analytics
     │
     ▼
 Threat Intelligence Dashboard
     │
     ▼
 Controlled Human-in-the-Loop Feedback Loop
 (Pending ──► Analyst Approved ──► Retraining)
```

---

## Key Components

### 1. Lexical Feature Extraction (`src/features.py`)
Extracts 20 deep lexical, structural, and cybersecurity indicators from target URLs without making outbound network requests (passive inspection):
- **Core metrics**: URL length, dot count, `@` symbol detection, HTTPS protocol check, hyphen count, digit frequency.
- **Structural metrics**: Domain length, path length, path depth, slash/query/equals/ampersand counts, subdomain count.
- **Security heuristics**: IPv4 hostnames, URL shortener detection (`bit.ly`, `tinyurl.com`, etc.), Shannon entropy calculation, authentication/banking lure keywords, special character ratios.

### 2. Machine Learning Classifier (`src/classifier.py`, `train.py`, `inference.py`)
- Employs a **Random Forest Classifier** trained with 100 estimators.
- Generates continuous probability estimates calibrated into a 3-tier risk system:
  - **`PHISHING`** (High Risk: Probability &ge; 0.65)
  - **`SUSPICIOUS`** (Medium Risk: Probability 0.35 &ndash; 0.65)
  - **`SAFE`** (Low Risk: Probability &lt; 0.35)
- Domain reputation safeguard: authoritative apex domains with standard paths are protected from false positives.
- Feature importances and evaluation metrics (accuracy, precision, recall, F1, confusion matrix) are automatically serialized into `model_metadata.json`.

### 3. Defensive Honeypot Trap (`src/honeypot.py`)
- Emulates a corporate Single Sign-On (SSO) gateway (`/login` and `/api/honeypot/login`).
- Calculates interaction risk based on user-agent signatures (e.g., `sqlmap`, `nikto`, `curl`), probe paths, administrative usernames, and SQL injection tokens.
- Introduces deliberate micro-delays to thwart automated brute-force scripts.
- **Zero Plaintext Password Storage**: Automatically computes a SHA-256 fingerprint; credentials are never stored or logged in plaintext.

### 4. Database Layer (`src/database.py`)
- SQLite database (`instance/honeypot_logs.db`) using strict parameterized queries to prevent SQL injection.
- Tables:
  - `classification_events`: URL scans, predictions, confidence, risk levels, extracted features, source IP.
  - `honeypot_events`: Intrusion telemetry, source IP, user-agent, route, method, identifier, password fingerprint, metadata, risk score.
  - `feedback_samples`: Quarantined candidate URLs staged for analyst validation.
  - `model_versions`: Model metadata, metrics, and artifact tracking.
  - `login_attempt`: Backward-compatible legacy log table with redacted credentials (`[HASH:...]`).

### 5. Attacker Behavior Analytics (`src/analytics.py`)
- Performs statistical and temporal analysis over honeypot logs:
  - Top attacking IP addresses and repeated offender tracking.
  - Scanner vs. browser user-agent categorization.
  - Targeted probe route hit counts (`/login`, `/admin`, etc.).
  - Common username patterns and injection probes.
  - Hourly attack volume distribution.

### 6. Controlled Retraining Feedback Loop (`/feedback`)
- Prevents **adversarial model poisoning**: honeypot entries or suspect submissions are never directly injected into training data.
- Enters a quarantined staging queue as `pending`.
- Security analysts review and mark samples as `approved` or `rejected`. Only approved samples are used for retraining.

### 7. Security Hardening
- **Security Headers**: Injected on all HTTP responses (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection`, `Content-Security-Policy`, `Referrer-Policy`).
- **Payload Limits**: Strict 2MB ceiling (`MAX_CONTENT_LENGTH`) triggering a 413 error handler.
- **No Command Execution**: No arbitrary system execution or outbound proxying.

---

## Directory Structure

```text
cybersec_project/
├── app.py                     # Main Flask web application & API server
├── inference.py               # Standalone CLI inference tool
├── train.py                   # Model training and evaluation pipeline
├── requirements.txt           # Project Python dependencies
├── .env.example               # Environment variables template
├── .gitignore                 # Repository git exclusion rules
├── README.md                  # System documentation & usage guide
├── models/
│   ├── model.joblib           # Trained Random Forest model (serialized)
│   └── model_metadata.json    # Performance metrics, feature importances, versioning
├── classifier/                # Backward-compatibility wrappers & dataset
│   ├── app.py
│   ├── inference.py
│   ├── train.py
│   └── data/
│       └── phishing_dataset.csv
├── src/
│   ├── classifier.py          # URLClassifier class & prediction logic
│   ├── features.py            # 20-feature URL lexical extraction engine
│   ├── database.py            # SQLite schema initialization & parameterized queries
│   ├── honeypot.py            # Honeypot risk assessment & deception logic
│   ├── analytics.py           # Attacker behavioral analysis engine
│   └── data_collector.py      # Passive threat feed ingestion & deduplication
├── templates/                 # Jinja2 HTML templates
│   ├── base.html              # Base theme, navigation, and disclaimer banner
│   ├── home.html              # System overview & quick inspect
│   ├── classify.html          # Interactive URL scanner & feature inspector
│   ├── login.html             # Honeypot corporate login trap
│   ├── dashboard.html         # Threat intelligence & telemetry dashboard
│   ├── feedback.html          # Analyst candidate review & approval queue
│   ├── report.html            # Legacy honeypot report table
│   └── error.html             # Custom 404, 413, 500 error pages
├── static/
│   └── css/
│       └── main.css           # Modern cybersecurity dark theme styling
└── tests/                     # Pytest automated test suite
    ├── test_app.py            # Flask endpoints, APIs, and security headers
    ├── test_classifier.py     # Model loading, predictions, and malformed URLs
    ├── test_features.py       # Lexical feature extraction and entropy checks
    ├── test_database.py       # Parameterized queries and schema management
    ├── test_honeypot.py       # Risk scoring and credential redaction
    ├── test_analytics.py      # Behavioral metrics and scanner breakdown
    └── test_data_collector.py # Offline dataset and feed ingestion
```

---

## Quickstart & Installation

### 1. Setup Virtual Environment

```bash
# Clone or navigate to the repository
cd cybersec_project

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Re-train the Model

A high-performance pre-trained model is already included in `models/model.joblib`. To re-train or benchmark:

```bash
python train.py --sample-size 50000 --random-state 42
```

### 4. Run the Web Application

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`.

---

## CLI Inference

You can evaluate any URL directly from the terminal without starting the web server:

```bash
python inference.py https://example.com/login-verify-account
```

Output:
```text
=======================================================
 URL THREAT CLASSIFICATION REPORT 
=======================================================
 Target URL     : https://example.com/login-verify-account
 Prediction     : SUSPICIOUS
 Risk Level     : MEDIUM
 Confidence     : 52.00%
 Phishing Prob  : 52.00%
-------------------------------------------------------
 Extracted Features:
   - length                   : 42
   - num_dots                 : 1
   - has_https                : 1
   - has_suspicious_keyword   : 1
   - is_ip                    : 0
   ...
=======================================================
```

---

## REST API Documentation

### 1. Health Status
`GET /health`
```json
{
  "status": "healthy",
  "database": true,
  "model_loaded": true,
  "version": "1.0.0"
}
```

### 2. URL Classification
`POST /api/classify`
```json
// Request Body
{
  "url": "http://192.168.1.1/update-account.php"
}

// Response (200 OK)
{
  "url": "http://192.168.1.1/update-account.php",
  "prediction": "PHISHING",
  "risk_level": "HIGH",
  "confidence": 0.88,
  "phishing_probability": 0.88,
  "model_version": "1.0.0",
  "features": {
    "length": 38,
    "is_ip": 1,
    "has_suspicious_keyword": 1,
    "entropy": 3.78,
    ...
  }
}
```

### 3. Honeypot Credential Trap
`POST /api/honeypot/login`
```json
// Request Body
{
  "username": "admin",
  "password": "attempted_password"
}

// Response (401 Unauthorized)
{
  "status": "error",
  "message": "Invalid security credentials. Access denied.",
  "event_id": 14
}
```

### 4. Threat Statistics
`GET /api/stats`
```json
{
  "total_urls": 42,
  "phishing_count": 18,
  "safe_count": 20,
  "suspicious_count": 4,
  "honeypot_interactions": 15,
  "top_ips": [
    { "source_ip": "127.0.0.1", "count": 15 }
  ],
  "recent_honeypot": [ ... ],
  "recent_classifications": [ ... ]
}
```

### 5. Telemetry Events
`GET /api/events?limit=50`
Returns recent logged honeypot intrusion records.

### 6. Model Metadata
`GET /api/model-info`
Returns loaded model version, algorithm, training timestamps, and full feature names list.

---

## Cybersecurity Operations Center (SOC) Interface

The user interface is built as a dark, high-telemetry **Security Operations Center (SOC) & Threat Intelligence Platform**:

* **Brand & Visual Language**: `PHISH//TRAP` (`#06090f` midnight background, `#0d131f` charcoal HUD panels, cyber-green, cyan, warning-amber, and critical-red accents with bracketed corner frames).
* **Sidebar Navigation**: Fixed cyber-dock with real-time status pulses (`SYSTEM: ONLINE`, `MODEL: ACTIVE`, `DATABASE: CONNECTED`).
* **Header HUD**: Live UTC digital security clock, DEFCON elevated threat badge, and educational guardrail disclaimer banner.
* **Architecture Hero Visualization**: Animated 5-node cyber defense pipeline (URL Ingestion → Lexical Feature Extractor → Random Forest Classifier → Honeypot Trap → Threat Intelligence) with animated data packets.
* **URL Threat Analyzer (`/classify`)**: Real-time passive inspection checklist progression, visual 0–100 threat score risk meter, verdict alert card, and expandable 20-feature ML telemetry inspector.
* **Honeypot Decoy Trap (`/login`)**: Deceptive enterprise SSO gateway with active isolation badge indicators (`ISOLATION: ACTIVE`, `CAPTURE: ENABLED`, `OUTBOUND: BLOCKED`).
* **Threat Intelligence Center (`/dashboard`)**: Offline HTML5 Canvas threat distribution donut, activity timeline, bot/scanner heuristic breakdowns, and top attacking IP addresses.
* **Machine Learning Engine Telemetry (`/model`)**: Live telemetry cards, 20-feature decision weighting bars, and empirical test confusion matrix.
* **Human-in-the-Loop Feedback Loop (`/feedback`)**: Anti-poisoning sample staging, quarantine queue, and analyst review workflow.

---

## Testing

Run the comprehensive pytest suite covering all modules, database operations, honeypot traps, API endpoints, model telemetry, and security mechanisms:

```bash
pytest -v
```

All 44 automated unit and integration tests validate the complete system flow.

---

## Security Guarantees & Defensive Design

1. **Passive URL Processing**: URLs are strictly parsed for lexical and structural features. No outbound HTTP requests or DNS queries are made to suspect domains during classification.
2. **Credential Protection**: Plaintext passwords submitted to the honeypot are never written to disk or logs. Only cryptographic SHA-256 fingerprints are retained for credential-stuffing correlation.
3. **Sandbox Isolation**: The honeypot simulates an enterprise SSO gateway but is completely isolated from system shells, execution commands, or live databases.
4. **Adversarial Poisoning Defense**: Trapped honeypot events are quarantined in a `pending` staging table and require explicit human analyst verification before retraining.
#   h y b r i d - p h i s h i n g - u r l - t r a p  
 