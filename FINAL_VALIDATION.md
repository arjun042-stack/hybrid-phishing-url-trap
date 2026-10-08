# Hybrid Phishing URL Trap - Final Validation Report & Demo Checklist

This document provides empirical validation results and demonstration procedures for the **Hybrid Phishing URL Trap: Integrating Machine Learning and Honeypots for Cybersecurity** project.

---

## 1. Environment & Runtime Specifications

- **Operating System**: Windows 11 (AMD64)
- **Shell**: PowerShell
- **Python Version**: Python 3.13.14 (Virtual Environment in `.\venv`)
- **Key Installed Dependencies**:
  - Flask 3.1.0
  - scikit-learn 1.6.1
  - pandas 2.2.3
  - numpy 2.2.3
  - joblib 1.4.2
  - requests 2.32.3
  - python-dotenv 1.0.1
  - pytest 9.1.1
- **Working Directory**: `c:\projects\cybersec_project-20261007T091828Z-1-001\cybersec_project`

---

## 2. Automated Test Suite Results

Ran test suite via command:
```powershell
.\venv\Scripts\python.exe -m pytest -v
```

- **Total Test Cases**: 44
- **Passed**: 44 (100%)
- **Failed**: 0
- **Deprecation Warnings**: 0
- **Execution Time**: ~7.5 seconds

### Test Suites Breakdown:
1. `tests/test_features.py` (6 tests): Validates Shannon entropy, 20 lexical features, IP hostnames (with zero subdomains), shorteners, `@` symbol detection, and malformed URL safety.
2. `tests/test_classifier.py` (4 tests): Validates model persistence, safe/phishing classification, domain reputation safeguard, and empty/invalid input handling.
3. `tests/test_database.py` (4 tests): Validates SQLite table creation, parameterized queries, password fingerprinting, and feedback queue staging.
4. `tests/test_honeypot.py` (4 tests): Validates normal vs. scanner risk scores, SQL injection token detection, deception delays, and zero plaintext credential leakage.
5. `tests/test_analytics.py` (2 tests): Validates behavioral aggregation, repeated attacker tracking, targeted route counters, and scanner vs. browser metrics.
6. `tests/test_data_collector.py` (6 tests): Validates local offline ingestion, external feed fetching, network timeouts, and JSON lines deduplication.
7. `tests/test_app.py` (17 tests): Validates Flask factory, web views, `/model`, `/health`, `/api/stats`, `/api/classify`, `/api/events` (including invalid/negative limits), `/api/model-info`, `/api/honeypot/login`, `/feedback` (resilient to bad parameters), proxy-forwarded IP extraction (`X-Forwarded-For`), 404 handler, and security headers.
8. `tests/test_integration_flow.py` (1 test): Validates the full 10-step end-to-end lifecycle from URL input to analyst feedback approval.

---

## 3. Real-World Component Validation

### Machine Learning Pipeline
- **Parity**: Identical 20 features extracted in `src/features.py`, used in `train.py`, and evaluated in `src/classifier.py`.
- **Model**: Serialized Random Forest classifier in `models/model.joblib`.
- **Evaluation**: Evaluated on 8,000 empirical test samples from `phishing_dataset.csv`:
  - Accuracy: **99.58%**
  - Precision: **99.79%**
  - Recall: **99.18%**
  - F1-Score: **99.48%**
- **Test Scenarios**:
  - `https://www.google.com` &rarr; `SAFE` (Risk: LOW, Confidence: 95.0%)
  - `http://192.168.1.1/update-account.php?user=admin` &rarr; `PHISHING` (Risk: HIGH, Confidence: 100.0%)
  - `ht!tp://:::invalid-domain??!!%&&#` &rarr; `PHISHING` (Risk: HIGH, Handled gracefully without crash)
  - `""` (Empty string) &rarr; `INVALID` (Risk: UNKNOWN, No crash)
  - `http://legit.com@phish.tk/paypal/login` &rarr; `PHISHING` (Risk: HIGH, Confidence: 100.0%)

### Honeypot & Deception Engine
- **Endpoint**: `/login` (Web UI) and `/api/honeypot/login` (REST API).
- **Target Tracking**: When redirected from a suspicious URL inspection, the `target` parameter is preserved across GET and POST into the candidate feedback queue.
- **Deception**: Simulates corporate Single Sign-On (SSO) gateway rejection (`Invalid security credentials. Access denied.`) with intentional timing delays to thwart brute-force bots.
- **Credential Protection**: Plaintext passwords are **NEVER** stored in database tables or logs. Computed SHA-256 fingerprints are stored for correlation.

### Database Isolation
- Verified that specifying a custom `db_path` writes exclusively to the designated SQLite database.
- Verified that uninitialized databases automatically build all 5 tables: `honeypot_events`, `classification_events`, `feedback_samples`, `model_versions`, and `login_attempt`.

### Dashboard & Analytics
- Live telemetry displayed at `/dashboard` and `/api/stats`.
- Accurately renders total URLs, phishing detections, honeypot traps, top attacking IPs, scanner breakdown, and recent events.
- Displays clean empty states when no database records exist (no fabricated metrics).

### Controlled Feedback Loop
- Prevents adversarial model poisoning: honeypot lures are quarantined in `feedback_samples` with status `pending`.
- Security analysts review and mark samples as `approved` or `rejected` via `/feedback`.

### Security Hardening
- **Security Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection`, `Content-Security-Policy`, `Referrer-Policy`.
- **Payload Restrictions**: Enforced 2MB limit (`MAX_CONTENT_LENGTH`) with custom 413 error handler.
- **Zero Shell Execution**: No command execution, no outbound proxying, no arbitrary eval.
- **SQLi Protection**: Parameterized SQLite queries exclusively.

### Cybersecurity Operations Center (SOC) Interface Validation
- **Theme**: Premium dark SOC aesthetic (`#06090f` background, `#0d131f` HUD cards, `#00ff9d` / `#00e5ff` / `#ff3b5c` / `#ffb020` security telemetry accents).
- **Navigation**: Fixed cyber dock with live status indicators (`SYSTEM: ONLINE`, `MODEL: ACTIVE`, `DATABASE: CONNECTED`), topbar live UTC clock and DEFCON indicator.
- **Visualizations**: 100% offline HTML5 Canvas Donut and Activity Timeline charts, SVG animated node graph with data packet routing.
- **URL Threat Analyzer**: Animated 6-step lexical scanner HUD, 0–100 threat score risk meter, verdict panel, and expandable 20-feature ML telemetry table.
- **Automated Browser Subagent Validation**: Verified all 6 core pages in real headless Chromium browser:
  - `/` (Home Operations Center): Verified hero, pipeline nodes, metric cards, timeline, terminal HUD.
  - `/classify` (URL Threat Analyzer): Successfully scanned `https://suspicious-paypal-security-login.xyz/verify` &rarr; 100% Phishing verdict, High risk.
  - `/dashboard` (Threat Intelligence): Verified live charts, top IPs (`127.0.0.1`), targeted paths, bot heuristics.
  - `/model` (ML Model Telemetry): Verified Random Forest metadata, 99.53% accuracy, 20 feature weights, confusion matrix.
  - `/login` (Decoy Honeypot): Verified enterprise SSO decoy portal, isolation flags (`ISOLATION: ACTIVE`, `CAPTURE: ENABLED`, `OUTBOUND: BLOCKED`).
  - **Console Audit**: 0 JavaScript errors, 0 missing fonts/assets, clean responsive execution.

---

## 4. Known Limitations & Research Boundaries

1. **Passive Lexical Analysis**: The ML classifier analyzes URL syntax, tokens, and structural characteristics without making active HTTP requests to the target server. This prevents outbound malware exposure, but does not inspect live web page DOM contents or SSL certificate chains.
2. **Simulated SSO Honeypot**: The honeypot simulates an enterprise SSO login interface to log credential attacks. It is an isolated decoy and intentionally does not connect to any authentic identity provider.
3. **Database Concurrency**: The system utilizes SQLite, which is ideal for research labs, local testing, and educational demonstrations. For high-volume enterprise production deployments, migrating to PostgreSQL is recommended.

---

## 5. Live Demonstration Procedure (Viva / Evaluator Walkthrough)

### Step 1: Start the Application
Open PowerShell in the project directory:
```powershell
.\venv\Scripts\python.exe app.py
```
Open a browser and navigate to: `http://127.0.0.1:5000`

### Step 2: Test URL Classification
1. Click **🔍 URL Classifier** in the navigation bar.
2. Enter a legitimate URL: `https://www.google.com` &rarr; Observe **LEGITIMATE (SAFE)** verdict, low risk, and lexical indicators table.
3. Enter a phishing lure: `http://192.168.1.1/login-verify-account.php` &rarr; Observe **PHISHING (MALICIOUS)** verdict, high risk, and the automated defense action card.

### Step 3: Trigger Honeypot Deception
1. From the phishing classification result, click **🪤 Route to Honeypot** (or click **🪤 Honeypot Trap** in the top navigation).
2. Enter synthetic credentials (e.g., `attacker@victim.corp` and `MaliciousPassword!`).
3. Click **Authenticate Session** &rarr; Notice simulated access denial response and anti-brute-force timing delay.

### Step 4: Inspect Threat Intelligence Dashboard
1. Navigate to **📊 Threat Dashboard** (`/dashboard`).
2. Verify that the recent honeypot intrusion appears with:
   - Source IP address (`127.0.0.1` or client IP)
   - Targeted route (`/login`)
   - Probed username (`attacker@victim.corp`)
   - Computed threat risk rating
   - User-Agent classification
3. Observe real-time aggregate statistics updated.

### Step 5: Validate Controlled Feedback Loop
1. Navigate to **🔁 Feedback Loop** (`/feedback`).
2. Observe the trapped candidate URL staged in the review queue with status **PENDING REVIEW**.
3. Explain the anti-poisoning defense: Click **Approve** to authorize the sample for retraining dataset inclusion.

### Step 6: CLI Inference Demonstration
Open a second PowerShell terminal:
```powershell
.\venv\Scripts\python.exe inference.py http://192.168.1.1/login-verify-account.php
```
Show the structured terminal output report displaying extracted features and risk assessment.
