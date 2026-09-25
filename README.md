# PhishingGuard: AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

> **Smart India Hackathon (Problem Statement 26106 - AICTE Cyber Security Cell)**  
> **Evolved Full-Stack Cybersecurity & Forensic Investigation System**

---

## 🛡️ Platform Overview
PhishingGuard is an evidence-grade email threat detection and forensic intelligence platform. It operates across two complementary tiers:
1. **Real-time Client Shield (Chrome MV3 Extension):** Proactively intercepts clicks on deceptive links, analyzes webmail DOM contents (Gmail), flags suspicious attachments, and prevents user credential compromise.
2. **Forensic Intelligence & Relay Investigation Layer (FastAPI Backend):** Ingests raw `.eml` emails or RFC 5322 header traces, validates cryptographic provenance (SPF, DKIM, DMARC), reconstructs transmission hops, identifies the earliest reliable origin IP, provides geographic enrichment, detects lookalike typo-squatting domains, and produces evidence-grade forensic audit records.

---

## 🚀 Key Forensic & Detection Capabilities
- **Raw Email & Header Forensics (`POST /api/forensics/analyze`):**
  - Full RFC 5322 MIME & header parsing (`From`, `Return-Path`, `Reply-To`, `Date`, `Message-ID`, `Received` chain).
  - Cryptographic authentication parsing (`Authentication-Results`, `Received-SPF`, `DKIM-Signature`).
  - Strict DKIM domain alignment checking against `From` header domain.
  - Deep anomaly heuristics:
    - Display Name Spoofing (embedded fake addresses & brand impersonation).
    - From vs Return-Path envelope mismatch.
    - Reply-To diversion (detects freemail hijacking in BEC / invoice fraud).
    - Message-ID domain mismatch.
    - Received chain timestamp inversions (identifies fabricated hops).
- **Origin Tracing & Geolocation (`forensics/origin_tracer.py`):**
  - Traverses Received chain chronologically, filters internal RFC 1918 / loopback IPs, and extracts the earliest verified public sending IP with a reliability confidence score.
  - Enriches IP with Country, Region, City, Lat/Lon, ASN, ISP, and Organization.
  - Multi-tier resolution: Local SQLite cache -> GeoLite2 database -> `ip-api.com` fallback -> offline safe default.
  - Threat infrastructure flagging: **TOR exit nodes**, commercial **VPN / proxy / datacenter** ranges, and **hyperscaler cloud** providers.
- **Domain Intelligence & Lookalike Detection (`forensics/domain_intel.py`):**
  - WHOIS age verification, registrar lookup, and **Newly Registered Domain (NRD < 30 days)** flagging.
  - DNS MX record verification, SPF policy, and DMARC enforcement extraction.
  - **Lookalike & Homoglyph Engine:** Levenshtein edit distance, confusable leetspeak substitution (`1` <-> `l`, `0` <-> `o`, `rn` <-> `m`), and IDN Punycode homograph detection against high-profile brands.
- **Hybrid Real-Time Email Classifier:** Combines heuristic rules with machine-learning NLP (TF-IDF + Logistic Regression).
- **Proactive URL & Attachment Safeguards:** VirusTotal threat intelligence integration, magic byte inspection (PE/ELF/OLE/PDF), RTLO Unicode disguise detection, and double-extension trapping.
- **Auditable Evidence Storage:** Computes cryptographic SHA-256 digests for every ingested email and maintains an immutable incident log in SQLite.

---

## 🛠️ Technology Stack
- **Backend API:** Python 3.11, FastAPI, Uvicorn, Pydantic v2, Starlette.
- **Forensic Engine:** Python `email` library, `geoip2`, `python-whois`, `dnspython`, `dkimpy`.
- **Machine Learning:** Scikit-learn, Pandas, NumPy, Joblib.
- **Database & Persistence:** SQLite, SQLAlchemy.
- **Client Frontend:** Chrome Manifest V3, HTML5, CSS3, Vanilla JavaScript.
- **Testing:** Pytest, HTTPX test client, RFC-compliant test fixtures.

---

## ⚙️ Setup and Installation

### 1. Prerequisites
Ensure you have **Python 3.9+** installed.

### 2. Backend Setup
```bash
# 1. Navigate to the backend directory
cd backend

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate  # On Windows (PowerShell: .\venv\Scripts\Activate.ps1)

# 3. Install pinned dependencies
pip install -r requirements.txt

# 4. Configure environment variables
# Copy .env.example to .env and configure keys
cp .env.example .env

# 5. Train the AI Model
python app/ml/train.py

# 6. Start the FastAPI server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
*Or simply execute the root runner script:* `.\run_backend.ps1`

### 3. Browser Extension Setup
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `extension/` directory.
4. Pin PhishingGuard to your Chrome toolbar.

---

## 🧪 Automated Forensic Test Suite
Run the comprehensive test suite across all Phase 1 and Phase 2 modules:
```bash
cd backend
.\venv\Scripts\pytest -v tests/
```

### Included Sample Fixtures (`backend/tests/fixtures/`)
1. `legitimate_email.eml`: Clean sender, valid SPF/DKIM/DMARC pass, monotonic hops.
2. `spoofed_sender.eml`: Display name brand spoofing + Return-Path envelope mismatch.
3. `spf_fail.eml`: Unauthorized sender IP triggering hard SPF failure and DMARC violation.
4. `bec_invoice_fraud.eml`: Executive impersonation with Reply-To freemail diversion.
5. `credential_harvesting.eml`: Password expiry lure with unaligned DKIM signature.
6. `forged_received_chain.eml`: Negative relay delay with backwards arrival timestamps.
7. `tor_origin.eml`: Transmission traced through anonymized Tor exit infrastructure (`185.220.101.5`).
8. `lookalike_domain.eml`: Homoglyph/typo-squatted domain (`paypa1-service.com`).

---

## 🔒 Security Configuration
- **API Authentication:** Forensic endpoints require `X-API-Key: <FORENSIC_API_KEY>` or `Authorization: Bearer <FORENSIC_API_KEY>` header.
- **CORS Protection:** Cross-Origin Resource Sharing is strictly limited to authorized Chrome extension origins and local development hosts.
- **Offline Resilience:** All GeoIP, WHOIS, and DNS lookups feature timeouts, local SQLite caching, and offline fallbacks for reliable demonstration in network-isolated environments.
