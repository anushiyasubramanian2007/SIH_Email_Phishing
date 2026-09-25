# PhishingGuard System Architecture: AI-Powered Threat Detection, Geolocation & Forensic Intelligence Platform

PhishingGuard has evolved into an end-to-end cyber threat intelligence and forensic platform addressing **Smart India Hackathon Problem Statement 26106 (AICTE Cyber Security Cell)**.

---

## 1. Dual-Core Platform Topology

```mermaid
graph TB
    subgraph Client & Analyst Layer
        EXT[Chrome MV3 Extension / Gmail DOM Shield]
        WEB_PORTAL[SOC Analyst Web Portal /dashboard]
        REST_CLIENT[External SIEM / SOAR / REST Consumers]
    end

    subgraph API Gateway & Authentication
        GW[FastAPI Gateway / Port 8000]
        CORS[CORS Policy Guard: Extension & Localhost]
        AUTH[Forensic API Key & Bearer Token Validator]
    end

    subgraph Real-Time Threat Engine
        HYBRID[Hybrid Verdict Fusion Engine]
        RULES[Static Rules & Attachment Malware Heuristics]
        NLP_RT[TF-IDF + Multi-Class AI Text Classifier]
        VT[VirusTotal v3 URL Threat Intel]
    end

    subgraph Forensic Intelligence Core
        RFC_PARSER[RFC 5322 MIME & Header Ingestion]
        AUTH_EVAL[SPF / DKIM / DMARC Cryptographic Evaluator]
        HOP_TRACER[Hop-by-Hop Transmission Tracer & Time Inversion Detector]
        ORIGIN_TRACER[Origin IP Extraction & Reliability Scorer]
        GEOIP_ENGINE[GeoIP2 / ip-api Fallback / Tor, VPN & Cloud Classifier]
        DOMAIN_INTEL[Domain Intel: DNS MX/SPF, WHOIS Age, Lookalike Levenshtein]
        FRAUD_FUSION[5-Factor Composite Fraud Scorer: 0-100]
        ATTRIBUTION[Origin Attribution & Threat Archetype Classifier]
    end

    subgraph Correlation, Graph & Case Management
        CORRELATION[Cross-Incident IOC Correlation Engine]
        CAMPAIGNS[Threat Campaign Auto-Clustering]
        GRAPH_GEN[NetworkX Threat Relationship Graph Builder]
        CASES[Case Management Lifecycle: Open, Investigate, Resolve]
    end

    subgraph Evidence Reporting & Legal Custody
        PDF_GEN[Court-Admissible PDF Generator ReportLab]
        SIEM_JSON[STIX / SIEM JSON Exporter]
        HASH_CHAIN[Append-Only SHA-256 Chained Audit Trail ISO/IEC 27037]
        PII_MASK[PII Redaction: Cards, IBAN, SSN, Phones]
    end

    subgraph Storage Layer
        SQLITE[(SQLite: Cases, Incidents, Indicators, GeoIP/Domain Caches, Audit Chain)]
    end

    EXT -->|Real-time Email/URL/File Payloads| GW
    WEB_PORTAL -->|Upload .EML / Case Management| GW
    REST_CLIENT -->|Authenticated REST API| GW

    GW --> CORS --> AUTH
    AUTH -->|Real-time Detection Routes| HYBRID
    AUTH -->|/api/forensics/*| RFC_PARSER
    AUTH -->|/api/cases/*| CASES
    AUTH -->|/api/reports/*| PDF_GEN

    HYBRID --> RULES & NLP_RT & VT

    RFC_PARSER --> AUTH_EVAL & HOP_TRACER & DOMAIN_INTEL
    HOP_TRACER --> ORIGIN_TRACER --> GEOIP_ENGINE
    AUTH_EVAL & DOMAIN_INTEL & GEOIP_ENGINE & NLP_RT --> FRAUD_FUSION
    FRAUD_FUSION --> ATTRIBUTION

    ATTRIBUTION --> CORRELATION
    CORRELATION --> CAMPAIGNS & CASES & GRAPH_GEN
    CORRELATION --> HASH_CHAIN

    CASES & CORRELATION --> PDF_GEN & SIEM_JSON

    GEOIP_ENGINE <--> SQLITE
    DOMAIN_INTEL <--> SQLITE
    CASES <--> SQLITE
    HASH_CHAIN <--> SQLITE
    HYBRID --> SQLITE
```

---

## 2. Multi-Factor Fraud Score Fusion Architecture

The forensic engine calculates an explainable composite risk score from 0 to 100 with mathematically balanced weights:

| Factor | Weight | Scoring Scope | Key Penalties & Triggers |
| :--- | :---: | :--- | :--- |
| **Factor 1: NLP Linguistic Threat** | **25%** | Multi-Class Scikit-Learn Classifier (Unigram + Bigram TF-IDF) | `bec_fraud` wire diversion (up to 25 pts), credential harvesting `phishing` (up to 25 pts), brand `impersonation` (up to 22 pts), urgency `suspicious` (up to 16 pts). |
| **Factor 2: Header & Transport Provenance** | **25%** | RFC 5322 header anomalies, display-name spoofing, hop inversions | Display name email injection (25 pts), Critical Reply-To freemail diversion (25 pts), Received hop time inversion (15 pts), From vs Return-Path mismatch (10 pts). |
| **Factor 3: Cryptographic Authentication** | **20%** | SPF, DKIM, and DMARC alignment validation | DMARC policy fail (20 pts), SPF hard failure (15 pts), DKIM fail / unaligned (10-12 pts), SPF softfail (8 pts). |
| **Factor 4: Domain Intel & Lookalike Risk** | **15%** | DNS records, WHOIS age, Levenshtein distance & homoglyphs | Lookalike brand typosquatting (15 pts), Newly Registered Domain < 30 days (12 pts), Consumer freemail diversion (10 pts), No MX records (5 pts). |
| **Factor 5: IP Infrastructure & Geolocation** | **15%** | Origin hop IP classification, ISP telemetry, TOR/VPN flags | Active Tor exit node (15 pts), Commercial VPN / bulletproof proxy (10 pts), Cloud compute relay (5 pts). |

### Risk Tiers
- **CRITICAL (75–100 pts or Tor Exit Node or Display-Name Email Injection):** Immediate containment recommended.
- **HIGH (50–74 pts or Critical BEC Freemail Diversion):** High threat risk; out-of-band verification required.
- **MEDIUM (30–49 pts):** Suspicious signals detected; proceed with heightened caution.
- **LOW (0–29 pts):** Benign corporate baseline; cryptographic and routing traces verified.

---

## 3. Operational Threat Origin Attribution Archetypes

The attribution engine classifies the adversary's operational methodology:

1. **Compromised Corporate Account / Account Takeover (ATO):**
   - *Hallmark:* Authentic SPF and DKIM pass on a legitimate enterprise domain, but headers exhibit Reply-To diversion to personal consumer webmail (e.g., Gmail) or financial wire transfer coercion.
   - *Typical Threat:* Business Email Compromise (BEC), CEO Fraud, Vendor Invoice Redirection.
2. **Direct Sender Spoofing & Identity Deception:**
   - *Hallmark:* Display name manipulation (`"CEO" <hacker@external.com>`), From vs Return-Path mismatch, or SPF/DMARC failure on spoofed domains.
   - *Typical Threat:* Executive impersonation, brand phishing.
3. **Lookalike Homoglyph / Typosquatting Domain:**
   - *Hallmark:* Visual homoglyphs (e.g. `paypa1`, `micros0ft`) or compound keyword domains (`enterprise-secure-update.com`) registered recently.
   - *Typical Threat:* Targeted credential harvesting campaigns.
4. **Anonymized Adversary Infrastructure:**
   - *Hallmark:* Earliest public hop originates from an active Tor exit node or commercial VPN proxy range.
   - *Typical Threat:* Advanced persistent threat (APT) reconnaissance or ransomware delivery.
5. **Forged Hop / Unauthenticated Relay:**
   - *Hallmark:* Negative delay deltas (time inversions) across Received headers or synthesized RFC headers.
   - *Typical Threat:* Open mail relays, manipulated delivery history.
6. **Verified Legitimate Infrastructure:**
   - *Hallmark:* Flawless cryptographic verification, consistent routing, established domain age (> 90 days), and clean reputation.

---

## 4. Complete REST API Reference

| Endpoint | Method | Auth | Description |
| :--- | :---: | :---: | :--- |
| **System & Health** | | | |
| `/api/health` | `GET` | Public | System status, version (2.0.0), and VirusTotal threat intel readiness |
| `/api/settings` | `GET`/`POST`| Restricted | Reads or safely updates runtime VirusTotal API key |
| `/dashboard` | `GET` | Public | Browser redirect to unified Web Analyst Portal |
| `/portal` | `GET` | Public | Browser redirect directly to Forensic Lab & Threat Graph interface |
| **Forensic Ingestion & Header Analysis** | | | |
| `/api/forensics/analyze` | `POST` | `X-API-Key` | Ingests `.eml` or raw RFC 5322 text. Performs SPF/DKIM/DMARC audit, origin tracing, domain intel, multi-factor fraud scoring, and origin attribution |
| `/api/forensics/graph-preview` | `POST` | `X-API-Key` | Generates D3/vis.js compatible interactive threat graph for a single email payload |
| **Case Management & Correlation** | | | |
| `/api/cases` | `POST` | `X-API-Key` | Opens a new forensic investigation case (`CASE-YYYYMMDD-XXXX`) |
| `/api/cases` | `GET` | `X-API-Key` | Lists all active investigation cases with email counts and severity |
| `/api/cases/{case_id}` | `GET` | `X-API-Key` | Retrieves single case details, status, and metadata |
| `/api/cases/{case_id}` | `PATCH`| `X-API-Key` | Updates case status (`OPEN`, `INVESTIGATING`, `CLOSED`), severity, or assignee |
| `/api/cases/{case_id}/emails` | `GET` | `X-API-Key` | Lists all emails associated with an investigation case |
| `/api/cases/{case_id}/add-email`| `POST` | `X-API-Key` | Associates an analyzed email incident with a case |
| `/api/cases/{case_id}/graph` | `GET` | `X-API-Key` | Generates full multi-node NetworkX threat relationship graph for an entire case |
| `/api/campaigns` | `GET` | `X-API-Key` | Lists automatically correlated threat campaigns sharing critical IOCs |
| `/api/indicators` | `GET` | `X-API-Key` | Queries indexed Threat Indicators (IOCs: IPs, domains, senders, ASNs, URLs) |
| **Evidence Reporting & Chain of Custody** | | | |
| `/api/reports/pdf/email` | `POST` | `X-API-Key` | Generates and streams court-admissible PDF forensic evidence report |
| `/api/reports/pdf/case/{id}`| `GET` | `X-API-Key` | Generates and streams case investigation PDF report |
| `/api/reports/json/case/{id}`| `GET` | `X-API-Key` | Exports structured STIX / SIEM JSON bundle for enterprise SOC ingestion |
| `/api/audit/chain` | `GET` | `X-API-Key` | Inspects append-only audit trail blocks |
| `/api/audit/verify` | `GET` | `X-API-Key` | Cryptographically validates entire SHA-256 audit hash chain (ISO/IEC 27037) |
| **Real-Time Client Extension Endpoints** | | | |
| `/api/analyze/email` | `POST` | Extension | Hybrid heuristic + NLP analysis of real-time webmail DOM email content |
| `/api/analyze/url` | `POST` | Extension | URL threat analysis (heuristics + VirusTotal v3) |
| `/api/analyze/attachment` | `POST` | Extension | Inspects double extensions, RTLO Unicode spoofing, macros, and file types |
| `/api/dashboard/stats` | `GET` | Extension | Aggregated incident statistics and recent logs for extension badge |

---

## 5. Security & Legal Compliance Standards
- **ISO/IEC 27037:2012:** Digital evidence handling compliance with immutable SHA-256 evidence fingerprinting and rolling cryptographic hash chaining.
- **RFC 5322 & RFC 2045:** Strict compliant MIME and Internet Message Format parsing with boundary injection safeguards.
- **Privacy & Redaction:** Built-in automated PII masking for credit card PANs, IBAN bank identifiers, Social Security / Tax IDs, and phone numbers.
