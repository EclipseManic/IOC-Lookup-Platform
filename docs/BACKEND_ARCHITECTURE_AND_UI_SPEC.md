# Universal IOC Lookup Platform — Backend Architecture & UI Design Specification

> **Document Version**: 2.0  
> **Target Audience**: Full-Stack Engineers, Frontend Developers, UI/UX Designers, Security Analysts  
> **Scope**: Complete architectural blueprint, data propagation pipelines, provider registries, enrichment cascades, scoring algorithms, API contracts, and UI component specifications.

---

## Table of Contents
1. [High-Level System Architecture](#1-high-level-system-architecture)
2. [Indicator Taxonomy & Classification Engine](#2-indicator-taxonomy--classification-engine)
3. [Provider & Adapter Ecosystem (Zero-Loss Extraction)](#3-provider--adapter-ecosystem-zero-loss-extraction)
4. [Enrichment Engine & Multi-Tier Fallback Cascades](#4-enrichment-engine--multi-tier-fallback-cascades)
5. [Evidence Aggregation, Scoring & Confidence Engine](#5-evidence-aggregation-scoring--confidence-engine)
6. [API & SSE Wire Protocols (Complete Schemas)](#6-api--sse-wire-protocols-complete-schemas)
7. [Frontend UI/UX Implementation Blueprint](#7-frontend-uiux-implementation-blueprint)
8. [Edge Cases, Error Handling & Health Monitoring](#8-edge-cases-error-handling--health-monitoring)

---

## 1. High-Level System Architecture

### 1.1 Architecture Diagram

```
                              ┌─────────────────────────────────────────────────────────┐
                              │                    Frontend Web App                     │
                              │       React 19 + TypeScript + Vite + Tailwind CSS        │
                              └───────────┬─────────────────────────────────▲───────────┘
                                          │                                 │
                            POST /lookup  │                                 │ SSE / Events & Polling
                                          ▼                                 │
┌───────────────────────────────────────────────────────────────────────────┴─────────────────────────────┐
│                                       FastAPI Backend Service                                           │
│                                                                                                         │
│   ┌───────────────────────────┐      ┌──────────────────────────┐      ┌───────────────────────────┐    │
│   │   Auth & Rate Limiter     ├─────►│ Classifier & Normalizer  ├─────►│   Domain-Specific Router  │    │
│   │ (TokenBucket + XFF/Proxy) │      │ (Auto-detect / Refanger) │      │  (Infrastructure/Threat)  │    │
│   └───────────────────────────┘      └──────────────────────────┘      └─────────────┬─────────────┘    │
│                                                                                      │                  │
│   ┌──────────────────────────────────────────────────────────────────────────────────┴──────────────┐   │
│   │                             Provider Dispatcher & Async Parallel Execution                      │   │
│   │                                                                                                 │   │
│   │  ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────┐  │   │
│   │  │ ThreatFox / URLhaus │   │ VirusTotal / OTX    │   │ AbuseIPDB (Verbose) │   │ Hudson Rock │  │   │
│   │  └─────────────────────┘   └─────────────────────┘   └─────────────────────┘   └─────────────┘  │   │
│   │  ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────┐  │   │
│   │  │ Tria.ge / Hybrid    │   │ Shodan InternetDB   │   │ HIBP (K-Anonymity)  │   │ urlscan.io  │  │   │
│   │  └─────────────────────┘   └─────────────────────┘   └─────────────────────┘   └─────────────┘  │   │
│   │                  [Circuit Breakers • Dynamic Retries • Per-Provider Rate Limiters]              │   │
│   └──────────────────────────────────────────┬──────────────────────────────────────────────────────┘   │
│                                              │                                                          │
│   ┌──────────────────────────────────────────┴──────────────────────────────────────────────────────┐   │
│   │                                  Deep Enrichment Engine                                         │   │
│   │                                                                                                 │   │
│   │  ┌─────────────────────────┐   ┌─────────────────────────┐   ┌───────────────────────────────┐  │   │
│   │  │ 3-Tier WHOIS Cascade    │   │ Host Intel & Open Ports │   │ Subdomain Certificate CT Logs │  │   │
│   │  │ (RDAP -> TCP -> VT)     │   │ (InternetDB -> Scan)    │   │ (crt.sh -> HackerTarget)      │  │   │
│   │  └─────────────────────────┘   └─────────────────────────┘   └───────────────────────────────┘  │   │
│   │  ┌─────────────────────────┐   ┌─────────────────────────┐   ┌───────────────────────────────┐  │   │
│   │  │ Email Security & Breaches│  │ Vulnerability Intel     │   │ Safe Recursive Hosting Pivot  │  │   │
│   │  │ (SPF/DKIM/DMARC, COMB)  │   │ (CISA KEV, EPSS, NVD)   │   │ (GreyNoise RIOT CDN Bypassing)│  │   │
│   │  └─────────────────────────┘   └─────────────────────────┘   └───────────────────────────────┘  │   │
│   └──────────────────────────────────────────┬──────────────────────────────────────────────────────┘   │
│                                              │                                                          │
│   ┌──────────────────────────────────────────▼──────────────────────────────────────────────────────┐   │
│   │                           Evidence Aggregator & Composite Scorer                                │   │
│   │  • Confidence Multipliers     • Normalized Verdict Signals     • Analyst FP Overrides           │   │
│   │  • Provider Weightings        • Evidence Strength Formula      • Coverage Ratio (0.0 - 1.0)     │   │
│   └──────────────────────────────────────────┬──────────────────────────────────────────────────────┘   │
│                                              │                                                          │
│   ┌──────────────────────────────────────────▼──────────────────────────────────────────────────────┐   │
│   │                           Task State Storage & Caching Layer                                    │   │
│   │                 In-Memory Task Registry / Redis Queue • SQLite Audit Database                   │   │
│   └─────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Indicator Taxonomy & Classification Engine

The platform ingests inputs either with **auto-detection** or explicit user selection.

### 2.1 Primary IOC Types (The Core 8)
1. **`ipv4`**: Standard 32-bit dotted-decimal IPv4 address (e.g., `192.0.2.1`).
2. **`ipv6`**: Standard 128-bit hexadecimal IPv6 address (e.g., `2001:db8::1`).
3. **`domain`**: Fully qualified domain name (e.g., `malicious-domain.com`).
4. **`url`**: Web URL with scheme or path (e.g., `https://example.com/login.php`, `example.com/payload.exe`).
5. **`md5`**: 32-character hexadecimal file hash.
6. **`sha1`**: 40-character hexadecimal file hash.
7. **`sha256`**: 64-character hexadecimal file hash.
8. **`email`**: User email address (e.g., `target@company.com`).

### 2.2 Extended Indicator Types
9. **`cve`**: Common Vulnerabilities and Exposures identifier matching `CVE-\d{4}-\d{4,7}`.
10. **`btc`**: Bitcoin wallet address (Legacy Base58 starting with `1` or `3`, or Bech32 starting with `bc1`).
11. **`eth`**: Ethereum address (`0x` followed by 40 hex characters).
12. **`username`**: Account handles or profile usernames. Supports prefixes `user:username` or `username:username`.
13. **`password`**: Cleartext passwords converted **client-side** to SHA-1 hash for privacy-preserving k-anonymity checks. Zero plaintext passwords ever cross the wire.

### 2.3 Search-Based Indicators
14. **`ssdeep`**: Context-triggered piecewise hash for fuzzy malware matching.
15. **`mutex`**: Windows mutual exclusion synchronization object name.
16. **`registry_key`**: Windows registry path.
17. **`named_pipe`**: Windows IPC named pipe (e.g., `\\.\pipe\malware_ipc`).
18. **`service_name`**: Windows system service name.

### 2.4 Defanging & Normalization Rules
Inputs often come defanged from security reports. The classifier automatically normalizes:
- Schemes: `hxxp://` or `hxxps://` $\rightarrow$ `http://` or `https://`
- Brackets: `example[.]com` $\rightarrow$ `example.com`, `192[.]168[.]1[.]1` $\rightarrow$ `192.168.1.1`
- Masked URLs: `me[at]example[dot]com` $\rightarrow$ `me@example.com`
- Whitespace and casing: Strips leading/trailing whitespace and normalizes hashes/domains to lowercase.

---

## 3. Provider & Adapter Ecosystem (Zero-Loss Extraction)

Each provider adapter queries external APIs, handles rate limits and circuit breaking, and normalizes output into `NormalizedResult`.

### 3.1 Complete Provider Master Table

| Provider | Supported Types | Auth / Key Required | Free Tier Rate Limit | Key Data Extracted |
| :--- | :--- | :--- | :--- | :--- |
| **Hudson Rock** | `email`, `domain`, `ipv4`, `ipv6`, `url`, `username` | **None** (Public OSINT) | 120 req/min | Infostealer compromise stats, stealer families, corporate credentials, exposed portals, password hygiene |
| **AbuseIPDB** | `ipv4`, `ipv6` | Free API Key | 1,000 req/day | Verbose reports (last 30 days), complaint comments, reporter countries, threat category classifications |
| **AlienVault OTX** | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256` | Free API Key | 10,000 req/day | Pulses, threat actors, malware families, `/url_list` malicious URLs, `/malware` associated hashes |
| **urlscan.io** | `url`, `domain` | Free API Key (or keyless search) | 60 req/min | WebPreviewInfo (page title, server, TLS issuer, validity days, ASN, brands, technologies, screenshot UUID) |
| **VirusTotal** | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256` | Free API Key | 4 req/min, 500/day | Positive engine detections, vendor breakdown, passive DNS, passive WHOIS attributes fallback |
| **ThreatFox** | `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256` | **None** (Public API) | 100 req/min | Active malware C2 indicators, malware family tags, confidence level, reporter info |
| **URLhaus** | `url`, `domain`, `md5`, `sha1`, `sha256` | **None** (Public API) | 100 req/min | Active malware distribution URLs, payload file status, tag taxonomy |
| **Shodan** | `ipv4` | Keyless InternetDB / Free API Key | Unlimited (InternetDB) | Open ports, service mappings, unpatched CVEs, CPE identifiers, hostnames, infrastructure tags |
| **GreyNoise** | `ipv4` | Free API Key / Keyless RIOT | 50 req/day | Mass internet scanner classification, benign/malicious intent, RIOT CDN whitelist verification |
| **HIBP** | `password`, `sha1` | **None** (Public K-Anonymity) | 300 req/min | 5-character SHA-1 prefix k-anonymity search, compromised occurrence counts |
| **StopForumSpam** | `email`, `ipv4`, `username` | **None** (Public API) | 120 req/min | Forum spammer reports, frequency, last seen timestamp |
| **AbstractAPI** | `email` | Free API Key | 100 req/month | Deliverability, MX records, SMTP checks, disposable email detection, quality score |
| **Hunter.io** | `email` | Free API Key | 25 req/month | Email verification status, MX records, disposable domain flags, web sources count |
| **Tria.ge** | `md5`, `sha1`, `sha256`, search-based | Free API Key | 60 req/min | Sandbox dynamic behavioral reports, IOC extractions, malware score |
| **Hybrid Analysis** | `md5`, `sha1`, `sha256`, search-based | Free API Key | 100 req/day | Falcon sandbox reports, threat scores, AV detections, network connections |
| **Hashlookup** | `md5`, `sha1`, `sha256` | **None** (Public CIRCL) | 120 req/min | Known good/NSRL database lookup, file names, file sizes, MIME types |
| **FileScan.io** | `md5`, `sha1`, `sha256` | **None** (Public) | 60 req/min | Multi-engine file analysis, threat level, packer detection |
| **OpenPhish** | `url` | **None** (Public Feed) | Cached local feed | Active zero-day phishing feed match |
| **Tor Exit** | `ipv4` | **None** (Public Directory) | Hourly cached list | Real-time Tor exit node membership flag |
| **ChainAbuse** | `btc`, `eth` | Free API Key | 100 req/day | Scam and ransomware report counts, victim descriptions |
| **Blockchain.info**| `btc` | **None** (Public API) | 60 req/min | Total received/sent Satoshis, final balance, transaction count |
| **Etherscan** | `eth` | Free API Key | 5 req/sec | ETH balance, transaction count |
| **cve.org / NVD** | `cve` | **None** (Public JSON) | 50 req/min | Official CVSS v3.1 base score, attack vector, severity, CPN descriptions |

---

## 4. Enrichment Engine & Multi-Tier Fallback Cascades

The enrichment engine executes auxiliary OSINT tasks in parallel with the reputation adapters. To guarantee **zero data loss**, every critical field operates on a **fallback cascade**.

```
   WHOIS Request
         │
         ├──► [Tier 1] ICANN / RIR RDAP (Structured JSON) ──(Success)──► Complete WhoisInfo
         │                 │ (Fail / 404 / Blocked)
         │                 ▼
         ├──► [Tier 2] Authoritative TCP Port 43 WHOIS   ──(Success)──► Regex-Parsed WhoisInfo
         │                 │ (Fail / Connection Refused)
         │                 ▼
         └──► [Tier 3] VirusTotal Passive WHOIS Attributes ────────────► Fallback WhoisInfo
```

### 4.1 3-Tier WHOIS Cascade
1. **Tier 1 (RDAP)**: Structured JSON query to `rdap.org` or regional internet registries (ARIN, RIPE, APNIC). Provides exact registrar, dates, status codes, and entities.
2. **Tier 2 (Authoritative Port 43 TCP WHOIS)**: Direct query to the authoritative TLD registry server discovered via IANA. Parsed via robust regex covering 25+ date and registrar formats.
3. **Tier 3 (VirusTotal Passive WHOIS Fallback)**: If live lookups fail or are rate-limited, VT passive whois attributes are parsed from cached scans.
- **Computed Indicators**:
  - `domain_age_days`: `(now - creation_date).days`
  - `is_newly_registered`: Flagged `true` if `domain_age_days < 30` (critical phishing indicator).
  - `privacy_protected`: Auto-detected if registrar or registrant contains known privacy proxy keywords (*Domains By Proxy*, *PrivacyGuardian*, *Withheld for Privacy*, etc.).
  - `fallback_tier_used`: Integer (1, 2, or 3) documenting data provenance.

### 4.2 Host Intelligence & Open Ports Matrix
- **Tier 1 (Keyless Shodan InternetDB)**: Queries `https://internetdb.shodan.io/{ip}` without any API key or quota limits. Returns:
  - `open_ports`: Integer port array.
  - `port_services`: Mapped via internal 45-port service dictionary (e.g., 22 $\rightarrow$ SSH, 3389 $\rightarrow$ RDP, 8080 $\rightarrow$ HTTP-Alt).
  - `unpatched_cves`: Known unpatched CVE strings associated with running software.
  - `cpes`: Common Platform Enumeration strings.
  - `tags`: Security posture tags (e.g., `vpn`, `tor`, `cloud`, `compromised`).
- **Tier 2 (Shodan API)**: Invoked if an API key is present and deeper banner details are required.
- **Tier 3 (Active TCP Scan)**: Non-blocking socket connect against top 15 common ports (optional, default disabled for stealth).

### 4.3 Subdomain Enumeration Cascade
- **Tier 1 (Certificate Transparency)**: Queries `crt.sh/?q=%.domain&output=json` to harvest all issued SSL/TLS certificates.
- **Tier 2 (HackerTarget Hostsearch)**: Fallback API if `crt.sh` times out or returns HTTP 502/504.

### 4.4 CDN-Aware Safe Recursive Hosting Pivot
- When analyzing a **Domain**, its `A` record is resolved to an IPv4 address.
- Before executing recursive host intelligence on that IP, it is checked against **GreyNoise RIOT (Rule It Out)**.
- If the IP belongs to a major CDN (Cloudflare, Akamai, Fastly, CloudFront, Azure Edge):
  - The pivot **short-circuits**. It marks the IP as `is_cdn = True` and displays CDN details.
  - It intentionally avoids scanning ports or attributing server CVEs to the customer's domain, eliminating false positives caused by shared edge nodes.

### 4.5 Email Security & Breach Cascade
- **DNSBL Blacklist Checks**: Executes parallel, non-blocking DNSBL queries (`zen.spamhaus.org`, `bl.spamcop.net`, `dnsbl.sorbs.net`, `b.barracudacentral.org`) in worker threads with strict 2s timeouts.
- **Email Security Protocols**: Validates SPF (`v=spf1`), DKIM (`v=DKIM1`), and DMARC (`v=DMARC1`) records.
- **Breach Aggregation**: Merges data from XposedOrNot and ProxyNova COMB into a unified breach count and date timeline.

---

## 5. Evidence Aggregation, Scoring & Confidence Engine

The scoring engine synthesizes multi-source observations into a single, transparent composite assessment.

### 5.1 Signal Mapping

| Provider Raw State / Verdict | Internal Signal | Semantic Meaning |
| :--- | :--- | :--- |
| `malicious` | `+1.0` | Active malware, phishing, C2, or exploit confirmed |
| `suspicious` | `+0.5` | High-risk attributes, low reputation, or newly registered |
| `neutral` / `record_found` | `0.0` | Informational record found with no malicious verdict |
| `clean` / `benign` | `-0.5` | Verified clean by reputable engine |
| `not_found` | `0.0` | No negative or positive reputation recorded (excluded) |
| `error` / `rate_limited` | Excluded | Network/quota failure (excluded from score calculation) |

### 5.2 Provider Weight Multipliers
Providers are assigned base weights according to detection fidelity:
- Tier 1 Top Authority (VirusTotal, MalwareBazaar, ThreatFox): `1.0 - 1.1`
- Behavioral / Sandboxes (Tria.ge, Hybrid Analysis): `0.95 - 1.0`
- Infrastructure / Network (AbuseIPDB, Shodan, GreyNoise): `0.75 - 0.85`
- OSINT / Contextual (Hudson Rock, HIBP, StopForumSpam): `0.65 - 0.76`
- Heuristic / Feeds (OpenPhish, URLhaus): `0.80 - 0.90`

### 5.3 Composite Score Calculation
$$\text{Composite Score} = \max\left(0.0, \min\left(100.0, \frac{\sum (w_i \times s_i)}{\sum w_i} \times 100\right)\right)$$

### 5.4 Final Verdict Classification
- **Critical / Malicious**: $\text{Score} \ge 70.0$ or $\ge 2$ Tier-1 providers vote malicious.
- **Suspicious**: $25.0 \le \text{Score} < 70.0$ or flagged by infostealer/breach intelligence.
- **Benign**: $\text{Score} < 25.0$ and at least 2 reputable providers confirm clean.
- **Context Only**: Informational indicators (e.g., CVEs, clean personal emails) with zero malicious signals.
- **Unknown**: Insufficient coverage ($< 2$ sources) or zero records found across all providers.

---

## 6. API & SSE Wire Protocols (Complete Schemas)

### 6.1 Start Lookup: `POST /api/lookup`
Starts an asynchronous investigation and returns immediately with a task ID.

**Request Payload:**
```json
{
  "input": "example.com",
  "ioc_type": "domain",      // Optional: auto-detected if omitted
  "refresh": false           // Optional: bypass cache if true
}
```

**Response Payload (`TaskStatusResponse`):**
```json
{
  "task_id": "8f3b2a1c9e4d",
  "status": "pending",
  "ioc_value": "example.com",
  "normalized": "example.com",
  "ioc_type": "domain"
}
```

---

### 6.2 Real-Time Task Streaming: `GET /api/tasks/{task_id}/stream`
Server-Sent Events (SSE) stream emitting real-time stage updates and provider responses.

**Event Format:**
```
event: stage
data: {"stage": "ThreatFox", "status": "running", "message": "Querying ThreatFox", "progress": 0.3}

event: stage
data: {"stage": "ThreatFox", "status": "done", "message": "Found 1 threat record", "progress": 1.0}

event: complete
data: {"task_id": "8f3b2a1c9e4d", "status": "done", "progress": 100.0}
```

---

### 6.3 Poll Task Result: `GET /api/tasks/{task_id}/result`
Retrieves the complete final assessment once `status === "done"`. If analysis is still in progress, returns HTTP `425 ("Analysis not yet complete")`.

**Response Payload (`LookupResponse`):**
```json
{
  "task_id": "8f3b2a1c9e4d",
  "input": "example.com",
  "normalized": "example.com",
  "ioc_type": "domain",
  "composite": {
    "score": 88.5,
    "verdict": "malicious",
    "confidence": "high",
    "confidence_level": "high",
    "summary": "2 providers flagged as malicious. High risk of C2 traffic.",
    "evidence_strength": 0.82,
    "coverage": 1.0,
    "needs_review": false,
    "analyst_review_recommended": false,
    "recommendation": "Block domain at firewall and DNS resolvers."
  },
  "results": [
    {
      "source": "ThreatFox",
      "status": "found",
      "verdict": "malicious",
      "provider_verdict": "malicious",
      "normalized_verdict": "malicious",
      "execution_state": "success",
      "raw_score": 100.0,
      "confidence": "high",
      "tags": ["malware:RedLine", "c2_server"],
      "provider_summary": "Active RedLine Stealer C2 host",
      "source_link": "https://threatfox.abuse.ch/",
      "raw_data": {}
    }
  ],
  "enrichment": {
    "whois": {
      "registrar": "NameCheap, Inc.",
      "creation_date": "2024-08-15T12:00:00Z",
      "expiration_date": "2025-08-15T12:00:00Z",
      "updated_date": "2024-08-20T10:00:00Z",
      "nameservers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
      "status_codes": ["clientTransferProhibited"],
      "registrant_country": "IS",
      "domain_age_days": 28,
      "is_newly_registered": true,
      "privacy_protected": true,
      "fallback_tier_used": 1
    },
    "dns": {
      "a": ["198.51.100.45"],
      "mx": ["mail.example.com"],
      "ns": ["dns1.registrar-servers.com"],
      "txt": ["v=spf1 -all"]
    },
    "subdomains": {
      "subdomains": ["api.example.com", "login.example.com", "cdn.example.com"],
      "count": 3,
      "source": "crt.sh"
    },
    "host_intel": {
      "open_ports": [80, 443, 8080],
      "port_services": {"80": "HTTP", "443": "HTTPS", "8080": "HTTP-Alt"},
      "unpatched_cves": ["CVE-2023-38606"],
      "cpes": ["cpe:/a:apache:http_server:2.4.49"],
      "tags": ["cloud", "compromised"],
      "hostnames": ["mail.example.com"],
      "source": "Shodan InternetDB"
    },
    "web_preview": {
      "screenshot_url": "/api/screenshot?scan_id=3a1b4c-uuid",
      "page_title": "Corporate Login Portal",
      "server": "nginx/1.24.0",
      "language": "en",
      "domain_age_days": 28,
      "tls_issuer": "Let's Encrypt",
      "tls_valid_days": 90,
      "asn_name": "DIGITALOCEAN-ASN",
      "detected_brands": ["Microsoft Office 365"],
      "detected_technologies": ["React", "Cloudflare", "Tailwind CSS"],
      "scan_uuid": "3a1b4c-uuid"
    },
    "infostealer": {
      "total_employee_compromises": 14,
      "total_client_compromises": 150,
      "top_corporate_services": ["vpn.example.com", "portal.example.com"],
      "top_external_services": ["github.com", "slack.com"],
      "stealer_families": {"RedLine": 12, "Lumma": 2},
      "password_strength_weak_pct": 68.2,
      "password_strength_strong_pct": 14.5,
      "total_compromised_urls": 42,
      "date_range": "2024-04-01 to 2024-08-20"
    },
    "abuse_reports": [
      {
        "reported_at": "2024-08-25T04:12:00Z",
        "reporter_country": "US",
        "comment": "SSH brute force attempts detected from this IP",
        "categories": ["18", "22"],
        "category_names": ["Brute-Force", "SSH"]
      }
    ],
    "malware_urls": [
      "http://example.com/invoice.exe",
      "http://example.com/payload.bin"
    ],
    "associated_hashes": [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ],
    "relationships": [
      {
        "source_ioc": "example.com",
        "target_ioc": "198.51.100.45",
        "relationship": "resolves_to",
        "via_source": "dns"
      }
    ],
    "completeness": {
      "whois": "ok",
      "dns": "ok",
      "subdomains": "ok",
      "host_intel": "ok"
    }
  }
}
```

---

### 6.4 Screenshot Proxy: `GET /api/screenshot?scan_id={uuid}`
Streams cached PNG screenshot bytes directly from backend memory, preventing client IP leakage to urlscan.io and resolving CSP blocking issues.

---

## 7. Frontend UI/UX Implementation Blueprint

Any UI designer or frontend engineer building against this platform should adhere to the following layout and component hierarchy:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ NAVBAR: Logo • Global Search Bar [IOC Type Dropdown] [Password Toggle] • Health & Status    │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ HERO ASSESSMENT BANNER                                                                      │
│ ┌───────────────────────┐ ┌──────────────────────────────────────┐ ┌──────────────────────┐ │
│ │  SCORE GAUGE DIAL     │ │  VERDICT BADGE (Malicious/Suspicious)│ │ CONFIDENCE & COVERAGE│ │
│ │  [ 88.5 / 100 ]       │ │  Executive Summary & Recommendation  │ │ 100% Coverage (11/11)│ │
│ └───────────────────────┘ └──────────────────────────────────────┘ └──────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ PRIMARY TAB NAVIGATION:                                                                     │
│ [ Reputations (11) ] [ Host & Vulns ] [ Infostealers ] [ Web Preview ] [ DNS & Network ]    │
├──────────────────────────────────────────────┬──────────────────────────────────────────────┤
│ LEFT COLUMN (60% Width)                      │ RIGHT COLUMN (40% Width)                     │
│                                              │                                              │
│ 1. Provider Breakdown Grid                   │ 1. Host Vulnerability Matrix                 │
│    • Provider name, verdict chip, weight     │    • Open port badges (color-coded by risk)  │
│    • Real-time latency, tags, links          │    • Active CVE IDs (with CVSS & NVD links)  │
│                                              │    • Network flags (VPN, Tor, Proxy, DC)     │
│ 2. Infostealer Exposure Card                 │                                              │
│    • Total Employee vs Client credentials    │ 2. Web Preview Card                          │
│    • Stealer family breakdown (bar chart)    │    • Live proxied screenshot thumbnail       │
│    • Compromised corporate portals list      │    • Brand impersonation alert banner        │
│    • Password hygiene weak % gauge           │    • Server banner, TLS certificate days     │
│                                              │                                              │
│ 3. Abuse Reports Timeline                    │ 3. WHOIS & Domain Provenance Card            │
│    • Sysadmin complaint comments             │    • Registrar & Domain Age Badge (<30d flag)│
│    • Threat categories & reporter country    │    • Privacy Proxy warning badge             │
│    • Pagination controls                     │    • Provenance Tier badge (Tier 1/2/3)      │
│                                              │                                              │
│ 4. Malware & C2 Indicators                   │ 4. Relationship Graph & Pivots               │
│    • Active malware URLs table               │    • Interactive pivot chips (IP, NS, MX)    │
│    • Associated file hashes (click to search)│    • Graph view linking Domain -> Host IP    │
└──────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

### 7.1 Key Visual Guidelines
1. **Color Tokens**:
   - Malicious / Critical: Crimson Red (`#EF4444` / `#DC2626`)
   - Suspicious: Amber Gold (`#F59E0B` / `#D97706`)
   - Benign / Clean: Emerald Green (`#10B981` / `#059669`)
   - Unknown / Context: Slate Gray (`#64748B` / `#475569`)
   - Information / Port Matrix: Electric Indigo (`#6366F1`)
2. **Data Provenance Badges**:
   - `Tier 1: RDAP Verified` (Cyan badge)
   - `Tier 2: Direct Port 43` (Blue badge)
   - `Tier 3: Passive VT Fallback` (Orange badge)
   - `Privacy Protected` (Purple shield badge)
   - `Newly Registered Domain (<30d)` (Red pulsating alert badge)

---

## 8. Edge Cases, Error Handling & Health Monitoring

1. **Intermittent DNS Outages (`getaddrinfo failed`)**:
   - Handled gracefully via exponential backoff retries.
   - Background threat feed tasks catch exceptions and retain warm cache, preventing event loop death.
2. **Quota & HTTP 429 Rate Limits**:
   - Individual provider 429s are isolated and classified as `execution_state = "rate_limited"`.
   - Never marked as errors or malicious signals; excluded from scoring denominators.
3. **Zero Plaintext Credential Exposure**:
   - Password lookups compute SHA-1 hash client-side before sending to `/api/lookup`.
   - Backend queries HIBP via k-anonymity 5-character prefix API (`api.pwnedpasswords.com/range/{prefix}`).
4. **Task Polling Resilience**:
   - UI polling loop tolerates transient poll hiccups (up to 20 retries) while deep enrichment completes.
   - Long-running email/domain lookups complete asynchronously within 2–4 seconds without blocking Uvicorn's main thread.
