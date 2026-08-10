# IOC Platform

A local IOC investigation workstation. It classifies indicators, queries available threat-intelligence sources, enriches results, calculates a composite verdict, stores lookup history in SQLite, supports investigations and batch analysis, and exports results in common security formats.

The project is designed to run directly on one computer with Python, SQLite, and its bundled web interface.

## What it supports

- IP addresses, domains, URLs, email addresses, CVEs, and common hashes
- Refanging of values such as `hxxp://example[.]com`
- Multiple threat-intelligence adapters with graceful skipping when a key is absent
- DNS, WHOIS/RDAP, SSL, GeoIP, email-security, CVE, and relationship enrichment
- Composite scoring with source confidence and false-positive feedback
- Lookup history and investigation cases
- CSV/JSON batch analysis
- CSV, HTML, STIX 2.1, MISP, Splunk, ECS, and LEEF exports
- A local React user interface served by FastAPI

## Intelligence sources and what “free” means

The application never contains provider credentials. Adapter credentials are
loaded from process environment variables and `.env` through `app/backend/config.py`.
The `/api/sources` endpoint and the Source coverage panel show each provider's
IOC coverage, whether it is public or key-backed, and whether its configured
credential came from `.env` or the process environment. Secret values are never
returned.

The current source set is 19 providers:

| Source | Free/public behavior | IOC coverage |
|---|---|---|
| OpenPhish | Public phishing feed | URL |
| URLhaus | Public Abuse.ch API | URL, domain, MD5/SHA-1/SHA-256 |
| Tor Exit | Public Tor exit list/DNSBL | IPv4 |
| IPinfo | Public lite endpoint; optional token improves detail | IPv4, IPv6 |
| GreyNoise | Public community endpoint with quota; optional key | IPv4 |
| Shodan | Public InternetDB; optional key unlocks host API | IPv4 |
| urlscan.io | Public search; key required only for active submissions | URL, domain |
| StopForumSpam | Public email abuse reputation | Email |
| CIRCL HashLookup | Public hash/package corpus enrichment | MD5, SHA-1, SHA-256 |
| RDAP/DNS/CRT.sh/Cloudflare DNS | Public contextual enrichment | IPs, domains, URLs, email domains |
| CISA KEV/EPSS/NVD | Public CVE intelligence; optional NVD key for quota | CVE |
| RIPEstat | Public ASN enrichment | ASN |
| MITRE ATT&CK | Public technique/tactic enrichment | ATT&CK IDs |
| blockchain.info | Public Bitcoin address statistics | Bitcoin |
| XposedOrNot | Public breach exposure lookup | Email |
| MalwareBazaar | API key required by the current endpoint | MD5/SHA-1/SHA-256 |
| ThreatFox | API key required by the current endpoint | IPs, domains, URLs, hashes |
| VirusTotal, AbuseIPDB, OTX, Tria.ge, Hybrid Analysis, Censys, SecurityTrails, PhishTank, Spur.us | Optional API keys | Type-specific coverage shown in `/api/sources` |

Public context is not a clean verdict. If no reputation provider covers an IOC,
the result is explicitly marked as contextual/enrichment-only. Source errors,
missing keys, rate limits, and not-found responses are kept separate from the
malicious/clean score.

## Run locally

Requirements:

- Python 3.11 or newer
- Internet access for external intelligence sources
- Optional API keys for the sources you want to use

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

The browser opens at `http://127.0.0.1:8000/`. Press `Ctrl+C` in the terminal to stop the tool.

The included UI build is ready to use. Node.js is needed only when changing frontend source code:

```powershell
cd ui
npm install
npm run build
```

## Configure intelligence sources

Edit `.env` and add only the keys you have. Missing keys do not prevent the application from starting; unavailable adapters are reported as skipped or unknown.

Common variables include:

| Variable | Source |
|---|---|
| `VT_API_KEY` | VirusTotal |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `URL_SCAN_API_KEY` | urlscan.io |
| `MB_AUTH_KEY` | MalwareBazaar |
| `THREATFOX_API_KEY` | ThreatFox |
| `TRIAGE_API_KEY` | Tria.ge |
| `HA_API_KEY` | Hybrid Analysis |
| `GREYNOISE_API_KEY` | GreyNoise |
| `OTX_API_KEY` | AlienVault OTX |
| `SHODAN_API_KEY` | Shodan |
| `SECURITYTRAILS_API_KEY` | SecurityTrails |
| `CENSYS_API_KEY` | Censys (`ID:secret`) |
| `IPINFO_API_KEY` | IPinfo |

The local SQLite database is stored at `data/ioc_platform.db`. Cached task and adapter data is stored under `.cache/`.

## Main local workflows

1. Enter an IOC on the Lookup page.
2. Watch source and enrichment stages complete.
3. Review the score, verdict, source evidence, enrichment, and relationships.
4. Mark false positives when needed.
5. Save related IOCs in an investigation or process multiple values on the Batch page.
6. Export the result from the Export tab.

## Tests

Backend:

```powershell
python -m pytest -q
```

Frontend:

```powershell
cd ui
npm test
npm run lint
npm run build
```

## Useful local endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/lookup` | Start analysis |
| `GET` | `/api/tasks/{task_id}` | Read task progress |
| `GET` | `/api/tasks/{task_id}/result` | Read completed results |
| `GET` | `/api/recent` | Lookup history |
| `GET/POST` | `/api/investigations` | Investigation cases |
| `POST` | `/api/batch` | Batch analysis |
| `POST` | `/api/export/stix` | STIX export |
| `POST` | `/api/export/misp` | MISP export |
| `POST` | `/api/export/siem` | SIEM export |
| `GET` | `/api/health` | Local application health |

Interactive API documentation is available at `http://127.0.0.1:8000/docs`.
