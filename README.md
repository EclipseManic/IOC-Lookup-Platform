# IOC Universal — Threat Intelligence Lookup Platform

Universal IOC lookup, enrichment, and investigation platform. Query any indicator across 5 threat intelligence sources with real-time progress, composite scoring, deep enrichment, and investigation workflow.

## Features

- **Multi-Source Lookups**: VirusTotal, AbuseIPDB, ThreatFox, MalwareBazaar, urlscan.io
- **Real-Time Pipeline**: Live progress tracking per source during analysis
- **Composite Scoring**: Weighted score from all sources with confidence bands
- **Deep Enrichment**: GeoIP, ASN, WHOIS/RDAP, reverse DNS, DNS records, SSL certificates
- **IOC Classification**: Auto-detects IPs, domains, URLs, hashes (MD5/SHA1/SHA256), emails, CVE, and more
- **Refanging**: Defanged IOC support (`hxxp://`, `[.]`, `[:]`)
- **Investigation Workbench**: Save IOCs to cases, add notes, browse history
- **Batch Analysis**: Upload CSV/JSON with up to 500 IOCs for bulk processing
- **STIX 2.1 Export**: Industry-standard threat intel format
- **CSV/JSON Export**: Download results for SIEM ingestion
- **58 Tests**: Comprehensive test suite with pytest

## Quick Start

```bash
pip install -r requirements.txt

# Configure API keys in .env or set as environment variables
copy .env.example .env

python run.py
```

Opens at `http://localhost:8000/`

## API Keys

Set these in `.env` or as system environment variables:

| Variable | Source | Required |
|----------|--------|----------|
| `VT_API_KEY` | VirusTotal | Optional |
| `AbuseDB_API_KEY` | AbuseIPDB | Optional |
| `URL_SCAN_API_KEY` | urlscan.io | Optional |
| `MB_AUTH_KEY` | MalwareBazaar / ThreatFox | Optional |

All lookups work without API keys — sources without keys are gracefully skipped.

## Architecture

```
├── run.py                          # Entry point — uvicorn + auto-browser
├── .env                            # API key configuration
├── requirements.txt                # Python dependencies
├── pyproject.toml                  # pytest configuration
├── app/backend/
│   ├── main.py                     # FastAPI routes (lookup, investigations, batch, export)
│   ├── pipeline.py                 # Async task orchestration with real-time progress
│   ├── classifier.py               # IOC type detection + refanging
│   ├── enrichment.py               # GeoIP, WHOIS, reverse DNS, DNS, SSL
│   ├── scorer.py                   # Weighted composite scoring engine
│   ├── models.py                   # SQLAlchemy models (IOC, Investigation, LookupResult)
│   ├── database.py                 # SQLite async setup
│   ├── batch.py                    # CSV/JSON batch processing
│   ├── stix_export.py              # STIX 2.1 bundle generation + CSV export
│   └── adapters/
│       ├── base.py                 # Data models + abstract adapter
│       ├── virus_total.py          # VirusTotal API v3
│       ├── abuse_ipdb.py           # AbuseIPDB API v2
│       ├── threatfox.py            # ThreatFox API v1
│       ├── malware_bazaar.py       # MalwareBazaar API v1
│       └── urlscan_io.py           # urlscan.io API v1
├── ui/
│   ├── templates/index.html        # SPA — single HTML shell
│   └── static/
│       ├── style.css               # Dark theme (300+ lines)
│       └── app.js                  # Full app logic (600+ lines)
├── data/                           # SQLite database directory
└── tests/                          # 58 passing tests
    ├── test_classifier.py          # IOC classification + refanging
    ├── test_scorer.py              # Scoring engine
    ├── test_enrichment.py          # Enrichment pipeline
    ├── test_stix.py                # STIX/CSV export
    └── test_batch.py               # Batch processing
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/lookup` | Start IOC analysis (returns task_id) |
| `GET` | `/api/tasks/{id}` | Poll task status + progress |
| `GET` | `/api/tasks/{id}/result` | Get completed analysis results |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/recent` | Recent lookups |
| `GET` | `/api/investigations` | List all investigations |
| `POST` | `/api/investigations` | Create investigation |
| `GET` | `/api/investigations/{id}` | Get investigation with IOCs |
| `PUT` | `/api/investigations/{id}` | Update investigation |
| `DELETE` | `/api/investigations/{id}` | Delete investigation |
| `POST` | `/api/investigations/{id}/iocs` | Add IOC to investigation |
| `PUT` | `/api/investigations/{id}/iocs/{ii}` | Update IOC notes |
| `DELETE` | `/api/investigations/{id}/iocs/{ii}` | Remove IOC from investigation |
| `POST` | `/api/batch` | Start batch analysis |
| `POST` | `/api/batch/upload` | Upload CSV/JSON file for batch |
| `GET` | `/api/batch/{id}` | Poll batch status |
| `GET` | `/api/batch/{id}/result` | Get batch results |
| `POST` | `/api/export/stix` | Export STIX 2.1 bundle |
| `POST` | `/api/export/csv` | Export CSV report |
| `POST` | `/api/save` | Lookup + save to history |

## Test Suite

```bash
pytest tests/ -v
```

58 tests covering classifier, scorer, enrichment, STIX export, batch processing, and API.

## Comparison

| Feature | IOC Universal | Event-Analyzer | Malware Analyzer | Phishing Detector |
|---------|:---:|:---:|:---:|:---:|
| IOC Type Support | All | EVTX-based | File-based | Email-based |
| Threat Intel Sources | 5 | 0 | 4 | 2 |
| Real-Time Pipeline | Yes | No | WebSocket | Polling |
| Composite Scoring | Yes | No | Category-aware | Floor-based |
| Deep Enrichment | GeoIP/DNS/WHOIS/SSL | None | None | None |
| Investigation Workflow | Yes | Yes | No | No |
| Batch Analysis | Yes | No | No | No |
| STIX 2.1 Export | Yes | No | No | No |
| Test Suite | 58 | 59 | 75 | Limited |
| No Docker Required | Yes | Yes | Yes | Yes |
