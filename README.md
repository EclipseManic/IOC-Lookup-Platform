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
loaded from the repo `.env` file (primary) and process environment variables (fallback) through `app/backend/config.py`.
The `/api/sources` endpoint and the Source coverage panel show each provider's
IOC coverage, whether it is public or key-backed, and whether its configured
credential came from `.env` or the process environment. Secret values are never
returned.

The current source set includes 28 provider adapters, plus public enrichment
services used for context:


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
| VirusTotal, AbuseIPDB, OTX, Tria.ge, Hybrid Analysis, Censys | Optional API keys | Type-specific coverage shown in `/api/sources` |
| AbstractAPI, Hunter.io, Team Cymru | Optional API keys or public enrichment | Type-specific coverage shown in `/api/sources` |

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

The application runs the Alembic migration to `head` during startup. To inspect or
perform migrations explicitly, use `python -m alembic upgrade head`; use a
separate `DATABASE_URL` when testing migrations. Startup refuses to adopt an
unversioned SQLite file whose existing tables are missing required columns, and
`alembic downgrade` refuses to run once batch records exist, because that step
would drop batch history and `lookup_results.batch_id` associations. Back up the
database file before any downgrade attempt.

```powershell
$env:DATABASE_URL="sqlite+aiosqlite:///./data/ioc_platform.db"
python -m alembic upgrade head
```

The browser opens at `http://127.0.0.1:8000/`. Press `Ctrl+C` in the terminal to stop the tool.

The included UI build is ready to use. Node.js is needed only when changing frontend source code:

```powershell
cd ui
npm install
npm run build
```

## Configure intelligence sources

**`.env` is the primary configuration source.** This is a single-user local tool — every setting, including provider credentials, is read from the repo `.env` first; process/system environment variables are only a fallback for values `.env` does not set. `.env` is gitignored. Keep `HOST=127.0.0.1`; if another device must reach the service, set `ALLOW_NETWORK_BIND=true`, use a strong `API_KEYS` value, and set an HTTPS `BASE_URL` behind a trusted TLS reverse proxy.

```powershell
# Recommended: put keys in .env as a literal, ${REF} or bare env-var name
# VT_API_KEY=actual_key
# VT_API_KEY=${MY_VT_KEY}
# VT_API_KEY=my_vt_key   # resolves my_vt_key (.env first, then system env)

# Fallback: variables set in the shell are used only when .env does not set them
$env:VT_API_KEY="your_key"; python run.py
```

Missing keys do not prevent the application from starting; unavailable adapters are reported as skipped or unknown. Check `/api/sources` or the Sources panel to see `credential_source: environment | .env | public_no_key`.

Common variables include:

| Variable | Source |
|---|---|
| `VT_API_KEY` | VirusTotal |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `URL_SCAN_API_KEY` | urlscan.io |
| `MB_AUTH_KEY` | MalwareBazaar |
| `THREATFOX_API_KEY` | ThreatFox |
| `URLHAUS_API_KEY` | URLhaus |
| `TRIAGE_API_KEY` | Tria.ge |
| `HA_API_KEY` | Hybrid Analysis |
| `GREYNOISE_API_KEY` | GreyNoise |
| `OTX_API_KEY` | AlienVault OTX |
| `SHODAN_API_KEY` | Shodan |
| `CENSYS_API_KEY` | Censys (`ID:secret`) |
| `IPINFO_API_KEY` | IPinfo |

Credential priority — every API key is resolved as follows:
1. `.env` file value under any of the key's accepted names — the literal key, an explicit reference (`VT_API_KEY=${MY_VT_KEY}`), or a bare reference to another variable (`VT_API_KEY=my_vt_key`). References resolve through `.env` first, then the process environment.
2. Process/system environment variable (e.g. `VT_API_KEY`) — used only when `.env` does not provide the key.

Set `IOC_ENV_FILE` to load a different file, or to an empty value to disable file loading (the test suite does this so it never reads real credentials).

Additional app-level settings:

| Variable | Purpose |
|---|---|
| `API_KEYS` | Required when network binding is enabled; use strong random keys |
| `ALLOW_NETWORK_BIND` | Must be `true` for an explicit non-loopback bind; keep `false` locally |
| `BASE_URL` | Required HTTPS URL when network binding is enabled |
| `REQUIRE_NETWORK_TLS` | Defaults to `true`; keep TLS enforcement enabled for remote use |
| `TRUST_PROXY` | Trust forwarded headers only behind a controlled proxy |
| `TRUSTED_PROXY_HOSTS` | Required when `TRUST_PROXY=true`; comma-separated proxy peer addresses |
| `TRUSTED_HOSTS` | Optional comma-separated host allowlist for local or reverse-proxy access |
| `ALLOW_GLOBAL_FEEDBACK` | Keep `false` in network mode unless global analyst feedback is intentional |
| `FAIL_FAST_MISSING_KEYS` | Set to `true` to reject startup when required provider keys are missing or placeholders |
| `REDIS_URL` | Optional shared cache/rate-limit backend; unset uses local files/in-process limits |
| `WEBHOOK_SECRET_KEY` | Required when `WEBHOOKS_ENABLED=true`; encrypts stored delivery secrets |
| `ENABLE_PUBLIC_URL_SUBMISSION` | Explicit opt-in for active urlscan submissions |
| `ENABLE_URL_CONTENT_FETCH` | Explicit opt-in for remote URL content enrichment |

Summary:

- Provider keys are resolved from `.env` before the process environment; see `.env.example` for the complete list.
- HIBP password lookups use the k-anonymity range API and do not require a key.
- Host-artifact types (`mutex`, `named_pipe`, `registry_key`, `service_name`, `ssdeep`) now query Hybrid Analysis / Tria.ge search when keys are present, otherwise show structural enrichment as `context only`.
- The sample `.env.example` ships empty — copy it to `.env` and add your keys there.

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
python -m pip install -r requirements-dev.txt
python -m pytest -q
pip-audit -r requirements.txt
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
| `POST` | `/api/tasks/{task_id}/cancel` | Cancel a running analysis |
| `GET` | `/api/recent` | Lookup history |
| `GET/POST` | `/api/investigations` | Investigation cases |
| `POST` | `/api/batch` | Batch analysis |
| `POST` | `/api/batch/{batch_id}/cancel` | Cancel a running batch |
| `POST` | `/api/export/stix` | STIX export |
| `POST` | `/api/export/misp` | MISP export |
| `POST` | `/api/export/siem` | SIEM export |
| `GET` | `/api/health` | Local application health |

Interactive API documentation is available at `http://127.0.0.1:8000/docs` for
the default loopback configuration. It is disabled automatically when
`API_KEYS` is configured.
