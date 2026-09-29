# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-user, local IOC (indicator of compromise) investigation workstation: a FastAPI backend (`app/backend/`) that classifies an indicator, fans it out to ~28 threat-intel provider adapters plus public enrichment services, scores the evidence into a verdict, and persists history in SQLite. A React 19 + Vite + Tailwind 4 UI (`ui/`) is built into `ui/dist/` and served by FastAPI at `/`.

## Commands

Backend (Python ≥3.11, run from repo root):

```powershell
pip install -r requirements-dev.txt
python run.py                                   # start app on 127.0.0.1:8000 (runs alembic upgrade head on startup, opens browser)
python -m pytest -q                             # full suite
python -m pytest tests/test_scorer.py -q        # single file
python -m pytest tests/test_scorer.py::test_name -q   # single test
python -m alembic upgrade head                  # explicit migration
python -m alembic check                         # CI: fails if models.py and migrations disagree
python -m compileall -q app tests               # CI syntax check
pip-audit -r requirements.txt
```

Frontend (Node ≥20.19, from `ui/`):

```powershell
npm run dev          # Vite on :5173, proxies /api (incl. SSE) to :8000 — run backend too
npm test             # vitest run (jsdom)
npx vitest run src/components/__tests__/SearchBar.test.tsx   # single test file
npm run lint
npm run build        # tsc --noEmit && vite build -> ui/dist
```

CI (`.github/workflows/ci.yml`) runs compileall, `alembic upgrade head`, `alembic check`, pytest, pip-audit for the backend and test/lint/build/`npm audit --audit-level=high` for the UI.

Notes:
- `ui/dist/` is committed and is what `python run.py` serves. After changing `ui/src`, run `npm run build` so the served UI matches.
- `tests/conftest.py` points `DATABASE_URL` at a per-process temp SQLite file before any app import; tests never touch `data/ioc_platform.db`. Keep that ordering if adding fixtures that import app modules.
- `tests/test_api_keys_live.py` is skipped unless `RUN_LIVE_API_TESTS=1`. `tests/api_keys_deep_check.py` is a standalone script (not collected by pytest) that makes real calls with configured keys.
- pytest uses `asyncio_mode = "auto"`; async tests need no decorator.

## Architecture

### Lookup flow

`POST /api/lookup` (`main.py`) → `pipeline.run_analysis()` runs as a background task identified by `task_id`. The UI follows progress via `GET /api/tasks/{id}` polling or `/api/tasks/{id}/stream` (SSE), then fetches `/api/tasks/{id}/result`.

Inside `run_analysis` (`pipeline.py`):
1. **Classify/normalize** – `classifier.normalize_ioc` refangs and detects the type (IPs, domains, URLs, emails, hashes, CVEs, crypto addresses, host artifacts, passwords, etc.). Passwords are replaced by a digest immediately and never stored raw.
2. **Route & plan** – `domain_router.route_assessment_domain` assigns an assessment domain (e.g. `vulnerability`, `credential_exposure`, `infrastructure`); `provider_capabilities.build_provider_plan` decides which adapters apply. The UI's stage list is rebuilt from this plan, so a provider that's not applicable doesn't appear. Private/reserved IPs short-circuit with no external lookups.
3. **Provider fan-out** – the pipeline (not the adapters) owns concurrency, per-provider rate limiting (`rate_limiter.py`), bounded retries with `Retry-After`, circuit breaking, caching (`cache.py`: file-based under `.cache/`, or Redis if `REDIS_URL`), and the per-IOC / batch deadlines. Providers that are unconfigured, disabled via `ENABLED_SOURCES`, or rate-limited still produce an explicit `NormalizedResult` with a non-success `execution_state` rather than disappearing.
4. **Enrichment** – `enrichment.enrich()` dispatches per type to DNS, RDAP/WHOIS, SSL, GeoIP, crt.sh, CISA KEV/EPSS/NVD, breach lookups, etc. Results are cached by type-specific TTL.
5. **Evidence → score** – `evidence.normalize_provider_result` converts raw provider payloads into typed evidence observations (from structured fields only, never substring scans of payload text); `scorer.aggregate_evidence` builds the `IOCAssessment` (verdict, confidence, provider health), and `compute_composite` produces the numeric score. `executive_summary.py` writes the analyst-facing summary. Analyst false-positive feedback (`IOCFeedback`) feeds into scoring.

Batch (`batch.py`, `/api/batch*`) runs `run_analysis` for many IOCs under a global concurrency cap and batch deadline, persisting `BatchRecord` + `LookupResult.batch_id`.

### Adapters (`app/backend/adapters/`)

Each adapter subclasses `SourceAdapter` (`adapters/base.py`), declares `name`, `supported_types`, `rate_limit: RateLimitConfig`, optionally `public_without_key` and capability flags (`direct_threat_evidence`, `produces_reputation`, `produces_infrastructure_context`, …), and implements `async lookup(ioc_value, ioc_type) -> NormalizedResult`. Use the shared client from `set_client`/`_get_client()` (`http_client.py`) instead of creating your own. Map HTTP failures through `adapters/_http.py` (`http_failure`, `read_json`, `malformed`, `not_configured`, `describe_exception`) so 401/403/429/5xx/empty/malformed responses get consistent execution states. A positive verdict requires an exact indicator match (`adapters/_matching.py`: `indicator_equals`); related-but-unequal records are context only. Tags are short labels — put structured values (ports, ASN, CVSS, counts) in `raw_data`, which scoring (`evidence.py`) reads before falling back to legacy `key: value` tags.

To add a provider: implement the adapter, register it in `pipeline._init_adapters()`, add its key to `config.Settings` (and `_API_KEY_FIELDS`, `.env.example`), and check how `provider_capabilities.capability_for` classifies it — some provider-name sets there (context-only, vulnerability, direct-evidence sources) are hardcoded.

`base.py` also defines the shared vocabulary and every Pydantic result model (`NormalizedResult`, `EnrichmentData`, `IOCAssessment`, `CompositeScore`, `LookupResponse`, …):
- `execution_state` (success / not_found / rate_limited / timeout / error / unavailable / …) is kept separate from `verdict`. A failed or missing provider must never be read as "clean".
- `normalize_provider_verdict` keeps `undetected`, `not_found`, `unknown`, and `unrated` separate on purpose, because each means a different kind of missing evidence.
- `raw_data` is truncated to 10 KiB via `truncate_raw_data`.

If only context sources (no reputation provider) cover an IOC, the result must be labeled contextual/enrichment-only and not given a clean verdict. Many tests enforce this.

### Configuration & security (`config.py`)

`settings` is a pydantic-settings singleton. The repo **`.env` is the primary source for every setting; the process environment is only a fallback** (`settings_customise_sources`). For API keys, all alias names (`AliasChoices`) are tried in `.env` before any are tried in the environment (`resolve_credential_with_origin`); a `.env` value can be a literal, `${OTHER_VAR}`, or a bare variable name. Explicit `Settings(...)` kwargs win over both. `settings.credential_origin(field)` records which alias/source supplied a key, and `/api/sources` reports it — never the value. `IOC_ENV_FILE` overrides the file path; `tests/conftest.py` sets it empty so tests never read real credentials (except with `RUN_LIVE_API_TESTS=1`).

Startup validation refuses non-loopback binds unless `ALLOW_NETWORK_BIND=true` plus `API_KEYS` and an HTTPS `BASE_URL`, and requires `WEBHOOK_SECRET_KEY` when webhooks are enabled. Active network actions (port scan, URL content fetch, public urlscan submission) are opt-in flags. Outbound fetches to user-supplied hosts go through public-address checks (SSRF controls in `enrichment.py`); keep new fetch paths behind the same checks.

### Persistence

SQLAlchemy async + aiosqlite; ORM models in `models.py`, engine/session and startup migration logic in `database.py` (it runs `alembic upgrade head` in a subprocess and refuses to adopt an unversioned DB with missing columns). Any model change needs a new Alembic revision in `alembic/versions/`, otherwise `alembic check` fails in CI. The downgrade path refuses to run once batch records exist.

### Exports

`stix_export.py` (STIX 2.1), `misp_export.py`, `siem_export.py` (Splunk/ECS/LEEF), plus CSV/HTML report endpoints in `main.py`.

### Frontend (`ui/src/`)

`services/api.ts` is the single API client. It sends `X-API-Key` from sessionStorage when the backend requires one and dispatches `AUTH_REQUIRED_EVENT` on 401. `hooks/useLookup.ts` drives task polling/streaming. The main pages are `pages/ResultView.tsx` (verdict, evidence, and enrichment panels), `Batch.tsx`, `History.tsx`, and `Investigations.tsx`. `lib/thresholds.ts` mirrors backend `thresholds.py`, so change both together.
