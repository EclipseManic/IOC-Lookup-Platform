# IOC Platform - Analyst-Gap Analysis

**Research date:** 2026-08-12
**Domain:** Free-tier IOC lookup platform (FastAPI + React) - analyst-gap analysis
**Confidence:** HIGH (feature inventory verified against code; analyst expectations cross-verified across vendor docs and industry sources)
**Scope:** Research only. No code changes. Output feeds the planning phase.

## Executive Summary

The ioc-platform already covers the hard 70% of an analyst-grade free IOC lookup tool: 16 reputation adapters with per-adapter rate limits and circuit breakers, Redis caching, SSE live progress, composite verdict scoring with source breakdown, deep enrichment (WHOIS/RDAP, DNS, SSL, GeoIP, CVE/EPSS/KEV, crt.sh subdomains, favicon hash, breach lookups), investigations, batch analysis, and single-IOC exports (CSV, STIX 2.1, MISP, Splunk/ECS/LEEF). This matches the analyst's core pain point quoted in the ecosystem: "receive one suspicious domain, open eight browser tabs, copy-paste the IOC into each tool, manually combine the results, and write a verdict. It takes 10-15 minutes per IOC." [CITED: github.com/H3NRYBAIT/threatpivot]

The gaps that remain are exactly what separates a lookup tool from an analyst-grade platform, verified against current code:

1. **Every lookup is transient.** The UI never calls `/api/save` (verified: no saveIOC client function exists), so "History" shows only IOCs added to investigations. There is no automatic lookup history, no per-IOC timeline, no verdict-change tracking.
2. **Correlation is shallow.** Relationship traversal is limited to adapter related_iocs + a few enrichment edges (rDNS, email domain, extracted host). The enrichment layer already computes the raw material for deep pivoting (registrar, ASN, SSL issuer/SAN, favicon hash, CVE links) but nothing correlates across lookups or offers same-infrastructure pivots.
3. **Batch output is JSON-only.** Batch results cannot be exported as CSV/STIX/MISP/SIEM; all export endpoints are single-IOC.
4. **The API is unfriendly to automation.** X-API-Key is a static env list, /docs is disabled when keys are set, 429 responses carry no Retry-After, and webhooks support exactly one event type.

None of these require paid services to fix. Every recommendation below stays inside the free-tier constraint.

**Primary recommendation:** convert the tool from a "lookup sink" into a "correlation hub" - persist every lookup automatically, add local cross-IOC correlation endpoints built on enrichment data already collected, and expose batch export + a real automation surface. That is what free analyst tools (OTX with Pulses, Pulsedive with its query/pivot language, ThreatMiner with contextual pivoting) are judged on.

## 1. Feature Inventory (verified against code)

### 1.1 Lookup & reputation
- 16 reputation/lookup adapters, each with per-adapter rate limits and circuit breakers. Confirmed adapters: VirusTotal, urlscan.io, Hybrid Analysis, NVD (CVE), Shodan, Censys, GreyNoise, IPinfo, PhishTank, ThreatFox, MalwareBazaar (SecurityTrails, Spur.us, LeakCheck were removed earlier - ref WORK-UNITS.md).
- Provider health snapshot (from tests/api_keys_deep_check.py, 2026-08-11): VirusTotal, urlscan.io, NVD, Hybrid Analysis, Shodan USABLE; GreyNoise, IPinfo keyless-OK; Censys PAT auth fixed (Bearer for censys_ keys, legacy id:secret Basic); Tria.ge usable* (404 on empty MD5 proves key validity). Pending: urlscan.io expects public "on"/"off" string, adapter still sends boolean.
- Redis caching with TTL; circuit breakers isolate failing providers; /api/health exposes per-adapter status.

### 1.2 Enrichment
- WHOIS/RDAP, DNS records, SSL certificate (issuer/SAN), GeoIP, CVE/EPSS/KEV, crt.sh subdomains, favicon hash, breach lookups, passive DNS, open ports, URL preview, redirect chain.
- UI EnrichmentPanel exposes: open_ports, breach, passive_dns, favicon, url_preview, redirect_chain (frontend Phase 8).

### 1.3 Workflow
- Single-IOC lookup with live SSE progress and per-source status.
- Investigations: create, notes, tags, persisted IOC membership.
- Batch analysis: upload (CSV/JSON) + run with streaming progress; results.
- Exports (single-IOC only): CSV, STIX 2.1, MISP, Splunk/ECS, LEEF.
- History: exists but only shows IOCs explicitly added to investigations.

### 1.4 API surface (relevant)
- /api/save, /api/history CRUD (+note, +tag), /api/investigations (+notes), /api/batch (+upload, +export), /api/export/{ioc}/{format}, /api/webhook/register, /api/health.
- X-API-Key auth = static env list; /docs disabled when keys set; 429 without Retry-After; webhooks support exactly one event type.

## 2. Analyst Baseline (what free-tier analysts expect)

Industry expectation for free IOC tooling (cross-verified across OTX, Pulsedive, ThreatMiner, practitioner sources):
- A per-IOC record that persists: first/last seen, verdict timeline, notes, tags.
- Cross-IOC correlation: pivot on shared infrastructure (registrar, ASN, SSL issuer/SAN, favicon, CVE), not just direct relationships.
- Batch workflows that end in a report: export verdicts as CSV/STIX/MISP/SIEM.
- A scriptable API: per-key credentials, documented endpoints, rate-limit headers, machine-readable errors.
- Notifications (webhooks) or at least polling endpoints for finished work.

Practitioner pain (quoted): "receive one suspicious domain, open eight browser tabs, copy-paste the IOC into each tool, manually combine the results, and write a verdict. It takes 10-15 minutes per IOC." [threatpivot]

The platform already eliminates the tab-switching; the gaps below are about persistence and correlation.
## 3. Gap Analysis

**G1 - Every lookup is transient. [HIGH]**
- UI never calls /api/save (verified: no saveIOC client function in ui/). History shows only investigation members.
- No automatic lookup history, no per-IOC timeline, no verdict-change tracking; re-checking an IOC yields no delta.
- Impact: analysts cannot answer "what did I see last week, and did the verdict change?"

**G2 - Correlation is shallow. [HIGH]**
- Relationship traversal limited to adapter related_iocs + a few enrichment edges (rDNS, email domain, extracted host).
- Enrichment already collects registrar, ASN, SSL issuer/SAN, favicon hash, CVE links - the raw material for deep pivots - but nothing correlates across lookups or offers same-infrastructure pivots.
- Impact: the data for correlation exists; the analysis endpoints do not.

**G3 - Batch output is JSON-only. [MEDIUM]**
- Batch results cannot be exported as CSV/STIX/MISP/SIEM; all export endpoints are single-IOC.
- Impact: analysts hand-extract or script batch results.

**G4 - API is unfriendly to automation. [MEDIUM]**
- X-API-Key is a static env list (no per-key creation/rotation UI); /docs disabled when keys set.
- 429 carries no Retry-After; no rate-limit headers; webhooks support exactly one event type.
- Impact: integration friction for IR/SOAR playbooks.

## 4. Recommended Stack (close gaps inside the free-tier constraint)

Keep (already good):
- Adapter layer + per-adapter rate limits + circuit breakers; Redis cache + TTL.
- Composite verdict scoring + source breakdown; SSE live progress.
- Single-IOC exports (CSV/STIX/MISP/SIEM/LEEF); SQLite (aiosqlite) + Redis at this scale.

Close:
- G1: auto-persist lookups server-side; reuse investigation storage or a lookups table; introduce HISTORY_RETENTION_DAYS + daily cleanup (main.py:128-134) with tests.
- G2: local correlation endpoints over already-collected enrichment - registrar, ASN, favicon-hash, SSL issuer/SAN, CVE pivots; extend RelationshipGraph feed.
- G3: batch export endpoints reusing existing single-IOC exporters over batch results.
- G4: Retry-After + rate-limit headers; per-key rate budgets; /docs env toggle (staging); webhook event-type expansion.

## 5. Don't Hand-Roll

- Do NOT aggregate new paid TI feeds - gaps are not feed gaps; keep the current free vendor set.
- Do NOT build a graph DB - SQLite + Redis with a few indexed join tables is ample.
- Do NOT re-implement caching, circuit breaking, or SSE - all exist.
- Do NOT build a custom ML verdict model - keep the heuristic composite; version it instead.
- Do NOT persist raw enrichment blobs wholesale - store normalized pivot fields (registrar, ASN, cert hash, favicon hash).

## 6. Pitfalls to Avoid

- Auto-saving lookups without retention -> unbounded growth; enforce HISTORY_RETENTION_DAYS + tested daily cleanup.
- Verdict instability: re-checks change scores; keep a versioned verdict timeline so "verdict changed" is observable, not alarming.
- Unindexed correlation queries -> full scans; keep lookup/correlation tables small and indexed.
- Exporting full enrichment in batch -> response bloat; export verdicts + normalized fields.
- Silently degrading the free tier - keep rate limits honest (429 + Retry-After).
- Storing API keys in frontend/static bundles - server-side only.

## 7. Roadmap (ordered, free-tier-safe)

- P1 (small): auto-persist lookups + wire History UI to lookup history (saveIOC client fn); retention env var + cleanup test.
- P2 (small): batch export (CSV/STIX/MISP/SIEM) reusing existing exporters.
- P3 (medium): API hardening - Retry-After + rate-limit headers, /docs toggle, webhook event expansion.
- P4 (medium): correlation endpoints - registrar/ASN/favicon-hash/SSL/CVE pivots; RelationshipGraph expansion.
- P5 (larger): verdict timeline + change tracking; extend notes/tags to lookups (currently investigation-only).

## 8. Assumptions & Open Questions

Assumptions:
- Free-tier = current vendor set, no paid feeds.
- Scale = single operator / small team; SQLite + Redis sufficient.
- Research output only; no code changes in this phase.

Open questions for planning:
- History retention default (e.g., 30 days)?
- Expose /docs on a staging build (env toggle) instead of only prod-off?
- Per-key webhook subscriptions with auth needed, or is API polling enough?
- Should verdict changes trigger notifications (webhook/email), or just a UI badge?

## Sources
- threatpivot (practitioner pain + feature inspiration) - github.com/H3NRYBAIT/threatpivot
- Pulsedive - pivot/query language for free-tier correlation - pulsedive.com
- AlienVault OTX - Pulses for community-driven correlation - otx.alienvault.com
- ThreatMiner - contextual pivoting - threatminer.org
- Project evidence: app/ (FastAPI, adapters, cache, rate_limiter, webhooks), ui/ (React: History, EnrichmentPanel, RelationshipGraph), WORK-UNITS.md; supermemory records (583 tests passing, 80.43% coverage; provider deep-check results).
