import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import datetime
from app.backend.adapters.base import LookupResponse
from app.backend.batch import (
    consolidate_batch_results,
    get_batch,
    parse_csv,
    parse_json,
    run_batch_analysis,
)
from app.backend.cache import CacheLayer
from app.backend.circuit_breaker import all_breaker_states
from app.backend.classifier import classify_ioc, refang
from app.backend.misp_export import build_misp_event
from app.backend.siem_export import export_siem
from app.backend.http_client import close_client as close_http_client
from app.backend.config import settings
from app.backend.database import get_db, init_db
from app.backend.models import IOC, Investigation, InvestigationIOC, LookupResult
from app.backend.pipeline import cleanup_old_tasks, get_cache, get_task_queue, get_task_redis, run_analysis, set_cache, set_rate_limiter
from app.backend.rate_limiter import RateLimiter
from app.backend.stix_export import build_stix_bundle, results_to_csv
from app.backend.webhooks import add_webhook, list_webhooks, remove_webhook
from app.backend.logger import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    _cache = CacheLayer(settings.redis_url)
    await _cache._get_redis()
    set_cache(_cache)

    _rate_limiter = RateLimiter(settings.redis_url)
    set_rate_limiter(_rate_limiter)

    cleanup_task = asyncio.create_task(_periodic_cleanup())
    try:
        yield
    except asyncio.CancelledError:
        pass
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        await _cache.close()
        await _rate_limiter.close()
        await close_http_client()
        set_cache(None)
        set_rate_limiter(None)


async def _periodic_cleanup():
    while True:
        try:
            await asyncio.sleep(1800)
            await cleanup_old_tasks()
        except Exception:
            logger.exception("Periodic cleanup failed")


app = FastAPI(title="Universal IOC Lookup Platform", version="0.2.0", lifespan=lifespan)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5173"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)


class LookupRequest(BaseModel):
    ioc: str
    investigation_id: int | None = None


class InvestigationCreate(BaseModel):
    name: str
    description: str = ""


class InvestigationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class NoteUpdate(BaseModel):
    notes: str = ""


# --- Health ---

@app.get("/api/adapters/health")
async def adapter_health():
    return {"adapters": all_breaker_states()}

@app.get("/api/health")
async def health():
    return {"status": "ok", "app": "Universal IOC Lookup Platform", "version": "0.2.0"}


@app.post("/api/cache/clear")
async def clear_cache():
    c = get_cache()
    if c is not None:
        await c.clear()
    return {"status": "ok"}


# --- Pipeline Lookup ---

@app.post("/api/lookup")
async def start_lookup(request: LookupRequest):
    normalized = refang(request.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")
    if len(normalized) > 4096:
        raise HTTPException(status_code=400, detail="IOC value too long")
    if classify_ioc(normalized) == "unknown":
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")

    task = await run_analysis(request.ioc.strip())
    return {
        "task_id": task.task_id,
        "status": task.status,
        "ioc_value": task.ioc_value,
        "normalized": task.normalized,
        "ioc_type": task.ioc_type,
    }


@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    task = await get_task_redis(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.to_dict()


@app.get("/api/tasks/{task_id}/stream")
async def stream_task(task_id: str, request: Request):
    queue = get_task_queue(task_id)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=2.0)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/tasks/{task_id}/result")
async def get_task_result(task_id: str):
    task = await get_task_redis(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis not yet complete")

    return LookupResponse(
        input=task.ioc_value,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        composite=task.composite,
        enrichment=task.enrichment or None,
        results=task.results,
        relationships=task.relationships,
        executive_summary=task.executive_summary,
    )


# --- Investigations ---

@app.get("/api/investigations")
async def list_investigations(db: AsyncSession = Depends(get_db)):
    stmt = select(Investigation).order_by(Investigation.updated_at.desc())
    result = await db.execute(stmt)
    invs = result.scalars().all()
    return [
        {
            "id": inv.id,
            "name": inv.name,
            "description": inv.description or "",
            "ioc_count": len(inv.iocs) if inv.iocs else 0,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        }
        for inv in invs
    ]


@app.post("/api/investigations")
async def create_investigation(body: InvestigationCreate, db: AsyncSession = Depends(get_db)):
    inv = Investigation(name=body.name, description=body.description)
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return {"id": inv.id, "name": inv.name, "description": inv.description,
            "created_at": inv.created_at.isoformat() if inv.created_at else None}


@app.get("/api/investigations/{inv_id}")
async def get_investigation(inv_id: int, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    iocs_data = []
    for ii in inv.iocs:
        ioc = ii.ioc
        lr = await db.execute(
            select(LookupResult).where(LookupResult.ioc_id == ioc.id).order_by(LookupResult.created_at.desc()).limit(1)
        )
        latest = lr.scalar_one_or_none()
        iocs_data.append({
            "id": ii.id,
            "ioc_id": ioc.id,
            "value": ioc.value,
            "ioc_type": ioc.ioc_type,
            "notes": ii.notes or "",
            "score": latest.composite_score if latest else None,
            "verdict": latest.composite_verdict if latest else None,
            "looked_up_at": latest.created_at.isoformat() if latest and latest.created_at else None,
        })

    return {
        "id": inv.id,
        "name": inv.name,
        "description": inv.description or "",
        "iocs": iocs_data,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
    }


@app.put("/api/investigations/{inv_id}")
async def update_investigation(inv_id: int, body: InvestigationUpdate, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if body.name is not None:
        inv.name = body.name
    if body.description is not None:
        inv.description = body.description
    await db.commit()
    return {"status": "updated"}


@app.delete("/api/investigations/{inv_id}")
async def delete_investigation(inv_id: int, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.delete(inv)
    await db.commit()
    return {"status": "deleted"}


@app.post("/api/investigations/{inv_id}/iocs")
async def add_ioc_to_investigation(inv_id: int, body: LookupRequest, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")
    ioc_type = classify_ioc(normalized)

    existing = await db.execute(select(IOC).where(IOC.value == normalized))
    ioc = existing.scalar_one_or_none()
    if not ioc:
        ioc = IOC(value=normalized, ioc_type=ioc_type)
        db.add(ioc)
        await db.flush()

    already = await db.execute(
        select(InvestigationIOC).where(
            InvestigationIOC.investigation_id == inv_id,
            InvestigationIOC.ioc_id == ioc.id,
        )
    )
    if not already.scalar_one_or_none():
        ii = InvestigationIOC(investigation_id=inv_id, ioc_id=ioc.id)
        db.add(ii)

    await db.commit()
    return {"status": "added", "ioc_id": ioc.id, "value": normalized}


@app.put("/api/investigations/{inv_id}/iocs/{ii_id}")
async def update_ioc_notes(inv_id: int, ii_id: int, body: NoteUpdate, db: AsyncSession = Depends(get_db)):
    ii = await db.get(InvestigationIOC, ii_id)
    if not ii or ii.investigation_id != inv_id:
        raise HTTPException(status_code=404, detail="Not found")
    ii.notes = body.notes
    await db.commit()
    return {"status": "updated"}


@app.delete("/api/investigations/{inv_id}/iocs/{ii_id}")
async def remove_ioc_from_investigation(inv_id: int, ii_id: int, db: AsyncSession = Depends(get_db)):
    ii = await db.get(InvestigationIOC, ii_id)
    if not ii or ii.investigation_id != inv_id:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ii)
    await db.commit()
    return {"status": "removed"}


# --- Recent Lookups ---

@app.get("/api/recent")
async def recent_lookups(db: AsyncSession = Depends(get_db)):
    from sqlalchemy.orm import selectinload

    stmt = (
        select(IOC)
        .options(selectinload(IOC.lookup_results))
        .order_by(IOC.created_at.desc())
        .limit(50)
    )
    result = await db.execute(stmt)
    iocs = result.unique().scalars().all()
    out = []
    for ioc in iocs:
        latest = None
        if ioc.lookup_results:
            latest = max(ioc.lookup_results, key=lambda lr: lr.created_at or "")
        out.append({
            "id": ioc.id,
            "value": ioc.value,
            "ioc_type": ioc.ioc_type,
            "verdict": latest.composite_verdict if latest else None,
            "score": latest.composite_score if latest else None,
            "confidence": latest.composite_confidence if latest else None,
            "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
        })
    return out


@app.delete("/api/recent/{ioc_id}")
async def delete_recent(ioc_id: int, db: AsyncSession = Depends(get_db)):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ioc)
    await db.commit()
    return {"status": "deleted"}


# --- Batch Analysis ---

class BatchRequest(BaseModel):
    iocs: list[str]


@app.post("/api/batch")
async def start_batch(body: BatchRequest):
    if not body.iocs:
        raise HTTPException(status_code=400, detail="No IOCs provided")
    if len(body.iocs) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 IOCs per batch")

    batch = await run_batch_analysis(body.iocs)
    return {"batch_id": batch.batch_id, "total": batch.total, "status": batch.status}


MAX_UPLOAD_SIZE = 10 * 1024 * 1024


@app.post("/api/batch/upload")
async def upload_batch_file(file: UploadFile = File(...)):
    try:
        raw = b""
        chunk_size = 0
        async for chunk in file.stream():
            chunk_size += len(chunk)
            if chunk_size > MAX_UPLOAD_SIZE:
                raise HTTPException(status_code=400, detail="File too large (max 10MB)")
            raw += chunk
        content = raw.decode("utf-8")
        filename = file.filename or "iocs.csv"
        if filename.endswith(".json"):
            iocs = parse_json(content)
        else:
            iocs = parse_csv(content)

        if not iocs:
            raise HTTPException(status_code=400, detail="No IOCs found in file")
        if len(iocs) > 500:
            raise HTTPException(status_code=400, detail="Maximum 500 IOCs per batch")

        batch = await run_batch_analysis(iocs)
        return {"batch_id": batch.batch_id, "total": batch.total, "status": batch.status}
    except HTTPException:
        raise
    except Exception:
        logger.exception("File upload failed")
        raise HTTPException(status_code=400, detail="Failed to parse file")


@app.get("/api/batch/{batch_id}")
async def get_batch_status(batch_id: str):
    batch = get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return batch.to_dict()


@app.get("/api/batch/{batch_id}/result")
async def get_batch_result(batch_id: str):
    batch = get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    if batch.status != "done":
        raise HTTPException(status_code=425, detail="Batch analysis not yet complete")
    return consolidate_batch_results(batch)


# --- Export ---

class ReportExportRequest(BaseModel):
    ioc: str

@app.post("/api/export/report")
async def export_report(body: ReportExportRequest):
    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")

    task = await run_analysis(body.ioc.strip())
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis not yet complete")

    response = LookupResponse(
        input=task.ioc_value,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        composite=task.composite,
        enrichment=task.enrichment,
        results=task.results,
        relationships=task.relationships,
    ).model_dump()

    html = _build_html_report(response)
    return HTMLResponse(html, media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="ioc_report_{normalized}.html"'})

def _build_html_report(data: dict) -> str:
    ioc_val = data.get("normalized") or data.get("input") or "Unknown"
    ioc_type = data.get("ioc_type", "")
    comp = data.get("composite", {})
    verdict = comp.get("verdict", "unknown")
    score = comp.get("score")
    score_str = f"{round(score * 100)}/100" if score is not None else "—"
    confidence = comp.get("confidence", "medium")
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    results = data.get("results", [])
    enrich = data.get("enrichment", {})
    summary = data.get("executive_summary", "")
    source_count = len(results)

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root { --bg: #f5f6fa; --bg-card: #ffffff; --text: #1a1a2e; --muted: #718096; --border: #e2e8f0; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.15rem; }
  .meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
  .banner { display: flex; align-items: center; gap: 1rem; background: var(--bg-card); padding: 1rem 1.25rem; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 1.5rem; }
  .badge { display: inline-block; padding: 0.2rem 0.7rem; border-radius: 20px; font-weight: 600; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; }
  .badge-malicious { background: #fed7d7; color: #c53030; }
  .badge-suspicious { background: #fefcbf; color: #975a16; }
  .badge-clean { background: #c6f6d5; color: #276749; }
  .badge-unknown { background: #e2e8f0; color: #4a5568; }
  .score-display { font-size: 1.8rem; font-weight: 800; }
  .score-red { color: #e53e3e; } .score-amber { color: #dd6b20; } .score-green { color: #38a169; }
  h2 { font-size: 1.1rem; font-weight: 600; margin: 1.5rem 0 0.75rem; padding-bottom: 0.3rem; border-bottom: 2px solid var(--border); color: #2d3748; }
  table { width: 100%; border-collapse: collapse; background: var(--bg-card); border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  th, td { text-align: left; padding: 0.5rem 0.75rem; font-size: 0.85rem; border-bottom: 1px solid var(--border); }
  th { background: #f7fafc; font-weight: 600; color: #4a5568; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 0.82rem; }
  .tag { display: inline-block; background: #edf2f7; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; margin: 0.1rem; color: #4a5568; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 0.5rem 0; }
  .stat-card { background: var(--bg-card); padding: 0.75rem 1rem; border-radius: 8px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  .stat-num { font-size: 1.4rem; font-weight: 700; } .stat-lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  .stat-sub { font-size: 0.82rem; color: #4a5568; margin-top: 0.2rem; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.75rem; color: var(--muted); text-align: center; }
</style>
</head>
<body><div class="container">
<h1>Threat Intelligence Report</h1>
<p class="meta">IOC Universal — {_e(date_str)}</p>
<div class="banner">
  <div>
    <div style="font-size:0.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:0.15rem">{_e(ioc_type)}</div>
    <div class="mono" style="font-weight:600;font-size:1.05rem">{_e(ioc_val)}</div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div><span class="badge badge-{_e(verdict)}">{_e(verdict)}</span></div>
    <div class="score-display score-{"red" if (score or 0) >= 0.7 else "amber" if (score or 0) >= 0.4 else "green"}">{_e(score_str)}</div>
    <div style="font-size:0.72rem;color:var(--muted)">confidence: {_e(confidence)} &middot; {source_count} source(s)</div>
  </div>
</div>"""

    if summary:
        v_color = "#e53e3e" if verdict == "malicious" else "#dd6b20" if verdict == "suspicious" else "#38a169"
        html += f'<div style="background:var(--bg-card);padding:1rem 1.25rem;border-radius:8px;margin-bottom:1rem;border-left:4px solid {v_color}"><strong>Executive Summary:</strong><br>{_e(summary)}</div>'

    html += '<h2>Source Results</h2>'
    if results:
        html += '<table><thead><tr><th>Source</th><th>Verdict</th><th>Score</th><th>Tags</th></tr></thead><tbody>'
        for r in results:
            rs = r.get("raw_score")
            rs_str = f"{round(rs * 100)}/100" if rs is not None else "—"
            tags = " ".join(f'<span class="tag">{_e(t)}</span>' for t in (r.get("tags") or [])[:8])
            html += f'<tr><td class="mono">{_e(r.get("source",""))}</td>'
            html += f'<td><span class="badge badge-{_e(r.get("verdict","unknown"))}">{_e(r.get("verdict","unknown"))}</span></td>'
            html += f'<td>{_e(rs_str)}</td><td>{tags}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p style="color:var(--muted)">No source results returned.</p>'

    html += '<h2>Enrichment</h2><div class="grid-2">'
    if enrich.get("geoip") and enrich["geoip"].get("country"):
        g = enrich["geoip"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(g.get("country",""))}</div><div class="stat-lbl">Country{"; " + _e(g.get("city","")) if g.get("city") else ""}</div><div class="stat-sub">AS{g.get("asn","")} &middot; {_e(g.get("isp",""))}</div></div>'
    if enrich.get("whois") and enrich["whois"].get("registrar"):
        w = enrich["whois"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(w.get("registrar",""))}</div><div class="stat-lbl">Registrar &middot; created {_e(w.get("creation_date","") or "?")}</div></div>'
    if enrich.get("ssl") and enrich["ssl"].get("subject"):
        s = enrich["ssl"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(s.get("subject",""))}</div><div class="stat-lbl">SSL{" [EXPIRED]" if s.get("is_expired") else ""}</div><div class="stat-sub">issuer: {_e(s.get("issuer","") or "?")} &middot; days left: {s.get("days_left","?")}</div></div>'
    if enrich.get("passive_dns") and enrich["passive_dns"].get("records"):
        pdns = enrich["passive_dns"]["records"]
        html += f'<div class="stat-card"><div class="stat-num">{len(pdns)}</div><div class="stat-lbl">Passive DNS Records</div></div>'
    if enrich.get("open_ports") and enrich["open_ports"]:
        ports = enrich["open_ports"]
        html += f'<div class="stat-card"><div class="stat-num">{len(ports)}</div><div class="stat-lbl">Open Ports</div><div class="stat-sub">{", ".join(str(p) for p in ports[:10])}</div></div>'
    if enrich.get("dns") and enrich["dns"].get("a_records"):
        dns = enrich["dns"]
        a_ct = len(dns.get("a_records") or [])
        aaaa_ct = len(dns.get("aaaa_records") or [])
        cname_ct = len(dns.get("cname_records") or [])
        html += f'<div class="stat-card"><div class="stat-num">{a_ct}A / {aaaa_ct}AAAA / {cname_ct}CNAME</div><div class="stat-lbl">DNS Records</div></div>'
    if enrich.get("cve") and enrich["cve"].get("id"):
        cve = enrich["cve"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(cve.get("id",""))}</div><div class="stat-lbl">CVE</div><div class="stat-sub">EPSS: {_e(str(round((cve.get("epss_score") or 0)*100,2)))}%{" [CISA KEV]" if cve.get("is_in_kev") else ""}</div></div>'
    if enrich.get("email_security"):
        es = enrich["email_security"]
        parts = []
        for k in ("spf","dkim","dmarc"):
            v = es.get(k)
            if v: parts.append(f'{k.upper()}: {_e(str(v)[:30])}')
        if parts: html += f'<div class="stat-card"><div class="stat-lbl">Email Security</div><div class="stat-sub">{" | ".join(parts)}</div></div>'
    html += '</div>'

    relations = data.get("relationships", [])
    if relations:
        html += '<h2>Relationships</h2><table><thead><tr><th>Target</th><th>Relationship</th></tr></thead><tbody>'
        seen_rel = set()
        for rr in relations:
            t = rr.get("target_ioc","")
            rl = rr.get("relationship","")
            key = f"{t}|{rl}"
            if key in seen_rel: continue
            seen_rel.add(key)
            html += f'<tr><td class="mono">{_e(t)}</td><td>{_e(rl)}</td></tr>'
        html += '</tbody></table>'

    html += f'<div class="footer">Generated by IOC Universal — https://github.com/anomalyco/ioc-platform</div></div></body></html>'
    return html

def _e(s):
    if s is None: return ""
    import html
    return html.escape(str(s))

@app.post("/api/export/stix")
async def export_stix(body: LookupRequest):
    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")

    task = await run_analysis(body.ioc.strip())
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis could not complete")

    response = LookupResponse(
        input=task.ioc_value,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        composite=task.composite,
        enrichment=task.enrichment,
        results=task.results,
        relationships=task.relationships,
    ).model_dump()

    bundle = build_stix_bundle(response)
    return bundle


@app.post("/api/export/misp")
async def export_misp(body: LookupRequest):
    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")

    task = await run_analysis(body.ioc.strip())
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis could not complete")

    response = LookupResponse(
        input=task.ioc_value,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        composite=task.composite,
        enrichment=task.enrichment,
        results=task.results,
        relationships=task.relationships,
    ).model_dump()

    event = build_misp_event(response)
    return event


class SIEMExportRequest(BaseModel):
    ioc: str
    format: str = "splunk"


@app.post("/api/export/siem")
async def export_siem_endpoint(body: SIEMExportRequest):
    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")

    task = await run_analysis(body.ioc.strip())
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis could not complete")

    response = LookupResponse(
        input=task.ioc_value,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        composite=task.composite,
        enrichment=task.enrichment,
        results=task.results,
        relationships=task.relationships,
    ).model_dump()

    try:
        text = export_siem(response, body.format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    content_type = {
        "splunk": "text/plain",
        "ecs": "application/x-ndjson",
        "leef": "text/plain",
    }.get(body.format, "text/plain")
    return PlainTextResponse(text, media_type=content_type)


@app.post("/api/export/csv")
async def export_csv(body: LookupRequest):
    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")

    task = await run_analysis(body.ioc.strip())
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis could not complete")

    results = [r.model_dump() for r in task.results]
    csv_content = results_to_csv(results)
    return PlainTextResponse(csv_content, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=ioc_report.csv"})


# --- Webhooks ---

class WebhookCreate(BaseModel):
    url: str
    events: list[str] = ["lookup.complete"]
    secret: str | None = None


@app.get("/api/webhooks")
async def get_webhooks():
    return await list_webhooks()


@app.post("/api/webhooks")
async def create_webhook(body: WebhookCreate):
    try:
        result = await add_webhook(body.url, body.events, body.secret)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    ok = await remove_webhook(webhook_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deleted"}


# --- Save Lookup Result ---

@app.post("/api/save")
async def save_lookup_result(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    normalized = refang(body.ioc.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")
    ioc_type = classify_ioc(normalized)

    existing = await db.execute(select(IOC).where(IOC.value == normalized))
    ioc = existing.scalar_one_or_none()
    if not ioc:
        ioc = IOC(value=normalized, ioc_type=ioc_type)
        db.add(ioc)
        await db.flush()

    task = await run_analysis(body.ioc.strip())
    if task.status == "done" and task.composite:
        score = task.composite.score if hasattr(task.composite, "score") else 0
        verdict = task.composite.verdict if hasattr(task.composite, "verdict") else "unknown"
        confidence = task.composite.confidence if hasattr(task.composite, "confidence") else "low"

        response_dict = LookupResponse(
            input=task.ioc_value,
            normalized=task.normalized,
            ioc_type=task.ioc_type or "unknown",
            composite=task.composite,
            enrichment=task.enrichment,
            results=task.results,
            relationships=task.relationships,
        ).model_dump()

        lr = LookupResult(
            ioc_id=ioc.id,
            task_id=task.task_id,
            composite_score=score,
            composite_verdict=verdict,
            composite_confidence=confidence,
            full_response=json.dumps(response_dict),
            source_count=len(task.results),
        )
        db.add(lr)
        await db.commit()

    return {"status": "saved", "ioc_id": ioc.id}


# --- Static files ---

ROOT = Path(__file__).resolve().parent.parent.parent
static_dir = ROOT / "ui" / "static"
templates_dir = ROOT / "ui" / "templates"

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def index():
    return FileResponse(str(templates_dir / "index.html"))
