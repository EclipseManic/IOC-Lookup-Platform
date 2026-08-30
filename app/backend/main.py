import asyncio
import hashlib
import hmac
import json
import os
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from datetime import datetime
from app.backend.adapters.base import LookupResponse
from app.backend.batch import (
    consolidate_batch_results,
    get_batch,
    get_batch_queue,
    cleanup_batch_queue,
    parse_csv,
    parse_json,
    run_batch_analysis,
    start_batch_analysis,
)
from app.backend.cache import CacheLayer
from app.backend.circuit_breaker import all_breaker_states
from app.backend.classifier import SUPPORTED_IOC_TYPES, classify_ioc, refang
from app.backend.misp_export import build_misp_event
from app.backend.siem_export import export_siem
from app.backend.http_client import close_client as close_http_client
from app.backend.config import settings
from app.backend.thresholds import DISPLAY_MALICIOUS, DISPLAY_SUSPICIOUS
from app.backend.database import get_db, init_db, retry_sqlite_commit
from app.backend.models import IOC, Investigation, InvestigationIOC, LookupResult, IOCFeedback
from app.backend.pipeline import ADAPTERS, cancel_analysis, cleanup_old_tasks, get_cache, get_rate_limiter, get_task_queue, get_task_redis, run_analysis, set_cache, set_rate_limiter, cleanup_task_queue
from app.backend.schemas import (
    BatchStatusResponse,
    CacheClearResponse,
    ErrorResponse,
    HealthResponse,
    InvestigationCreateResponse,
    InvestigationDetail,
    InvestigationSummary,
    IOCInInvestigation,
    RecentIOCResponse,
    SaveResponse,
    StatusResponse,
    TaskStatusResponse,
    WebhookResponse,
    FeedbackRequest,
    FeedbackResponse,
)
from app.backend.rate_limiter import RateLimiter
from app.backend.stix_export import build_stix_bundle, results_to_csv
from app.backend.webhooks import add_webhook, list_webhooks, remove_webhook, shutdown_webhook_tasks
from app.backend.logger import configure_logging, get_logger, _correlation_id

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    _setup_exception_hooks()
    await init_db()

    _cache = CacheLayer()
    await _cache._get_redis()
    set_cache(_cache)

    _rate_limiter = RateLimiter()
    set_rate_limiter(_rate_limiter)

    cleanup_task = asyncio.create_task(_periodic_cleanup())
    from app.backend.enrichment import start_cisa_background_refresh, stop_cisa_background_refresh
    await start_cisa_background_refresh()
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
        await stop_cisa_background_refresh()
        await shutdown_webhook_tasks()
        await _cache.close()
        await _rate_limiter.close()
        await close_http_client()
        set_cache(None)
        set_rate_limiter(None)


def _global_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))


def _setup_exception_hooks():
    sys.excepthook = _global_exception_handler
    asyncio.get_event_loop().set_exception_handler(_async_exception_handler)


def _async_exception_handler(loop, context):
    exc = context.get("exception")
    msg = context.get("message", "Unhandled async exception")
    if exc:
        logger.error("Async exception: %s", msg, exc_info=exc)
    else:
        logger.error("Async exception: %s", msg)


async def _periodic_cleanup():
    while True:
        try:
            await asyncio.sleep(1800)
            await cleanup_old_tasks()
        except Exception:
            logger.exception("Periodic cleanup failed")


app = FastAPI(
    title="Universal IOC Lookup Platform",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs" if not settings.api_keys else None,
    redoc_url="/redoc" if not settings.api_keys else None,
    openapi_url="/openapi.json" if not settings.api_keys else None,
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cid = request.headers.get("X-Correlation-ID") or str(uuid4())
        _correlation_id.set(cid)
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        api_keys = settings.api_keys
        if api_keys:
            valid_keys = [k.strip() for k in api_keys.split(",") if k.strip()]
            if valid_keys:
                path = request.url.path
                if path.startswith("/api/") and not path.startswith("/api/health") and not path.startswith("/api/adapters/health") and not path.startswith("/api/sources"):
                    provided = request.headers.get("X-API-Key", "")
                    if not any(hmac.compare_digest(provided, valid_key) for valid_key in valid_keys):
                        return Response(status_code=401, content="Invalid or missing API key", media_type="text/plain")
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    RATE_LIMITS: dict[str, tuple[int, int]] = {
        "/api/lookup": (60, 60),
        "/api/batch": (10, 60),
        "/api/enrich": (30, 60),
    }

    async def dispatch(self, request: Request, call_next):
        for prefix, (limit, window) in self.RATE_LIMITS.items():
            if request.url.path.startswith(prefix):
                # Status polling of batches (GET) should not be throttled to 10/min
                if prefix == "/api/batch" and request.method == "GET":
                    continue
                client_ip = request.client.host if request.client else "unknown"
                limiter = get_rate_limiter()
                if limiter is not None:
                    allowed = await limiter.acquire(f"ip:{client_ip}:{prefix}:{request.method}", limit, window)
                    if not allowed:
                        return Response(status_code=429, content="Rate limit exceeded. Try again later.", media_type="text/plain")
                break
        return await call_next(request)


app.add_middleware(AuthMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Correlation-ID"],
)


# --- Exception Handlers ---

def _error_response(detail: str, error_code: str | None = None) -> ErrorResponse:
    return ErrorResponse(
        detail=detail,
        error_code=error_code,
        request_id=_correlation_id.get(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Validation error: %s", exc.errors())
    detail = "; ".join(f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg', '')}" for e in exc.errors())
    return JSONResponse(
        status_code=422,
        content=_error_response(detail, error_code="validation_error").model_dump(),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_response(exc.detail).model_dump(),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.critical("Unhandled exception: %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content=_error_response("Internal server error", error_code="internal_error").model_dump(),
    )


class LookupRequest(BaseModel):
    ioc: str
    task_id: str | None = None
    ioc_type: str | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_input(cls, value):
        if isinstance(value, dict) and "ioc" not in value and "input" in value:
            return {**value, "ioc": value["input"]}
        return value


class InvestigationCreate(BaseModel):
    name: str
    description: str = ""


class InvestigationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class NoteUpdate(BaseModel):
    notes: str = ""


# --- Health ---

@app.get("/api/adapters/health", response_model=dict)
async def adapter_health():
    return {"adapters": all_breaker_states()}


@app.get("/api/sources", response_model=dict)
async def source_inventory():
    """Safe source inventory: reports configuration state, never credentials."""
    from app.backend.adapters.base import is_valid_api_key

    env_file = Path(__file__).resolve().parent.parent.parent / ".env"
    env_file_names: set[str] = set()
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                env_file_names.add(line.split("=", 1)[0].strip())
    credential_names = {
        "MalwareBazaar": ["MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY", "ABUSECH_AUTH_KEY"],
        "ThreatFox": ["THREATFOX_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY", "ABUSECH_AUTH_KEY"],
        "URLhaus": ["URLHAUS_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY", "ABUSECH_AUTH_KEY"],
        "VirusTotal": ["VT_API_KEY"], "AbuseIPDB": ["ABUSEIPDB_API_KEY", "AbuseDB_API_KEY"],
        "urlscan.io": ["URL_SCAN_API_KEY"], "Tria.ge": ["TRIAGE_API_KEY", "TRIA_GE_API_KEY"],
        "Hybrid Analysis": ["HA_API_KEY"], "GreyNoise": ["GREYNOISE_API_KEY"],
        "AlienVault OTX": ["OTX_API_KEY", "ALIENVAULT_OTX_KEY"], "Shodan": ["SHODAN_API_KEY"],
        "SecurityTrails": ["SECURITYTRAILS_API_KEY"], "PhishTank": ["PHISHTANK_API_KEY"],
        "Spur.us": ["SPUR_US_API_KEY"], "Censys": ["CENSYS_API_KEY"],
        "IPinfo": ["IPINFO_API_KEY", "IPINFO_ACCESS_TOKEN"],
        "Hudson Rock": ["HUDSON_API_KEY", "HUDSON_ROCK_API_KEY", "HUDSONROCK_API_KEY"],
        "HIBP Pwned Passwords": [],
    }
    sources = []
    for adapter in ADAPTERS:
        key = getattr(adapter, "api_key", None)
        requires_key = key is not None and not getattr(adapter, "public_without_key", False)
        enabled_by_policy = settings.is_source_enabled(adapter.name)
        env_names = credential_names.get(adapter.name, [])
        env_name = next((name for name in env_names if name in os.environ or name in env_file_names), env_names[0] if env_names else None)
        configured = is_valid_api_key(key) if key is not None else True
        if configured and key:
            if env_name and env_name in env_file_names and env_name not in os.environ:
                credential_source = ".env"
            else:
                credential_source = "environment"
        elif not requires_key or getattr(adapter, "public_without_key", False):
            credential_source = "public_no_key"
        else:
            credential_source = "not_configured"
        sources.append({
            "name": adapter.name,
            "supported_types": list(adapter.supported_types),
            "public_without_key": bool(getattr(adapter, "public_without_key", False)),
            "requires_key": requires_key,
            "configured": configured,
            "available": enabled_by_policy and (configured or bool(getattr(adapter, "public_without_key", False)) or key is None),
            "enabled_by_policy": enabled_by_policy,
            "credential_env": env_name,
            "credential_source": credential_source,
            "rate_limit_per_minute": adapter.rate_limit.requests_per_minute,
        })
    return {
        "sources": sources,
        "count": len(sources),
        "available_count": sum(1 for s in sources if s["available"]),
        "credential_configured_count": sum(1 for s in sources if s["credential_source"] in {".env", "environment"}),
    }

@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", app="Universal IOC Lookup Platform", version="0.2.0")


@app.post("/api/cache/clear", response_model=CacheClearResponse)
async def clear_cache():
    c = get_cache()
    if c is not None:
        await c.clear()
    return CacheClearResponse(status="ok")


# --- Pipeline Lookup ---

async def _resolve_task(ioc: str, task_id: str | None = None, db: AsyncSession | None = None):
    if task_id:
        task = await get_task_redis(task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.status != "done":
            raise HTTPException(status_code=425, detail="Analysis not yet complete")
        return task
    fp_override = False
    if db is not None:
        fp_override = refang(ioc.strip()) in await _fetch_fp_overrides(db)
    task = await run_analysis(ioc.strip(), fp_override=fp_override)
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis could not complete")
    return task


async def _fetch_fp_overrides(db: AsyncSession) -> set[str]:
    rows = (
        await db.execute(select(IOCFeedback.ioc_value).where(IOCFeedback.feedback == "false_positive"))
    ).scalars().all()
    return set(rows)


def _normalize_ioc(value: str) -> str:
    normalized = refang(value.strip())
    if not normalized:
        raise HTTPException(status_code=400, detail="Empty IOC value")
    if len(normalized) > 2048:
        raise HTTPException(status_code=400, detail="IOC value too long")
    return normalized


def _task_to_response(task) -> LookupResponse:
    return LookupResponse(
        input=task.ioc_value,
        normalized=task.normalized,
        ioc_type=task.ioc_type or "unknown",
        composite=task.composite,
        final_assessment=getattr(task, "final_assessment", None),
        provider_health=getattr(task, "provider_health", []),
        enrichment=task.enrichment or None,
        results=task.results,
        relationships=task.relationships,
        executive_summary=task.executive_summary,
    )


@app.post("/api/lookup", response_model=TaskStatusResponse)
async def start_lookup(request: LookupRequest, db: AsyncSession = Depends(get_db)):
    req_type = request.ioc_type
    normalized = _normalize_ioc(request.ioc)
    if req_type and req_type not in SUPPORTED_IOC_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported IOC type")
    if not req_type and classify_ioc(normalized) == "unknown":
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")

    fp_override = normalized in await _fetch_fp_overrides(db)

    # For passwords, convert to SHA-1 hash for privacy-preserving k-anonymity lookup (HIBP)
    target_ioc = normalized
    effective_type = req_type
    if req_type == "password":
        import hashlib
        if not re.fullmatch(r"^[a-f0-9]{40}$", normalized, re.IGNORECASE):
            target_ioc = hashlib.sha1(normalized.encode("utf-8")).hexdigest()
        else:
            target_ioc = normalized.lower()
        effective_type = "password"

    # A lookup can take up to the pipeline timeout. Queue it and return the
    # identifier immediately so the UI can reliably poll or use SSE instead
    # of timing out before it learns the task id.
    task_id = uuid4().hex[:12]
    asyncio.create_task(
        run_analysis(
            target_ioc,
            task_id=task_id,
            fp_override=fp_override,
            ioc_type_override=effective_type,
        )
    )
    return TaskStatusResponse(
        task_id=task_id,
        status="pending",
        ioc_value=target_ioc,
        normalized=target_ioc,
        ioc_type=request.ioc_type or classify_ioc(normalized),
    )


@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    task = await get_task_redis(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.to_dict()


SSE_HEARTBEAT_INTERVAL = 15.0
SSE_IDLE_TIMEOUT = 300.0
SSE_QUEUE_TIMEOUT = 2.0


@app.get("/api/tasks/{task_id}/stream")
async def stream_task(task_id: str, request: Request):
    queue = get_task_queue(task_id)

    async def event_generator():
        last_heartbeat = asyncio.get_running_loop().time()
        last_event = asyncio.get_running_loop().time()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=SSE_QUEUE_TIMEOUT)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                    last_event = asyncio.get_running_loop().time()
                except asyncio.TimeoutError:
                    now = asyncio.get_running_loop().time()
                    if now - last_event >= SSE_IDLE_TIMEOUT:
                        break
                    if now - last_heartbeat >= SSE_HEARTBEAT_INTERVAL:
                        last_heartbeat = now
                        yield "event: heartbeat\ndata: {}\n\n"
                    else:
                        yield ": keepalive\n\n"
        finally:
            cleanup_task_queue(task_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/tasks/{task_id}/result")
async def get_task_result(task_id: str):
    task = await get_task_redis(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != "done":
        raise HTTPException(status_code=425, detail="Analysis not yet complete")

    return _task_to_response(task)


# --- Investigations ---

@app.get("/api/investigations", response_model=list[InvestigationSummary])
async def list_investigations(db: AsyncSession = Depends(get_db)):
    stmt = select(Investigation).order_by(Investigation.updated_at.desc())
    result = await db.execute(stmt)
    invs = result.scalars().all()
    return [
        InvestigationSummary(
            id=inv.id,
            name=inv.name,
            description=inv.description or "",
            ioc_count=len(inv.iocs) if inv.iocs else 0,
            created_at=inv.created_at.isoformat() if inv.created_at else None,
            updated_at=inv.updated_at.isoformat() if inv.updated_at else None,
        )
        for inv in invs
    ]


@app.post("/api/investigations", response_model=InvestigationCreateResponse)
async def create_investigation(body: InvestigationCreate, db: AsyncSession = Depends(get_db)):
    inv = Investigation(name=body.name, description=body.description)
    db.add(inv)
    await retry_sqlite_commit(db)
    await db.refresh(inv)
    return InvestigationCreateResponse(
        id=inv.id,
        name=inv.name,
        description=inv.description,
        created_at=inv.created_at.isoformat() if inv.created_at else None,
    )


@app.get("/api/investigations/{inv_id}", response_model=InvestigationDetail)
async def get_investigation(inv_id: int, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Investigation)
        .options(
            selectinload(Investigation.iocs).selectinload(InvestigationIOC.ioc),
        )
        .where(Investigation.id == inv_id)
    )
    inv = (await db.execute(stmt)).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    ioc_ids = [ii.ioc_id for ii in inv.iocs if ii.ioc_id is not None]

    latest_by_ioc: dict[int, LookupResult] = {}
    if ioc_ids:
        rows = (
            await db.execute(
                select(LookupResult)
                .where(LookupResult.ioc_id.in_(ioc_ids))
                .order_by(LookupResult.ioc_id, LookupResult.created_at.desc())
            )
        ).scalars().all()
        for lr in rows:
            latest_by_ioc.setdefault(lr.ioc_id, lr)

    iocs_data = []
    for ii in inv.iocs:
        ioc = ii.ioc
        latest = latest_by_ioc.get(ioc.id)
        iocs_data.append(IOCInInvestigation(
            id=ii.id,
            ioc_id=ioc.id,
            value=ioc.value,
            ioc_type=ioc.ioc_type,
            notes=ii.notes or "",
            score=latest.composite_score if latest else None,
            verdict=latest.composite_verdict if latest else None,
            looked_up_at=latest.created_at.isoformat() if latest and latest.created_at else None,
        ))

    return InvestigationDetail(
        id=inv.id,
        name=inv.name,
        description=inv.description or "",
        iocs=iocs_data,
        created_at=inv.created_at.isoformat() if inv.created_at else None,
        updated_at=inv.updated_at.isoformat() if inv.updated_at else None,
    )


@app.put("/api/investigations/{inv_id}", response_model=StatusResponse)
async def update_investigation(inv_id: int, body: InvestigationUpdate, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if body.name is not None:
        inv.name = body.name
    if body.description is not None:
        inv.description = body.description
    await retry_sqlite_commit(db)
    return StatusResponse(status="updated")


@app.delete("/api/investigations/{inv_id}", response_model=StatusResponse)
async def delete_investigation(inv_id: int, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.delete(inv)
    await retry_sqlite_commit(db)
    return StatusResponse(status="deleted")


@app.post("/api/investigations/{inv_id}/iocs")
async def add_ioc_to_investigation(inv_id: int, body: LookupRequest, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    normalized = _normalize_ioc(body.ioc)
    ioc_type = classify_ioc(normalized)

    existing = await db.execute(select(IOC).where(IOC.value == normalized))
    ioc = existing.scalar_one_or_none()
    if not ioc:
        ioc = IOC(value=normalized, ioc_type=ioc_type)
        db.add(ioc)
        await db.flush()
    ioc_id = ioc.id

    already = await db.execute(
        select(InvestigationIOC).where(
            InvestigationIOC.investigation_id == inv_id,
            InvestigationIOC.ioc_id == ioc_id,
        )
    )
    if not already.scalar_one_or_none():
        ii = InvestigationIOC(investigation_id=inv_id, ioc_id=ioc_id)
        db.add(ii)

    await retry_sqlite_commit(db)

    await _auto_score_ioc(normalized, ioc_id, db)
    return {"status": "added", "ioc_id": ioc_id, "value": normalized}


@app.put("/api/investigations/{inv_id}/iocs/{ii_id}", response_model=StatusResponse)
async def update_ioc_notes(inv_id: int, ii_id: int, body: NoteUpdate, db: AsyncSession = Depends(get_db)):
    ii = await db.get(InvestigationIOC, ii_id)
    if not ii or ii.investigation_id != inv_id:
        raise HTTPException(status_code=404, detail="Not found")
    ii.notes = body.notes
    await retry_sqlite_commit(db)
    return StatusResponse(status="updated")


@app.delete("/api/investigations/{inv_id}/iocs/{ii_id}", response_model=StatusResponse)
async def remove_ioc_from_investigation(inv_id: int, ii_id: int, db: AsyncSession = Depends(get_db)):
    ii = await db.get(InvestigationIOC, ii_id)
    if not ii or ii.investigation_id != inv_id:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ii)
    await retry_sqlite_commit(db)
    return StatusResponse(status="removed")


# --- Recent Lookups ---

@app.get("/api/recent", response_model=list[RecentIOCResponse])
async def recent_lookups(db: AsyncSession = Depends(get_db)):
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
        out.append(RecentIOCResponse(
            id=ioc.id,
            value=ioc.value,
            ioc_type=ioc.ioc_type,
            verdict=latest.composite_verdict if latest else None,
            score=latest.composite_score if latest else None,
            confidence=latest.composite_confidence if latest else None,
            created_at=ioc.created_at.isoformat() if ioc.created_at else None,
        ))
    return out


@app.delete("/api/recent/{ioc_id}", response_model=StatusResponse)
async def delete_recent(ioc_id: int, db: AsyncSession = Depends(get_db)):
    ioc = await db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(ioc)
    await retry_sqlite_commit(db)
    return StatusResponse(status="deleted")


# --- False-Positive Feedback (A-2) ---

@app.post("/api/feedback", response_model=FeedbackResponse)
async def submit_feedback(body: FeedbackRequest, db: AsyncSession = Depends(get_db)):
    from app.backend.classifier import classify_ioc
    value = _normalize_ioc(body.ioc)
    if classify_ioc(value) == "unknown":
        raise HTTPException(status_code=400, detail="Unrecognizable IOC format")
    if body.feedback not in ("false_positive", "confirmed"):
        raise HTTPException(status_code=400, detail="feedback must be 'false_positive' or 'confirmed'")

    existing = (
        await db.execute(select(IOCFeedback).where(IOCFeedback.ioc_value == value))
    ).scalar_one_or_none()
    if existing:
        existing.feedback = body.feedback
        existing.note = body.note
    else:
        existing = IOCFeedback(ioc_value=value, feedback=body.feedback, note=body.note)
        db.add(existing)
    await retry_sqlite_commit(db)
    await db.refresh(existing)
    return FeedbackResponse(
        ioc_value=existing.ioc_value,
        feedback=existing.feedback,
        note=existing.note,
        created_at=existing.created_at.isoformat() if existing.created_at else None,
    )


@app.get("/api/feedback/{ioc}", response_model=FeedbackResponse)
async def get_feedback(ioc: str, db: AsyncSession = Depends(get_db)):
    value = _normalize_ioc(ioc)
    row = (
        await db.execute(select(IOCFeedback).where(IOCFeedback.ioc_value == value))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="No feedback recorded for this IOC")
    return FeedbackResponse(
        ioc_value=row.ioc_value,
        feedback=row.feedback,
        note=row.note,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


@app.delete("/api/feedback/{ioc}", response_model=StatusResponse)
async def delete_feedback(ioc: str, db: AsyncSession = Depends(get_db)):
    value = _normalize_ioc(ioc)
    row = (
        await db.execute(select(IOCFeedback).where(IOCFeedback.ioc_value == value))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="No feedback recorded for this IOC")
    await db.delete(row)
    await retry_sqlite_commit(db)
    return StatusResponse(status="deleted")


# --- Batch Analysis ---

class BatchRequest(BaseModel):
    iocs: list[str]
    timeout: Optional[float] = None
    concurrency: Optional[int] = None


@app.post("/api/batch", response_model=BatchStatusResponse)
async def start_batch(body: BatchRequest, db: AsyncSession = Depends(get_db)):
    if not body.iocs:
        raise HTTPException(status_code=400, detail="No IOCs provided")
    if len(body.iocs) > settings.max_batch_iocs:
        raise HTTPException(status_code=400, detail=f"Maximum {settings.max_batch_iocs} IOCs per batch")

    fp_overrides = await _fetch_fp_overrides(db)
    try:
        batch = start_batch_analysis(body.iocs, fp_overrides=fp_overrides,
                                     timeout=body.timeout, concurrency=body.concurrency)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return BatchStatusResponse(batch_id=batch.batch_id, total=batch.total, status=batch.status)


MAX_UPLOAD_SIZE = 10 * 1024 * 1024


@app.post("/api/batch/upload", response_model=BatchStatusResponse)
async def upload_batch_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    try:
        raw = b""
        chunk_size = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
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
        if len(iocs) > settings.max_batch_iocs:
            raise HTTPException(status_code=400, detail=f"Maximum {settings.max_batch_iocs} IOCs per batch")

        fp_overrides = await _fetch_fp_overrides(db)
        batch = start_batch_analysis(iocs, fp_overrides=fp_overrides)
        return BatchStatusResponse(batch_id=batch.batch_id, total=batch.total, status=batch.status)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
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


@app.get("/api/batch/{batch_id}/stream")
async def stream_batch(batch_id: str, request: Request):
    if not get_batch(batch_id):
        raise HTTPException(status_code=404, detail="Batch not found")
    queue = get_batch_queue(batch_id)

    async def event_generator():
        last_heartbeat = asyncio.get_running_loop().time()
        last_event = asyncio.get_running_loop().time()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(queue.get(), timeout=SSE_QUEUE_TIMEOUT)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                    last_event = asyncio.get_running_loop().time()
                except asyncio.TimeoutError:
                    now = asyncio.get_running_loop().time()
                    if now - last_event >= SSE_IDLE_TIMEOUT:
                        break
                    if now - last_heartbeat >= SSE_HEARTBEAT_INTERVAL:
                        last_heartbeat = now
                        yield "event: heartbeat\ndata: {}\n\n"
                    else:
                        yield ": keepalive\n\n"
        finally:
            cleanup_batch_queue(batch_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# --- Export ---

class ReportExportRequest(BaseModel):
    ioc: str
    task_id: str | None = None

@app.post("/api/export/report")
async def export_report(body: ReportExportRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)

    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    html = _build_html_report(response)
    return HTMLResponse(html, media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="ioc_report_{normalized}.html"'})

def _build_html_report(data: dict) -> str:
    ioc_val = data.get("normalized") or data.get("input") or "Unknown"
    ioc_type = data.get("ioc_type", "")
    comp = data.get("composite", {})
    verdict = comp.get("verdict", "unknown")
    score = comp.get("score")
    score_str = f"{round(score)}/100" if score is not None else "—"
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
<body><div class="container">"""

    html += f"""
<h1>Threat Intelligence Report</h1>
<p class="meta">IOC Universal — {_e(date_str)}</p>
<div class="banner">
  <div>
    <div style="font-size:0.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:0.15rem">{_e(ioc_type)}</div>
    <div class="mono" style="font-weight:600;font-size:1.05rem">{_e(ioc_val)}</div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div><span class="badge badge-{_e(verdict)}">{_e(verdict)}</span></div>
    <div class="score-display score-{"red" if (score or 0) >= DISPLAY_MALICIOUS else "amber" if (score or 0) >= DISPLAY_SUSPICIOUS else "green"}">{_e(score_str)}</div>
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
        html += f'<div class="stat-card"><div class="stat-num">{_e(g.get("country",""))}</div><div class="stat-lbl">Country{"; " + _e(g.get("city","")) if g.get("city") else ""}</div><div class="stat-sub">AS{_e(g.get("asn",""))} &middot; {_e(g.get("isp",""))}</div></div>'
    if enrich.get("whois") and enrich["whois"].get("registrar"):
        w = enrich["whois"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(w.get("registrar",""))}</div><div class="stat-lbl">Registrar &middot; created {_e(w.get("creation_date","") or "?")}</div></div>'
    if enrich.get("ssl") and enrich["ssl"].get("subject"):
        s = enrich["ssl"]
        html += f'<div class="stat-card"><div class="stat-num">{_e(s.get("subject",""))}</div><div class="stat-lbl">SSL{" [EXPIRED]" if s.get("is_expired") else ""}</div><div class="stat-sub">issuer: {_e(s.get("issuer","") or "?")} &middot; days left: {_e(s.get("days_left","?"))}</div></div>'
    if enrich.get("passive_dns") and enrich["passive_dns"].get("records"):
        pdns = enrich["passive_dns"]["records"]
        html += f'<div class="stat-card"><div class="stat-num">{len(pdns)}</div><div class="stat-lbl">Passive DNS Records</div></div>'
    if enrich.get("open_ports") and enrich["open_ports"]:
        ports = enrich["open_ports"]
        html += f'<div class="stat-card"><div class="stat-num">{len(ports)}</div><div class="stat-lbl">Open Ports</div><div class="stat-sub">{", ".join(_e(str(p)) for p in ports[:10])}</div></div>'
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
async def export_stix(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)

    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    bundle = build_stix_bundle(response)
    return bundle


@app.post("/api/export/misp")
async def export_misp(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)

    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

    event = build_misp_event(response)
    return event


class SIEMExportRequest(BaseModel):
    ioc: str
    format: str = "splunk"
    task_id: str | None = None


@app.post("/api/export/siem")
async def export_siem_endpoint(body: SIEMExportRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)

    task = await _resolve_task(body.ioc, body.task_id, db)
    response = _task_to_response(task).model_dump()

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
async def export_csv(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)

    task = await _resolve_task(body.ioc, body.task_id, db)

    results = [r.model_dump() for r in task.results]
    csv_content = results_to_csv(results)
    return PlainTextResponse(csv_content, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=ioc_report.csv"})


# --- Webhooks ---

class WebhookCreate(BaseModel):
    url: str
    events: list[str] = ["lookup.complete"]
    secret: str | None = None


@app.get("/api/webhooks", response_model=list[WebhookResponse])
async def get_webhooks():
    if not settings.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks are disabled")
    return await list_webhooks()


@app.post("/api/webhooks", response_model=WebhookResponse)
async def create_webhook(body: WebhookCreate):
    if not settings.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks are disabled")
    try:
        result = await add_webhook(body.url, body.events, body.secret)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/webhooks/{webhook_id}", response_model=StatusResponse)
async def delete_webhook(webhook_id: str):
    if not settings.webhooks_enabled:
        raise HTTPException(status_code=403, detail="Webhooks are disabled")
    ok = await remove_webhook(webhook_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return StatusResponse(status="deleted")


# --- Save Lookup Result ---

async def _auto_score_ioc(normalized: str, ioc_id: int, db: AsyncSession) -> bool:
    from app.backend.cache import cache_key
    from app.backend.pipeline import cache as _cache

    task = None
    ck = cache_key("save", classify_ioc(normalized), normalized)
    if _cache is not None:
        cached = await _cache.get(ck)
        if cached and cached.get("task_id"):
            cached_task = await get_task_redis(cached["task_id"])
            if cached_task is not None and cached_task.status == "done":
                task = cached_task

    if task is None:
        task = await run_analysis(normalized, fp_override=normalized in await _fetch_fp_overrides(db))

    if task.status == "done" and task.composite:
        score = task.composite.score if hasattr(task.composite, "score") else 0
        verdict = task.composite.verdict if hasattr(task.composite, "verdict") else "unknown"
        confidence = task.composite.confidence if hasattr(task.composite, "confidence") else "low"

        response_dict = json.loads(_task_to_response(task).model_dump_json())

        lr = LookupResult(
            ioc_id=ioc_id,
            task_id=task.task_id,
            composite_score=score,
            composite_verdict=verdict,
            composite_confidence=confidence,
            full_response=json.dumps(response_dict),
            source_count=len(task.results),
        )
        db.add(lr)
        await retry_sqlite_commit(db)
        return True
    return False


@app.post("/api/save", response_model=SaveResponse)
async def save_lookup_result(body: LookupRequest, db: AsyncSession = Depends(get_db)):
    normalized = _normalize_ioc(body.ioc)
    ioc_type = classify_ioc(normalized)

    existing = await db.execute(select(IOC).where(IOC.value == normalized))
    ioc = existing.scalar_one_or_none()
    if not ioc:
        ioc = IOC(value=normalized, ioc_type=ioc_type)
        db.add(ioc)
        await db.flush()
    ioc_id = ioc.id

    task = None
    if body.task_id:
        task = await get_task_redis(body.task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
    else:
        from app.backend.cache import cache_key
        from app.backend.pipeline import cache as _cache

        ck = cache_key("save", ioc_type, normalized)
        if _cache is not None:
            cached = await _cache.get(ck)
            if cached and cached.get("task_id"):
                cached_task = await get_task_redis(cached["task_id"])
                if cached_task is not None and cached_task.status == "done":
                    task = cached_task

    if task is None:
        task = await run_analysis(normalized, fp_override=normalized in await _fetch_fp_overrides(db))

    if task.status == "done" and task.composite:
        score = task.composite.score if hasattr(task.composite, "score") else 0
        verdict = task.composite.verdict if hasattr(task.composite, "verdict") else "unknown"
        confidence = task.composite.confidence if hasattr(task.composite, "confidence") else "low"

        response_dict = json.loads(_task_to_response(task).model_dump_json())

        lr = LookupResult(
            ioc_id=ioc_id,
            task_id=task.task_id,
            composite_score=score,
            composite_verdict=verdict,
            composite_confidence=confidence,
            full_response=json.dumps(response_dict),
            source_count=len(task.results),
        )
        db.add(lr)
        await retry_sqlite_commit(db)

    return SaveResponse(status="saved", ioc_id=ioc_id)
# --- Local React UI ---

ROOT = Path(__file__).resolve().parent.parent.parent
ui_dist_dir = ROOT / "ui" / "dist"
ui_assets_dir = ui_dist_dir / "assets"

if ui_assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(ui_assets_dir)), name="ui-assets")


@app.get("/")
async def index():
    index_file = ui_dist_dir / "index.html"
    if not index_file.exists():
        return PlainTextResponse(
            "The local UI has not been built. Run `cd ui`, `npm install`, and `npm run build`.",
            status_code=503,
        )
    return FileResponse(str(index_file))
