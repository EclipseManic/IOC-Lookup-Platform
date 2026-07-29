import asyncio
import hmac
import ipaddress
import json
import socket
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.backend.http_client import get_client

_webhooks: dict[str, dict] = {}
_lock = asyncio.Lock()


def _validate_webhook_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return "Webhook URL must use HTTPS"
    host = parsed.hostname
    if not host:
        return "Invalid webhook URL"
    try:
        loop = asyncio.get_event_loop()
        addr = await loop.run_in_executor(None, socket.gethostbyname, host)
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "Webhook URL must point to a public address"
    except Exception:
        return "Could not resolve webhook URL"
    return None


class WebhookModel:
    def __init__(self, url: str, events: list[str] | None = None, secret: str | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.url = url
        self.events = events or ["lookup.complete"]
        self.secret = secret
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "events": self.events,
            "has_secret": bool(self.secret),
            "created_at": self.created_at,
        }

    def matches_event(self, event: str) -> bool:
        return event in self.events


async def add_webhook(url: str, events: list[str] | None = None, secret: str | None = None) -> dict:
    err = _validate_webhook_url(url)
    if err:
        raise ValueError(err)
    wh = WebhookModel(url, events, secret)
    async with _lock:
        _webhooks[wh.id] = {"url": wh.url, "events": wh.events, "secret": wh.secret, "created_at": wh.created_at}
    return wh.to_dict()


async def remove_webhook(webhook_id: str) -> bool:
    async with _lock:
        if webhook_id in _webhooks:
            del _webhooks[webhook_id]
            return True
        return False


async def list_webhooks() -> list[dict]:
    async with _lock:
        return [
            {"id": k, "url": v["url"], "events": v["events"], "has_secret": bool(v.get("secret")), "created_at": v.get("created_at", "")}
            for k, v in _webhooks.items()
        ]


def _sign_payload(payload: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), payload, "sha256").hexdigest()


async def dispatch_event(event: str, data: dict):
    async with _lock:
        targets = list(_webhooks.values())

    if not targets:
        return

    client = get_client()
    payload = json.dumps({"event": event, **data}).encode()

    for wh in targets:
        if event not in wh.get("events", ["lookup.complete"]):
            continue

        headers = {"Content-Type": "application/json"}
        secret = wh.get("secret")
        if secret:
            headers["X-Webhook-Signature"] = _sign_payload(payload, secret)

        for attempt in range(3):
            try:
                resp = await client.post(wh["url"], content=payload, headers=headers, timeout=10.0)
                if resp.is_success:
                    break
            except Exception:
                pass
            if attempt < 2:
                await asyncio.sleep(1.5 ** attempt)


async def dispatch_lookup_complete(task_id: str, ioc_value: str, verdict: str, score: float):
    await dispatch_event("lookup.complete", {
        "task_id": task_id,
        "ioc_value": ioc_value,
        "verdict": verdict,
        "score": score,
        "result_url": f"/api/tasks/{task_id}/result",
    })
