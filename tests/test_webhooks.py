import sys

sys.path.insert(0, ".")

import asyncio
import hashlib
import hmac

import pytest

from app.backend import webhooks as webhooks_mod


# ─── URL validation ──────────────────────────────────────────────────────────


def test_validate_rejects_non_https():
    async def main():
        err = await webhooks_mod._validate_webhook_url("http://example.com/hook")
        assert err == "Webhook URL must use HTTPS"

    asyncio.run(main())


def test_validate_rejects_missing_host():
    async def main():
        err = await webhooks_mod._validate_webhook_url("https:///hook")
        assert err == "Invalid webhook URL"

    asyncio.run(main())


def test_validate_rejects_private_ip(monkeypatch):
    async def fake_resolve(host):
        return __import__("ipaddress").ip_address("192.168.1.10")

    monkeypatch.setattr(webhooks_mod, "_resolve_host", fake_resolve)

    async def main():
        err = await webhooks_mod._validate_webhook_url("https://192.168.1.10/hook")
        assert err == "Webhook URL must point to a public address"

    asyncio.run(main())


def test_validate_ok_for_public(monkeypatch):
    async def fake_resolve(host):
        return __import__("ipaddress").ip_address("8.8.8.8")

    monkeypatch.setattr(webhooks_mod, "_resolve_host", fake_resolve)

    async def main():
        err = await webhooks_mod._validate_webhook_url("https://hooks.example.com/x")
        assert err is None

    asyncio.run(main())


def test_validate_resolve_failure(monkeypatch):
    async def fake_resolve(host):
        raise Exception("dns down")

    monkeypatch.setattr(webhooks_mod, "_resolve_host", fake_resolve)

    async def main():
        err = await webhooks_mod._validate_webhook_url("https://nohost.invalid/hook")
        assert err == "Could not resolve webhook URL"

    asyncio.run(main())


# ─── Signing ─────────────────────────────────────────────────────────────────


def test_sign_payload_hmac_sha256():
    payload = b'{"event":"lookup.complete"}'
    sig = webhooks_mod._sign_payload(payload, "s3cret")
    expected = hmac.new(b"s3cret", payload, hashlib.sha256).hexdigest()
    assert sig == expected
    assert len(sig) == 64


# ─── Dispatch ────────────────────────────────────────────────────────────────


def test_dispatch_event_no_targets_returns(monkeypatch):
    async def fake_list():
        return []

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)

    async def main():
        await webhooks_mod.dispatch_event("lookup.complete", {"task_id": "t1"})

    asyncio.run(main())


def test_dispatch_event_filters_by_event(monkeypatch):
    async def fake_list():
        return [{"id": "w1", "url": "https://h/x", "events": ["other"], "secret": None}]

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)
    sent = []

    class FakeResp:
        is_success = True

    class FakeClient:
        async def post(self, url, content=None, headers=None, timeout=None):
            sent.append((url, content, headers))
            return FakeResp()

    monkeypatch.setattr(webhooks_mod, "get_client", lambda: FakeClient())

    async def main():
        await webhooks_mod.dispatch_event("lookup.complete", {"task_id": "t1"})
        assert sent == []

    asyncio.run(main())


def test_dispatch_event_success_with_signature(monkeypatch):
    async def fake_list():
        return [{"id": "w1", "url": "https://hooks.example.com/x", "events": ["lookup.complete"], "secret": "k"}]

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)
    async def safe_target(url):
        return None
    monkeypatch.setattr(webhooks_mod, "_validate_webhook_url", safe_target)
    sent = []

    class FakeResp:
        is_success = True

    class FakeClient:
        async def post(self, url, content=None, headers=None, timeout=None):
            sent.append((url, content, headers))
            return FakeResp()

    monkeypatch.setattr(webhooks_mod, "get_client", lambda: FakeClient())

    async def main():
        await webhooks_mod.dispatch_event("lookup.complete", {"task_id": "t1"})
        assert len(sent) == 1
        url, content, headers = sent[0]
        assert url == "https://hooks.example.com/x"
        assert headers["X-Webhook-Signature"]
        assert headers["Content-Type"] == "application/json"

    asyncio.run(main())


def test_dispatch_event_retries_on_failure(monkeypatch):
    async def fake_list():
        return [{"id": "w1", "url": "https://hooks.example.com/x", "events": ["lookup.complete"], "secret": None}]

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)
    async def safe_target(url):
        return None
    monkeypatch.setattr(webhooks_mod, "_validate_webhook_url", safe_target)
    attempts = []
    import random

    monkeypatch.setattr(random, "uniform", lambda a, b: 0.0)
    monkeypatch.setattr(webhooks_mod, "_RETRY_ATTEMPTS", 2)

    class FakeResp:
        is_success = False

    class FakeClient:
        async def post(self, url, content=None, headers=None, timeout=None):
            attempts.append(url)
            return FakeResp()

    monkeypatch.setattr(webhooks_mod, "get_client", lambda: FakeClient())

    async def main():
        await webhooks_mod.dispatch_event("lookup.complete", {"task_id": "t1"})
        assert len(attempts) == 2

    asyncio.run(main())


def test_dispatch_event_swallows_exception(monkeypatch):
    async def fake_list():
        return [{"id": "w1", "url": "https://hooks.example.com/x", "events": ["lookup.complete"], "secret": None}]

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)
    monkeypatch.setattr(webhooks_mod, "_RETRY_ATTEMPTS", 1)

    class FakeClient:
        async def post(self, url, content=None, headers=None, timeout=None):
            raise ConnectionError("boom")

    monkeypatch.setattr(webhooks_mod, "get_client", lambda: FakeClient())

    async def main():
        await webhooks_mod.dispatch_event("lookup.complete", {"task_id": "t1"})

    asyncio.run(main())


def test_dispatch_lookup_complete_builds_url(monkeypatch):
    from app.backend.config import settings

    captured = {}
    old_base = settings.base_url

    async def fake_dispatch(event, data):
        captured.update(data)

    monkeypatch.setattr(webhooks_mod, "dispatch_event", fake_dispatch)
    monkeypatch.setattr(settings, "base_url", "https://app.example.com")

    async def main():
        await webhooks_mod.dispatch_lookup_complete("t1", "8.8.8.8", "malicious", 90.0)

    asyncio.run(main())
    assert captured["task_id"] == "t1"
    assert captured["result_url"] == "https://app.example.com/api/tasks/t1/result"

    monkeypatch.setattr(settings, "base_url", old_base)


# ─── DB-backed CRUD (uses real async_session → real test DB) ─────────────────


def test_add_remove_list_webhook(monkeypatch):
    async def no_error(url):
        return None

    monkeypatch.setattr(webhooks_mod, "_validate_webhook_url", no_error)

    async def main():
        created = await webhooks_mod.add_webhook(
            "https://hooks.example.com/hook1", events=["lookup.complete"], secret="s"
        )
        assert created["id"]
        assert created["url"] == "https://hooks.example.com/hook1"
        assert created["has_secret"] is True

        found = [w for w in await webhooks_mod.list_webhooks() if w["id"] == created["id"]]
        assert found
        assert found[0]["events"] == ["lookup.complete"]
        assert found[0]["has_secret"] is True

        removed = await webhooks_mod.remove_webhook(created["id"])
        assert removed is True
        assert await webhooks_mod.remove_webhook(created["id"]) is False

    asyncio.run(main())


def test_add_webhook_rejects_bad_url():
    async def bad(url):
        return "Webhook URL must use HTTPS"

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(webhooks_mod, "_validate_webhook_url", bad)

    async def main():
        with pytest.raises(ValueError):
            await webhooks_mod.add_webhook("http://bad/hook")

    asyncio.run(main())
    monkeypatch.undo()
