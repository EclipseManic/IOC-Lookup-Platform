import asyncio
import json
import time

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.urlscan_io")


class UrlScanIOAdapter(SourceAdapter):
    name = "urlscan.io"
    supported_types = ["domain", "url"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=10, max_retries=1, timeout_seconds=10.0)
    SCAN_POLL_ATTEMPTS = 7
    SCAN_POLL_DELAY = 2.0

    def __init__(self):
        self.api_key = settings.urlscanio_api_key

    async def _submit_scan(self, ioc_value: str) -> str | None:
        client = self._get_client()
        try:
            resp = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": self.api_key, "Content-Type": "application/json"},
                json={"url": ioc_value, "public": "on"},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                return resp.json().get("uuid")
        except Exception as exc:
            logger.warning(f"urlscan.io scan submission failed for {ioc_value}: {exc}")
        return None

    async def _poll_scan(self, scan_uuid: str, timeout: float = 15.0) -> dict | None:
        client = self._get_client()
        deadline = time.time() + timeout
        for _ in range(self.SCAN_POLL_ATTEMPTS):
            if time.time() > deadline:
                break
            try:
                resp = await client.get(
                    f"https://urlscan.io/api/v1/result/{scan_uuid}/",
                    timeout=10,
                )
                if resp.status_code == 200:
                    return resp.json()
            except Exception as exc:
                logger.debug("urlscan.io scan poll attempt failed: %s", exc)
            if time.time() < deadline:
                await asyncio.sleep(self.SCAN_POLL_DELAY)
        return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        headers = {"API-Key": self.api_key} if is_valid_api_key(self.api_key) else {}
        query_value = json.dumps(ioc_value, ensure_ascii=False)
        resp = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.{ioc_type}:{query_value}", "size": 5},
                headers=headers or None,
                timeout=15,
            )

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"], http_status=resp.status_code,
                retry_after_seconds=retry_after_seconds(resp),
            )
        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["invalid_api_key"],
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        if not isinstance(data, dict):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unexpected_response"],
            )

        results = data.get("results", [])
        if not isinstance(results, list):
            results = []

        has_cached_results = bool(results)

        malicious = 0
        all_tags = set()
        all_categories = set()
        first = None
        last = None
        related = []
        samples = []
        total = len(results)

        page_domains = set()
        page_ips = set()
        page_countries = set()
        page_asns = set()
        screenshot_url = ""

        # Rich page metadata for WebPreviewInfo
        page_title = ""
        page_server = ""
        page_language = ""
        domain_age_days: int | None = None
        tls_issuer = ""
        tls_valid_days: int | None = None
        page_asn_name = ""
        detected_brands: list[str] = []
        detected_technologies: list[str] = []
        page_mime_type = ""
        result_scan_uuid = ""

        for entry in results:
            if not isinstance(entry, dict):
                continue

            page = entry.get("page", {})
            if not isinstance(page, dict):
                page = {}

            dom = page.get("domain", "")
            if dom:
                page_domains.add(dom)
            ip = page.get("ip", "")
            if ip:
                page_ips.add(ip)
            country = page.get("country", "")
            if country:
                page_countries.add(country)
            asn = page.get("asn", "")
            if asn:
                page_asns.add(asn)
            server = page.get("server", "")
            if server:
                all_tags.add(f"server: {server}")
                if not page_server:
                    page_server = server

            if not screenshot_url:
                screenshot_url = entry.get("screenshot", "") or page.get("screenshot", "") or ""

            # Extract rich page metadata from the first result
            if not page_title:
                page_title = page.get("title", "") or ""
            if not page_language:
                page_language = page.get("language", "") or ""
            if domain_age_days is None:
                age = page.get("domainAgeDays")
                if age is not None:
                    try:
                        domain_age_days = int(age)
                    except (ValueError, TypeError):
                        pass
            if not tls_issuer:
                tls_issuer = page.get("tlsIssuer", "") or ""
            if tls_valid_days is None:
                tvd = page.get("tlsValidDays")
                if tvd is not None:
                    try:
                        tls_valid_days = int(tvd)
                    except (ValueError, TypeError):
                        pass
            if not page_asn_name:
                page_asn_name = page.get("asnname", "") or ""
            if not page_mime_type:
                page_mime_type = page.get("mimeType", "") or ""

            # Capture scan UUID from the task for screenshot proxying
            task = entry.get("task", {})
            if isinstance(task, dict) and not result_scan_uuid:
                result_scan_uuid = task.get("uuid", "") or ""

            # Extract brand detection from verdicts
            result_entry = entry.get("result", {})
            if isinstance(result_entry, dict):
                brands_data = result_entry.get("verdicts", {}).get("overall", {}).get("brands", [])
                if isinstance(brands_data, list):
                    for brand in brands_data:
                        if isinstance(brand, str) and brand not in detected_brands:
                            detected_brands.append(brand)
                        elif isinstance(brand, dict):
                            bname = brand.get("name", "")
                            if bname and bname not in detected_brands:
                                detected_brands.append(bname)

            lists_data = entry.get("lists", {})
            if isinstance(lists_data, dict):
                for list_ip in (lists_data.get("ips", []) or []):
                    related.append((list_ip, "related_ip"))
                for list_domain in (lists_data.get("domains", []) or []):
                    related.append((list_domain, "related_domain"))
                for h in (lists_data.get("hashes", []) or []):
                    if isinstance(h, str):
                        samples.append(h)
                        related.append((h, "related_hash"))
                for cert in (lists_data.get("certificates", []) or []):
                    if isinstance(cert, dict):
                        cn = cert.get("subjectName", "")
                        if cn:
                            all_tags.add(f"cert_cn:{cn}")

            if not isinstance(result_entry, dict):
                result_entry = {}
            overall = result_entry.get("verdicts", {}).get("overall", {})
            if not overall:
                overall = entry.get("verdicts", {}).get("overall", {})
            if overall.get("malicious"):
                malicious += 1

            tags = page.get("tags", [])
            if isinstance(tags, list):
                all_tags.update(tags)

            cats = entry.get("categories", [])
            if isinstance(cats, list):
                all_categories.update(cats)

            if isinstance(task, dict):
                url = task.get("url", "")
                if url and url.lower() != ioc_value.lower():
                    related.append((url, "related_scan"))

            score = overall.get("score", 0)
            if score:
                samples.append(f"Score: {score}")

            submitted = task.get("time") if isinstance(task, dict) else None
            if submitted:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(submitted.replace("Z", "+00:00"))
                    if first is None or dt < first:
                        first = dt
                    if last is None or dt > last:
                        last = dt
                except Exception as exc:
                    logger.debug("urlscan.io date parse failed: %s", exc)

        for d in page_domains:
            all_tags.add(f"domain: {d}")
        for c in page_countries:
            all_tags.add(f"country: {c}")
        for a in page_asns:
            all_tags.add(f"asn: {a}")
        if screenshot_url:
            samples.insert(0, f"Screenshot: {screenshot_url}")

        is_malicious = malicious > 0
        score_val = min(malicious / total, 1.0) if total > 0 else 0.0
        confidence = "high" if malicious >= 3 else "medium" if malicious > 0 else "low"

        report_url = ""
        if results and isinstance(results[0], dict):
            task = results[0].get("task", {})
            if isinstance(task, dict):
                report_url = task.get("reportURL", "") or task.get("screenshotURL", "") or ""
        if screenshot_url and not report_url:
            report_url = screenshot_url

        scan_uuid = None
        scan_completed = False
        if not has_cached_results and is_valid_api_key(self.api_key) and settings.enable_public_url_submission:
            scan_uuid = await self._submit_scan(ioc_value)
        if scan_uuid:
            all_tags.add("active_scan_submitted")
            active = await self._poll_scan(scan_uuid)
            if active:
                scan_completed = True
                all_tags.add("active_scan_completed")
                verdicts = active.get("verdicts", {})
                if isinstance(verdicts, dict):
                    overall = verdicts.get("overall", {})
                    if isinstance(overall, dict) and overall.get("malicious"):
                        is_malicious = True
                        score_val = max(score_val, overall.get("score", 0) / 100.0)
                page = active.get("page", {})
                if isinstance(page, dict):
                    if page.get("domain"):
                        all_tags.add(f"active_domain:{page['domain']}")
                    if page.get("ip"):
                        all_tags.add(f"active_ip:{page['ip']}")
                    if page.get("country"):
                        all_tags.add(f"active_country:{page['country']}")
                    if page.get("asn"):
                        all_tags.add(f"active_asn:{page['asn']}")
                    if page.get("server"):
                        all_tags.add(f"active_server:{page['server']}")
                if not screenshot_url:
                    screenshot_url = active.get("screenshot") or active.get("page", {}).get("screenshot", "")
                if screenshot_url:
                    report_url = f"https://urlscan.io/result/{scan_uuid}/"
                if not result_scan_uuid:
                    result_scan_uuid = scan_uuid

        if not is_malicious and not has_cached_results and not scan_completed:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0,
            )

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict="malicious" if is_malicious else "clean",
            confidence=confidence,
            raw_score=round(score_val, 4),
            tags=sorted(all_tags),
            categories=sorted(all_categories),
            first_seen=first,
            last_seen=last,
            related_iocs=related,
            source_link=report_url,
            reports_count=total,
            samples=samples[:10],
            raw_data={
                **data,
                "web_preview": {
                    "screenshot_url": screenshot_url,
                    "page_title": page_title,
                    "server": page_server,
                    "language": page_language,
                    "domain_age_days": domain_age_days,
                    "tls_issuer": tls_issuer,
                    "tls_valid_days": tls_valid_days,
                    "asn_name": page_asn_name,
                    "detected_brands": detected_brands,
                    "detected_technologies": detected_technologies,
                    "mime_type": page_mime_type,
                    "scan_uuid": result_scan_uuid,
                },
            },
        )
