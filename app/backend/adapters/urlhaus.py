import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key


class URLHausAdapter(SourceAdapter):
    name = "URLhaus"
    supported_types = ["url", "domain", "md5", "sha1", "sha256"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=60)

    def __init__(self):
        super().__init__()
        from app.backend.config import settings
        self.api_key = settings.urlhaus_api_key

    def _auth_headers(self) -> dict:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if is_valid_api_key(self.api_key):
            headers["Auth-Key"] = self.api_key
        return headers

    async def _post(self, url: str, data: dict) -> dict:
        client = self._get_client()
        try:
            resp = await client.post(url, data=data, headers=self._auth_headers(), timeout=15)
        except httpx.ConnectError:
            try:
                async with httpx.AsyncClient(verify=False, timeout=15) as fb_client:
                    resp = await fb_client.post(url, data=data, headers=self._auth_headers())
            except Exception:
                return {}
        except Exception:
            return {}

        if resp.status_code == 429:
            return {"query_status": "rate_limited"}
        if resp.status_code != 200:
            return {}
        try:
            return resp.json()
        except Exception:
            return {}

    async def _query_host(self, ioc_value: str) -> dict:
        return await self._post("https://urlhaus-api.abuse.ch/v1/host/", {"host": ioc_value})

    async def _query_url(self, ioc_value: str) -> dict:
        return await self._post("https://urlhaus-api.abuse.ch/v1/url/", {"url": ioc_value})

    async def _query_payload(self, ioc_value: str) -> dict:
        return await self._post("https://urlhaus-api.abuse.ch/v1/payload/", {"hash": ioc_value})

    async def _query_tag(self, tag: str) -> dict:
        return await self._post("https://urlhaus-api.abuse.ch/v1/tag/", {"tag": tag})

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type == "domain":
            data = await self._query_host(ioc_value)
        elif ioc_type in ("md5", "sha1", "sha256"):
            data = await self._query_payload(ioc_value)
        else:
            data = await self._query_url(ioc_value)

        if not data:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
            )

        if data.get("query_status") == "rate_limited":
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"],
            )

        query_status = data.get("query_status", "")

        if query_status == "ok":
            tags = ["malware_url"]
            threat = data.get("threat", "")
            if threat:
                tags.append(f"threat:{threat}")
            for t in data.get("tags", []):
                if isinstance(t, str):
                    tags.append(t)
            ref = data.get("urlhaus_reference", "")
            if ref:
                tags.append(f"ref:{ref}")

            if threat:
                try:
                    tag_data = await self._query_tag(threat)
                    if tag_data.get("query_status") == "ok":
                        tag_urls = tag_data.get("urls", [])
                        if isinstance(tag_urls, list):
                            tags.append(f"tag_urls:{len(tag_urls)}")
                except Exception as exc:
                    logger.debug("URLhaus tag lookup failed: %s", exc)

            url_status = data.get("url_status", "")
            if url_status == "online":
                verdict = "malicious"
                raw_score = 1.0
            elif url_status in ("offline", "unknown"):
                verdict = "suspicious"
                raw_score = 0.5
            else:
                verdict = "unknown"
                raw_score = 0.0

            urls = data.get("urls", [])
            if isinstance(urls, list):
                for u in urls[:10]:
                    if isinstance(u, dict):
                        tags.append(f"url:{u.get('url', '')[:80]}")

            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict=verdict, raw_score=raw_score, tags=tags,
                source_link=ref or None, reports_count=len(urls) if isinstance(urls, list) else 0,
            )

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=0.0, status="not_found",
        )
