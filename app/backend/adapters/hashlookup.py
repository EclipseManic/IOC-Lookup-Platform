import re
import httpx
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, retry_after_seconds
from app.backend.logger import get_logger
logger = get_logger("adapter.hashlookup")
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_TYPE_MAP = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}
class HashlookupAdapter(SourceAdapter):
    name = "Hashlookup"
    supported_types = ["md5", "sha1", "sha256"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=30)
    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type not in self.supported_types:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown", tags=["unsupported_type"])
        if not _HASH_RE.match(ioc_value):
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown", tags=["invalid_hash_format"])
        # strict length per type
        expected = {"md5": 32, "sha1": 40, "sha256": 64}
        if len(ioc_value) != expected.get(ioc_type, 0):
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown", tags=["invalid_hash_length"])
        hash_type = _TYPE_MAP[ioc_type]
        url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{ioc_value}"
        client = self._get_client()
        try:
            resp = await client.get(url, timeout=10)
        except httpx.TimeoutException:
            self._record_failure()
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="error", tags=["timeout"])
        except httpx.HTTPError as exc:
            self._record_failure()
            logger.warning("Hashlookup request failed: %s", exc.__class__.__name__)
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="error", tags=["request_error"])
        if resp.status_code == 404:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown", raw_score=0.0, status="not_found", tags=["not_found"])
        if resp.status_code == 429:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown", tags=["rate_limited"], http_status=resp.status_code, retry_after_seconds=retry_after_seconds(resp))
        if resp.status_code != 200:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="error", tags=[f"http_{resp.status_code}"])
        try:
            data = resp.json()
        except Exception:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="error", tags=["unexpected_response"])
        tags = []
        for key in ("FileName", "mimetype", "filetype", "trust", "ssdeep", "tlsh", "imphash", "FileSize"):
            val = data.get(key)
            if val is not None and str(val).strip():
                tags.append(f"{key}:{str(val)[:120]}")
        # additional generic fields
        for key in ("Product", "Parent", "Parents"):
            val = data.get(key)
            if val:
                if isinstance(val, list):
                    for v in val[:3]:
                        if v:
                            tags.append(f"{key}:{str(v)[:80]}")
                elif str(val).strip():
                    tags.append(f"{key}:{str(val)[:80]}")
        # include hash values as tags if present
        for hk in ("md5", "sha1", "sha256"):
            hv = data.get(hk)
            if hv and hv.lower() != ioc_value.lower():
                tags.append(f"{hk}:{hv[:16]}...")
        source_link = f"https://hashlookup.circl.lu/lookup/{hash_type}/{ioc_value}"
        self._record_success()
        # CIRCL Hashlookup is a known-FILE reference corpus (NSRL + known
        # software + some malware). A hit means "this file is known", NOT
        # "this file is safe" -- known-malware samples are present here too.
        # Emit a neutral/informational signal so the per-source badge is honest
        # and never contributes a false "clean" verdict. The reputation scorer
        # already excludes Hashlookup from clean/negative evidence.
        tags = ["known_file", "present_in_reference_corpus", *tags]
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", provider_verdict="known_file",
            raw_score=0.0, confidence="low",
            tags=tags, source_link=source_link, status="found",
        )
