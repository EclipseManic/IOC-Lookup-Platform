"""Free StopForumSpam email reputation lookup."""

import inspect

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter


class StopForumSpamAdapter(SourceAdapter):
    name = "StopForumSpam"
    supported_types = ["email"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=30)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        response = await client.get(
            "https://api.stopforumspam.org/api",
            params={"email": ioc_value, "json": ""},
            timeout=15,
        )
        if response.status_code == 429:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown", tags=["rate_limited"])
        if response.status_code != 200:
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="error", tags=[f"http_{response.status_code}"])

        data = response.json()
        if inspect.isawaitable(data):
            data = await data
        data = data if isinstance(data, dict) else {}
        info = data.get("email") if isinstance(data.get("email"), dict) else {}
        appears = int(info.get("appears", 0) or 0)
        frequency = int(info.get("frequency", 0) or 0)
        confidence = float(info.get("confidence", 0) or 0)
        if not appears:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
                tags=["not_listed"],
            )

        # This is abuse/spam reputation, not malware attribution. Keep weak
        # sightings suspicious and reserve malicious for strong confidence.
        verdict = "malicious" if confidence >= 0.5 else "suspicious"
        score = max(0.2, min(0.9, confidence if confidence > 0 else min(0.8, 0.2 + frequency / 10)))
        tags = ["spam_report", f"appears:{appears}", f"frequency:{frequency}", f"confidence:{confidence:.2f}"]
        last_seen = info.get("lastseen")
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=score,
            confidence="high" if confidence >= 0.5 else "low",
            tags=tags, last_seen=last_seen,
        )
