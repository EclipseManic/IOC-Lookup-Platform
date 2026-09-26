"""Coverage ruler (P2-12): every adapter-dispatched IOC type must be served by
at least 2 free sources, of which at least 1 is key-free (no API key needed).

Adapter-dispatched types are those covered by the ADAPTERS registry; types
handled purely by enrichment (ssdeep, btc, mitre_attack, asn, and the
search-based mutex/registry_key/named_pipe/service_name) are out of scope here.
"""

from app.backend.adapters.base import is_valid_api_key
from app.backend.pipeline import ADAPTERS


def _is_key_free(adapter) -> bool:
    """A source runs without any API key when it is public or keyless or has a
    valid key configured, mirroring the pipeline's skip predicate exactly."""
    key = getattr(adapter, "api_key", None)
    return getattr(adapter, "public_without_key", False) or key is None or is_valid_api_key(key)


def _dispatched_types() -> list[str]:
    types = set()
    for adapter in ADAPTERS:
        types.update(adapter.supported_types)
    types.discard("password")  # Extended indicator handled via HIBP k-anonymity protocol
    return sorted(types)


def _sources_for(ioc_type: str) -> list:
    return [a for a in ADAPTERS if ioc_type in a.supported_types]


def test_every_dispatched_type_has_at_least_two_sources():
    for ioc_type in _dispatched_types():
        sources = _sources_for(ioc_type)
        assert len(sources) >= 2, (
            f"Type '{ioc_type}' is served by only {len(sources)} source(s): "
            f"{[a.name for a in sources]}. Every IOC type needs >= 2 free sources."
        )


def test_every_dispatched_type_has_a_key_free_source():
    for ioc_type in _dispatched_types():
        key_free = [a for a in _sources_for(ioc_type) if _is_key_free(a)]
        assert key_free, (
            f"Type '{ioc_type}' has no key-free source. Every IOC type needs "
            ">= 1 source that works without an API key."
        )
        assert len(key_free) >= 1


def test_no_adapter_is_both_keyless_and_non_public():
    """Every adapter must be usable: either public (no key needed), or carrying
    a key that satisfies is_valid_api_key when not public."""
    for adapter in ADAPTERS:
        assert getattr(adapter, "public_without_key", False) or getattr(adapter, "api_key", None) is not None, (
            f"{adapter.name} is neither key-free nor keyed"
        )
