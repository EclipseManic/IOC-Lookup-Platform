import asyncio
import base64
import ipaddress
import os
import re
import socket
import ssl
import time
from datetime import datetime

import httpx
import mmh3

from app.backend.http_client import get_client as _get_http_client
from app.backend.logger import get_logger

logger = get_logger("enrichment")
from app.backend.adapters.base import (
    BreachInfo,
    CVEInfo,
    DNSInfo,
    EmailSecurityInfo,
    EnrichmentData,
    FaviconInfo,
    GeoIPInfo,
    NormalizedResult,
    PassiveDNSInfo,
    ReverseDNSInfo,
    SSLInfo,
    SubdomainInfo,
    WhoisInfo,
)


async def enrich(value: str, ioc_type: str) -> EnrichmentData:
    dispatch = {
        "ipv4": enrich_ip,
        "ipv6": enrich_ip,
        "domain": enrich_domain,
        "url": enrich_url,
        "md5": enrich_hash,
        "sha1": enrich_hash,
        "sha256": enrich_hash,
        "email": enrich_email,
        "cve": enrich_cve,
        "ssdeep": enrich_ssdeep,
        "btc": enrich_btc,
        "mitre_attack": enrich_mitre_attack,
        "asn": enrich_asn,
        "mutex": lambda value: enrich_host_artifact(value, "mutex"),
        "named_pipe": lambda value: enrich_host_artifact(value, "named_pipe"),
        "registry_key": lambda value: enrich_host_artifact(value, "registry_key"),
        "service_name": lambda value: enrich_host_artifact(value, "service_name"),
    }
    fn = dispatch.get(ioc_type, enrich_unknown)
    return await fn(value)


async def _probe_port(loop, semaphore, ip: str, p: int) -> int | None:
    def _check(p: int) -> bool:
        import socket as _socket
        from contextlib import closing

        with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)) as s:
            s.settimeout(1.5)
            try:
                return s.connect_ex((ip, p)) == 0
            except OSError:
                return False

    async with semaphore:
        try:
            ok = await asyncio.wait_for(
                loop.run_in_executor(None, _check, p), timeout=2.0
            )
            return p if ok else None
        except (asyncio.TimeoutError, OSError):
            return None


async def _quick_port_scan(ip: str) -> list[int]:
    COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
    loop = asyncio.get_running_loop()
    semaphore = asyncio.Semaphore(4)

    try:
        async with asyncio.timeout(8):
            results = await asyncio.gather(
                *(_probe_port(loop, semaphore, ip, p) for p in COMMON_PORTS)
            )
    except asyncio.TimeoutError:
        return []
    return [p for p in results if p is not None]


async def _passive_dns(domain: str) -> PassiveDNSInfo | None:
    from app.backend.adapters.base import is_valid_api_key
    from app.backend.config import settings
    try:
        client = _get_http_client()
        api_key = settings.securitytrails_api_key
        if is_valid_api_key(api_key):
            headers = {"APIKEY": api_key, "Accept": "application/json"}
            r = await client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/history/dns/a",
                headers=headers, timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                records = data.get("records", [])
                return PassiveDNSInfo(records=records[:50])
        return None
    except Exception:
        return None


async def _passive_dns_by_ip(ip: str) -> PassiveDNSInfo | None:
    from app.backend.adapters.base import is_valid_api_key
    from app.backend.config import settings
    try:
        client = _get_http_client()
        api_key = settings.securitytrails_api_key
        if is_valid_api_key(api_key):
            headers = {"APIKEY": api_key, "Accept": "application/json"}
            r = await client.get(
                f"https://api.securitytrails.com/v1/domain/list?ip={ip}",
                headers=headers, timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                domains = data.get("domains", [])
                return PassiveDNSInfo(records=[{"domain": d} for d in domains[:50]])
        return None
    except Exception:
        return None


async def enrich_ip(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}

    geoip, rdns, whois, pdns = await asyncio.gather(
        _geoip_ipapi(value),
        _reverse_dns(value),
        _rdap_lookup(value),
        _passive_dns_by_ip(value),
        return_exceptions=True,
    )

    completeness["geoip"] = "error" if isinstance(geoip, Exception) or geoip is None else "ok"
    completeness["reverse_dns"] = "error" if isinstance(rdns, Exception) or rdns is None else "ok"
    completeness["whois"] = "error" if isinstance(whois, Exception) or whois is None else "ok"

    from app.backend.config import settings
    from app.backend.adapters.base import is_valid_api_key

    open_ports_result = None
    shodan_key = settings.shodan_api_key
    ip_version = ipaddress.ip_address(value).version
    if is_valid_api_key(shodan_key) and ip_version == 4:
        from app.backend.adapters.shodan import ShodanAdapter
        try:
            shodan = ShodanAdapter()
            shodan.set_client(_get_http_client())
            shodan_result = await shodan.lookup(value, "ipv4")
            if shodan_result.tags:
                port_tag = next((t for t in shodan_result.tags if t.startswith("ports:")), None)
                if port_tag:
                    port_str = port_tag.replace("ports:", "")
                    open_ports_result = [int(p) for p in port_str.split(",") if p.strip().isdigit()]
                    completeness["port_scan"] = "ok"
        except Exception as exc:
            logger.debug("Shodan port scan enrichment failed for %s: %s", value, exc)
    if open_ports_result is None:
        if ip_version == 4 and settings.enable_active_port_scan:
            open_ports_result = await _quick_port_scan(value)
            completeness["port_scan"] = "ok"
        else:
            open_ports_result = []
            completeness["port_scan"] = "disabled" if not settings.enable_active_port_scan else "not_available"

    geoip_val = geoip if not isinstance(geoip, Exception) else None
    rdns_val = rdns if not isinstance(rdns, Exception) else None
    whois_val = whois if not isinstance(whois, Exception) else None
    pdns_val = pdns if not isinstance(pdns, Exception) else None

    completeness["passive_dns"] = "ok" if pdns_val and pdns_val.records else "error"

    return EnrichmentData(
        geoip=geoip_val,
        reverse_dns=rdns_val,
        whois=whois_val,
        passive_dns=pdns_val,
        relationships=_rdns_relationships(value, rdns_val) if rdns_val else [],
        completeness=completeness,
        open_ports=open_ports_result if open_ports_result else [],
    )


async def enrich_domain(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}

    whois, dns_records, ssl_info, subdomains, favicon, pdns = await asyncio.gather(
        _rdap_lookup(value),
        _dns_lookup(value),
        _ssl_cert(value),
        _crt_sh_subdomains(value),
        _favicon_hash(value),
        _passive_dns(value),
        return_exceptions=True,
    )

    completeness["whois"] = "error" if isinstance(whois, Exception) or whois is None else "ok"
    completeness["dns"] = "error" if isinstance(dns_records, Exception) or dns_records is None else "ok"
    completeness["ssl"] = "error" if isinstance(ssl_info, Exception) or ssl_info is None else "ok"
    completeness["subdomains"] = "error" if isinstance(subdomains, Exception) or subdomains is None else "ok"
    completeness["favicon"] = "not_found" if isinstance(favicon, Exception) or favicon is None else "ok"

    pdns_val = pdns if not isinstance(pdns, Exception) else None
    completeness["passive_dns"] = "ok" if pdns_val and pdns_val.records else "error"

    return EnrichmentData(
        whois=whois if not isinstance(whois, Exception) else None,
        dns=dns_records if not isinstance(dns_records, Exception) else None,
        ssl=ssl_info if not isinstance(ssl_info, Exception) else None,
        subdomains=subdomains if not isinstance(subdomains, Exception) else None,
        favicon=favicon if not isinstance(favicon, Exception) else None,
        passive_dns=pdns_val,
        completeness=completeness,
    )


async def _is_public_fetch_target(url: str) -> bool:
    """Reject URL fetches that resolve to non-public addresses.

    This is a defence-in-depth control for the explicitly opt-in URL content
    fetch feature. Normal operation leaves that feature disabled altogether.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        addresses = await asyncio.get_running_loop().run_in_executor(
            None, lambda: socket.getaddrinfo(parsed.hostname, parsed.port or 443)
        )
    except socket.gaierror:
        return False

    try:
        resolved = {ipaddress.ip_address(item[4][0]) for item in addresses}
    except ValueError:
        return False
    return bool(resolved) and all(address.is_global for address in resolved)


async def _url_redirect_chain(url: str) -> list[dict]:
    import re
    try:
        client = _get_http_client()
        chain = []
        seen = set()
        current = url
        for _ in range(6):
            if not await _is_public_fetch_target(current):
                logger.warning("Blocked unsafe URL enrichment target: %s", current)
                break
            seen.add(current)
            r = await client.get(current, follow_redirects=False, timeout=10)
            status = r.status_code
            location = r.headers.get("Location", "")
            chain.append({"url": current, "status": status, "location": location})
            if status in (301, 302, 303, 307, 308) and location and location not in seen:
                from urllib.parse import urljoin
                current = urljoin(current, location)
            else:
                break
            if len(chain) >= 5:
                break
        return chain
    except Exception:
        return []


async def _url_content_preview(url: str) -> dict:
    import re
    try:
        if not await _is_public_fetch_target(url):
            logger.warning("Blocked unsafe URL enrichment target: %s", url)
            return {}
        client = _get_http_client()
        r = await client.get(url, timeout=10, follow_redirects=True)
        if r.status_code != 200:
            return {}
        text = r.text
        title = ""
        m = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:200]
        meta_desc = ""
        m = re.search(r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', text, re.IGNORECASE)
        if not m:
            m = re.search(r'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']description["\']', text, re.IGNORECASE)
        if m:
            meta_desc = m.group(1).strip()[:300]
        text_content = re.sub(r'<[^>]+>', ' ', text)
        text_content = re.sub(r'\s+', ' ', text_content).strip()[:500]
        return {
            "url": url,
            "title": title,
            "meta_description": meta_desc,
            "text_preview": text_content,
        }
    except Exception:
        return {}


async def enrich_url(value: str) -> EnrichmentData:
    from urllib.parse import urlparse
    domain = urlparse(value).hostname or value
    result = await enrich_domain(domain)
    result.completeness["domain_extraction"] = "ok" if domain != value else "error"
    result.relationships = [{"source_ioc": value, "target_ioc": domain, "relationship": "extracted_host", "via_source": "url_parse"}]

    from app.backend.config import settings

    # Fetching an analyst-supplied URL makes the IOC workstation an SSRF
    # primitive. Keep that active behavior opt-in; reputation adapters and
    # passive domain enrichment remain available by default.
    if not settings.enable_url_content_fetch:
        result.completeness["redirect_chain"] = "disabled"
        result.completeness["url_preview"] = "disabled"
        result.analysis_notes.append(
            "Active URL retrieval is disabled to protect the analyst workstation. "
            "Enable ENABLE_URL_CONTENT_FETCH only in an isolated environment."
        )
        return result

    redirect_chain, url_preview = await asyncio.gather(
        _url_redirect_chain(value),
        _url_content_preview(value),
        return_exceptions=True,
    )
    result.redirect_chain = redirect_chain if not isinstance(redirect_chain, Exception) else []
    result.url_preview = url_preview if not isinstance(url_preview, Exception) else {}
    result.completeness["redirect_chain"] = "ok" if result.redirect_chain else "error"
    result.completeness["url_preview"] = "ok" if result.url_preview.get("title") else "error"
    return result


async def enrich_hash(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}
    results = []
    from app.backend.config import settings

    if not settings.hashlookup_enabled:
        completeness["hash_lookup"] = "not_applicable"
        return EnrichmentData(completeness=completeness, extra={"hash_results": results})
    c = _get_http_client()
    try:
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "sha256")
        r = await c.get(f"https://hashlookup.circl.lu/lookup/{hash_type}/{value}")
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                results.append({
                    "filename": data.get("FileName", ""),
                    "size": data.get("FileSize", ""),
                    "mime": data.get("mimetype", ""),
                    "source": data.get("source", ""),
                    "database": data.get("db", ""),
                    "trust": data.get("hashlookup:trust"),
                    "md5": data.get("MD5", ""),
                    "sha1": data.get("SHA-1", ""),
                    "sha256": data.get("SHA-256", ""),
                    "ssdeep": data.get("SSDEEP", ""),
                    "tlsh": data.get("TLSH", ""),
                })
            completeness["hash_lookup"] = "ok"
        else:
            completeness["hash_lookup"] = "not_found"
    except Exception:
        completeness["hash_lookup"] = "error"
    return EnrichmentData(completeness=completeness, extra={"hash_results": results})


async def _dnsbl_check(email: str) -> list[dict]:
    domain = email.split("@")[-1] if "@" in email else email
    dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    ]
    results = []
    import socket
    try:
        ip = socket.gethostbyname(domain)
        parts = ip.split(".")
        rev = ".".join(reversed(parts))
        for bl in dnsbls:
            query = f"{rev}.{bl}"
            try:
                socket.gethostbyname(query)
                results.append({"blacklist": bl, "listed": True, "ip": ip})
            except socket.gaierror:
                pass
    except socket.gaierror:
        pass
    return results


async def enrich_email(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}
    domain = value.split("@")[-1] if "@" in value else value

    domain_result, leakcheck, xposed, proxynova, email_sec, dnsbl = await asyncio.gather(
        _enrich_domain_for_email(domain),
        _leakcheck_lookup(value),
        _xposedornot_lookup(value),
        _proxynova_comb_lookup(value),
        _email_security(domain),
        _dnsbl_check(value),
        return_exceptions=True,
    )

    completeness["domain_extraction"] = "ok" if domain != value else "error"

    completeness["leakcheck"] = "ok" if not isinstance(leakcheck, Exception) and leakcheck is not None else "not_configured"
    completeness["xposedornot"] = "ok" if not isinstance(xposed, Exception) and xposed is not None else "error"

    if isinstance(proxynova, Exception) or proxynova is None:
        completeness["proxynova_comb"] = "unavailable"
    else:
        completeness["proxynova_comb"] = "ok"

    completeness["email_security"] = "ok" if not isinstance(email_sec, Exception) and email_sec is not None else "error"
    # An empty DNSBL result is a successful negative lookup, not a provider
    # outage.  The UI must not present it as an error.
    completeness["dnsbl"] = "ok" if isinstance(dnsbl, list) and dnsbl else "not_found"

    # Merge breach results
    all_sources = [leakcheck, xposed, proxynova]
    all_failed = all(isinstance(r, Exception) or r is None for r in all_sources)

    if all_failed:
        merged_breach = BreachInfo(breach_count=None, source="none")
    else:
        all_names: list[str] = []
        all_dates: list[str] = []
        all_exposed: list[str] = []
        for r in all_sources:
            if isinstance(r, Exception) or r is None:
                continue
            br: BreachInfo = r
            all_names.extend(br.breach_names)
            if br.most_recent_breach:
                all_dates.append(br.most_recent_breach)
            all_exposed.extend(br.exposed_data_types)

        seen: set[str] = set()
        deduped_names: list[str] = []
        for name in all_names:
            key = name.lower().strip()
            if key not in seen:
                seen.add(key)
                deduped_names.append(name)

        merged_breach = BreachInfo(
            breach_count=len(deduped_names),
            breach_names=deduped_names,
            most_recent_breach=max(all_dates) if all_dates else "",
            exposed_data_types=list(dict.fromkeys(all_exposed)),
            source="multiple",
        )

    result = domain_result if not isinstance(domain_result, Exception) else EnrichmentData()
    result.completeness.update(completeness)
    result.breach = merged_breach
    result.email_security = email_sec if not isinstance(email_sec, Exception) else None
    result.extra = result.extra or {}
    result.extra["dnsbl_result"] = dnsbl if not isinstance(dnsbl, Exception) else None
    result.relationships = [{"source_ioc": value, "target_ioc": domain, "relationship": "email_domain", "via_source": "email_parse"}]
    return result


async def _enrich_domain_for_email(domain: str) -> EnrichmentData:
    whois, dns_records, ssl_info = await asyncio.gather(
        _rdap_lookup(domain),
        _dns_lookup(domain),
        _ssl_cert(domain),
        return_exceptions=True,
    )
    return EnrichmentData(
        whois=whois if not isinstance(whois, Exception) else None,
        dns=dns_records if not isinstance(dns_records, Exception) else None,
        ssl=ssl_info if not isinstance(ssl_info, Exception) else None,
    )


async def _exploitdb_lookup(cve_id: str) -> list[dict]:
    import re
    try:
        c = _get_http_client()
        r = await c.get(f"https://www.exploit-db.com/search?cve={cve_id}", timeout=10)
        if r.status_code != 200:
            return []
        results = []
        for m in re.finditer(r'/exploits/(\d+)', r.text):
            eid = m.group(1)
            results.append({"id": eid, "url": f"https://www.exploit-db.com/exploits/{eid}"})
            if len(results) >= 5:
                break
        dates = [m.group(1) for m in re.finditer(r'<td[^>]*>(\d{4}-\d{2}-\d{2})</td>', r.text)]
        for i, date in enumerate(dates):
            if i < len(results):
                results[i]["date"] = date
        return results
    except Exception:
        return []


async def _poc_github_check(cve_id: str) -> list[dict]:
    import re
    try:
        c = _get_http_client()
        r = await c.get(f"https://api.github.com/search/repositories?q={cve_id}+poC&sort=stars&order=desc", timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        items = data.get("items", [])[:5]
        return [
            {"name": item["full_name"], "url": item["html_url"], "stars": item.get("stargazers_count", 0)}
            for item in items
        ]
    except Exception:
        return []


async def enrich_cve(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}

    in_kev, kev_date = await _cisa_kev(value)
    epss_score, epss_percentile = await _first_epss(value)
    nvd_data = await _nvd_cve(value)

    completeness["cisa_kev"] = "ok"
    completeness["epss"] = "ok" if epss_score is not None else "error"
    completeness["nvd"] = "ok" if nvd_data else "error"

    exploits, poc = await asyncio.gather(
        _exploitdb_lookup(value),
        _poc_github_check(value),
        return_exceptions=True,
    )

    exploit_list = exploits if not isinstance(exploits, Exception) else []
    poc_list = poc if not isinstance(poc, Exception) else []

    completeness["exploitdb"] = "ok" if exploit_list else "not_found"
    completeness["poc_github"] = "ok" if poc_list else "not_found"

    return EnrichmentData(
        cve=CVEInfo(
            is_in_kev=in_kev,
            kev_date_added=kev_date,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            cvss_vector=nvd_data.get("vectorString", ""),
            cwe=nvd_data.get("cwe", []),
            references=nvd_data.get("references", []),
            public_exploits_exist=len(exploit_list) > 0,
            poc_available=len(poc_list) > 0,
            affected_products=nvd_data.get("affectedProducts", []),
            cvss_breakdown=nvd_data.get("cvssBreakdown", {}),
        ),
        completeness=completeness,
        extra={"exploitdb": exploit_list, "poc_github": poc_list},
    )


async def enrich_ssdeep(value: str) -> EnrichmentData:
    """Parse fuzzy-hash structure; threat matching requires a corpus/search API."""
    parts = value.split(":", 2)
    block_size = int(parts[0]) if parts and parts[0].isdigit() else None
    first_chunk = parts[1] if len(parts) > 1 else ""
    second_chunk = parts[2] if len(parts) > 2 else ""
    return EnrichmentData(
        completeness={"structural_analysis": "ok", "fuzzy_match_corpus": "unavailable"},
        extra={
            "ssdeep": {
                "block_size": block_size,
                "first_chunk_length": len(first_chunk),
                "second_chunk_length": len(second_chunk),
                "alphabet": "".join(sorted(set(first_chunk + second_chunk))),
            }
        },
    )


async def enrich_btc(value: str) -> EnrichmentData:
    """Fetch public Bitcoin address statistics from blockchain.info."""
    try:
        client = _get_http_client()
        response = await client.get(
            f"https://blockchain.info/rawaddr/{value}",
            params={"limit": 5},
            timeout=15,
        )
        if response.status_code == 404:
            return EnrichmentData(completeness={"blockchain_address": "not_found"})
        if response.status_code != 200:
            return EnrichmentData(completeness={"blockchain_address": f"http_{response.status_code}"})
        data = response.json()
        transactions = data.get("txs", []) if isinstance(data, dict) else []
        return EnrichmentData(
            completeness={"blockchain_address": "ok"},
            extra={
                "bitcoin": {
                    "address": value,
                    "hash160": data.get("hash160", ""),
                    "n_tx": data.get("n_tx", 0),
                    "total_received_btc": (data.get("total_received", 0) or 0) / 100_000_000,
                    "total_sent_btc": (data.get("total_sent", 0) or 0) / 100_000_000,
                    "final_balance_btc": (data.get("final_balance", 0) or 0) / 100_000_000,
                    "recent_transactions": [
                        {
                            "hash": tx.get("hash", ""),
                            "time": tx.get("time"),
                            "result_btc": (tx.get("result", 0) or 0) / 100_000_000,
                        }
                        for tx in transactions[:5]
                        if isinstance(tx, dict)
                    ],
                }
            },
        )
    except Exception as exc:
        logger.debug("Bitcoin enrichment failed for %s: %s", value, exc)
        return EnrichmentData(completeness={"blockchain_address": "error"})


async def enrich_asn(value: str) -> EnrichmentData:
    """Enrich an ASN with holder and announced-prefix data from RIPEstat."""
    try:
        client = _get_http_client()
        overview, prefixes = await asyncio.gather(
            client.get(
                "https://stat.ripe.net/data/as-overview/data.json",
                params={"resource": value}, timeout=15,
            ),
            client.get(
                "https://stat.ripe.net/data/announced-prefixes/data.json",
                params={"resource": value}, timeout=15,
            ),
            return_exceptions=True,
        )
        data = overview.json() if not isinstance(overview, Exception) and overview.status_code == 200 else {}
        prefix_data = prefixes.json() if not isinstance(prefixes, Exception) and prefixes.status_code == 200 else {}
        overview_data = data.get("data", {}) if isinstance(data, dict) else {}
        announced = prefix_data.get("data", {}).get("prefixes", []) if isinstance(prefix_data, dict) else []
        announced = [p for p in announced if isinstance(p, dict)][:100]
        if not overview_data and not announced:
            return EnrichmentData(completeness={"ripestat": "not_found"})
        return EnrichmentData(
            completeness={"ripestat": "ok"},
            extra={"asn": {
                "resource": value,
                "holder": overview_data.get("holder", ""),
                "announced_prefix_count": len(announced),
                "announced_prefixes": announced,
                "block": overview_data.get("block", {}),
            }},
        )
    except Exception as exc:
        logger.debug("ASN enrichment failed for %s: %s", value, exc)
        return EnrichmentData(completeness={"ripestat": "error"})


async def enrich_mitre_attack(value: str) -> EnrichmentData:
    """Fetch the public ATT&CK page metadata for a tactic or technique ID."""
    try:
        is_tactic = value.upper().startswith("TA")
        path = "tactics" if is_tactic else "techniques"
        client = _get_http_client()
        response = await client.get(f"https://attack.mitre.org/{path}/{value.upper()}/", timeout=15)
        if response.status_code != 200:
            return EnrichmentData(completeness={"mitre_attack": f"http_{response.status_code}"})
        html = response.text
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        desc_match = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
            html, re.IGNORECASE,
        )
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else value
        description = re.sub(r"\s+", " ", desc_match.group(1)).strip() if desc_match else ""
        return EnrichmentData(
            completeness={"mitre_attack": "ok"},
            extra={"mitre_attack": {
                "id": value.upper(),
                "kind": "tactic" if is_tactic else "technique",
                "title": title,
                "description": description,
                "url": f"https://attack.mitre.org/{path}/{value.upper()}/",
            }},
        )
    except Exception as exc:
        logger.debug("MITRE enrichment failed for %s: %s", value, exc)
        return EnrichmentData(completeness={"mitre_attack": "error"})


async def enrich_host_artifact(value: str, ioc_type: str = "") -> EnrichmentData:
    """Return useful structural context for host artifacts without a sandbox corpus."""
    artifact_type = ioc_type
    if not artifact_type:
        if value.lower().startswith("\\\\") and "\\pipe\\" in value.lower():
            artifact_type = "named_pipe"
        elif "\\" in value and re.match(r"^[A-Za-z_][A-Za-z0-9_]*\\", value):
            artifact_type = "registry_key"
        else:
            artifact_type = "mutex"

    details: dict[str, object] = {"value": value, "type": artifact_type}
    if artifact_type == "named_pipe":
        match = re.match(r"^\\\\([^\\]+)\\pipe\\(.+)$", value, re.IGNORECASE)
        if match:
            details.update({"server": match.group(1), "pipe_name": match.group(2)})
    elif artifact_type == "registry_key":
        hive, _, key = value.partition("\\")
        details.update({"hive": hive, "key_path": key, "depth": len([p for p in key.split("\\") if p])})
    elif artifact_type == "mutex":
        details.update({"namespace": value.split("\\", 1)[0] if "\\" in value else "global", "name": value.rsplit("\\", 1)[-1]})
    else:
        details["name"] = value

    return EnrichmentData(
        completeness={"structural_analysis": "ok", "threat_corpus": "unavailable"},
        extra={"host_artifact": details},
    )


async def enrich_unknown(value: str) -> EnrichmentData:
    return EnrichmentData(completeness={"enrichment": "skipped"})


# ─── Existing helpers ─────────────────────────────────


async def _geoip_ipapi(ip: str) -> GeoIPInfo | None:
    try:
        c = _get_http_client()
        r = await c.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,as,asname,isp,org,lat,lon",
            timeout=5,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("status") != "success":
            return None
        return GeoIPInfo(
            country=d.get("country"),
            country_code=d.get("countryCode"),
            city=d.get("city"),
            asn=d.get("as"),
            asn_name=d.get("asname"),
            isp=d.get("isp"),
            org=d.get("org"),
            latitude=d.get("lat"),
            longitude=d.get("lon"),
        )
    except Exception:
        return None


async def _reverse_dns(ip: str) -> ReverseDNSInfo | None:
    try:
        hostname = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip)
        return ReverseDNSInfo(hostnames=[hostname[0]])
    except Exception:
        return None


_rdap_bootstrap: dict | None = None


async def _get_rdap_url(domain: str) -> str | None:
    global _rdap_bootstrap
    try:
        if _rdap_bootstrap is None:
            c = _get_http_client()
            r = await c.get("https://data.iana.org/rdap/dns.json", timeout=10)
            if r.status_code == 200:
                _rdap_bootstrap = r.json()
        tld = domain.rsplit(".", 1)[-1].lower()
        if _rdap_bootstrap and "services" in _rdap_bootstrap:
            for svc in _rdap_bootstrap["services"]:
                if isinstance(svc, list) and len(svc) >= 2:
                    tlds, urls = svc[0], svc[1]
                    if isinstance(tlds, list) and tld in tlds:
                        if isinstance(urls, list) and urls:
                            base = urls[0].rstrip("/")
                            return f"{base}/domain/{domain}"
    except Exception as exc:
        logger.debug("RDAP bootstrap lookup failed for %s: %s", domain, exc)
    fallbacks = {
        "com": "https://rdap.verisign.com/com/v1/domain",
        "net": "https://rdap.verisign.com/net/v1/domain",
        "org": "https://rdap.publicinterestregistry.org/rdap/domain",
        "info": "https://rdap.afilias.net/rdap/domain",
        "io": "https://rdap.nic.io/domain",
        "me": "https://rdap.nic.me/domain",
        "co": "https://rdap.nic.co/domain",
    }
    base = fallbacks.get(tld)
    if base:
        return f"{base}/{domain}"
    return None


def _rdap_registrar(data: dict) -> str:
    """Extract the registrar name from RDAP entities (role 'registrar' vCard fn)."""
    try:
        for ent in data.get("entities") or []:
            roles = ent.get("roles") or []
            if "registrar" not in roles:
                continue
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2:
                for field in vcard[1] or []:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                        return str(field[3]).strip()[:100]
    except Exception:
        pass
    return ""


async def _rdap_lookup(target: str) -> WhoisInfo | None:
    try:
        if _is_ip(target):
            url = f"https://rdap.arin.net/registry/ip/{target}"
        else:
            url = await _get_rdap_url(target)
        if not url:
            return await _whois_fallback(target)
        c = _get_http_client()
        r = await c.get(url, timeout=8)
        if r.status_code != 200:
            return await _whois_fallback(target)
        d = r.json()
        port43 = d.get("port43") or ""
        registrar = _rdap_registrar(d)
        if not registrar and port43:
            return await _whois_fallback(target, server=port43)
        return WhoisInfo(
            registrar=registrar,
            creation_date=_rdap_date(d, "registrationDate") or "",
            expiration_date=_rdap_date(d, "expirationDate") or "",
            abuse_email=_extract_abuse_email(d),
            org=d.get("name", d.get("handle", "")),
        )
    except Exception:
        return await _whois_fallback(target)


_WHOIS_SERVERS: dict[str, str] = {}


async def _whois_tld_servers() -> dict[str, str]:
    global _WHOIS_SERVERS
    if _WHOIS_SERVERS:
        return _WHOIS_SERVERS
    try:
        c = _get_http_client()
        r = await c.get("https://www.iana.org/domains/root/db")
        if r.status_code == 200:
            import re
            for m in re.finditer(r'/domains/root/db/([^.]+)\.html[^>]*>([^<]+)</a>', r.text):
                tld = m.group(1).lower()
                whois = m.group(2).strip()
                if whois.endswith(".whois-servers.net"):
                    _WHOIS_SERVERS[tld] = whois
    except Exception:
        pass
    fallbacks = {
        "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
        "org": "whois.pir.org", "info": "whois.afilias.net",
        "me": "whois.nic.me", "co": "whois.nic.co",
        "io": "whois.nic.io", "uk": "whois.nic.uk",
        "de": "whois.denic.de", "fr": "whois.nic.fr",
        "eu": "whois.eu", "ru": "whois.tcinet.ru",
    }
    for tld, server in fallbacks.items():
        if tld not in _WHOIS_SERVERS:
            _WHOIS_SERVERS[tld] = server
    return _WHOIS_SERVERS


async def _whois_raw_query(domain: str, server: str | None = None) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    if not server:
        servers = await _whois_tld_servers()
        server = servers.get(tld)
    if not server:
        return None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=5
        )
        writer.write(f"{domain}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), timeout=10)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


async def _parse_whois_text(text: str) -> WhoisInfo | None:
    result = WhoisInfo()
    for line in text.splitlines():
        low = line.lower().strip()
        if "registrar:" in low and ":" in line:
            result.registrar = (result.registrar or "") + line.split(":", 1)[1].strip()[:100]
        if "creation date:" in low or "created:" in low or "created on:" in low:
            val = line.split(":", 1)[1].strip()[:30]
            if not result.creation_date:
                result.creation_date = val
        if "registry expiry date:" in low or "expiration date:" in low or "expire:" in low or "registry expiration date:" in low:
            val = line.split(":", 1)[1].strip()[:30]
            if not result.expiration_date:
                result.expiration_date = val
        if "abuse" in low and "email" in low and "@" in line:
            result.abuse_email = line.split(":", 1)[1].strip()
        if "org name:" in low or "organisation:" in low or "org:" in low or "registrant organization:" in low:
            result.org = result.org or line.split(":", 1)[1].strip()[:100]
    if any([result.registrar, result.creation_date, result.org]):
        return result
    return None


async def _whois_discover_server(tld: str) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("whois.iana.org", 43), timeout=5
        )
        writer.write(f"{tld}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), timeout=10)
        writer.close()
        await writer.wait_closed()
        for line in data.decode("utf-8", errors="replace").splitlines():
            low = line.lower().strip()
            if low.startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                if server:
                    return server
    except Exception:
        return None
    return None


async def _whois_fallback(target: str, server: str | None = None) -> WhoisInfo | None:
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', target):
        return None
    raw = await _whois_raw_query(target, server=server)
    if raw:
        parsed = await _parse_whois_text(raw)
        if parsed:
            return parsed
    if server:
        return None
    tld = target.rsplit(".", 1)[-1].lower()
    discovered = await _whois_discover_server(tld)
    if discovered:
        raw = await _whois_raw_query(target, server=discovered)
        if raw:
            parsed = await _parse_whois_text(raw)
            if parsed:
                return parsed
    if os.name == "nt":
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return await _parse_whois_text(stdout.decode("utf-8", errors="replace"))
    except Exception:
        return None


async def _dns_lookup(domain: str) -> DNSInfo | None:
    try:
        result = DNSInfo()
        loop = asyncio.get_event_loop()

        async def doh(record_type: str) -> list[str]:
            client = _get_http_client()
            response = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": record_type},
                headers={"Accept": "application/dns-json"},
                timeout=10,
            )
            if response.status_code != 200:
                return []
            answers = response.json().get("Answer", [])
            values = []
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                value = str(answer.get("data", "")).strip().strip('"')
                if record_type == "MX":
                    value = value.split(maxsplit=1)[-1] if value else ""
                if value:
                    values.append(value.rstrip("."))
            return list(dict.fromkeys(values))

        records = await asyncio.gather(
            *(doh(record_type) for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")),
            return_exceptions=True,
        )
        for record_type, values in zip(("a", "aaaa", "mx", "ns", "txt", "cname"), records):
            if isinstance(values, list):
                setattr(result, record_type, values)

        if not result.a and not result.aaaa:
            try:
                info = await loop.run_in_executor(None, socket.getaddrinfo, domain, 80)
                for entry in info:
                    addr = entry[4][0]
                    if entry[0] == socket.AF_INET and addr not in result.a:
                        result.a.append(addr)
                    elif entry[0] == socket.AF_INET6 and addr not in result.aaaa:
                        result.aaaa.append(addr)
            except Exception:
                pass

        if not result.cname:
            try:
                hostname, aliases, _ = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
                if aliases:
                    result.cname = [a for a in aliases if a.lower() != domain.lower()]
            except Exception:
                pass

        return result
    except Exception:
        return None


def _san_is_wildcard(san: str) -> bool:
    value = str(san)
    if value.lower().startswith("dns:"):
        value = value[4:]
    return value.startswith("*.")


async def _ssl_cert(hostname: str) -> SSLInfo | None:
    try:
        loop = asyncio.get_event_loop()

        def _fetch():
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return None
                    sans = []
                    for entry in cert.get("subjectAltName", []):
                        if len(entry) == 2:
                            sans.append(f"{entry[0]}:{entry[1]}")
                    subj_list = cert.get("subject", [])
                    subject = dict(subj_list) if isinstance(subj_list, dict) else (
                        {k: v for arr in subj_list for k, v in arr} if subj_list else {}
                    )
                    iss_list = cert.get("issuer", [])
                    issuer = dict(iss_list) if isinstance(iss_list, dict) else (
                        {k: v for arr in iss_list for k, v in arr} if iss_list else {}
                    )

                    not_after_str = str(cert.get("notAfter", ""))
                    is_expired = False
                    days_remaining = None
                    from datetime import datetime, timezone
                    for fmt in ["%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"]:
                        try:
                            parsed = datetime.strptime(not_after_str, fmt)
                            parsed = parsed.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            is_expired = parsed < now
                            days_remaining = (parsed - now).days
                            break
                        except (ValueError, TypeError):
                            continue

                    common_name = subject.get("commonName", "")
                    is_wildcard = str(common_name).startswith("*.") or any(
                        _san_is_wildcard(san) for san in sans
                    )
                    issuer_cn = str(issuer.get("commonName", ""))
                    is_self_signed = str(subject.get("commonName", "")) == issuer_cn

                    return SSLInfo(
                        subject=str(subject.get("commonName", "")),
                        issuer=str(issuer.get("commonName", "")),
                        serial=str(cert.get("serialNumber", "")),
                        not_before=str(cert.get("notBefore", "")),
                        not_after=not_after_str,
                        fingerprint="",
                        subject_alt_names=sans,
                        is_expired=is_expired,
                        is_self_signed=is_self_signed,
                        is_wildcard=is_wildcard,
                        days_remaining=days_remaining,
                    )

        return await loop.run_in_executor(None, _fetch)
    except Exception:
        return None


def _rdns_relationships(ip: str, rdns: ReverseDNSInfo | None) -> list[dict]:
    if not rdns or not rdns.hostnames:
        return []
    return [{"source_ioc": ip, "target_ioc": h, "relationship": "resolves_to", "via_source": "reverse_dns"} for h in rdns.hostnames]


def _extract_abuse_email(data: dict) -> str:
    for entity in data.get("entities", []):
        if isinstance(entity, dict):
            for vcard_arr in entity.get("vcardArray", []):
                if isinstance(vcard_arr, list):
                    for item in vcard_arr:
                        if isinstance(item, list) and len(item) > 3 and item[0] == "email":
                            return item[3]
    return ""


def _rdap_date(data: dict, key: str) -> str | None:
    for event in data.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") == key:
            return event.get("eventDate", "")
    return None


def _is_ip(v: str) -> bool:
    parts = v.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p)


# ─── 1. crt.sh Certificate Transparency ────────────


async def _crt_sh_subdomains(domain: str) -> SubdomainInfo | None:
    try:
        c = _get_http_client()
        for attempt in range(3):
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers={"User-Agent": "IOC-Platform/1.0", "Accept": "application/json"}, timeout=15)
            if r.status_code == 502 and attempt < 2:
                await asyncio.sleep(2 ** attempt)
                continue
            break
        if r.status_code != 200:
            return None
        entries = r.json()
        seen: set[str] = set()
        subs: list[str] = []
        dot_domain = "." + domain.lower()
        for entry in entries:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n.endswith(dot_domain) and n not in seen:
                    seen.add(n)
                    subs.append(n)
        return SubdomainInfo(subdomains=subs[:100])
    except Exception:
        return None


# ─── 2. CISA Known Exploited Vulnerabilities ───────


_cisa_cache: dict | None = None
_cisa_cache_time: float = 0
_CISA_TTL: float = 3600
_cisa_lock: asyncio.Lock | None = None
_cisa_refresh_task: asyncio.Task | None = None


async def _fetch_cisa_feed() -> dict | None:
    c = _get_http_client()
    r = await c.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if r.status_code == 200:
        return r.json()
    return None


async def _refresh_cisa_cache(force: bool = False) -> None:
    global _cisa_cache, _cisa_cache_time
    if not force and _cisa_cache is not None and time.time() - _cisa_cache_time < _CISA_TTL:
        return
    data = await _fetch_cisa_feed()
    if data:
        _cisa_cache = data
        _cisa_cache_time = time.time()


async def start_cisa_background_refresh() -> None:
    global _cisa_lock, _cisa_refresh_task
    if _cisa_lock is None:
        _cisa_lock = asyncio.Lock()
    if _cisa_refresh_task is None or _cisa_refresh_task.done():
        async def _loop():
            while True:
                async with _cisa_lock:
                    await _refresh_cisa_cache(force=True)
                await asyncio.sleep(_CISA_TTL)
        _cisa_refresh_task = asyncio.create_task(_loop())


async def stop_cisa_background_refresh() -> None:
    global _cisa_refresh_task
    task = _cisa_refresh_task
    _cisa_refresh_task = None
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _cisa_kev(cve_id: str) -> tuple[bool, str]:
    global _cisa_lock
    try:
        if _cisa_lock is None:
            _cisa_lock = asyncio.Lock()
        async with _cisa_lock:
            await _refresh_cisa_cache()
            if _cisa_cache and "vulnerabilities" in _cisa_cache:
                for vuln in _cisa_cache["vulnerabilities"]:
                    if isinstance(vuln, dict) and vuln.get("cveID", "").upper() == cve_id.upper():
                        return True, vuln.get("dateAdded", "")
            return False, ""
    except Exception:
        return False, ""


# ─── 3. FIRST EPSS ─────────────────────────────────


async def _first_epss(cve_id: str) -> tuple[float | None, float | None]:
    try:
        c = _get_http_client()
        r = await c.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        if r.status_code != 200:
            return None, None
        data = r.json()
        entries = data.get("data", [])
        if entries:
            epss = float(entries[0].get("epss", 0))
            pct = float(entries[0].get("percentile", 0))
            return epss, pct
        return 0.0, 0.0
    except Exception:
        return None, None


# ─── 4. NVD CVE API ────────────────────────────────


async def _nvd_cve(cve_id: str) -> dict:
    from app.backend.config import settings

    try:
        headers = {"User-Agent": "IOC-Platform/1.0"}
        if settings.nvd_api_key:
            headers["X-Api-Key"] = settings.nvd_api_key
        c = _get_http_client()
        r = await c.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            headers=headers,
        )
        if r.status_code != 200:
            return {}
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        cvss_data = {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            group = metrics.get(key, [])
            if group:
                cvss_data = group[0].get("cvssData", {})
                break

        weaknesses = cve_data.get("weaknesses", [])
        cwe_list = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val:
                    cwe_list.append(val)

        refs = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)

        return {
            "vectorString": cvss_data.get("vectorString", ""),
            "cwe": cwe_list,
            "references": refs,
        }
    except Exception:
        return {}


# ─── 5a. LeakCheck (primary — API key required) ────


async def _leakcheck_lookup(email: str) -> BreachInfo | None:
    from app.backend.adapters.base import is_valid_api_key
    from app.backend.config import settings

    if not is_valid_api_key(settings.leakcheck_api_key):
        return None
    try:
        c = _get_http_client()
        r = await c.get(
            f"https://leakcheck.io/api/v2/query/{email}",
            headers={
                "X-API-Key": settings.leakcheck_api_key,
                "Accept": "application/json",
            },
        )
        if r.status_code in (401, 403):
            return None
        if r.status_code == 404:
            return BreachInfo(breach_count=0, breach_names=[])
        if r.status_code == 429:
            return None
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get("success"):
            return None
        found = data.get("found", 0)
        rows = data.get("result", [])
        names: list[str] = []
        dates: list[str] = []
        fields: set[str] = set()
        for row in rows:
            src = row.get("source", {})
            name = src.get("name", "")
            if name:
                names.append(name)
            d = src.get("breach_date", "")
            if d:
                dates.append(d)
            for f in row.get("fields", []):
                if isinstance(f, str):
                    fields.add(f)
        dates.sort(reverse=True)
        return BreachInfo(
            breach_count=found,
            breach_names=names[:50],
            most_recent_breach=dates[0] if dates else "",
            exposed_data_types=sorted(fields),
            source="leakcheck",
        )
    except httpx.TimeoutException:
        return None
    except Exception:
        return None


# ─── 5b. XposedOrNot (free, no key — rate-limited) ─


_xon_semaphore = asyncio.Semaphore(1)


async def _xposedornot_lookup(email: str) -> BreachInfo | None:
    async with _xon_semaphore:
        await asyncio.sleep(0.5)
        for attempt in range(3):
            try:
                c = _get_http_client()
                r = await c.get(
                    f"https://api.xposedornot.com/v1/check-email/{email}?details=true",
                )
                if r.status_code == 404:
                    return BreachInfo(breach_count=0, breach_names=[])
                if r.status_code == 429:
                    if attempt < 2:
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    return None
                if r.status_code != 200:
                    return None
                data = r.json()
                breaches = data.get("breaches", [])
                if not breaches:
                    return BreachInfo(breach_count=0, breach_names=[])
                names: list[str] = []
                all_dates: list[str] = []
                all_exposed: list[str] = []
                for b in breaches:
                    # XposedOrNot has returned both object records and a
                    # compact nested list of breach names over time.
                    if isinstance(b, list):
                        names.extend(str(name) for name in b if name)
                        continue
                    if isinstance(b, str):
                        names.append(b)
                        continue
                    if not isinstance(b, dict):
                        continue
                    name = b.get("name", "")
                    if name:
                        names.append(name)
                    d = b.get("breach_date", "")
                    if d:
                        all_dates.append(d)
                    exposed = b.get("exposed_data", [])
                    if isinstance(exposed, list):
                        all_exposed.extend(exposed)
                all_dates.sort(reverse=True)
                return BreachInfo(
                    breach_count=len(names),
                    breach_names=names[:50],
                    most_recent_breach=all_dates[0] if all_dates else "",
                    exposed_data_types=list(dict.fromkeys(all_exposed)),
                    source="xposedornot",
                )
            except httpx.TimeoutException:
                return None
            except Exception:
                return None
    return None


# ─── 5c. ProxyNova Comb (best-effort, undocumented) ─


async def _proxynova_comb_lookup(email: str) -> BreachInfo | None:
    """Unofficial ProxyNova Comb endpoint. Undocumented, unstable — best-effort only."""
    try:
        c = _get_http_client()
        r = await c.post(
            "https://proxynova.com/tools/comb/",
            data={"email": email},
        )
        if r.status_code != 200:
            return None
        try:
            payload = r.json()
        except Exception:
            return None
        records = payload.get("records", [])
        if not records:
            return BreachInfo(breach_count=0, breach_names=[])
        return BreachInfo(
            breach_count=len(records),
            breach_names=[f"proxynova_comb_{i+1}" for i in range(min(len(records), 50))],
            most_recent_breach="",
            source="proxynova_comb_unofficial",
        )
    except Exception:
        return None


# ─── 6. Favicon hash (mmh3) ────────────────────────


async def _favicon_hash(domain: str) -> FaviconInfo | None:
    try:
        favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
        c = _get_http_client()
        r = await c.get(favicon_url)
        if r.status_code == 200 and len(r.content) > 100:
            b64 = base64.b64encode(r.content).decode()
            hash_val = mmh3.hash(b64)
            return FaviconInfo(favicon_hash=hash_val, favicon_url=favicon_url)
        return None
    except Exception:
        return None


# ─── 7. SPF/DKIM/DMARC via DNS TXT ─────────────────


async def _dns_txt_query(name: str) -> list[str]:
    try:
        c = _get_http_client()
        r = await c.get(
            f"https://cloudflare-dns.com/dns-query?name={name}&type=TXT",
            headers={"Accept": "application/dns-json"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        answers = data.get("Answer", [])
        return [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]
    except Exception:
        return []


async def _email_security(domain: str) -> EmailSecurityInfo | None:
    try:
        spf_records, dkim_records, dmarc_records = await asyncio.gather(
            _dns_txt_query(domain),
            _dns_txt_query(f"default._domainkey.{domain}"),
            _dns_txt_query(f"_dmarc.{domain}"),
            return_exceptions=True,
        )

        spf_records = spf_records if not isinstance(spf_records, Exception) else []
        dkim_records = dkim_records if not isinstance(dkim_records, Exception) else []
        dmarc_records = dmarc_records if not isinstance(dmarc_records, Exception) else []

        spf = "pass" if any(r.startswith("v=spf1") for r in spf_records) else "missing"
        dkim = "pass" if any("v=DKIM1" in r for r in dkim_records) else "missing"
        dmarc = "pass" if any(r.startswith("v=DMARC1") for r in dmarc_records) else "missing"

        return EmailSecurityInfo(spf=spf, dkim=dkim, dmarc=dmarc)
    except Exception:
        return None


def normalize_cve_enrichment(cve: CVEInfo, cve_id: str) -> NormalizedResult:
    raw_score = 0.0
    verdict = "unknown"
    confidence = "low"
    tags: list[str] = []

    if cve.is_in_kev:
        raw_score = 1.0
        verdict = "malicious"
        confidence = "high"
        tags.append("cisa_kev")
        if cve.kev_date_added:
            tags.append(f"kev_added:{cve.kev_date_added}")

    epss_weight = (cve.epss_score or 0) * 0.7
    if not cve.is_in_kev and (cve.epss_score or 0) > 0:
        raw_score = min(round(epss_weight + 0.1, 4), 1.0)
        if (cve.epss_score or 0) >= 0.1:
            verdict = "malicious"
            confidence = "high"
        elif (cve.epss_score or 0) >= 0.01:
            verdict = "suspicious"
            confidence = "medium"
        else:
            verdict = "unknown"
            confidence = "low"
        if (cve.epss_percentile or 0) > 0:
            tags.append(f"epss_p{int((cve.epss_percentile or 0) * 100)}")

    if cve.cvss_vector:
        tags.append("cvss_scored")
        try:
            parts = cve.cvss_vector.split("/")
            for p in parts:
                if p.startswith("CVSS:") or p.startswith("3."):
                    continue
                if ":" in p and p.split(":")[0] in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
                    tags.append(p.replace(":", "_").lower())
        except Exception:
            pass

    if cve.cwe:
        tags.extend(f"cwe:{w.split(':')[-1].strip() if ':' in w else w}" for w in cve.cwe)

    categories = [w.split(":")[-1].strip() if ":" in w else w for w in cve.cwe if w]

    if not cve.is_in_kev and (cve.epss_score or 0) == 0 and not cve.cvss_vector:
        raw_score = 0.0
        verdict = "unknown"

    return NormalizedResult(
        ioc=cve_id,
        ioc_type="cve",
        source="CVE",
        verdict=verdict,
        raw_score=raw_score,
        confidence=confidence,
        tags=tags,
        categories=categories,
        source_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )
