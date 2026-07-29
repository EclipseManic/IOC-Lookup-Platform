import asyncio
import base64
import socket
import ssl
import time
from datetime import datetime

import httpx
import mmh3

from app.backend.http_client import get_client as _get_http_client
from app.backend.logger import logger
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
        "domain": enrich_domain,
        "url": enrich_url,
        "md5": enrich_hash,
        "sha1": enrich_hash,
        "sha256": enrich_hash,
        "email": enrich_email,
        "cve": enrich_cve,
    }
    fn = dispatch.get(ioc_type, enrich_unknown)
    return await fn(value)


async def _quick_port_scan(ip: str) -> list[int]:
    import socket as _socket
    COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
    open_ports = []
    loop = asyncio.get_event_loop()
    for port in COMMON_PORTS:
        try:
            def _check(p):
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(1.5)
                result = s.connect_ex((ip, p))
                s.close()
                return result == 0
            if await loop.run_in_executor(None, _check, port):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports


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
    if is_valid_api_key(shodan_key):
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
        except Exception:
            pass
    if open_ports_result is None:
        open_ports_result = await _quick_port_scan(value)

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


async def _url_redirect_chain(url: str) -> list[dict]:
    import re
    try:
        client = _get_http_client()
        chain = []
        seen = set()
        current = url
        for _ in range(6):
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
    c = _get_http_client()
    try:
        r = await c.get(f"https://hashlookup-oblivious.circl.lu/lookup/{value}")
        if r.status_code == 200:
            data = r.json()
            results.append(data.get("message", ""))
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

    for key, src_val in [("leakcheck", leakcheck), ("xposedornot", xposed)]:
        if isinstance(src_val, Exception) or src_val is None:
            completeness[key] = "error"
        else:
            completeness[key] = "ok"

    if isinstance(proxynova, Exception) or proxynova is None:
        completeness["proxynova_comb"] = "unavailable"
    else:
        completeness["proxynova_comb"] = "ok"

    completeness["email_security"] = "ok" if not isinstance(email_sec, Exception) and email_sec is not None else "error"
    completeness["dnsbl"] = "ok" if not isinstance(dnsbl, Exception) and dnsbl else "error"

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
    except Exception:
        pass
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


async def _rdap_lookup(target: str) -> WhoisInfo | None:
    try:
        if _is_ip(target):
            url = f"https://rdap.arin.net/registry/ip/{target}"
        else:
            url = await _get_rdap_url(target) or f"https://rdap.verisign.com/com/v1/domain/{target}"
        c = _get_http_client()
        r = await c.get(url, timeout=8)
        if r.status_code != 200:
            return await _whois_fallback(target)
        d = r.json()
        abuse = _extract_abuse_email(d)
        return WhoisInfo(
            registrar=d.get("port43") or "",
            creation_date=_rdap_date(d, "registrationDate") or "",
            expiration_date=_rdap_date(d, "expirationDate") or "",
            abuse_email=abuse,
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


async def _whois_raw_query(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
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


async def _whois_fallback(target: str) -> WhoisInfo | None:
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', target):
        return None
    raw = await _whois_raw_query(target)
    if raw:
        parsed = await _parse_whois_text(raw)
        if parsed:
            return parsed
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

        try:
            hostname, aliases, _ = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
            if aliases:
                result.cname = [a for a in aliases if a.lower() != domain.lower()]
        except Exception:
            pass

        return result
    except Exception:
        return None


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
                        str(san).startswith("*.") for san in sans
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


async def _cisa_kev(cve_id: str) -> tuple[bool, str]:
    global _cisa_cache, _cisa_cache_time
    try:
        if _cisa_cache is None or time.time() - _cisa_cache_time > 86400:
            c = _get_http_client()
            r = await c.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if r.status_code == 200:
                _cisa_cache = r.json()
                _cisa_cache_time = time.time()
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
