import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit


def refang(text: str) -> str:
    text = re.sub(r"hxxps\[?:\]?//", "https://", text, flags=re.IGNORECASE)
    text = re.sub(r"hxxp\[?:\]?//", "http://", text, flags=re.IGNORECASE)
    text = re.sub(r"\[\.\]", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"\\\.", ".", text)
    text = text.replace(r"\@", "@").replace(r"\_", "_")
    return text


def defang(text: str) -> str:
    text = text.replace("http://", "hxxp://")
    text = text.replace("https://", "hxxps://")
    text = text.replace(".", "[.]")
    return text


@dataclass(frozen=True)
class NormalizedIOC:
    value: str
    ioc_type: str
    candidate_types: tuple[str, ...]
    type_confidence: float
    valid: bool

    @property
    def identity_key(self) -> str:
        """Stable key used by deduplication, cache, and persistence."""
        return f"{self.ioc_type}:{self.value}"


def normalize_ioc(value: str, expected_type: str | None = None) -> NormalizedIOC:
    """Deterministically normalize and validate an IOC before planning."""
    raw_str = str(value or "")
    # Check for explicit password prefix like pass:secret or password:secret
    if expected_type == "password" or raw_str.lower().startswith(("pass:", "password:")):
        clean_pwd = re.sub(r"^(?:pass|password):", "", raw_str, flags=re.IGNORECASE).strip()
        if clean_pwd and len(clean_pwd) <= 256:
            return NormalizedIOC(clean_pwd, "password", ("password",), 1.0, True)

    text = refang(raw_str).strip().strip("`'\"<>()[],;")
    if not text:
        return NormalizedIOC("", "unknown", (), 0.0, False)
    if expected_type == "password" and len(text) <= 256:
        return NormalizedIOC(text, "password", ("password",), 1.0, True)
    if re.fullmatch(r"\d+(?:\.\d+){3}", text) and any(int(part) > 255 for part in text.split(".")):
        return NormalizedIOC(text, "unknown", (), 0.0, False)
    if text.lower().startswith("http."):
        return NormalizedIOC(text, "unknown", (), 0.0, False)
    # DNS treats a terminal dot as equivalent to the absolute hostname form.
    # Normalize it before pattern selection so batch deduplication and cache
    # identity do not split ``Example.COM`` from ``Example.COM.``.
    if "/" not in text and "@" not in text and re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\.?", text):
        text = text.rstrip(".")
    candidates = []
    for type_name, pattern, *flags in PATTERNS:
        if re.match(pattern, text, flags[0] if flags else 0):
            if type_name == "domain" and text.lower().startswith("http"):
                continue
            if type_name == "filename" and re.fullmatch(r"[a-f0-9]{16,}", text, re.IGNORECASE):
                # An unlabelled hexadecimal token is more likely an
                # incomplete hash/fingerprint than a filename. Avoid silently
                # inventing artifact metadata for hash-like input.
                continue
            if type_name in {"mutex", "service_name"}:
                if len(text) < 6 or text.isdigit() or re.fullmatch(r"[a-f0-9]{16,}", text, re.I):
                    continue
                if text.isalpha() and text.islower() and len(text) < 12:
                    continue
                if type_name == "service_name" and ("\\" in text or "-" in text):
                    continue
            candidates.append(type_name)
    try:
        address = ipaddress.ip_address(text)
        text = address.compressed
        candidates = ["ipv4" if address.version == 4 else "ipv6"]
    except ValueError:
        pass
    primary = candidates[0] if candidates else "unknown"
    if primary == "url":
        parsed = urlsplit(text)
        if parsed.hostname:
            host = parsed.hostname.rstrip(".").lower()
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                pass
            port_number = parsed.port
            default_port = (parsed.scheme.lower() == "http" and port_number == 80) or (parsed.scheme.lower() == "https" and port_number == 443)
            host_for_url = f"[{host}]" if ":" in host else host
            port = f":{port_number}" if port_number and not default_port else ""
            # Keep meaningful path/query content while normalizing percent
            # escapes for unreserved characters and hex casing.
            path = re.sub(r"%([0-9a-fA-F]{2})", lambda m: "%" + m.group(1).upper(), parsed.path or "")
            path = re.sub(r"%([0-9A-F]{2})", lambda m: chr(int(m.group(1), 16)) if chr(int(m.group(1), 16)).isalnum() else m.group(0), path)
            text = urlunsplit((parsed.scheme.lower(), f"{host_for_url}{port}", path, parsed.query, parsed.fragment))
    elif primary == "domain":
        text = text.encode("idna").decode("ascii").lower().rstrip(".")
    elif primary in {"md5", "sha1", "sha256", "sha512", "ja3", "ja4", "tlsh"}:
        text = text.lower()
    elif primary == "email":
        local, _, domain = text.rpartition("@")
        text = f"{local}@{domain.lower().rstrip('.') }"
    elif primary == "cve":
        text = text.upper()
    elif primary == "asn":
        text = "AS" + re.sub(r"^AS", "", text, flags=re.IGNORECASE)
    elif primary == "windows_path":
        text = text.replace("/", "\\")
    elif primary == "linux_path":
        text = re.sub(r"/{2,}", "/", text)
    if re.fullmatch(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text, re.I):
        text = ":".join(re.findall(r"[0-9a-f]{2}", text, re.I)).lower()
        candidates = ["mac"]
        primary = "mac"
    candidates = list(dict.fromkeys(candidates))
    if primary == "unknown":
        return NormalizedIOC(text, primary, tuple(candidates), 0.0, False)
    return NormalizedIOC(text, primary, tuple(candidates), 1.0 if len(candidates) == 1 else 0.7, True)


PATTERNS: list[tuple[str, str]] = [
    ("cve", r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    ("url", r"^https?://[^\s]+$", re.IGNORECASE),
    ("email", r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),
    ("md5", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("sha1", r"^[a-f0-9]{40}$", re.IGNORECASE),
    ("sha256", r"^[a-f0-9]{64}$", re.IGNORECASE),
    ("sha512", r"^[a-f0-9]{128}$", re.IGNORECASE),
    # Ethereum externally-owned account address.
    ("eth", r"^0x[a-fA-F0-9]{40}$"),
    # JA4 fingerprints are structured tokens, not service names. JA3 is
    # commonly submitted with an explicit prefix because a bare 32-char
    # fingerprint is indistinguishable from an MD5 hash.
    ("ja4", r"^[tq]\d{2}d\d{4}h\d(?:_[a-z0-9]*)?$", re.IGNORECASE),
    ("ja3", r"^ja3:[a-f0-9]{32}$", re.IGNORECASE),
    ("tlsh", r"^T1[0-9A-Z]{68,70}$", re.IGNORECASE),
    ("mac", r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE),
    ("ssdeep", r"^\d+:[a-zA-Z0-9/+:=]+:[a-zA-Z0-9/+:=]+$"),
    ("btc", r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    ("btc", r"^bc1[a-zA-Z0-9]{38,58}$"),
    ("mitre_attack", r"^(TA\d{4}|T\d{4}(\.\d{3})?)$"),
    ("asn", r"^AS\d+$", re.IGNORECASE),
    ("user_agent", r"^(?:Mozilla|curl|wget|python-requests|Go-http-client|Java)/[^\s]+$", re.IGNORECASE),
    ("named_pipe", r"^\\\\[^\\]+\\pipe\\"),
    # Registry keys must start with a known hive to avoid swallowing mutexes like Global\MyMutex
    ("registry_key", r"^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[A-Za-z0-9_\\]+$", re.IGNORECASE),
    ("windows_path", r"^(?:[A-Za-z]:[\\/].+|\\\\[^\\/]+[\\/].+)$"),
    ("linux_path", r"^/(?:[^\x00\r\n]+)$"),
    # A bare filename is metadata, not file reputation. Keep it broad enough
    # to represent analyst-supplied names while excluding hostnames.
    ("filename", r"^(?:[^\\/:*?\"<>|.\s]+|[^\\/:*?\"<>|\s]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|js|jar|msi|docm|xlsm|pptm|hta|apk|sh|bin|txt|pdf|docx?|xlsx?|pptx?))$", re.IGNORECASE),
    ("domain", r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"),
    # Host artifacts last — service_name before mutex so My_Service123 is not swallowed
    ("service_name", r"^[A-Za-z0-9_]{6,}$"),
    ("mutex", r"^[A-Za-z0-9_\\-]{6,}$"),
]

_SEARCH_BASED_TYPES = {"mutex", "registry_key", "named_pipe", "service_name"}
SUPPORTED_IOC_TYPES = {
    "cve", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "sha512",
    "ssdeep", "tlsh", "btc", "eth", "mitre_attack", "asn", "mac", "ja3", "ja4", "user_agent", "filename", "windows_path", "linux_path",
    "mutex", "named_pipe", "registry_key", "service_name", "password",
}


def classify_ioc(value: str) -> str:
    return normalize_ioc(value).ioc_type

    for type_name, pattern, *flags in PATTERNS:
        flag = flags[0] if flags else 0
        if re.match(pattern, value, flag):
            if type_name == "md5":
                return type_name
            if type_name == "domain" and value.startswith("http"):
                continue
            # Host-artifact guards: avoid swallowing simple tokens
            if type_name in ("mutex", "service_name"):
                if len(value) < 6:
                    continue
                if value.isdigit():
                    continue
                # Random hexadecimal tokens are hashes/fingerprints, not
                # human-readable host artifacts. Do not invent a mutex or
                # service classification when no artifact marker is present.
                if re.fullmatch(r"[a-f0-9]{16,}", value, re.IGNORECASE):
                    continue
                # Pure lowercase alpha like hello/foobar should be unknown,
                # not a mutex. Real mutexes often have underscore, hyphen,
                # backslash, mixed case, or are longer.
                if value.isalpha() and value.islower() and len(value) < 12:
                    continue
                if value.islower() and value.isalnum() and "_" not in value and "\\" not in value and "-" not in value:
                    # e.g. foobar123, hello123 — no artifact markers
                    if len(value) < 12:
                        continue
                # service_name must not contain backslash or hyphen
                if type_name == "service_name" and ("\\" in value or "-" in value):
                    continue
                # mutex should have at least one artifact marker unless long
                if type_name == "mutex" and len(value) < 10 and "_" not in value and "\\" not in value and "-" not in value:
                    continue
            return type_name
    return "unknown"


def is_search_based(ioc_type: str) -> bool:
    return ioc_type in _SEARCH_BASED_TYPES
