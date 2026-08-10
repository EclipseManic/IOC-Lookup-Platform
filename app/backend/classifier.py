import ipaddress
import re


def refang(text: str) -> str:
    text = re.sub(r"hxxps\[?:\]?//", "https://", text, flags=re.IGNORECASE)
    text = re.sub(r"hxxp\[?:\]?//", "http://", text, flags=re.IGNORECASE)
    text = re.sub(r"\[\.\]", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"\\\.", ".", text)
    return text


def defang(text: str) -> str:
    text = text.replace("http://", "hxxp://")
    text = text.replace("https://", "hxxps://")
    text = text.replace(".", "[.]")
    return text


PATTERNS: list[tuple[str, str]] = [
    ("cve", r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    ("domain", r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"),
    ("url", r"^https?://[^\s]+$", re.IGNORECASE),
    ("email", r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),
    ("md5", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("sha1", r"^[a-f0-9]{40}$", re.IGNORECASE),
    ("sha256", r"^[a-f0-9]{64}$", re.IGNORECASE),
    ("ssdeep", r"^\d+:[a-zA-Z0-9/+:=]+:[a-zA-Z0-9/+:=]+$"),
    ("btc", r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    ("btc", r"^bc1[a-zA-Z0-9]{38,58}$"),
    ("mitre_attack", r"^(TA\d{4}|T\d{4}(\.\d{3})?)$"),
    ("asn", r"^AS\d+$", re.IGNORECASE),
    ("named_pipe", r"^\\\\[^\\]+\\pipe\\"),
    ("registry_key", r"^[A-Za-z_][A-Za-z0-9_]*\\[A-Za-z0-9_\\]+$"),
    ("mutex", r"^[a-zA-Z0-9_\\-]+$"),
    ("service_name", r"^[a-zA-Z0-9_]+$"),
]

_SEARCH_BASED_TYPES = {"mutex", "registry_key", "named_pipe", "service_name"}
SUPPORTED_IOC_TYPES = {
    "cve", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256",
    "ssdeep", "btc", "mitre_attack", "asn", "mutex", "named_pipe", "registry_key", "service_name",
}


def classify_ioc(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        return "ipv4" if address.version == 4 else "ipv6"
    except ValueError:
        pass

    for type_name, pattern, *flags in PATTERNS:
        flag = flags[0] if flags else 0
        if re.match(pattern, value, flag):
            if type_name == "md5":
                return type_name
            if type_name == "domain" and value.startswith("http"):
                continue
            return type_name
    return "unknown"


def is_search_based(ioc_type: str) -> bool:
    return ioc_type in _SEARCH_BASED_TYPES
