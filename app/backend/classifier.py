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
    ("ipv4", r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    ("ipv6", r"^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$"),
    ("domain", r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"),
    ("url", r"^https?://[^\s]+$", re.IGNORECASE),
    ("email", r"^[\w.+-]+@[\w-]+\.[\w.-]+$"),
    ("imphash", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("ja3", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("ja3s", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("md5", r"^[a-f0-9]{32}$", re.IGNORECASE),
    ("sha1", r"^[a-f0-9]{40}$", re.IGNORECASE),
    ("sha256", r"^[a-f0-9]{64}$", re.IGNORECASE),
    ("ssdeep", r"^\d+:[a-zA-Z0-9/+:=]+:[a-zA-Z0-9/+:=]+$"),
    ("btc", r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    ("btc", r"^bc1[a-zA-Z0-9]{38,58}$"),
    ("mitre_attack", r"^(TA\d{4}|T\d{4}(\.\d{3})?)$"),
    ("asn", r"^AS\d+$", re.IGNORECASE),
    ("mutex", r"^[a-zA-Z0-9_\\-]+$"),
    ("named_pipe", r"^\\\\[^\\]+\\pipe\\"),
    ("registry_key", r"^[A-Za-z_][A-Za-z0-9_]*\\[A-Za-z0-9_\\]+$"),
    ("service_name", r"^[a-zA-Z0-9_]+$"),
]

_SEARCH_BASED_TYPES = {"mutex", "registry_key", "named_pipe", "service_name"}


def classify_ioc(value: str) -> str:
    for type_name, pattern, *flags in PATTERNS:
        flag = flags[0] if flags else 0
        if re.match(pattern, value, flag):
            if type_name in ("md5", "imphash", "ja3", "ja3s"):
                return type_name
            if type_name == "domain" and value.startswith("http"):
                continue
            if type_name == "ipv4":
                if all(0 <= int(o) <= 255 for o in value.split(".")):
                    return "ipv4"
                continue
            return type_name
    return "unknown"


def is_search_based(ioc_type: str) -> bool:
    return ioc_type in _SEARCH_BASED_TYPES
