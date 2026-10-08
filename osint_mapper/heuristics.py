from urllib.parse import urlparse

HIGH_RISK_TERMS = (
    "admin",
    "dev",
    "development",
    "jira",
    "portal",
    "staging",
    "test",
    "vpn",
)
CRITICAL_TERMS = ("admin", "vpn", ".bak", ".sql")
SENSITIVE_PATH_TERMS = ("/admin", "/api", ".bak", ".sql", ".pdf")


def classify_asset(value: str) -> tuple[str, str]:
    lowered = value.lower()
    parsed = urlparse(value)
    haystack = f"{parsed.hostname or ''}{parsed.path}" if parsed.scheme else lowered
    matches = [term for term in HIGH_RISK_TERMS if term in haystack]
    matches.extend(term for term in SENSITIVE_PATH_TERMS if term in lowered)
    if matches:
        unique_matches = ", ".join(dict.fromkeys(matches))
        severity = "Critical" if any(term in lowered for term in CRITICAL_TERMS) else "High"
        return severity, f"Matched sensitive indicator(s): {unique_matches}"
    return "Low", ""
