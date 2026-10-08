import re
import json
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    candidate = candidate.rstrip(".")
    if not DOMAIN_RE.fullmatch(candidate):
        raise ValueError("Enter a valid domain such as example.com.")
    return candidate


def parse_certificate_names(records: Iterable[dict], domain: str) -> set[str]:
    suffix = f".{domain.lower()}"
    names: set[str] = set()
    for record in records:
        raw_names = str(record.get("name_value", ""))
        for raw_name in raw_names.splitlines():
            name = raw_name.strip().lower().removeprefix("*.")
            if name == domain.lower() or name.endswith(suffix):
                names.add(name)
    return names


def extract_emails(values: Iterable[str], domain: str) -> set[str]:
    suffix = f"@{domain.lower()}"
    emails: set[str] = set()
    for value in values:
        for email in EMAIL_RE.findall(value):
            normalized = email.lower()
            if normalized.endswith(suffix):
                emails.add(normalized)
    return emails


def normalize_historical_urls(values: Iterable[str], domain: str) -> set[str]:
    urls: set[str] = set()
    for value in values:
        url = value.strip()
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            host = parsed.hostname.lower()
            if host == domain or host.endswith(f".{domain}"):
                urls.add(url)
    return urls


def parse_theharvester_output(payload: str | dict, domain: str) -> tuple[set[str], set[str], set[str]]:
    """Extract emails, hostnames, and IPs from theHarvester JSON or XML output."""
    emails: set[str] = set()
    hosts: set[str] = set()
    ips: set[str] = set()
    if isinstance(payload, dict):
        data = payload
        values = data
        for key, target in (("emails", emails), ("hosts", hosts), ("ips", ips)):
            items = values.get(key, [])
            if isinstance(items, list):
                target.update(str(item).strip().lower() for item in items if str(item).strip())
    else:
        text = payload.strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            return parse_theharvester_output(data, domain)
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            root = None
        if root is not None:
            for element in root.iter():
                key = element.tag.lower().split("}")[-1]
                value = (element.text or "").strip().lower()
                if key in {"email", "emails"} and value:
                    emails.add(value)
                elif key in {"host", "hostname", "hosts"} and value:
                    hosts.add(value)
                elif key in {"ip", "ips", "address"} and value:
                    ips.add(value)
    suffix = f".{domain.lower()}"
    hosts = {host for host in hosts if host == domain.lower() or host.endswith(suffix)}
    emails = {email for email in emails if email.endswith(f"@{domain.lower()}")}
    return emails, hosts, ips
