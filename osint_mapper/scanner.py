from collections.abc import Callable

import requests

from .clients import fetch_certificate_records, fetch_wayback_urls
from .heuristics import classify_asset
from .models import Asset, ScanResult
from .parsers import extract_emails, normalize_domain, normalize_historical_urls, parse_certificate_names
from .clients import run_passive_theharvester
from .parsers import parse_theharvester_output
import subprocess


def scan_domain(
    raw_domain: str,
    *,
    session: requests.Session | None = None,
    certificate_fetcher: Callable[..., list[dict]] = fetch_certificate_records,
    wayback_fetcher: Callable[..., list[str]] = fetch_wayback_urls,
    harvester_runner: Callable[..., object] | None = None,
) -> ScanResult:
    domain = normalize_domain(raw_domain)
    result = ScanResult(domain=domain)
    try:
        records = certificate_fetcher(domain, session=session)
        for name in sorted(parse_certificate_names(records, domain)):
            risk, reason = classify_asset(name)
            result.subdomains.append(Asset(name, "crt.sh", risk, reason))
    except (requests.RequestException, ValueError) as exc:
        result.warnings.append(f"Certificate Transparency lookup failed: {exc}")
        result.source_status["crt.sh"] = "Unavailable"
    else:
        result.source_status["crt.sh"] = "Available"

    try:
        historical_values = wayback_fetcher(domain, session=session)
        urls = normalize_historical_urls(historical_values, domain)
        for url in sorted(urls):
            risk, reason = classify_asset(url)
            result.historical_urls.append(Asset(url, "Wayback Machine", risk, reason))
        result.emails = [
            Asset(email, "Historical pages", "Low")
            for email in sorted(extract_emails(historical_values, domain))
        ]
    except (requests.RequestException, ValueError) as exc:
        result.warnings.append(f"Wayback lookup failed: {exc}")
        result.source_status["Internet Archive"] = "Unavailable"
    else:
        result.source_status["Internet Archive"] = "Available"
    if harvester_runner is not None:
        try:
            payload, _ = run_passive_theharvester(domain, runner=harvester_runner)
            emails, hosts, ips = parse_theharvester_output(payload, domain)
            result.emails.extend(Asset(email, "theHarvester", "Low") for email in sorted(emails))
            result.harvester_hosts = [
                Asset(host, "theHarvester", *classify_asset(host)) for host in sorted(hosts)
            ]
            result.harvester_ips = [
                Asset(ip, "theHarvester", "Low") for ip in sorted(ips)
            ]
            result.source_status["theHarvester"] = "Available"
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            result.warnings.append(f"theHarvester lookup failed: {exc}")
            result.source_status["theHarvester"] = "Unavailable"
    return result
