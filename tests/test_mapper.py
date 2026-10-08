import pytest

from osint_mapper.clients import fetch_certificate_records, fetch_wayback_urls, run_passive_theharvester
from osint_mapper.heuristics import classify_asset
from osint_mapper.models import Asset, ScanResult
from osint_mapper.parsers import (
    extract_emails,
    normalize_domain,
    parse_theharvester_output,
    parse_certificate_names,
)
from osint_mapper.report import build_pdf
from osint_mapper.scanner import scan_domain


def test_certificate_names_are_filtered_normalized_and_deduplicated():
    records = [
        {"name_value": "*.DEV.Example.com\nexample.com\nother.example.net"},
        {"name_value": "dev.example.com"},
    ]
    assert parse_certificate_names(records, "example.com") == {"dev.example.com", "example.com"}


@pytest.mark.parametrize("value", ["example.com", "https://Example.com/"])
def test_normalize_domain(value):
    assert normalize_domain(value) == "example.com"


def test_invalid_domain_is_rejected():
    with pytest.raises(ValueError):
        normalize_domain("not a domain")


def test_extract_emails_stays_on_target_domain():
    assert extract_emails(["A@Example.com and outsider@example.net"], "example.com") == {"a@example.com"}


def test_parse_theharvester_json_filters_target_domain():
    emails, hosts, ips = parse_theharvester_output(
        '{"emails":["a@example.com","b@other.net"],"hosts":["dev.example.com","other.net"],"ips":["192.0.2.1"]}',
        "example.com",
    )
    assert emails == {"a@example.com"}
    assert hosts == {"dev.example.com"}
    assert ips == {"192.0.2.1"}


def test_parse_theharvester_xml():
    emails, hosts, ips = parse_theharvester_output(
        "<results><email>a@example.com</email><host>vpn.example.com</host><ip>192.0.2.2</ip></results>",
        "example.com",
    )
    assert emails == {"a@example.com"}
    assert hosts == {"vpn.example.com"}
    assert ips == {"192.0.2.2"}


def test_risk_heuristic_flags_sensitive_terms():
    assert classify_asset("vpn.example.com")[0] == "Critical"
    assert classify_asset("https://example.com/about")[0] == "Low"


def test_scan_uses_both_passive_sources():
    result = scan_domain(
        "example.com",
        certificate_fetcher=lambda domain, session=None: [{"name_value": "dev.example.com"}],
        wayback_fetcher=lambda domain, session=None: ["https://example.com/api/v1/users"],
    )
    assert [asset.value for asset in result.subdomains] == ["dev.example.com"]
    assert result.historical_urls[0].risk == "High"


def test_theharvester_command_has_no_active_bruteforce_flag():
    class Completed:
        stdout = "user@example.com"
        stderr = ""

    def runner(command, **kwargs):
        assert "-c" not in command
        return Completed()

    output, command = run_passive_theharvester("example.com", runner=runner)
    assert "user@example.com" in output
    assert command[0] == "theHarvester"


def test_pdf_is_generated():
    result = scan_domain(
        "example.com",
        certificate_fetcher=lambda domain, session=None: [],
        wayback_fetcher=lambda domain, session=None: [],
    )
    assert build_pdf(result).startswith(b"%PDF")


def test_pdf_handles_long_archived_urls():
    result = ScanResult(
        domain="example.com",
        historical_urls=[
            Asset(
                "https://example.com/" + ("very-long-path-" * 30),
                "Wayback Machine",
                "High",
                "Matched sensitive indicator(s): /api/",
            )
        ],
    )
    assert build_pdf(result).startswith(b"%PDF")


def test_pdf_handles_multiple_high_risk_findings():
    result = ScanResult(
        domain="example.com",
        historical_urls=[
            Asset(f"https://example.com/admin/{index}", "Wayback Machine", "High", "admin")
            for index in range(50)
        ],
    )
    assert build_pdf(result).startswith(b"%PDF")


def test_certificate_lookup_retries_without_wildcard_on_404():
    class Response:
        status_code = 404

    class Session:
        def __init__(self):
            self.queries = []

        def get(self, url, *, params, **kwargs):
            self.queries.append(params["q"])
            if len(self.queries) == 1:
                error = __import__("requests").HTTPError(response=Response())
                raise error
            return type(
                "Success",
                (),
                {
                    "status_code": 200,
                    "raise_for_status": lambda self: None,
                    "json": lambda self: [],
                },
            )()

    session = Session()
    assert fetch_certificate_records("example.com", session=session) == []
    assert session.queries == ["%.example.com", "example.com"]


def test_certificate_lookup_retries_transient_gateway_failure():
    class Response:
        status_code = 502

        def raise_for_status(self):
            raise __import__("requests").HTTPError(response=self)

    class Session:
        calls = 0

        def get(self, *args, **kwargs):
            self.calls += 1
            if self.calls < 3:
                return Response()
            return type("Success", (), {"status_code": 200, "raise_for_status": lambda self: None, "json": lambda self: []})()

    session = Session()
    assert fetch_certificate_records("example.com", session=session) == []
    assert session.calls == 3


def test_wayback_retries_transient_gateway_failure():
    class Response:
        status_code = 502

        def raise_for_status(self):
            raise __import__("requests").HTTPError(response=self)

    class Session:
        calls = 0

        def get(self, *args, **kwargs):
            self.calls += 1
            if self.calls < 3:
                return Response()
            return type("Success", (), {"status_code": 200, "raise_for_status": lambda self: None, "json": lambda self: []})()

    session = Session()
    assert fetch_wayback_urls("example.com", session=session) == []
    assert session.calls == 3
