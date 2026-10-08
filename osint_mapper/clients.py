from collections.abc import Callable
import shutil
import time
import tempfile
from pathlib import Path
from typing import Any

import requests

CRT_SH_URL = "https://crt.sh/"
WAYBACK_URL = "https://web.archive.org/cdx/search/cdx"


def _get_json(
    url: str,
    params: dict[str, str],
    timeout: float,
    session: requests.Session,
    retries: int = 2,
) -> Any:
    for attempt in range(retries + 1):
        try:
            response = session.get(
                url,
                params=params,
                timeout=timeout,
                headers={"User-Agent": "PassiveAttackSurfaceMapper/1.0"},
            )
            if response.status_code in {502, 503, 504} and attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            response.raise_for_status()
            return response.json()
        except requests.Timeout:
            if attempt == retries:
                raise
            time.sleep(0.5 * (attempt + 1))
    raise RuntimeError("Request retry loop ended unexpectedly.")


def fetch_certificate_records(
    domain: str,
    *,
    timeout: float = 20,
    session: requests.Session | None = None,
) -> list[dict]:
    client = session or requests.Session()
    try:
        payload = _get_json(
            CRT_SH_URL,
            {"q": f"%.{domain}", "output": "json"},
            timeout,
            client,
        )
    except requests.HTTPError as exc:
        if exc.response is None or exc.response.status_code != 404:
            raise
        payload = _get_json(CRT_SH_URL, {"q": domain, "output": "json"}, timeout, client)
    if not isinstance(payload, list):
        raise ValueError("crt.sh returned an unexpected response.")
    return [item for item in payload if isinstance(item, dict)]


def fetch_wayback_urls(
    domain: str,
    *,
    timeout: float = 30,
    session: requests.Session | None = None,
) -> list[str]:
    client = session or requests.Session()
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "filter": "statuscode:200",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "1000",
    }
    response = None
    for attempt in range(3):
        try:
            response = client.get(
                WAYBACK_URL,
                params=params,
                timeout=timeout,
                headers={"User-Agent": "PassiveAttackSurfaceMapper/1.0"},
            )
            if response.status_code in {502, 503, 504} and attempt < 2:
                time.sleep(0.5 * (attempt + 1))
                continue
            break
        except requests.Timeout:
            if attempt == 2:
                raise
            time.sleep(0.5 * (attempt + 1))
    if response is None:
        raise RuntimeError("Wayback request did not return a response.")
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, list):
        raise ValueError("Wayback returned an unexpected response.")
    rows = payload[1:] if payload and isinstance(payload[0], list) else payload
    return [row[0] for row in rows if isinstance(row, list) and row and isinstance(row[0], str)]


def run_passive_theharvester(
    domain: str,
    *,
    runner: Callable[..., Any],
    timeout: float = 120,
) -> tuple[str, list[str]]:
    """Run an installed theHarvester without active DNS brute forcing.

    The caller supplies the runner so the function is safe to test. No ``-c`` or
    other active enumeration flag is ever included.
    """
    with tempfile.TemporaryDirectory(prefix="passive-osint-") as directory:
        output_base = str(Path(directory) / "theharvester")
        executable = shutil.which("theHarvester") or shutil.which("theharvester") or "theHarvester"
        command = [
            executable,
            "-d",
            domain,
            "-b",
            "bing,crtsh,github-code",
            "-f",
            output_base,
        ]
        completed = runner(command, capture_output=True, text=True, timeout=timeout, check=True)
        output = f"{completed.stdout}\n{completed.stderr}"
        for extension in (".json", ".xml"):
            output_path = f"{output_base}{extension}"
            try:
                with open(output_path, encoding="utf-8") as output_file:
                    return output_file.read(), command
            except FileNotFoundError:
                continue
        return output, command
