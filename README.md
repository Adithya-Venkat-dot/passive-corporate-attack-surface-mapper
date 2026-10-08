# Passive Corporate Attack Surface Mapper

This mini-project discovers publicly documented corporate assets without sending
traffic to the target's servers. It queries:

- **crt.sh** for Certificate Transparency names and subdomains.
- **Internet Archive CDX API** for historically archived URLs. This project
  uses direct CDX API requests rather than `waybackpy` to keep the integration
  small and transparent.
- Optional **theHarvester** integration, restricted to passive providers and
  deliberately excluding active DNS brute forcing.

The dashboard can parse theHarvester JSON or XML output and display its
target-domain emails, hostnames, and IP addresses. Public provider responses
are cached for five minutes and transient provider failures are retried.

## Open-source license

This project is released under the [MIT License](LICENSE). You may use,
modify, and redistribute it subject to that license. Only use it for domains
you own or are explicitly authorized to assess.

## Run on Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
streamlit run app.py
```

Open `http://127.0.0.1:8501` in a browser.

### Optional theHarvester on Kali

Install theHarvester using the package available in your Kali release, or
install it in the active virtual environment:

```bash
sudo apt install -y theharvester
theHarvester --help
```

If the executable is installed under a different capitalization, the
application detects both `theHarvester` and `theharvester` on `PATH`. The
optional integration uses only passive providers and never adds `-c`.

## Run locally on Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
streamlit run app.py
```

Run tests with:

```powershell
py -m pip install pytest
py -m pytest
```

TheHarvester is optional. The core dashboard works without it.

The results are leads for authorized defensive assessment, not proof that an
asset is reachable or vulnerable. The risk labels are transparent keyword
heuristics and require human verification.
