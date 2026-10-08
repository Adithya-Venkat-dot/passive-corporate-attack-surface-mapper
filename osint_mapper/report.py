from fpdf import FPDF

from .models import ScanResult


def _break_long_tokens(pdf: FPDF, text: str) -> str:
    """Insert width-safe break points into long URLs and other tokens."""
    max_width = pdf.epw - 2
    words: list[str] = []
    for token in text.split(" "):
        while pdf.get_string_width(token) > max_width:
            split_at = max(1, len(token) // 2)
            while split_at > 1 and pdf.get_string_width(token[:split_at]) > max_width:
                split_at -= 1
            words.append(token[:split_at])
            token = token[split_at:]
        words.append(token)
    return " ".join(words)


def build_pdf(result: ScanResult) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(text="Passive Attack Surface Summary")
    pdf.ln(10)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(
        0,
        7,
        text=(
            f"Domain: {result.domain}\n"
            f"Subdomains: {len(result.subdomains)} | "
            f"Emails: {len(result.emails)} | "
            f"Historical URLs: {len(result.historical_urls)}\n"
            f"theHarvester hosts: {len(result.harvester_hosts)} | "
            f"IPs: {len(result.harvester_ips)}\n"
            f"High-risk findings: {len(result.high_risk_assets)}"
        ),
    )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(text="High-risk findings")
    pdf.ln(8)
    pdf.set_font("Helvetica", size=10)
    findings = result.high_risk_assets or [None]
    for asset in findings:
        if asset is None:
            pdf.cell(text="No high-risk indicators were found by the configured heuristics.")
        else:
            finding = f"[{asset.source}] {asset.value} - {asset.reason}"
            pdf.multi_cell(
                pdf.epw,
                6,
                text=_break_long_tokens(pdf, finding),
                new_x="LMARGIN",
                new_y="NEXT",
            )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(text="Source status")
    pdf.ln(8)
    pdf.set_font("Helvetica", size=10)
    for source, status in result.source_status.items():
        pdf.cell(pdf.epw, 6, text=_break_long_tokens(pdf, f"{source}: {status}"), new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())
