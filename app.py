import streamlit as st
import subprocess

from osint_mapper.report import build_pdf
from osint_mapper.scanner import scan_domain

st.set_page_config(page_title="Passive Attack Surface Mapper", page_icon="🔎", layout="wide")
st.title("Passive Corporate Attack Surface Mapper")
st.caption("Public-source enumeration only: crt.sh and the Internet Archive. No target hosts are contacted.")

@st.cache_data(ttl=300, show_spinner=False)
def cached_scan(domain: str, include_harvester: bool):
    runner = subprocess.run if include_harvester else None
    return scan_domain(domain, harvester_runner=runner)

with st.form("scan_form"):
    domain = st.text_input("Corporate domain", placeholder="example.com")
    include_harvester = st.checkbox(
        "Run optional passive theHarvester sources",
        help="Requires theHarvester to be installed. Active DNS brute-forcing is never enabled.",
    )
    st.caption("Public provider results are cached for 5 minutes. Change the domain or clear the cache to refresh.")
    submitted = st.form_submit_button("Run passive scan", type="primary")

if submitted:
    if not domain.strip():
        st.error("Enter a domain before scanning.")
    else:
        with st.spinner("Querying public data sources..."):
            result = cached_scan(domain, include_harvester)
        st.session_state["scan_result"] = result

result = st.session_state.get("scan_result")
if result:
    if result.warnings:
        for warning in result.warnings:
            st.warning(warning)
    if result.source_status:
        st.subheader("Provider status")
        st.dataframe(
            [{"Source": source, "Status": status} for source, status in result.source_status.items()],
            use_container_width=True,
            hide_index=True,
        )
    metrics = st.columns(4)
    metrics[0].metric("Subdomains", len(result.subdomains))
    metrics[1].metric("Emails", len(result.emails))
    metrics[2].metric("Historical URLs", len(result.historical_urls))
    metrics[3].metric("High-risk indicators", len(result.high_risk_assets))

    subdomains, emails, history, harvester = st.tabs(
        ["Subdomain attack surface", "Exposed emails", "Historical endpoints", "theHarvester results"]
    )
    with subdomains:
        st.dataframe(
            [{"Asset": a.value, "Source": a.source, "Risk": a.risk, "Reason": a.reason} for a in result.subdomains],
            use_container_width=True,
            hide_index=True,
        )
    with emails:
        st.dataframe(
            [{"Email": a.value, "Source": a.source} for a in result.emails],
            use_container_width=True,
            hide_index=True,
        )
    with history:
        st.dataframe(
            [
                {
                    "URL": a.value,
                    "Category": (
                        "Admin/API" if "/admin" in a.value.lower() or "/api" in a.value.lower()
                        else "Sensitive file" if any(ext in a.value.lower() for ext in (".pdf", ".bak", ".sql"))
                        else "Other"
                    ),
                    "Source": a.source,
                    "Severity": a.risk,
                    "Reason": a.reason,
                }
                for a in result.historical_urls
            ],
            use_container_width=True,
            hide_index=True,
        )
    with harvester:
        st.write("Emails")
        st.dataframe([{"Email": a.value, "Source": a.source} for a in result.emails if a.source == "theHarvester"], use_container_width=True, hide_index=True)
        st.write("Hosts")
        st.dataframe([{"Host": a.value, "Severity": a.risk, "Reason": a.reason} for a in result.harvester_hosts], use_container_width=True, hide_index=True)
        st.write("IP addresses")
        st.dataframe([{"IP address": a.value, "Source": a.source} for a in result.harvester_ips], use_container_width=True, hide_index=True)

    st.download_button(
        "Download executive summary (PDF)",
        data=build_pdf(result),
        file_name=f"{result.domain}-passive-summary.pdf",
        mime="application/pdf",
    )
