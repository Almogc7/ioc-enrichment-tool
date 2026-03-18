import json

import pandas as pd
import streamlit as st

from IOC_Enricher import IOCEnricher, MAX_BATCH_SIZE, asdict, prepare_iocs

st.set_page_config(page_title="IOC Enricher", layout="wide", page_icon="🔍")

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.verdict-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-weight: 700;
    font-size: 0.82em;
}
.badge-high       { background:#fde8e8; color:#b42318; border:1px solid #f5c6c6; }
.badge-suspicious { background:#fef3cd; color:#b54708; border:1px solid #f3d07a; }
.badge-low        { background:#fff8e1; color:#9a6a00; border:1px solid #f0d080; }
.badge-clean      { background:#e8f5e9; color:#067647; border:1px solid #b2dfbd; }
</style>
""", unsafe_allow_html=True)

# ── Page header ───────────────────────────────────────────────────────────────
st.title("🔍 IOC Enricher")
st.caption("Enrich indicators against VirusTotal, AbuseIPDB, and AlienVault OTX.")

# ── Input ─────────────────────────────────────────────────────────────────────
ioc_input = st.text_area(
    "Enter IOCs (one per line)",
    height=130,
    placeholder="8.8.8.8\nevil.com\nabc123def456...",
)
uploaded_file = st.file_uploader("Or upload a .txt file", type=["txt"])

iocs: list = []
if ioc_input:
    iocs.extend([line.strip() for line in ioc_input.splitlines() if line.strip()])
if uploaded_file:
    iocs.extend([line.decode("utf-8").strip() for line in uploaded_file.readlines() if line.strip()])
prepared_iocs = prepare_iocs(iocs)

if prepared_iocs.duplicates_removed:
    st.info(f"Removed {prepared_iocs.duplicates_removed} duplicate IOC(s) before enrichment.")
if prepared_iocs.truncated_count:
    st.warning(
        f"Batch limited to {prepared_iocs.max_batch_size} IOC(s). {prepared_iocs.truncated_count} IOC(s) were not processed."
    )
if prepared_iocs.invalid_iocs:
    with st.expander(f"Review invalid IOC entries ({len(prepared_iocs.invalid_iocs)})"):
        st.write(prepared_iocs.invalid_iocs)
st.caption(f"Current batch guardrail: maximum {MAX_BATCH_SIZE} valid IOC(s) per run.")

if st.button("Enrich IOCs", type="primary", key="enrich_iocs_button"):
    if prepared_iocs.valid_iocs:
        enricher = IOCEnricher()
        with st.spinner(f"Enriching {len(prepared_iocs.valid_iocs)} IOC(s) — this may take a moment..."):
            results = [asdict(result) for result in enricher.enrich_many(prepared_iocs.valid_iocs)]
        st.session_state["ioc_results"] = results
    else:
        st.warning("Please enter or upload at least one valid IOC.")

# ── Results ───────────────────────────────────────────────────────────────────
if "ioc_results" in st.session_state and st.session_state["ioc_results"]:
    raw = st.session_state["ioc_results"]

    # ── Flatten each result into analyst-friendly table row ──────────────────
    def flatten(r: dict) -> dict:
        vt  = r["sources"].get("virustotal",    {})
        ab  = r["sources"].get("abuseipdb",     {})
        otx = r["sources"].get("alienvault_otx", {})
        score_breakdown = r.get("score_breakdown", {})

        try:
            ts = r["checked_at"][:19].replace("T", " ") + " UTC"
        except Exception:
            ts = r["checked_at"]

        why_flagged = ", ".join(
            f"{component['label']} +{component['contribution']}"
            for component in score_breakdown.get("components", [])[:3]
        ) or "No strong scoring signals"

        return {
            "IOC":           r["value"],
            "Type":          r["ioc_type"].upper(),
            "Risk Score":    r["risk_score"],
            "Verdict":       r["verdict"],
            "Why Flagged":   why_flagged,
            "From Cache":    "Yes" if r.get("cache_hit") else "No",
            "VT Malicious":  vt.get("malicious",  "–") if vt.get("enabled") else "–",
            "VT Suspicious": vt.get("suspicious", "–") if vt.get("enabled") else "–",
            "Abuse Score":   ab.get("abuse_confidence_score", "–") if ab.get("enabled") else "–",
            "OTX Pulses":    otx.get("pulse_count", "–") if otx.get("enabled") else "–",
            "Country":       ab.get("country_code") or "–",
            "ISP":           ab.get("isp") or "–",
            "Checked At":    ts,
        }

    rows   = [flatten(r) for r in raw]
    df     = pd.DataFrame(rows)
    df_raw = pd.DataFrame(raw)

    # ── Summary metrics ───────────────────────────────────────────────────────
    st.subheader("Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total IOCs",     len(df))
    c2.metric("High Risk",      int((df_raw["risk_score"] >= 70).sum()))
    c3.metric("Suspicious",     int(((df_raw["risk_score"] >= 40) & (df_raw["risk_score"] < 70)).sum()))
    c4.metric("Avg Risk Score", f"{df_raw['risk_score'].mean():.1f}")

    cache_hits = int(sum(1 for result in raw if result.get("cache_hit")))
    if cache_hits:
        st.info(f"{cache_hits} IOC(s) were served from local cache during this run.")

    # Alert banner when high-risk IOCs are present
    high_risk_list = df[df["Risk Score"] >= 70]["IOC"].tolist()
    if high_risk_list:
        st.error(f"⚠️ **{len(high_risk_list)} HIGH RISK IOC(s) detected:** {', '.join(high_risk_list)}")

    # ── Filters ───────────────────────────────────────────────────────────────
    st.subheader("Filters")
    fc1, fc2 = st.columns([2, 3])
    verdict_opts = sorted(df["Verdict"].dropna().unique().tolist())
    sel_verdicts = fc1.multiselect("Verdict", verdict_opts, default=verdict_opts, key="verdict_filter")
    risk_range   = fc2.slider("Risk Score Range", 0, 100, (0, 100), key="risk_filter")

    mask = df["Verdict"].isin(sel_verdicts) & df["Risk Score"].between(risk_range[0], risk_range[1])
    view = df[mask].sort_values("Risk Score", ascending=False).reset_index(drop=True)

    # ── Styled table ──────────────────────────────────────────────────────────
    VERDICT_COLORS = {
        "high-confidence malicious": "#b42318",
        "suspicious":                "#b54708",
        "low-confidence suspicious": "#b54708",
        "no strong evidence":        "#067647",
    }

    SCORE_BACKGROUNDS = [
        (70, 101, "#fde8e8"),
        (40,  70, "#fef3cd"),
        (15,  40, "#fffbe6"),
        ( 0,  15, "#e8f5e9"),
    ]

    def style_score(val):
        try:
            v = int(val)
        except (ValueError, TypeError):
            return ""
        for lo, hi, color in SCORE_BACKGROUNDS:
            if lo <= v < hi:
                return f"background-color: {color}; font-weight: 700;"
        return ""

    def style_verdict(val):
        color = VERDICT_COLORS.get(str(val), "#475467")
        return f"color: {color}; font-weight: 700;"

    styled = (
        view.style
        .map(style_score,   subset=["Risk Score"])
        .map(style_verdict, subset=["Verdict"])
    )

    st.subheader("Results")
    st.dataframe(styled, use_container_width=True, hide_index=True)

    export_col1, export_col2 = st.columns(2)
    export_col1.download_button(
        "⬇ Download CSV",
        view.to_csv(index=False).encode("utf-8"),
        "ioc_enrichment_results.csv",
        "text/csv",
    )
    export_col2.download_button(
        "⬇ Download JSON",
        json.dumps(raw, indent=2, ensure_ascii=False).encode("utf-8"),
        "ioc_enrichment_results.json",
        "application/json",
    )

    # ── Per-IOC detail cards ──────────────────────────────────────────────────
    st.subheader("IOC Detail Breakdown")
    st.caption("Expand each IOC to see the full breakdown per intelligence source.")

    visible_iocs = set(view["IOC"].tolist())
    filtered_raw = sorted(
        [r for r in raw if r["value"] in visible_iocs],
        key=lambda x: x["risk_score"],
        reverse=True,
    )

    for r in filtered_raw:
        vt  = r["sources"].get("virustotal",    {})
        ab  = r["sources"].get("abuseipdb",     {})
        otx = r["sources"].get("alienvault_otx", {})
        score_breakdown = r.get("score_breakdown", {})
        score   = r["risk_score"]
        verdict = r["verdict"]

        badge_cls = (
            "badge-high"       if score >= 70 else
            "badge-suspicious" if score >= 40 else
            "badge-low"        if score >= 15 else
            "badge-clean"
        )

        label = f"{r['value']}  •  {r['ioc_type'].upper()}  •  Risk {score}/100  •  {verdict}"
        with st.expander(label, expanded=(score >= 70)):

            hc1, hc2 = st.columns([4, 1])
            with hc1:
                st.markdown(f"**IOC:** `{r['value']}`&nbsp;&nbsp; **Type:** `{r['ioc_type'].upper()}`")
                st.markdown(
                    f"**Verdict:** <span class='verdict-badge {badge_cls}'>{verdict}</span>",
                    unsafe_allow_html=True,
                )
            with hc2:
                st.metric("Risk Score", f"{score} / 100")

            if r.get("cache_hit"):
                st.caption("Result source: local cache")

            st.progress(score / 100)

            if score_breakdown.get("components"):
                st.markdown("**Why flagged**")
                for component in score_breakdown["components"]:
                    st.markdown(
                        f"- {component['label']}: +{component['contribution']} (raw value: {component['raw_value']})"
                    )

            st.divider()

            sc1, sc2, sc3 = st.columns(3)

            # ── VirusTotal ────────────────────────────────────────────────────
            with sc1:
                st.markdown("**🔬 VirusTotal**")
                st.caption(f"Status: {vt.get('status', 'unknown').replace('_', ' ')}")
                if not vt.get("enabled"):
                    st.caption(vt.get("error", "API key not configured."))
                elif vt.get("error"):
                    st.warning(f"Error: {vt['error']}")
                else:
                    mal   = vt.get("malicious",  0)
                    sus   = vt.get("suspicious", 0)
                    hrm   = vt.get("harmless",   0)
                    undet = vt.get("undetected", 0)
                    total = mal + sus + hrm + undet
                    st.metric("Malicious",  f"{mal} / {total}")
                    st.metric("Suspicious", sus)
                    if vt.get("tags"):
                        st.caption("Tags: " + ", ".join(vt["tags"][:6]))
                    if vt.get("categories"):
                        cats = list(vt["categories"].values())[:4]
                        st.caption("Categories: " + ", ".join(cats))

            # ── AbuseIPDB ─────────────────────────────────────────────────────
            with sc2:
                st.markdown("**🚨 AbuseIPDB**")
                st.caption(f"Status: {ab.get('status', 'unknown').replace('_', ' ')}")
                if not ab.get("enabled"):
                    st.caption(ab.get("error", "API key not configured."))
                elif ab.get("error"):
                    st.warning(f"Error: {ab['error']}")
                else:
                    st.metric("Abuse Confidence", f"{ab.get('abuse_confidence_score', 0)}%")
                    st.metric("Total Reports",    ab.get("total_reports", 0))
                    if ab.get("country_code"):
                        st.caption(f"Country: {ab['country_code']}")
                    if ab.get("isp"):
                        st.caption(f"ISP: {ab['isp']}")
                    if ab.get("usage_type"):
                        st.caption(f"Usage type: {ab['usage_type']}")
                    if ab.get("last_reported_at"):
                        st.caption(f"Last reported: {ab['last_reported_at'][:10]}")

            # ── AlienVault OTX ────────────────────────────────────────────────
            with sc3:
                st.markdown("**📡 AlienVault OTX**")
                st.caption(f"Status: {otx.get('status', 'unknown').replace('_', ' ')}")
                if not otx.get("enabled"):
                    st.caption(otx.get("error", "API key not configured."))
                elif otx.get("error"):
                    st.warning(f"Error: {otx['error']}")
                else:
                    st.metric("Pulse Count", otx.get("pulse_count", 0))
                    pulse_names = otx.get("pulse_names", [])
                    if pulse_names:
                        st.caption("Threat campaigns:")
                        for name in pulse_names:
                            st.markdown(f"&nbsp;&nbsp;• {name}")

    # ── Raw JSON toggle ───────────────────────────────────────────────────────
    with st.expander("Show raw source JSON"):
        st.json(raw)

history_rows = IOCEnricher().recent_history(limit=10)
if history_rows:
    with st.expander("Recent local enrichment history"):
        st.dataframe(pd.DataFrame(history_rows), use_container_width=True, hide_index=True)
