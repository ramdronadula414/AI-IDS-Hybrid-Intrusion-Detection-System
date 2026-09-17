"""AI-IDS Streamlit presentation shell.

The detection implementation remains in ``app_core.py``.  This file only
adapts navigation, portable analyzer choices and the visual presentation.
"""

from pathlib import Path
from collections import Counter
import html
import re
import streamlit as st

_CORE_PATH = Path(__file__).with_name("app_core.py")
_source = _CORE_PATH.read_text(encoding="utf-8")

# ---------------------------------------------------------------------
# Portable product copy
# ---------------------------------------------------------------------
_source = _source.replace(
    "Premium Streamlit dashboard for the CIC-IDS2017 AI-based IDS.",
    "Premium Streamlit dashboard for the Hybrid AI-based Intrusion Detection System.",
)
_source = _source.replace(
    """                <b>DATASET</b><br>\n                CIC-IDS2017\n                <br><br>\n                <b>FEATURES</b><br>""",
    """                <b>DETECTION LAYERS</b><br>\n                ML Detection · Behavioral IDS · Payload Inspection · Correlation\n                <br><br>\n                <b>FEATURES</b><br>""",
)
_source = _source.replace("Two-stage intrusion detection", "Hybrid intrusion detection")
_source = _source.replace(
    """            AI-powered network intrusion detection and\n            attack classification""",
    """            Detect · Analyze · Correlate · Protect""",
)
_source = _source.replace(
    """        AI-IDS Security Center • CIC-IDS2017 •\n        XGBoost-powered Network Intrusion Detection""",
    """        AI-IDS Security Center • Hybrid Intrusion Detection •\n        PCAP-first Security Analysis""",
)

# Analyzer headings while preserving the original callbacks and processing.
_source = _source.replace(
    '''elif page == "Traffic Analyzer":\n\n    st.markdown("### Traffic Analyzer")\n\n    st.caption(\n        "Analyze CICFlowMeter-compatible CSV files or "\n        "Wireshark PCAP/PCAPNG captures."\n    )''',
    '''elif page == "Traffic Analyzer":\n\n    if st.session_state.get("_ai_ids_input_mode") == "Upload PCAP / PCAPNG":\n        st.markdown("### PCAP Analyzer")\n        st.caption(\n            "Primary investigation workflow — analyze a PCAP/PCAPNG capture "\n            "with ML, behavioral detection, payload inspection and correlation."\n        )\n    else:\n        st.markdown("### CSV Analyzer")\n        st.caption(\n            "Analyze an external CICFlowMeter-compatible network-flow CSV. "\n            "No local CIC-IDS2017 dataset is required."\n        )''',
)
_source = _source.replace(
    '"Upload a CICFlowMeter/CIC-IDS2017 CSV and classify "',
    '"Upload a CICFlowMeter-compatible CSV and classify "',
)

# ---------------------------------------------------------------------
# Replace only the Security Dashboard presentation.  The PCAP/CSV/batch/
# model pages and all backend calls in app_core.py stay untouched.
# ---------------------------------------------------------------------
_dashboard = r'''if page == "Security Dashboard":

    report = st.session_state.get("pcap_security_report") or {}
    alerts = report.get("alerts", []) if isinstance(report, dict) else []

    final_decision = str(report.get("final_decision", "MONITORING"))
    severity = str(report.get("severity", "NORMAL"))
    analyzed_flows = int(report.get("total_flows", 0) or report.get("flows_analyzed", 0) or 0)
    total_alerts = len(alerts)

    st.markdown(
        """
        <div class="soc-page-title">Security Dashboard</div>
        <div class="soc-page-subtitle">Real-time overview of your network security</div>
        """,
        unsafe_allow_html=True,
    )

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_metric(
            "Overall Status",
            final_decision,
            "Active threats detected" if final_decision == "ATTACK" else "No active correlated threat",
            "metric-accent-red" if final_decision == "ATTACK" else "metric-accent-green",
        )
    with k2:
        render_metric(
            "Severity Level",
            severity,
            "Maximum severity detected",
            "metric-accent-red" if severity == "CRITICAL" else "metric-accent-amber" if severity in {"HIGH", "MEDIUM"} else "metric-accent-green",
        )
    with k3:
        render_metric(
            "Total Alerts",
            total_alerts,
            "Correlated security events",
            "metric-accent-purple",
        )
    with k4:
        render_metric(
            "Analyzed Flows",
            analyzed_flows,
            "Network flows processed",
            "metric-accent-blue",
        )

    threat_counts = Counter({
        "Bot / C2 Beaconing": 0,
        "Port Scan": 0,
        "Brute Force": 0,
        "DDoS / DoS": 0,
        "Slow HTTP": 0,
        "Web Attacks": 0,
        "Other": 0,
    })
    severity_counts = Counter({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})

    source_counter = Counter()
    target_counter = Counter()
    source_last_seen = {}
    target_last_seen = {}

    for alert in alerts:
        atype = str(alert.get("attack_type", "Other"))
        low = atype.lower()
        if "beacon" in low or "bot" in low:
            threat_counts["Bot / C2 Beaconing"] += 1
        elif "portscan" in low or "port scan" in low:
            threat_counts["Port Scan"] += 1
        elif "brute force" in low:
            threat_counts["Brute Force"] += 1
        elif "ddos" in low or low == "dos" or low.startswith("dos "):
            threat_counts["DDoS / DoS"] += 1
        elif "slow http" in low:
            threat_counts["Slow HTTP"] += 1
        elif "web attack" in low or "xss" in low or "sql injection" in low:
            threat_counts["Web Attacks"] += 1
        else:
            threat_counts["Other"] += 1

        sev = str(alert.get("severity", "LOW")).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

        last_seen = str(alert.get("last_seen", alert.get("first_seen", "Unknown")))
        source = alert.get("source_ip")
        if source and "," not in str(source):
            source_counter[str(source)] += 1
            source_last_seen[str(source)] = last_seen
        for src in alert.get("source_ips", []) or []:
            source_counter[str(src)] += 1
            source_last_seen[str(src)] = last_seen
        for attacker in alert.get("attackers", []) or []:
            src = attacker.get("ip")
            if src:
                source_counter[str(src)] += 1
                source_last_seen[str(src)] = last_seen

        target = alert.get("target_ip")
        if target:
            target_counter[str(target)] += 1
            target_last_seen[str(target)] = last_seen

    left_dist, severity_dist, activity = st.columns([1.08, .9, 1.1])

    with left_dist:
        st.markdown('<div class="soc-panel-title">Threat Type Distribution</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-panel-sub">Latest correlated security events</div>', unsafe_allow_html=True)
        nonzero = [(name, count) for name, count in threat_counts.items() if count]
        if nonzero:
            rows = []
            palette = ["#ff4d59", "#ffae32", "#1db6ff", "#a46cff", "#21e0b1", "#ff6aa5", "#8ba6b9"]
            for idx, (name, count) in enumerate(threat_counts.items()):
                pct = round((count / total_alerts) * 100) if total_alerts else 0
                rows.append(f'<div class="legend-row"><span><i style="background:{palette[idx]}"></i>{html.escape(name)}</span><b>{count} ({pct}%)</b></div>')
            dominant = palette[0] if total_alerts else "#183444"
            st.markdown(
                f'''<div class="dist-card"><div class="donut donut-threat" style="--p:{dominant}"><div><b>{total_alerts}</b><span>Total Alerts</span></div></div><div class="legend">{"".join(rows)}</div></div>''',
                unsafe_allow_html=True,
            )
        else:
            st.markdown('<div class="empty-soc">No threat distribution yet. Run a PCAP analysis.</div>', unsafe_allow_html=True)

    with severity_dist:
        st.markdown('<div class="soc-panel-title">Severity Distribution</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-panel-sub">Risk levels from latest analysis</div>', unsafe_allow_html=True)
        sev_rows = []
        sev_palette = {"CRITICAL":"#ff4d59", "HIGH":"#ff8d32", "MEDIUM":"#ffc333", "LOW":"#20dfaa"}
        for name in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts[name]
            pct = round((count / total_alerts) * 100) if total_alerts else 0
            sev_rows.append(f'<div class="legend-row"><span><i style="background:{sev_palette[name]}"></i>{name.title()}</span><b>{count} ({pct}%)</b></div>')
        st.markdown(
            f'''<div class="dist-card"><div class="donut donut-severity"><div><b>{total_alerts}</b><span>Total</span></div></div><div class="legend">{"".join(sev_rows)}</div></div>''',
            unsafe_allow_html=True,
        )

    with activity:
        st.markdown('<div class="soc-panel-title">Investigation Snapshot</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-panel-sub">Latest capture/session activity</div>', unsafe_allow_html=True)
        st.markdown(
            f'''<div class="activity-card">
                <div class="activity-grid">
                    <div><b>{analyzed_flows}</b><span>Flows Analyzed</span></div>
                    <div><b class="danger">{total_alerts}</b><span>Alerts Detected</span></div>
                    <div><b>{len(source_counter)}</b><span>Source IPs</span></div>
                    <div><b>{len(target_counter)}</b><span>Target IPs</span></div>
                </div>
                <div class="activity-note"><span class="live-dot"></span> Hybrid detection engines ready</div>
            </div>''',
            unsafe_allow_html=True,
        )

    engine_left, ip_right = st.columns([1.55, .9])
    with engine_left:
        st.markdown('<div class="soc-panel-title gap-top">Detection Engine Results</div>', unsafe_allow_html=True)
        engine_rows = pd.DataFrame({
            "Detection Engine": ["🧠 XGBoost ML IDS", "👥 Behavioral IDS", "🔍 Payload Inspection", "🔗 Correlation Engine"],
            "Result": [
                f"{report.get('ml_attack_flows', 0)} malicious flow(s)",
                f"{report.get('behavioral_alerts', 0)} alert(s)",
                f"{report.get('web_alerts', 0)} web payload alert(s)",
                final_decision,
            ],
            "Interpretation": [
                "Flow-level ML classification",
                "Cross-flow behavioral analysis",
                "HTTP payload inspection",
                "Final correlated security decision",
            ],
            "Status": [
                "ALERT" if report.get("ml_attack_flows", 0) else "BENIGN",
                "ALERT" if report.get("behavioral_alerts", 0) else "BENIGN",
                "ALERT" if report.get("web_alerts", 0) else "BENIGN",
                final_decision,
            ],
        })
        st.dataframe(engine_rows, use_container_width=True, hide_index=True)

    with ip_right:
        st.markdown('<div class="soc-panel-title gap-top">Top Source IPs <span class="small-muted">(by alerts)</span></div>', unsafe_allow_html=True)
        if source_counter:
            src_rows = [{"Source IP": ip, "Alerts": count, "Last Seen": source_last_seen.get(ip, "Unknown")} for ip, count in source_counter.most_common(4)]
            st.dataframe(pd.DataFrame(src_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("No source alert data yet.")
        st.markdown('<div class="soc-panel-title mini-gap">Top Target IPs <span class="small-muted">(by alerts)</span></div>', unsafe_allow_html=True)
        if target_counter:
            dst_rows = [{"Target IP": ip, "Alerts": count, "Last Seen": target_last_seen.get(ip, "Unknown")} for ip, count in target_counter.most_common(4)]
            st.dataframe(pd.DataFrame(dst_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("No target alert data yet.")

    st.markdown('<div class="soc-panel-title gap-top">Recent Security Alerts</div>', unsafe_allow_html=True)
    if alerts:
        recent_cols = st.columns(min(3, len(alerts)))
        for idx, alert in enumerate(alerts[:3]):
            sev = str(alert.get("severity", "MEDIUM")).upper()
            attack = html.escape(str(alert.get("attack_type", "Security Alert")))
            src = html.escape(str(alert.get("source_ip", "Unknown")))
            dst = html.escape(str(alert.get("target_ip", "Unknown")))
            port = alert.get("target_port")
            target = f"{dst}:{port}" if port is not None else dst
            reason = html.escape(str(alert.get("reason", "Suspicious activity detected")))
            seen = html.escape(str(alert.get("first_seen", "Unknown")))
            css_sev = sev.lower() if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "medium"
            with recent_cols[idx]:
                st.markdown(
                    f'''<div class="recent-alert recent-{css_sev}">
                        <div class="recent-head"><span class="recent-icon">⚠</span><b>{attack}</b><small>{seen}</small></div>
                        <p>{reason}</p>
                        <div class="recent-route"><code>{src}</code><span>→</span><code>{target}</code></div>
                        <div class="sev-badge sev-{css_sev}">{sev}</div>
                    </div>''',
                    unsafe_allow_html=True,
                )
    else:
        st.markdown('<div class="empty-soc wide">No recent security alerts. Open PCAP Analyzer and run a capture to populate this dashboard.</div>', unsafe_allow_html=True)


## =========================================================
# PAGE 2: TRAFFIC ANALYZER
# =========================================================

elif page == "Traffic Analyzer":'''

_pattern = r'if page == "Security Dashboard":.*?## =========================================================\n# PAGE 2: TRAFFIC ANALYZER\n# =========================================================\n\nelif page == "Traffic Analyzer":'
_source, replacements = re.subn(_pattern, _dashboard, _source, count=1, flags=re.S)
if replacements != 1:
    raise RuntimeError("Could not apply Security Dashboard presentation replacement")

# ---------------------------------------------------------------------
# Navigation adapter — card UI, Security Dashboard first, PCAP second.
# ---------------------------------------------------------------------
_original_radio = st.radio
_NAV_ITEMS = {
    "🛡️  Security Dashboard": "Security Dashboard",
    "🔗  PCAP Analyzer": "Traffic Analyzer",
    "📄  CSV Analyzer": "Traffic Analyzer",
    "📁  Batch Analysis": "Batch Detection",
    "📊  Model Performance": "Model Performance",
}


def _navigation_radio(label, options, *args, **kwargs):
    options = list(options)
    if label == "Navigation" and "Traffic Analyzer" in options:
        selected = _original_radio(label, list(_NAV_ITEMS.keys()), *args, **kwargs)
        if "PCAP Analyzer" in selected:
            st.session_state["_ai_ids_input_mode"] = "Upload PCAP / PCAPNG"
        elif "CSV Analyzer" in selected:
            st.session_state["_ai_ids_input_mode"] = "Upload CSV"
        else:
            st.session_state.pop("_ai_ids_input_mode", None)
        return _NAV_ITEMS[selected]

    if label == "Choose traffic input":
        forced_mode = st.session_state.get("_ai_ids_input_mode")
        if forced_mode in {"Upload PCAP / PCAPNG", "Upload CSV"}:
            return forced_mode
        portable_options = [item for item in ["Upload PCAP / PCAPNG", "Upload CSV"] if item in options]
        return _original_radio(label, portable_options, *args, **kwargs)

    return _original_radio(label, options, *args, **kwargs)


st.radio = _navigation_radio
exec(compile(_source, str(_CORE_PATH), "exec"), globals())

# ---------------------------------------------------------------------
# Final visual layer — intentionally presentation-only.
# ---------------------------------------------------------------------
st.markdown(
    """
    <style>
    :root{
        --bg:#020d16; --panel:#061b28; --panel2:#082230; --line:rgba(57,198,217,.19);
        --cyan:#25ddf5; --cyan2:#18bfff; --teal:#21e0b1; --text:#eef9fc; --muted:#7e9ca8;
        --red:#ff4d59; --orange:#ff9e32; --amber:#ffc63d; --purple:#a86dff;
    }
    .stApp{
        background:
          radial-gradient(circle at 62% -8%,rgba(10,129,191,.14),transparent 30%),
          radial-gradient(circle at 100% 0%,rgba(20,224,177,.07),transparent 26%),
          linear-gradient(180deg,#020d16 0%,#051622 58%,#03101a 100%)!important;
    }
    .block-container{max-width:1660px!important;padding-top:.65rem!important;padding-bottom:2rem!important}

    section[data-testid="stSidebar"]{
        background:linear-gradient(180deg,#020c15 0%,#041622 62%,#03111b 100%)!important;
        border-right:1px solid rgba(47,196,220,.20)!important;
    }
    section[data-testid="stSidebar"]>div{padding-top:1.15rem!important}
    .brand{padding:4px 6px 21px!important;margin-bottom:18px!important}
    .brand-icon{width:53px!important;height:53px!important;border-radius:14px!important;box-shadow:0 0 30px rgba(31,220,240,.22)!important}
    .brand-title{font-size:22px!important;background:linear-gradient(90deg,#67ecff,#45f1c2)!important;-webkit-background-clip:text!important;background-clip:text!important}
    .brand-subtitle{font-size:10.5px!important;color:#7e9da9!important}

    /* Remove actual radio circles across Streamlit versions. */
    section[data-testid="stSidebar"] [role="radiogroup"]{gap:10px!important}
    section[data-testid="stSidebar"] label[data-baseweb="radio"]>div:first-child,
    section[data-testid="stSidebar"] [role="radiogroup"] label>div:first-child,
    section[data-testid="stSidebar"] [role="radiogroup"] input[type="radio"],
    section[data-testid="stSidebar"] [role="radiogroup"] [data-testid="stRadio"] svg{
        display:none!important;visibility:hidden!important;width:0!important;margin:0!important;padding:0!important
    }
    section[data-testid="stSidebar"] [role="radiogroup"] label{
        min-height:64px!important;padding:15px 16px!important;border-radius:13px!important;
        border:1px solid rgba(69,159,183,.25)!important;
        background:linear-gradient(145deg,rgba(6,25,37,.96),rgba(4,18,28,.98))!important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.015),0 8px 22px rgba(0,0,0,.16)!important;
        transition:.18s ease!important;
    }
    section[data-testid="stSidebar"] [role="radiogroup"] label:hover{
        transform:translateY(-1px)!important;border-color:rgba(36,222,239,.48)!important;
        background:linear-gradient(145deg,rgba(7,42,56,.98),rgba(5,27,39,.98))!important
    }
    section[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked),
    section[data-testid="stSidebar"] [role="radiogroup"] label[aria-checked="true"]{
        border-color:#24e3ef!important;
        background:linear-gradient(135deg,rgba(8,72,84,.98),rgba(6,41,52,.98))!important;
        box-shadow:0 0 22px rgba(36,227,239,.22),inset 0 0 22px rgba(28,221,218,.07)!important
    }
    section[data-testid="stSidebar"] [role="radiogroup"] label p{font-size:13px!important;font-weight:800!important;color:#edfafd!important}

    .soc-page-title{font-size:35px;font-weight:900;line-height:1.04;letter-spacing:-1px;color:#edfaff;margin-top:4px}
    .soc-page-subtitle{font-size:13px;color:#82a4b0;margin:6px 0 17px}
    .soc-panel-title{font-size:14px;font-weight:850;color:#27e5ef;margin:15px 0 0;padding:0 2px}
    .soc-panel-sub{font-size:10.5px;color:#74929e;margin:3px 0 9px;padding:0 2px}
    .gap-top{margin-top:20px}.mini-gap{margin-top:14px}.small-muted{font-size:10px;font-weight:500;color:#7896a2}

    .metric-card{min-height:123px!important;padding:18px!important;border-radius:12px!important;background:linear-gradient(145deg,rgba(6,27,39,.96),rgba(5,20,30,.98))!important;border:1px solid rgba(67,169,190,.30)!important;box-shadow:0 10px 28px rgba(0,0,0,.20)!important}
    .metric-label{font-size:10px!important;letter-spacing:.7px!important}.metric-value{font-size:27px!important;margin-top:9px!important}.metric-note{font-size:10px!important;margin-top:6px!important}
    .metric-accent-red{border-top:1px solid rgba(255,77,89,.85)!important;box-shadow:inset 0 2px 0 rgba(255,77,89,.45),0 10px 28px rgba(0,0,0,.2)!important}
    .metric-accent-green{border-top:1px solid rgba(33,224,177,.85)!important;box-shadow:inset 0 2px 0 rgba(33,224,177,.42),0 10px 28px rgba(0,0,0,.2)!important}
    .metric-accent-blue{border-top:1px solid rgba(37,221,245,.85)!important;box-shadow:inset 0 2px 0 rgba(37,221,245,.42),0 10px 28px rgba(0,0,0,.2)!important}
    .metric-accent-purple{border-top:1px solid rgba(168,109,255,.85)!important;box-shadow:inset 0 2px 0 rgba(168,109,255,.42),0 10px 28px rgba(0,0,0,.2)!important}
    .metric-accent-amber{border-top:1px solid rgba(255,198,61,.85)!important;box-shadow:inset 0 2px 0 rgba(255,198,61,.42),0 10px 28px rgba(0,0,0,.2)!important}

    .dist-card,.activity-card{min-height:220px;border-radius:12px;border:1px solid var(--line);background:linear-gradient(145deg,rgba(5,27,39,.96),rgba(4,19,28,.98));padding:16px;display:flex;align-items:center;gap:18px;box-shadow:0 10px 26px rgba(0,0,0,.16)}
    .donut{width:142px;height:142px;min-width:142px;border-radius:50%;display:grid;place-items:center;position:relative;background:conic-gradient(#ff4d59 0 27%,#ffae32 27% 48%,#1db6ff 48% 64%,#a46cff 64% 76%,#21e0b1 76% 88%,#ff6aa5 88% 100%)}
    .donut-severity{background:conic-gradient(#ff4d59 0 24%,#ff8d32 24% 62%,#ffc333 62% 86%,#20dfaa 86% 100%)}
    .donut:after{content:"";position:absolute;inset:22px;border-radius:50%;background:#061b28;border:1px solid rgba(255,255,255,.03)}
    .donut>div{z-index:2;text-align:center;display:flex;flex-direction:column}.donut b{font-size:25px;color:#effbfe}.donut span{font-size:10px;color:#a2b8c1;margin-top:2px}
    .legend{flex:1;min-width:0}.legend-row{display:flex;justify-content:space-between;gap:12px;font-size:10px;color:#a4b8c0;margin:6px 0}.legend-row span{display:flex;align-items:center;gap:7px;min-width:0}.legend-row i{width:9px;height:9px;border-radius:50%;display:inline-block;flex:none}.legend-row b{color:#dcebef;font-weight:650}
    .activity-card{display:block}.activity-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.activity-grid div{padding:16px;border-radius:10px;background:rgba(8,40,54,.62);border:1px solid rgba(62,175,195,.15)}.activity-grid b{display:block;font-size:23px;color:#22e2ee}.activity-grid b.danger{color:#ff595f}.activity-grid span{display:block;font-size:9px;color:#7899a4;margin-top:3px}.activity-note{margin-top:12px;font-size:10px;color:#8ba5ae}.live-dot{display:inline-block;width:7px;height:7px;background:#21e0a8;border-radius:50%;box-shadow:0 0 12px #21e0a8;margin-right:7px}
    .empty-soc{height:220px;border-radius:12px;border:1px dashed rgba(54,180,200,.25);background:rgba(5,26,37,.65);display:grid;place-items:center;text-align:center;color:#7998a3;font-size:11px;padding:20px}.empty-soc.wide{height:auto;min-height:80px;margin-top:8px}

    [data-testid="stDataFrame"]{border-radius:11px!important;border:1px solid rgba(57,177,198,.22)!important;overflow:hidden!important;background:#061b28!important}
    [data-testid="stDataFrame"] *{font-size:11px!important}

    .recent-alert{min-height:150px;border-radius:12px;background:linear-gradient(145deg,rgba(6,27,39,.97),rgba(5,19,28,.99));border:1px solid rgba(73,166,185,.22);padding:14px 15px;position:relative;box-shadow:0 10px 24px rgba(0,0,0,.15)}
    .recent-critical{border-color:rgba(255,77,89,.80);box-shadow:inset 0 0 22px rgba(255,77,89,.05)}.recent-high{border-color:rgba(255,145,48,.75)}.recent-medium{border-color:rgba(255,198,61,.72)}.recent-low{border-color:rgba(33,224,177,.62)}
    .recent-head{display:grid;grid-template-columns:32px 1fr auto;align-items:center;gap:8px}.recent-icon{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;background:rgba(255,83,91,.12);color:#ff5d65}.recent-head b{font-size:12px;color:#eef9fc}.recent-head small{font-size:8.5px;color:#7e99a4}.recent-alert p{font-size:9.5px;color:#9bb0b8;line-height:1.35;margin:10px 0}.recent-route{display:flex;align-items:center;gap:8px;font-size:9px;color:#8ba6b0}.recent-route code{background:transparent!important;color:#d4e8ed!important;padding:0!important}.sev-badge{display:inline-block;margin-top:11px;padding:5px 10px;border-radius:5px;font-size:9px;font-weight:900;letter-spacing:.3px}.sev-critical{background:rgba(255,77,89,.18);color:#ff666f;border:1px solid rgba(255,77,89,.35)}.sev-high{background:rgba(255,145,48,.18);color:#ffae4a;border:1px solid rgba(255,145,48,.34)}.sev-medium{background:rgba(255,198,61,.17);color:#ffd158;border:1px solid rgba(255,198,61,.32)}.sev-low{background:rgba(33,224,177,.16);color:#49edbf;border:1px solid rgba(33,224,177,.30)}

    [data-testid="stFileUploader"]{border:1px dashed rgba(37,221,245,.42)!important;border-radius:13px!important;background:linear-gradient(145deg,rgba(5,31,43,.91),rgba(4,21,30,.97))!important;padding:10px!important}
    [data-testid="stFileUploaderDropzone"]{background:transparent!important;border:none!important}
    .stButton>button,.stDownloadButton>button{border-radius:10px!important;min-height:45px!important;font-weight:850!important}

    @media(max-width:1050px){.soc-page-title{font-size:28px}.dist-card{display:block}.donut{margin:0 auto 14px}.activity-grid{grid-template-columns:1fr 1fr}.metric-value{font-size:24px!important}}
    </style>
    """,
    unsafe_allow_html=True,
)
