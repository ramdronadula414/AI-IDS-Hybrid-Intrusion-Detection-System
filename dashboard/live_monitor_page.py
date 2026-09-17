"""Streamlit page for persistent AI-IDS live monitoring data."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
import html
import sqlite3

import pandas as pd
import streamlit as st

from src.live_event_store import LiveEventStore


def _friendly_time(value: object) -> str:
    if not value:
        return "Unknown"
    text = str(value)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return text


def _latest_session(store: LiveEventStore) -> dict | None:
    if not store.db_path.exists():
        return None
    with sqlite3.connect(store.db_path, timeout=5.0) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT session_id, started_at, ended_at, interface,
                   window_seconds, bpf_filter, status
            FROM live_sessions
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
    return dict(row) if row else None


def _metric(title: str, value: object, note: str, accent: str) -> None:
    safe_title = html.escape(str(title))
    safe_value = html.escape(str(value))
    safe_note = html.escape(str(note))
    st.markdown(
        f"<div class='metric-card {accent}'><div class='metric-label'>{safe_title}</div>"
        f"<div class='metric-value'>{safe_value}</div><div class='metric-note'>{safe_note}</div></div>",
        unsafe_allow_html=True,
    )


def render_live_monitor_page() -> None:
    """Render the dashboard reader for Step 5 SQLite live-event storage."""
    store = LiveEventStore()

    st.markdown(
        '<div class="soc-page-title">Live Network Monitor</div>'
        '<div class="soc-page-subtitle">Persistent view of continuously captured and correlated network activity</div>',
        unsafe_allow_html=True,
    )

    top_left, top_right = st.columns([4, 1])
    with top_left:
        st.caption(f"Event database: {store.db_path}")
    with top_right:
        if st.button("↻ Refresh", use_container_width=True, key="refresh_live_monitor"):
            st.rerun()

    try:
        overview = store.overview()
        windows = store.recent_windows(limit=100)
        alerts = store.recent_alerts(limit=100)
        session = _latest_session(store)
    except Exception as exc:
        st.error(f"Unable to read live monitoring database: {exc}")
        return

    latest = windows[0] if windows else {}
    decision = str(latest.get("final_decision") or "WAITING")
    severity = str(latest.get("severity") or "NORMAL")
    attack_type = str(latest.get("attack_type") or "None")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        _metric(
            "Current Status",
            decision,
            f"Latest window: {attack_type}",
            "metric-accent-red" if decision == "ATTACK" else "metric-accent-green",
        )
    with m2:
        _metric(
            "Severity",
            severity,
            "Latest correlated risk level",
            "metric-accent-red" if severity == "CRITICAL" else "metric-accent-amber" if severity in {"HIGH", "MEDIUM"} else "metric-accent-green",
        )
    with m3:
        _metric(
            "Stored Alerts",
            f"{overview['total_alerts']:,}",
            f"{overview['attack_windows']:,} attack window(s)",
            "metric-accent-purple",
        )
    with m4:
        _metric(
            "Analyzed Flows",
            f"{overview['total_flows']:,}",
            f"{overview['total_packets']:,} packets persisted",
            "metric-accent-blue",
        )

    session_col, latest_col = st.columns([1, 1.45])
    with session_col:
        st.markdown('<div class="soc-panel-title gap-top">Monitoring Session</div>', unsafe_allow_html=True)
        if session:
            status = str(session.get("status") or "UNKNOWN")
            status_icon = "●" if status == "RUNNING" else "○"
            st.markdown(
                f"**{status_icon} {status}**  \n"
                f"Interface: `{session.get('interface', 'Unknown')}`  \n"
                f"Window: `{session.get('window_seconds', 'Unknown')} s`  \n"
                f"Filter: `{session.get('bpf_filter') or 'None'}`  \n"
                f"Started: `{_friendly_time(session.get('started_at'))}`  \n"
                f"Ended: `{_friendly_time(session.get('ended_at')) if session.get('ended_at') else '—'}`"
            )
        else:
            st.info("No live-monitor session has been stored yet.")

    with latest_col:
        st.markdown('<div class="soc-panel-title gap-top">Latest Analyzed Window</div>', unsafe_allow_html=True)
        if latest:
            latest_table = pd.DataFrame(
                [
                    {
                        "Window": latest.get("sequence"),
                        "Packets": latest.get("packet_count"),
                        "Flows": latest.get("flow_count"),
                        "Decision": latest.get("final_decision"),
                        "Severity": latest.get("severity"),
                        "Attack": latest.get("attack_type"),
                        "Engine": latest.get("detection_source"),
                        "Analyzed": _friendly_time(latest.get("analyzed_at")),
                    }
                ]
            )
            st.dataframe(latest_table, use_container_width=True, hide_index=True)
            reason = latest.get("reason")
            if reason:
                st.caption(str(reason))
        else:
            st.info("No analyzed live windows are available yet.")

    threat_counts = Counter()
    severity_counts = Counter()
    for alert in alerts:
        threat_counts[str(alert.get("attack_type") or "Unknown")] += 1
        severity_counts[str(alert.get("severity") or "Unknown").upper()] += 1

    dist_left, dist_right = st.columns(2)
    with dist_left:
        st.markdown('<div class="soc-panel-title gap-top">Live Threat Distribution</div>', unsafe_allow_html=True)
        if threat_counts:
            threat_df = pd.DataFrame(
                [{"Attack Type": name, "Alerts": count} for name, count in threat_counts.most_common()]
            ).set_index("Attack Type")
            st.bar_chart(threat_df)
        else:
            st.caption("No live threats have been stored.")

    with dist_right:
        st.markdown('<div class="soc-panel-title gap-top">Live Severity Distribution</div>', unsafe_allow_html=True)
        if severity_counts:
            severity_df = pd.DataFrame(
                [{"Severity": name, "Alerts": count} for name, count in severity_counts.items()]
            ).set_index("Severity")
            st.bar_chart(severity_df)
        else:
            st.caption("No severity events have been stored.")

    st.markdown('<div class="soc-panel-title gap-top">Recent Live Alerts</div>', unsafe_allow_html=True)
    if alerts:
        alert_rows = []
        for alert in alerts[:50]:
            target = str(alert.get("target_ip") or "Unknown")
            if alert.get("target_port") not in {None, "None", ""}:
                target += f":{alert.get('target_port')}"
            alert_rows.append(
                {
                    "Time": _friendly_time(alert.get("created_at")),
                    "Severity": alert.get("severity"),
                    "Attack Type": alert.get("attack_type"),
                    "Engine": alert.get("detection_engine"),
                    "Source IP": alert.get("source_ip"),
                    "Target": target,
                    "Notified": "Yes" if alert.get("notification_emitted") else "No",
                    "Reason": alert.get("reason"),
                }
            )
        st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, hide_index=True)
    else:
        st.markdown(
            '<div class="empty-soc wide">No live security alerts have been persisted yet.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="soc-panel-title gap-top">Recent Analyzed Windows</div>', unsafe_allow_html=True)
    if windows:
        window_rows = []
        for item in windows[:50]:
            window_rows.append(
                {
                    "Time": _friendly_time(item.get("analyzed_at")),
                    "Session": str(item.get("session_id", ""))[:8],
                    "Window": item.get("sequence"),
                    "Packets": item.get("packet_count"),
                    "Flows": item.get("flow_count"),
                    "Decision": item.get("final_decision"),
                    "Severity": item.get("severity"),
                    "Attack": item.get("attack_type"),
                    "Detection Source": item.get("detection_source"),
                }
            )
        st.dataframe(pd.DataFrame(window_rows), use_container_width=True, hide_index=True)

    with st.expander("Run the live monitor from Kali"):
        st.code(
            "python src/live_monitor.py \\\n--interface eth0 \\\n--window 10 \\\n--filter \"tcp or udp\"",
            language="bash",
        )
        st.caption(
            "The monitor writes completed windows and alerts into the SQLite event database. "
            "This page reads that shared store; Step 7 will add automatic dashboard refresh."
        )
