"""Streamlit page for persistent AI-IDS live monitoring data.

Includes auto-refreshing live telemetry and dashboard-managed notification
configuration for console, desktop, Telegram, Discord and SMTP email alerts.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import html
import sqlite3

import pandas as pd
import streamlit as st

from src.live_event_store import LiveEventStore
from src.notification_config import load_notification_config, save_notification_config
from src.notification_engine import notify


DEFAULT_REFRESH_SECONDS = 3
REFRESH_OPTIONS = [2, 3, 5, 10, 15, 30]
CHANNEL_OPTIONS = ["console", "desktop", "telegram", "discord", "email"]
SEVERITY_OPTIONS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


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


def _render_notification_configuration() -> None:
    config = load_notification_config()
    configured_channels = [
        channel for channel in config.get("channels", ["console"])
        if channel in CHANNEL_OPTIONS
    ] or ["console"]
    telegram = config.get("telegram", {})
    discord = config.get("discord", {})
    email = config.get("email", {})

    st.markdown('<div class="soc-panel-title gap-top">Threat Notification Configuration</div>', unsafe_allow_html=True)
    st.caption(
        "Choose where live threat alerts should be delivered. Settings are stored locally on this AI-IDS host, "
        "are excluded from Git, and are read dynamically by the running live monitor."
    )

    with st.form("notification_configuration_form", clear_on_submit=False):
        channels = st.multiselect(
            "Notification channels",
            CHANNEL_OPTIONS,
            default=configured_channels,
            format_func=lambda value: {
                "console": "Terminal / Console",
                "desktop": "Desktop Notification",
                "telegram": "Telegram",
                "discord": "Discord Webhook",
                "email": "Email (SMTP)",
            }[value],
        )

        current_minimum = str(config.get("minimum_severity", "LOW")).upper()
        if current_minimum not in SEVERITY_OPTIONS:
            current_minimum = "LOW"
        minimum_severity = st.selectbox(
            "Minimum severity to notify",
            SEVERITY_OPTIONS,
            index=SEVERITY_OPTIONS.index(current_minimum),
            help="For example, HIGH sends HIGH and CRITICAL alerts only.",
        )

        if "desktop" in channels:
            st.info("Desktop notifications use `notify-send` on the machine running AI-IDS.")

        if "telegram" in channels:
            st.markdown("##### Telegram")
            tg_left, tg_right = st.columns(2)
            with tg_left:
                telegram_token = st.text_input(
                    "Bot Token",
                    value=str(telegram.get("bot_token", "")),
                    type="password",
                    help="Create a Telegram bot and paste its bot token here.",
                )
            with tg_right:
                telegram_chat_id = st.text_input(
                    "Chat ID",
                    value=str(telegram.get("chat_id", "")),
                )
        else:
            telegram_token = str(telegram.get("bot_token", ""))
            telegram_chat_id = str(telegram.get("chat_id", ""))

        if "discord" in channels:
            st.markdown("##### Discord")
            discord_webhook = st.text_input(
                "Discord Webhook URL",
                value=str(discord.get("webhook_url", "")),
                type="password",
            )
        else:
            discord_webhook = str(discord.get("webhook_url", ""))

        if "email" in channels:
            st.markdown("##### Email / SMTP")
            e1, e2 = st.columns(2)
            with e1:
                smtp_host = st.text_input(
                    "SMTP Host",
                    value=str(email.get("smtp_host", "smtp.gmail.com")),
                )
                smtp_username = st.text_input(
                    "SMTP Username",
                    value=str(email.get("username", "")),
                )
                email_from = st.text_input(
                    "From Email",
                    value=str(email.get("from_address", "")),
                )
            with e2:
                smtp_port = st.number_input(
                    "SMTP Port",
                    min_value=1,
                    max_value=65535,
                    value=int(email.get("smtp_port", 587) or 587),
                    step=1,
                )
                smtp_password = st.text_input(
                    "SMTP / App Password",
                    value=str(email.get("password", "")),
                    type="password",
                )
                email_to = st.text_input(
                    "Recipient Email(s)",
                    value=str(email.get("to_addresses", "")),
                    help="Separate multiple recipients with commas.",
                )
            tls_left, tls_right = st.columns(2)
            with tls_left:
                smtp_ssl = st.checkbox(
                    "Use SSL",
                    value=bool(email.get("use_ssl", False)),
                )
            with tls_right:
                smtp_starttls = st.checkbox(
                    "Use STARTTLS",
                    value=bool(email.get("use_starttls", True)),
                )
        else:
            smtp_host = str(email.get("smtp_host", "smtp.gmail.com"))
            smtp_port = int(email.get("smtp_port", 587) or 587)
            smtp_username = str(email.get("username", ""))
            smtp_password = str(email.get("password", ""))
            email_from = str(email.get("from_address", ""))
            email_to = str(email.get("to_addresses", ""))
            smtp_ssl = bool(email.get("use_ssl", False))
            smtp_starttls = bool(email.get("use_starttls", True))

        save_clicked = st.form_submit_button(
            "Save Notification Configuration",
            use_container_width=True,
        )

    if save_clicked:
        if not channels:
            st.error("Select at least one notification channel.")
        elif "telegram" in channels and (not telegram_token.strip() or not telegram_chat_id.strip()):
            st.error("Telegram requires both Bot Token and Chat ID.")
        elif "discord" in channels and not discord_webhook.strip():
            st.error("Discord requires a webhook URL.")
        elif "email" in channels and (
            not smtp_host.strip() or not email_from.strip() or not email_to.strip()
        ):
            st.error("Email requires SMTP Host, From Email and Recipient Email(s).")
        elif smtp_ssl and smtp_starttls:
            st.error("Choose SSL or STARTTLS for SMTP, not both.")
        else:
            saved = {
                "channels": channels,
                "minimum_severity": minimum_severity,
                "telegram": {
                    "bot_token": telegram_token.strip(),
                    "chat_id": telegram_chat_id.strip(),
                },
                "discord": {
                    "webhook_url": discord_webhook.strip(),
                },
                "email": {
                    "smtp_host": smtp_host.strip(),
                    "smtp_port": int(smtp_port),
                    "username": smtp_username.strip(),
                    "password": smtp_password,
                    "from_address": email_from.strip(),
                    "to_addresses": email_to.strip(),
                    "use_ssl": bool(smtp_ssl),
                    "use_starttls": bool(smtp_starttls),
                },
            }
            path = save_notification_config(saved)
            st.success(f"Notification configuration saved to {path}")

    test_left, test_right = st.columns([1, 3])
    with test_left:
        test_clicked = st.button(
            "Send Test Notification",
            use_container_width=True,
            key="send_test_live_notification",
        )
    with test_right:
        st.caption("The test uses the saved configuration and sends a CRITICAL test alert to every enabled channel.")

    if test_clicked:
        test_alert = {
            "severity": "CRITICAL",
            "attack_type": "AI-IDS Test Alert",
            "detection_engine": "Notification Configuration",
            "source_ip": "127.0.0.1",
            "target_ip": "Configured notification channel",
            "target_port": None,
            "reason": "This is a test notification generated from the AI-IDS dashboard.",
        }
        with st.spinner("Sending test notification..."):
            result = notify(test_alert)
        if result.succeeded:
            st.success("Delivered: " + ", ".join(result.succeeded))
        if result.failed:
            for channel, error in result.failed.items():
                st.error(f"{channel.title()} failed: {error}")
        if result.skipped:
            st.warning("Test notification was skipped by the configured severity threshold.")


def _render_live_data(store: LiveEventStore, auto_refresh: bool, refresh_seconds: int) -> None:
    """Render one snapshot from the shared SQLite event store."""
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

    status_left, status_right = st.columns([4, 1])
    with status_left:
        if auto_refresh:
            st.markdown(
                f"<span class='live-dot'></span> **LIVE** · refreshing every {refresh_seconds}s · "
                f"last dashboard update `{datetime.now().strftime('%H:%M:%S')}`",
                unsafe_allow_html=True,
            )
        else:
            st.caption(
                f"Automatic refresh paused · snapshot updated {datetime.now().strftime('%H:%M:%S')}"
            )
    with status_right:
        if st.button("↻ Refresh now", use_container_width=True, key="refresh_live_monitor_now"):
            st.rerun()

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        _metric(
            "Current Status", decision, f"Latest window: {attack_type}",
            "metric-accent-red" if decision == "ATTACK" else "metric-accent-green",
        )
    with m2:
        _metric(
            "Severity", severity, "Latest correlated risk level",
            "metric-accent-red" if severity == "CRITICAL" else "metric-accent-amber" if severity in {"HIGH", "MEDIUM"} else "metric-accent-green",
        )
    with m3:
        _metric(
            "Stored Alerts", f"{overview['total_alerts']:,}",
            f"{overview['attack_windows']:,} attack window(s)", "metric-accent-purple",
        )
    with m4:
        _metric(
            "Analyzed Flows", f"{overview['total_flows']:,}",
            f"{overview['total_packets']:,} packets persisted", "metric-accent-blue",
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
            latest_table = pd.DataFrame([{
                "Window": latest.get("sequence"),
                "Packets": latest.get("packet_count"),
                "Flows": latest.get("flow_count"),
                "Decision": latest.get("final_decision"),
                "Severity": latest.get("severity"),
                "Attack": latest.get("attack_type"),
                "Engine": latest.get("detection_source"),
                "Analyzed": _friendly_time(latest.get("analyzed_at")),
            }])
            st.dataframe(latest_table, use_container_width=True, hide_index=True)
            if latest.get("reason"):
                st.caption(str(latest.get("reason")))
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
            st.bar_chart(pd.DataFrame(
                [{"Attack Type": name, "Alerts": count} for name, count in threat_counts.most_common()]
            ).set_index("Attack Type"))
        else:
            st.caption("No live threats have been stored.")
    with dist_right:
        st.markdown('<div class="soc-panel-title gap-top">Live Severity Distribution</div>', unsafe_allow_html=True)
        if severity_counts:
            st.bar_chart(pd.DataFrame(
                [{"Severity": name, "Alerts": count} for name, count in severity_counts.items()]
            ).set_index("Severity"))
        else:
            st.caption("No severity events have been stored.")

    st.markdown('<div class="soc-panel-title gap-top">Recent Live Alerts</div>', unsafe_allow_html=True)
    if alerts:
        rows = []
        for alert in alerts[:50]:
            target = str(alert.get("target_ip") or "Unknown")
            if alert.get("target_port") not in {None, "None", ""}:
                target += f":{alert.get('target_port')}"
            rows.append({
                "Time": _friendly_time(alert.get("created_at")),
                "Severity": alert.get("severity"),
                "Attack Type": alert.get("attack_type"),
                "Engine": alert.get("detection_engine"),
                "Source IP": alert.get("source_ip"),
                "Target": target,
                "Notified": "Yes" if alert.get("notification_emitted") else "No",
                "Reason": alert.get("reason"),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.markdown('<div class="empty-soc wide">No live security alerts have been persisted yet.</div>', unsafe_allow_html=True)

    st.markdown('<div class="soc-panel-title gap-top">Recent Analyzed Windows</div>', unsafe_allow_html=True)
    if windows:
        rows = []
        for item in windows[:50]:
            rows.append({
                "Time": _friendly_time(item.get("analyzed_at")),
                "Session": str(item.get("session_id", ""))[:8],
                "Window": item.get("sequence"),
                "Packets": item.get("packet_count"),
                "Flows": item.get("flow_count"),
                "Decision": item.get("final_decision"),
                "Severity": item.get("severity"),
                "Attack": item.get("attack_type"),
                "Detection Source": item.get("detection_source"),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_live_monitor_page() -> None:
    """Render the auto-refreshing live monitor and notification setup."""
    store = LiveEventStore()

    st.markdown(
        '<div class="soc-page-title">Live Network Monitor</div>'
        '<div class="soc-page-subtitle">Continuously refreshed network security telemetry and live threat notifications</div>',
        unsafe_allow_html=True,
    )

    live_tab, notification_tab = st.tabs(["Live Analysis", "Notification Configuration"])

    with live_tab:
        control_left, control_mid, control_right = st.columns([3, 1, 1])
        with control_left:
            st.caption(f"Event database: {store.db_path}")
        with control_mid:
            auto_refresh = st.toggle(
                "Auto refresh", value=True, key="live_auto_refresh",
                help="Refresh only the live-data section without reloading the full dashboard.",
            )
        with control_right:
            refresh_seconds = st.selectbox(
                "Interval", REFRESH_OPTIONS,
                index=REFRESH_OPTIONS.index(DEFAULT_REFRESH_SECONDS),
                format_func=lambda value: f"{value} sec",
                key="live_refresh_seconds",
                disabled=not auto_refresh,
            )

        fragment_factory = getattr(st, "fragment", None)
        if callable(fragment_factory):
            run_every = f"{refresh_seconds}s" if auto_refresh else None
            live_fragment = fragment_factory(run_every=run_every)(_render_live_data)
            live_fragment(store, auto_refresh, refresh_seconds)
        else:
            st.warning(
                "This Streamlit version does not support fragment auto-refresh. "
                "Manual refresh remains available."
            )
            _render_live_data(store, False, refresh_seconds)

        with st.expander("Run the live monitor from Kali"):
            st.code(
                "python src/live_monitor.py \\\n--interface eth0 \\\n--window 10 \\\n--filter \"tcp or udp\"",
                language="bash",
            )
            st.caption(
                "Notification settings are loaded dynamically when an alert is sent, "
                "so most notification changes do not require restarting the live monitor."
            )

    with notification_tab:
        _render_notification_configuration()
