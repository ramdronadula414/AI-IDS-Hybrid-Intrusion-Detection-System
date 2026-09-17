"""AI-IDS live monitoring dashboard.

Provides three integrated views:
- auto-refreshing live analysis
- target/capture configuration
- threat notification configuration

Configuration widgets intentionally live outside Streamlit forms so dependent
fields update immediately when users change target types or notification
channels.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import html
import sqlite3

import pandas as pd
import streamlit as st

from src.live_capture import list_interfaces
from src.live_event_store import LiveEventStore
from src.monitoring_config import (
    PROTOCOLS,
    TARGET_TYPES,
    build_bpf_filter,
    load_monitoring_config,
    save_monitoring_config,
)
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
    st.markdown(
        f"<div class='metric-card {accent}'><div class='metric-label'>{html.escape(str(title))}</div>"
        f"<div class='metric-value'>{html.escape(str(value))}</div>"
        f"<div class='metric-note'>{html.escape(str(note))}</div></div>",
        unsafe_allow_html=True,
    )


def _section(title: str, subtitle: str = "") -> None:
    st.markdown(
        f"<div class='config-section-title'>{html.escape(title)}</div>"
        + (f"<div class='config-section-sub'>{html.escape(subtitle)}</div>" if subtitle else ""),
        unsafe_allow_html=True,
    )


def _render_live_data(store: LiveEventStore, auto_refresh: bool, refresh_seconds: int) -> None:
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
            st.caption(f"Automatic refresh paused · snapshot updated {datetime.now().strftime('%H:%M:%S')}")
    with status_right:
        if st.button("↻ Refresh now", use_container_width=True, key="refresh_live_monitor_now"):
            st.rerun()

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        _metric("Current Status", decision, f"Latest window: {attack_type}", "metric-accent-red" if decision == "ATTACK" else "metric-accent-green")
    with m2:
        _metric("Severity", severity, "Latest correlated risk level", "metric-accent-red" if severity == "CRITICAL" else "metric-accent-amber" if severity in {"HIGH", "MEDIUM"} else "metric-accent-green")
    with m3:
        _metric("Stored Alerts", f"{overview['total_alerts']:,}", f"{overview['attack_windows']:,} attack window(s)", "metric-accent-purple")
    with m4:
        _metric("Analyzed Flows", f"{overview['total_flows']:,}", f"{overview['total_packets']:,} packets persisted", "metric-accent-blue")

    session_col, latest_col = st.columns([1, 1.55])
    with session_col:
        _section("Monitoring Session")
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
        _section("Latest Analyzed Window")
        if latest:
            st.dataframe(
                pd.DataFrame([{
                    "Window": latest.get("sequence"),
                    "Packets": latest.get("packet_count"),
                    "Flows": latest.get("flow_count"),
                    "Decision": latest.get("final_decision"),
                    "Severity": latest.get("severity"),
                    "Attack": latest.get("attack_type"),
                    "Engine": latest.get("detection_source"),
                    "Analyzed": _friendly_time(latest.get("analyzed_at")),
                }]),
                use_container_width=True,
                hide_index=True,
            )
            if latest.get("reason"):
                st.caption(str(latest.get("reason")))
        else:
            st.info("No analyzed live windows are available yet.")

    threat_counts = Counter(str(a.get("attack_type") or "Unknown") for a in alerts)
    severity_counts = Counter(str(a.get("severity") or "Unknown").upper() for a in alerts)

    dist_left, dist_right = st.columns(2)
    with dist_left:
        _section("Live Threat Distribution")
        if threat_counts:
            st.bar_chart(pd.DataFrame(
                [{"Attack Type": name, "Alerts": count} for name, count in threat_counts.most_common()]
            ).set_index("Attack Type"))
        else:
            st.caption("No live threats have been stored.")
    with dist_right:
        _section("Live Severity Distribution")
        if severity_counts:
            st.bar_chart(pd.DataFrame(
                [{"Severity": name, "Alerts": count} for name, count in severity_counts.items()]
            ).set_index("Severity"))
        else:
            st.caption("No severity events have been stored.")

    _section("Recent Live Alerts")
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

    _section("Recent Analyzed Windows")
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


def _render_monitoring_configuration() -> None:
    config = load_monitoring_config()
    interfaces = list_interfaces()
    saved_interface = str(config.get("interface", "eth0"))
    if saved_interface and saved_interface not in interfaces:
        interfaces.insert(0, saved_interface)
    if not interfaces:
        interfaces = ["eth0"]

    st.markdown(
        "<div class='config-hero'><div class='config-hero-icon'>📡</div>"
        "<div><div class='config-hero-title'>Live Monitoring Configuration</div>"
        "<div class='config-hero-sub'>Choose exactly which traffic this local AI-IDS sensor should observe.</div></div></div>",
        unsafe_allow_html=True,
    )
    st.info(
        "The domain/IP field creates a passive capture filter only. The sensor must be positioned where the target traffic is visible; no website login password is required."
    )

    _section("Target", "Select a scope. The target field updates immediately when you change Target Type.")
    c1, c2 = st.columns(2)
    with c1:
        target_name = st.text_input(
            "Target Name",
            value=str(config.get("target_name", "Local Network")),
            placeholder="Production Website",
            key="monitor_target_name",
        )
        current_type = str(config.get("target_type", "Entire Interface"))
        if current_type not in TARGET_TYPES:
            current_type = "Entire Interface"
        target_type = st.selectbox(
            "Target Type",
            TARGET_TYPES,
            index=TARGET_TYPES.index(current_type),
            key="monitor_target_type",
        )
    with c2:
        interface = st.selectbox(
            "Sensor Interface",
            interfaces,
            index=interfaces.index(saved_interface) if saved_interface in interfaces else 0,
            key="monitor_interface",
            help="Traffic must pass through or be mirrored to this interface for the IDS to see it.",
        )
        if target_type == "IP Address":
            target_value = st.text_input(
                "IP Address",
                value=str(config.get("target_value", "")),
                placeholder="192.168.1.20",
                key="monitor_target_value_ip",
            )
        elif target_type == "Domain / Website":
            target_value = st.text_input(
                "Website / Domain",
                value=str(config.get("target_value", "")),
                placeholder="https://example.com or example.com",
                key="monitor_target_value_domain",
            )
        else:
            target_value = ""
            st.text_input(
                "Website / Domain / IP",
                value="Entire interface traffic",
                disabled=True,
                key="monitor_target_value_all",
            )

    _section("Capture Policy", "Control protocols, ports, capture duration and alert suppression.")
    p1, p2, p3 = st.columns([1.2, 1, 1])
    with p1:
        saved_protocols = [p for p in config.get("protocols", ["tcp", "udp"]) if p in PROTOCOLS]
        protocols = st.multiselect(
            "Protocols",
            PROTOCOLS,
            default=saved_protocols or ["tcp", "udp"],
            format_func=str.upper,
            key="monitor_protocols",
        )
        ports = st.text_input(
            "Ports (optional)",
            value=str(config.get("ports", "")),
            placeholder="80,443,22",
            key="monitor_ports",
            help="Leave empty to monitor all ports matching the target and protocol selection.",
        )
    with p2:
        window_seconds = st.number_input(
            "Capture Window (seconds)",
            min_value=2.0,
            max_value=300.0,
            value=float(config.get("window_seconds", 10.0)),
            step=1.0,
            key="monitor_window",
        )
        keep_pcaps = st.checkbox(
            "Keep captured PCAP windows",
            value=bool(config.get("keep_pcaps", False)),
            key="monitor_keep_pcaps",
        )
    with p3:
        cooldown_seconds = st.number_input(
            "Alert Cooldown (seconds)",
            min_value=0.0,
            max_value=3600.0,
            value=float(config.get("cooldown_seconds", 60.0)),
            step=5.0,
            key="monitor_cooldown",
        )
        st.caption("Cooldown prevents duplicate notifications for repeated matching alerts.")

    candidate = {
        "target_name": target_name.strip() or "Unnamed Target",
        "target_type": target_type,
        "target_value": target_value.strip(),
        "interface": interface,
        "protocols": protocols,
        "ports": ports.strip(),
        "window_seconds": float(window_seconds),
        "cooldown_seconds": float(cooldown_seconds),
        "keep_pcaps": bool(keep_pcaps),
    }

    action_left, action_right = st.columns(2)
    with action_left:
        validate_clicked = st.button("🔎 Validate Target", use_container_width=True, key="validate_monitoring_target")
    with action_right:
        save_clicked = st.button("💾 Save Monitoring Configuration", use_container_width=True, key="save_monitoring_configuration")

    if validate_clicked or save_clicked:
        try:
            bpf_filter, resolved = build_bpf_filter(candidate)
            st.session_state["monitoring_preview"] = {
                "filter": bpf_filter,
                "resolved": resolved,
                "config": candidate,
            }
            if save_clicked:
                path = save_monitoring_config(candidate)
                st.success(f"Monitoring configuration saved: {path}")
            else:
                st.success("Target configuration is valid.")
        except Exception as exc:
            st.session_state.pop("monitoring_preview", None)
            st.error(f"Monitoring configuration is invalid: {exc}")

    preview = st.session_state.get("monitoring_preview")
    if preview:
        resolved = preview.get("resolved", {})
        bpf_filter = preview.get("filter")
        st.markdown("---")
        _section("Resolved Monitoring Target", "This is the actual passive traffic selector that will be used by the sensor.")
        r1, r2 = st.columns(2)
        with r1:
            st.write(f"**Target:** `{resolved.get('normalized_target', 'Unknown')}`")
            addresses = resolved.get("addresses", []) or []
            st.write("**Resolved address(es):** " + (", ".join(f"`{item}`" for item in addresses) if addresses else "Entire interface"))
        with r2:
            st.write(f"**Interface:** `{candidate['interface']}`")
            st.write(f"**BPF filter:** `{bpf_filter or 'None'}`")

        command = [
            "python src/live_monitor.py",
            f"--interface {candidate['interface']}",
            f"--window {candidate['window_seconds']:g}",
            f"--cooldown {candidate['cooldown_seconds']:g}",
        ]
        if bpf_filter:
            command.append(f"--filter \"{bpf_filter}\"")
        if candidate.get("keep_pcaps"):
            command.append("--keep-pcaps")
        st.code(" \\\n  ".join(command), language="bash")
        st.caption("The next phase will use this saved configuration to start and stop the monitor directly from the dashboard.")


def _render_notification_configuration() -> None:
    config = load_notification_config()
    configured_channels = [c for c in config.get("channels", ["console"]) if c in CHANNEL_OPTIONS] or ["console"]
    telegram = config.get("telegram", {})
    discord = config.get("discord", {})
    email = config.get("email", {})

    st.markdown(
        "<div class='config-hero notification-hero'><div class='config-hero-icon'>🔔</div>"
        "<div><div class='config-hero-title'>Threat Notification Configuration</div>"
        "<div class='config-hero-sub'>Configure alert delivery for live threats. Channel-specific fields open immediately when selected.</div></div></div>",
        unsafe_allow_html=True,
    )

    _section("Alert Routing", "Choose one or more destinations and a minimum severity threshold.")
    left, right = st.columns([1.8, 1])
    with left:
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
            key="notification_channels",
        )
    with right:
        current_minimum = str(config.get("minimum_severity", "LOW")).upper()
        if current_minimum not in SEVERITY_OPTIONS:
            current_minimum = "LOW"
        minimum_severity = st.selectbox(
            "Minimum severity to notify",
            SEVERITY_OPTIONS,
            index=SEVERITY_OPTIONS.index(current_minimum),
            key="notification_minimum_severity",
        )

    if "desktop" in channels:
        st.info("Desktop alerts use `notify-send` on the host running AI-IDS.")

    if "telegram" in channels:
        _section("Telegram", "Enter the bot token and destination chat ID.")
        a, b = st.columns(2)
        with a:
            telegram_token = st.text_input("Bot Token", value=str(telegram.get("bot_token", "")), type="password", key="notify_telegram_token")
        with b:
            telegram_chat_id = st.text_input("Chat ID", value=str(telegram.get("chat_id", "")), key="notify_telegram_chat")
    else:
        telegram_token = str(telegram.get("bot_token", ""))
        telegram_chat_id = str(telegram.get("chat_id", ""))

    if "discord" in channels:
        _section("Discord", "Paste the webhook URL for the destination channel.")
        discord_webhook = st.text_input("Discord Webhook URL", value=str(discord.get("webhook_url", "")), type="password", key="notify_discord_webhook")
    else:
        discord_webhook = str(discord.get("webhook_url", ""))

    if "email" in channels:
        _section("Email / SMTP", "Use an app password or dedicated SMTP credential instead of your normal account password.")
        e1, e2 = st.columns(2)
        with e1:
            smtp_host = st.text_input("SMTP Host", value=str(email.get("smtp_host", "smtp.gmail.com")), key="notify_smtp_host")
            smtp_username = st.text_input("SMTP Username", value=str(email.get("username", "")), key="notify_smtp_username")
            email_from = st.text_input("From Email", value=str(email.get("from_address", "")), key="notify_email_from")
        with e2:
            smtp_port = st.number_input("SMTP Port", min_value=1, max_value=65535, value=int(email.get("smtp_port", 587) or 587), step=1, key="notify_smtp_port")
            smtp_password = st.text_input("SMTP / App Password", value=str(email.get("password", "")), type="password", key="notify_smtp_password")
            email_to = st.text_input("Recipient Email(s)", value=str(email.get("to_addresses", "")), key="notify_email_to")
        t1, t2 = st.columns(2)
        with t1:
            smtp_ssl = st.checkbox("Use SSL", value=bool(email.get("use_ssl", False)), key="notify_smtp_ssl")
        with t2:
            smtp_starttls = st.checkbox("Use STARTTLS", value=bool(email.get("use_starttls", True)), key="notify_smtp_starttls")
    else:
        smtp_host = str(email.get("smtp_host", "smtp.gmail.com"))
        smtp_port = int(email.get("smtp_port", 587) or 587)
        smtp_username = str(email.get("username", ""))
        smtp_password = str(email.get("password", ""))
        email_from = str(email.get("from_address", ""))
        email_to = str(email.get("to_addresses", ""))
        smtp_ssl = bool(email.get("use_ssl", False))
        smtp_starttls = bool(email.get("use_starttls", True))

    save_clicked = st.button("💾 Save Notification Configuration", use_container_width=True, key="save_notification_configuration")

    if save_clicked:
        if not channels:
            st.error("Select at least one notification channel.")
        elif "telegram" in channels and (not telegram_token.strip() or not telegram_chat_id.strip()):
            st.error("Telegram requires both Bot Token and Chat ID.")
        elif "discord" in channels and not discord_webhook.strip():
            st.error("Discord requires a webhook URL.")
        elif "email" in channels and (not smtp_host.strip() or not email_from.strip() or not email_to.strip()):
            st.error("Email requires SMTP Host, From Email and Recipient Email(s).")
        elif smtp_ssl and smtp_starttls:
            st.error("Choose SSL or STARTTLS for SMTP, not both.")
        else:
            path = save_notification_config({
                "channels": channels,
                "minimum_severity": minimum_severity,
                "telegram": {"bot_token": telegram_token.strip(), "chat_id": telegram_chat_id.strip()},
                "discord": {"webhook_url": discord_webhook.strip()},
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
            })
            st.success(f"Notification configuration saved securely on this host: {path}")

    test_left, test_right = st.columns([1.3, 3])
    with test_left:
        test_clicked = st.button("🧪 Send Test Notification", use_container_width=True, key="send_test_live_notification")
    with test_right:
        st.caption("Sends a CRITICAL test alert using the currently saved configuration.")

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
        for channel, error in result.failed.items():
            st.error(f"{channel.title()} failed: {error}")
        if getattr(result, "skipped", False):
            st.warning("Test notification was skipped by the configured severity threshold.")


def render_live_monitor_page() -> None:
    store = LiveEventStore()

    st.markdown(
        '<div class="soc-page-title">Live Network Monitor</div>'
        '<div class="soc-page-subtitle">Continuously refreshed network security telemetry, target configuration and live threat notifications</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <style>
        .config-hero{display:flex;align-items:center;gap:18px;padding:22px 24px;margin:8px 0 20px;border:1px solid rgba(37,221,245,.28);border-radius:14px;background:linear-gradient(145deg,rgba(5,33,45,.95),rgba(4,22,32,.98));min-height:96px}
        .config-hero-icon{font-size:34px}.config-hero-title{font-size:22px;font-weight:900;color:#eefcff}.config-hero-sub{font-size:12px;color:#86a7b3;margin-top:5px;line-height:1.5}.config-section-title{font-size:17px;font-weight:900;color:#2be6ee;margin:23px 0 2px}.config-section-sub{font-size:11px;color:#7899a5;margin-bottom:12px}.notification-hero{min-height:112px;padding:26px 28px}
        div[data-testid="stTabs"] button p{font-size:14px!important;font-weight:800!important}.stTextInput input,.stNumberInput input{min-height:43px!important}.stSelectbox>div>div,.stMultiSelect>div>div{min-height:43px!important}.stButton>button{min-height:48px!important;font-size:13px!important}
        </style>
        """,
        unsafe_allow_html=True,
    )

    live_tab, monitoring_tab, notification_tab = st.tabs([
        "📊 Live Analysis",
        "🎯 Monitoring Configuration",
        "🔔 Notification Configuration",
    ])

    with live_tab:
        control_left, control_mid, control_right = st.columns([3, 1, 1])
        with control_left:
            st.caption(f"Event database: {store.db_path}")
        with control_mid:
            auto_refresh = st.toggle("Auto refresh", value=True, key="live_auto_refresh")
        with control_right:
            refresh_seconds = st.selectbox(
                "Interval",
                REFRESH_OPTIONS,
                index=REFRESH_OPTIONS.index(DEFAULT_REFRESH_SECONDS),
                format_func=lambda value: f"{value} sec",
                key="live_refresh_seconds",
                disabled=not auto_refresh,
            )

        fragment_factory = getattr(st, "fragment", None)
        if callable(fragment_factory):
            live_fragment = fragment_factory(run_every=f"{refresh_seconds}s" if auto_refresh else None)(_render_live_data)
            live_fragment(store, auto_refresh, refresh_seconds)
        else:
            st.warning("This Streamlit version does not support fragment auto-refresh. Manual refresh remains available.")
            _render_live_data(store, False, refresh_seconds)

    with monitoring_tab:
        _render_monitoring_configuration()

    with notification_tab:
        _render_notification_configuration()
