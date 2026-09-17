"""Notification backends for live AI-IDS alerts.

Configuration comes from dashboard-managed local settings first, with existing
environment variables retained as fallbacks. Backends fail independently so a
notification problem never stops packet capture or IDS analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email.message import EmailMessage
import json
import os
import shutil
import smtplib
import ssl
import subprocess
from typing import Any
from urllib import parse, request

from src.notification_config import load_notification_config


SEVERITY_ICON = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
}
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SUPPORTED_CHANNELS = {"console", "desktop", "telegram", "discord", "email"}
DEFAULT_CHANNELS = ("console",)


@dataclass
class NotificationResult:
    attempted: list[str] = field(default_factory=list)
    succeeded: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    skipped: bool = False

    @property
    def external_succeeded(self) -> bool:
        return any(channel != "console" for channel in self.succeeded)


def _env_truthy(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def enabled_channels() -> list[str]:
    config = load_notification_config()
    configured = config.get("channels")
    if isinstance(configured, list):
        channels = [
            str(item).strip().lower()
            for item in configured
            if str(item).strip().lower() in SUPPORTED_CHANNELS
        ]
        if channels:
            return list(dict.fromkeys(channels))

    raw = os.getenv("AI_IDS_NOTIFY_CHANNELS", ",".join(DEFAULT_CHANNELS))
    channels: list[str] = []
    for item in raw.split(","):
        channel = item.strip().lower()
        if channel and channel in SUPPORTED_CHANNELS and channel not in channels:
            channels.append(channel)
    return channels or list(DEFAULT_CHANNELS)


def minimum_severity() -> str:
    config = load_notification_config()
    level = str(config.get("minimum_severity", "LOW")).upper()
    return level if level in SEVERITY_RANK else "LOW"


def should_notify(alert: dict[str, Any]) -> bool:
    severity = str(alert.get("severity", "LOW")).upper()
    return SEVERITY_RANK.get(severity, 1) >= SEVERITY_RANK[minimum_severity()]


def format_alert(alert: dict[str, Any]) -> str:
    severity = str(alert.get("severity", "UNKNOWN")).upper()
    prefix = SEVERITY_ICON.get(severity, "[ALERT]")
    attack_type = alert.get("attack_type", "Unknown")
    source = alert.get("source_ip", "Unknown")
    target = alert.get("target_ip", "Unknown")
    port = alert.get("target_port")
    destination = f"{target}:{port}" if port not in {None, "", "None"} else str(target)
    reason = alert.get("reason", "Suspicious network activity detected")
    return f"{prefix} {attack_type} | {source} -> {destination} | {reason}"


def format_detailed_alert(alert: dict[str, Any]) -> str:
    lines = [
        "AI-IDS Security Alert",
        f"Severity: {str(alert.get('severity', 'UNKNOWN')).upper()}",
        f"Attack Type: {alert.get('attack_type', 'Unknown')}",
        f"Detection Engine: {alert.get('detection_engine', 'Unknown')}",
        f"Source IP: {alert.get('source_ip', 'Unknown')}",
        f"Target IP: {alert.get('target_ip', 'Unknown')}",
    ]
    if alert.get("target_port") not in {None, "", "None"}:
        lines.append(f"Target Port: {alert.get('target_port')}")
    if alert.get("first_seen"):
        lines.append(f"First Seen: {alert.get('first_seen')}")
    if alert.get("last_seen"):
        lines.append(f"Last Seen: {alert.get('last_seen')}")
    lines.append(f"Reason: {alert.get('reason', 'Suspicious network activity detected')}")
    return "\n".join(lines)


def notify_console(alert: dict[str, Any]) -> None:
    print("\n" + "!" * 72)
    print("LIVE AI-IDS ALERT")
    print(format_alert(alert))
    print("!" * 72)


def notify_desktop(alert: dict[str, Any]) -> None:
    binary = shutil.which("notify-send")
    if not binary:
        raise RuntimeError("notify-send is not installed or not available in PATH")
    severity = str(alert.get("severity", "UNKNOWN")).upper()
    urgency = "critical" if severity in {"CRITICAL", "HIGH"} else "normal"
    subprocess.run(
        [binary, "--urgency", urgency, "--app-name", "AI-IDS",
         f"AI-IDS {severity}: {alert.get('attack_type', 'Security Alert')}",
         format_alert(alert)],
        check=True,
        timeout=10,
    )


def notify_telegram(alert: dict[str, Any]) -> None:
    config = load_notification_config().get("telegram", {})
    token = str(config.get("bot_token") or os.getenv("AI_IDS_TELEGRAM_BOT_TOKEN", "")).strip()
    chat_id = str(config.get("chat_id") or os.getenv("AI_IDS_TELEGRAM_CHAT_ID", "")).strip()
    if not token or not chat_id:
        raise RuntimeError("Telegram bot token and chat ID are required")

    body = parse.urlencode({
        "chat_id": chat_id,
        "text": format_detailed_alert(alert),
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    req = request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=body,
        method="POST",
    )
    with request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload.get("ok"):
        raise RuntimeError("Telegram API returned an unsuccessful response")


def notify_discord(alert: dict[str, Any]) -> None:
    config = load_notification_config().get("discord", {})
    webhook_url = str(config.get("webhook_url") or os.getenv("AI_IDS_DISCORD_WEBHOOK_URL", "")).strip()
    if not webhook_url:
        raise RuntimeError("Discord webhook URL is required")

    payload = json.dumps({
        "username": "AI-IDS",
        "content": f"```\n{format_detailed_alert(alert)}\n```",
        "allowed_mentions": {"parse": []},
    }).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=10) as response:
        if response.status not in {200, 204}:
            raise RuntimeError(f"Discord webhook returned HTTP {response.status}")


def notify_email(alert: dict[str, Any]) -> None:
    config = load_notification_config().get("email", {})
    host = str(config.get("smtp_host") or os.getenv("AI_IDS_SMTP_HOST", "")).strip()
    port = int(config.get("smtp_port") or os.getenv("AI_IDS_SMTP_PORT", "587"))
    username = str(config.get("username") or os.getenv("AI_IDS_SMTP_USERNAME", "")).strip()
    password = str(config.get("password") or os.getenv("AI_IDS_SMTP_PASSWORD", ""))
    sender = str(config.get("from_address") or os.getenv("AI_IDS_EMAIL_FROM", username)).strip()
    recipients_raw = str(config.get("to_addresses") or os.getenv("AI_IDS_EMAIL_TO", ""))
    recipients = [item.strip() for item in recipients_raw.split(",") if item.strip()]
    if not host or not sender or not recipients:
        raise RuntimeError("SMTP host, sender and recipient email are required")

    severity = str(alert.get("severity", "UNKNOWN")).upper()
    attack_type = str(alert.get("attack_type", "Security Alert"))
    message = EmailMessage()
    message["Subject"] = f"[AI-IDS {severity}] {attack_type}"
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(format_detailed_alert(alert))

    use_ssl = bool(config.get("use_ssl", _env_truthy("AI_IDS_SMTP_SSL", False)))
    use_starttls = bool(config.get("use_starttls", _env_truthy("AI_IDS_SMTP_STARTTLS", not use_ssl)))
    context = ssl.create_default_context()

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=10, context=context) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            if use_starttls:
                smtp.starttls(context=context)
                smtp.ehlo()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)


DISPATCHERS = {
    "console": notify_console,
    "desktop": notify_desktop,
    "telegram": notify_telegram,
    "discord": notify_discord,
    "email": notify_email,
}


def notify(alert: dict[str, Any], channels: list[str] | None = None) -> NotificationResult:
    """Dispatch an alert to configured backends without failing the IDS."""
    result = NotificationResult()
    if not should_notify(alert):
        result.skipped = True
        return result

    for channel in channels or enabled_channels():
        result.attempted.append(channel)
        try:
            DISPATCHERS[channel](alert)
            result.succeeded.append(channel)
            if channel != "console":
                print(f"[Notification] {channel}: delivered")
        except Exception as exc:
            result.failed[channel] = str(exc)
            print(f"[Notification] {channel}: failed — {exc}")
    return result
