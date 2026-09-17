"""Notification backends for live AI-IDS alerts.

Phase 1 intentionally implements console notifications only. Email, Telegram,
Discord or desktop notifications can be added after live detection is stable.
"""

from __future__ import annotations

from typing import Any


SEVERITY_ICON = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
}


def format_alert(alert: dict[str, Any]) -> str:
    severity = str(alert.get("severity", "UNKNOWN")).upper()
    prefix = SEVERITY_ICON.get(severity, "[ALERT]")
    attack_type = alert.get("attack_type", "Unknown")
    source = alert.get("source_ip", "Unknown")
    target = alert.get("target_ip", "Unknown")
    port = alert.get("target_port")
    destination = f"{target}:{port}" if port is not None else str(target)
    reason = alert.get("reason", "Suspicious network activity detected")
    return f"{prefix} {attack_type} | {source} -> {destination} | {reason}"


def notify_console(alert: dict[str, Any]) -> None:
    print("\n" + "!" * 72)
    print("LIVE AI-IDS ALERT")
    print(format_alert(alert))
    print("!" * 72)


def notify(alert: dict[str, Any]) -> None:
    """Dispatch one alert. Phase 1 uses the terminal only."""
    notify_console(alert)
