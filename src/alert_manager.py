"""Alert deduplication and cooldown management for live AI-IDS monitoring."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any


def _alert_key(alert: dict[str, Any]) -> tuple:
    return (
        str(alert.get("attack_type", "Unknown")),
        str(alert.get("source_ip", "Unknown")),
        str(alert.get("target_ip", "Unknown")),
        str(alert.get("target_port", "Unknown")),
    )


@dataclass
class AlertManager:
    cooldown_seconds: float = 60.0
    _last_seen: dict[tuple, float] = field(default_factory=dict)

    def filter_new_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return alerts that have not been emitted during the cooldown window."""
        now = time.monotonic()
        fresh = []
        for alert in alerts:
            key = _alert_key(alert)
            previous = self._last_seen.get(key)
            if previous is None or (now - previous) >= self.cooldown_seconds:
                self._last_seen[key] = now
                fresh.append(alert)
        return fresh

    def reset(self) -> None:
        self._last_seen.clear()
