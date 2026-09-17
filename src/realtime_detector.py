"""Real-time detection adapter for AI-IDS live capture windows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pandas.errors import EmptyDataError

from src.pcap_pipeline import analyze_pcap


class NoUsableFlowsError(RuntimeError):
    """Raised when a captured window contains packets but no CICFlowMeter flows."""


def analyze_live_window(pcap_path: Path | str) -> dict[str, Any]:
    """Run one captured PCAP window through the existing hybrid AI-IDS pipeline.

    Live windows can legitimately contain packets that CICFlowMeter cannot turn
    into model-ready flows (for example some loopback/local-only traffic or an
    incomplete short-lived capture). Those windows are treated as a normal
    skip condition instead of crashing the live monitor.
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"Live capture not found: {path}")
    if path.stat().st_size == 0:
        raise NoUsableFlowsError(f"Live capture is empty: {path}")

    try:
        report = analyze_pcap(path)
    except EmptyDataError as exc:
        raise NoUsableFlowsError(
            "Packets were captured, but CICFlowMeter produced an empty flow CSV. "
            "This window has no usable model flows."
        ) from exc
    except ValueError as exc:
        message = str(exc)
        if "no usable" in message.lower() or "no columns to parse" in message.lower():
            raise NoUsableFlowsError(message) from exc
        raise

    if not isinstance(report, dict):
        raise TypeError("AI-IDS pipeline did not return a report dictionary")

    return report
