"""Real-time detection adapter for AI-IDS live capture windows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.pcap_pipeline import analyze_pcap


def analyze_live_window(pcap_path: Path | str) -> dict[str, Any]:
    """Run one captured PCAP window through the existing hybrid AI-IDS pipeline."""
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"Live capture not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Live capture is empty: {path}")
    report = analyze_pcap(path)
    if not isinstance(report, dict):
        raise TypeError("AI-IDS pipeline did not return a report dictionary")
    return report
