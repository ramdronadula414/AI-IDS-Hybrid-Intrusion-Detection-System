"""Live flow-window helpers for AI-IDS.

Phase 1 keeps the existing, validated PCAP pipeline as the source of truth.
This module owns rolling-window metadata and cleanup so later phases can swap
in a lower-latency flow engine without changing the live-monitor interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time


@dataclass(frozen=True)
class FlowWindow:
    pcap_path: Path
    packet_count: int
    sequence: int
    created_at: float


def make_window(pcap_path: Path | str, packet_count: int, sequence: int) -> FlowWindow:
    return FlowWindow(
        pcap_path=Path(pcap_path),
        packet_count=int(packet_count),
        sequence=int(sequence),
        created_at=time.time(),
    )


def cleanup_capture(path: Path | str) -> None:
    """Delete a generated live-capture PCAP if it exists."""
    Path(path).unlink(missing_ok=True)
