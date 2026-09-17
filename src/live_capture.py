"""Live packet capture utilities for AI-IDS.

This module captures traffic only from a locally selected interface and writes
short PCAP windows for the existing AI-IDS pipeline. It performs no attack
actions and sends no packets.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scapy.all import PcapWriter, get_if_list, sniff


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CAPTURE_DIR = PROJECT_ROOT / "data" / "live"


@dataclass(frozen=True)
class CaptureResult:
    interface: str
    pcap_path: Path
    packet_count: int
    started_at: str
    finished_at: str
    duration_seconds: float


def list_interfaces() -> list[str]:
    """Return interfaces visible to Scapy."""
    return sorted(set(get_if_list()))


def validate_interface(interface: str) -> str:
    available = list_interfaces()
    if interface not in available:
        raise ValueError(
            f"Network interface '{interface}' was not found. "
            f"Available interfaces: {', '.join(available) or 'none'}"
        )
    return interface


def capture_window(
    interface: str,
    duration_seconds: float = 5.0,
    output_dir: Path | str = DEFAULT_CAPTURE_DIR,
    bpf_filter: Optional[str] = None,
) -> CaptureResult:
    """Capture one time-bounded PCAP window from a local interface.

    The caller normally needs root/CAP_NET_RAW privileges on Linux.
    The PCAP writer is created lazily on the first captured packet so an idle
    interface does not produce an invalid empty capture or a Scapy link-layer
    warning.
    """
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be greater than zero")

    validate_interface(interface)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    started = datetime.now(timezone.utc)
    stamp = started.strftime("%Y%m%dT%H%M%S_%fZ")
    safe_iface = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in interface)
    pcap_path = output_dir / f"live_{safe_iface}_{stamp}.pcap"

    packet_count = 0
    writer: PcapWriter | None = None

    def _write(packet):
        nonlocal packet_count, writer
        if writer is None:
            writer = PcapWriter(str(pcap_path), append=False, sync=True)
        writer.write(packet)
        packet_count += 1

    sniff_kwargs = {
        "iface": interface,
        "prn": _write,
        "store": False,
        "timeout": float(duration_seconds),
    }
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    try:
        sniff(**sniff_kwargs)
    finally:
        if writer is not None:
            writer.close()

    finished = datetime.now(timezone.utc)

    if packet_count == 0:
        pcap_path.unlink(missing_ok=True)

    return CaptureResult(
        interface=interface,
        pcap_path=pcap_path,
        packet_count=packet_count,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_seconds=(finished - started).total_seconds(),
    )
