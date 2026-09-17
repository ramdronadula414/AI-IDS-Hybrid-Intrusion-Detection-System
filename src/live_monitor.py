"""CLI live network monitor for AI-IDS.

Phase 1 workflow:
    local interface -> short PCAP window -> existing hybrid AI-IDS pipeline
    -> cooldown/dedup -> terminal alert

Run on Kali/Linux with sufficient packet-capture privileges, for example:
    sudo -E python src/live_monitor.py --list-interfaces
    sudo -E python src/live_monitor.py --interface eth0 --window 5

Use Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.alert_manager import AlertManager
from src.live_capture import capture_window, list_interfaces
from src.live_flow_engine import cleanup_capture, make_window
from src.notification_engine import notify
from src.realtime_detector import analyze_live_window


def _extract_alerts(report: dict) -> list[dict]:
    alerts = report.get("alerts", [])
    return alerts if isinstance(alerts, list) else []


def run_live_monitor(
    interface: str,
    window_seconds: float = 5.0,
    cooldown_seconds: float = 60.0,
    bpf_filter: str | None = None,
    keep_pcaps: bool = False,
    max_windows: int | None = None,
) -> None:
    manager = AlertManager(cooldown_seconds=cooldown_seconds)
    sequence = 0

    print("=" * 72)
    print("AI-IDS LIVE NETWORK MONITOR")
    print("=" * 72)
    print(f"Interface       : {interface}")
    print(f"Capture window  : {window_seconds:.1f} seconds")
    print(f"Alert cooldown  : {cooldown_seconds:.1f} seconds")
    print(f"BPF filter      : {bpf_filter or 'None'}")
    print("Stop            : Ctrl+C")

    try:
        while max_windows is None or sequence < max_windows:
            sequence += 1
            print(f"\n[Window {sequence}] Capturing traffic...")

            result = capture_window(
                interface=interface,
                duration_seconds=window_seconds,
                bpf_filter=bpf_filter,
            )

            window = make_window(result.pcap_path, result.packet_count, sequence)
            print(f"Packets captured: {window.packet_count}")

            if window.packet_count == 0:
                print("No packets captured; skipping analysis.")
                continue

            try:
                print("Running hybrid AI-IDS analysis...")
                report = analyze_live_window(window.pcap_path)
                decision = report.get("final_decision", "UNKNOWN")
                severity = report.get("severity", "UNKNOWN")
                attack_type = report.get("attack_type", "Unknown")

                print(
                    f"Window result: decision={decision} | "
                    f"severity={severity} | attack={attack_type}"
                )

                fresh_alerts = manager.filter_new_alerts(_extract_alerts(report))
                if fresh_alerts:
                    for alert in fresh_alerts:
                        notify(alert)
                elif decision == "ATTACK":
                    print("Attack already notified within cooldown window.")
                else:
                    print("No new live alerts.")
            finally:
                if not keep_pcaps:
                    cleanup_capture(window.pcap_path)

    except KeyboardInterrupt:
        print("\nLive monitor stopped by user.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-IDS live network monitor")
    parser.add_argument("--interface", "-i", help="Network interface to monitor")
    parser.add_argument("--window", type=float, default=5.0, help="Capture window in seconds (default: 5)")
    parser.add_argument("--cooldown", type=float, default=60.0, help="Duplicate-alert cooldown in seconds")
    parser.add_argument("--filter", dest="bpf_filter", help="Optional BPF capture filter, e.g. 'tcp or udp'")
    parser.add_argument("--keep-pcaps", action="store_true", help="Keep generated live PCAP windows")
    parser.add_argument("--max-windows", type=int, help="Stop after N capture windows (useful for testing)")
    parser.add_argument("--list-interfaces", action="store_true", help="List capture interfaces and exit")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for interface in list_interfaces():
            print(f"  - {interface}")
        return

    if not args.interface:
        raise SystemExit("Use --interface <name> or --list-interfaces")

    run_live_monitor(
        interface=args.interface,
        window_seconds=args.window,
        cooldown_seconds=args.cooldown,
        bpf_filter=args.bpf_filter,
        keep_pcaps=args.keep_pcaps,
        max_windows=args.max_windows,
    )


if __name__ == "__main__":
    main()
