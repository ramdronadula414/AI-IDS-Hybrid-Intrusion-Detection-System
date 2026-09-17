"""CLI live network monitor for AI-IDS.

Step 8 architecture:
    continuous capture -> queue -> background hybrid analysis
        -> alert cooldown/dedup
        -> console / desktop / Telegram / Discord / email notifications
        -> SQLite live event store

Notification failures are isolated from detection so packet capture and analysis
continue even when an external service is unavailable or misconfigured.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
import sys
from threading import Event, Thread
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.alert_manager import AlertManager
from src.live_capture import capture_window, list_interfaces
from src.live_event_store import DEFAULT_EVENT_DB, LiveEventStore
from src.live_flow_engine import FlowWindow, cleanup_capture, make_window
from src.notification_engine import enabled_channels, notify
from src.realtime_detector import NoUsableFlowsError, analyze_live_window


@dataclass
class LiveStats:
    windows_captured: int = 0
    windows_enqueued: int = 0
    windows_analyzed: int = 0
    windows_skipped_empty: int = 0
    windows_skipped_no_flows: int = 0
    analysis_errors: int = 0
    persistence_errors: int = 0
    alerts_emitted: int = 0
    notification_failures: int = 0
    packets_captured: int = 0


def _extract_alerts(report: dict) -> list[dict]:
    alerts = report.get("alerts", [])
    return alerts if isinstance(alerts, list) else []


def _analysis_worker(
    work_queue: Queue,
    stop_event: Event,
    manager: AlertManager,
    keep_pcaps: bool,
    stats: LiveStats,
    store: LiveEventStore,
    session_id: str,
    interface: str,
) -> None:
    """Consume completed capture windows and analyze/persist them."""
    while True:
        if stop_event.is_set() and work_queue.empty():
            break

        try:
            window: FlowWindow = work_queue.get(timeout=0.25)
        except Empty:
            continue

        try:
            print(
                f"\n[Analyzer] Window {window.sequence}: "
                f"processing {window.packet_count} packet(s)..."
            )

            try:
                report = analyze_live_window(window.pcap_path)
            except NoUsableFlowsError as exc:
                stats.windows_skipped_no_flows += 1
                print(
                    f"[Analyzer] Window {window.sequence}: "
                    f"no usable CICFlowMeter flows; skipped."
                )
                print(f"[Analyzer] Detail: {exc}")
                continue
            except Exception as exc:
                stats.analysis_errors += 1
                print(
                    f"[Analyzer] Window {window.sequence}: "
                    f"analysis failed: {exc}"
                )
                continue

            stats.windows_analyzed += 1

            decision = report.get("final_decision", "UNKNOWN")
            severity = report.get("severity", "UNKNOWN")
            attack_type = report.get("attack_type", "Unknown")

            print(
                f"[Analyzer] Window {window.sequence} result: "
                f"decision={decision} | severity={severity} | "
                f"attack={attack_type}"
            )

            all_alerts = _extract_alerts(report)
            fresh_alerts = manager.filter_new_alerts(all_alerts)
            delivered_alerts: list[dict] = []

            if fresh_alerts:
                for alert in fresh_alerts:
                    result = notify(alert)
                    if result.succeeded:
                        delivered_alerts.append(alert)
                        stats.alerts_emitted += 1
                    if result.failed:
                        stats.notification_failures += len(result.failed)
            elif decision == "ATTACK":
                print(
                    f"[Analyzer] Window {window.sequence}: "
                    "attack already notified within cooldown window."
                )
            else:
                print(
                    f"[Analyzer] Window {window.sequence}: "
                    "no new live alerts."
                )

            try:
                store.record_window(
                    session_id=session_id,
                    sequence=window.sequence,
                    interface=interface,
                    pcap_path=window.pcap_path,
                    packet_count=window.packet_count,
                    report=report,
                    captured_at=datetime.fromtimestamp(
                        window.created_at,
                        tz=timezone.utc,
                    ).isoformat(),
                    notified_alerts=delivered_alerts,
                )
                print(
                    f"[Store] Window {window.sequence}: persisted to "
                    f"{store.db_path}"
                )
            except Exception as exc:
                stats.persistence_errors += 1
                print(
                    f"[Store] Window {window.sequence}: persistence failed: {exc}"
                )
        finally:
            if not keep_pcaps:
                cleanup_capture(window.pcap_path)
            work_queue.task_done()


def run_live_monitor(
    interface: str,
    window_seconds: float = 5.0,
    cooldown_seconds: float = 60.0,
    bpf_filter: str | None = None,
    keep_pcaps: bool = False,
    max_windows: int | None = None,
    queue_size: int = 0,
    event_db: Path | str = DEFAULT_EVENT_DB,
) -> None:
    """Continuously capture while a background worker analyzes prior windows."""
    if max_windows is not None and max_windows <= 0:
        raise ValueError("max_windows must be greater than zero")
    if queue_size < 0:
        raise ValueError("queue_size cannot be negative")

    manager = AlertManager(cooldown_seconds=cooldown_seconds)
    stats = LiveStats()
    work_queue: Queue = Queue(maxsize=queue_size)
    stop_event = Event()
    store = LiveEventStore(event_db)
    session_id = uuid.uuid4().hex
    channels = enabled_channels()

    store.start_session(
        session_id=session_id,
        interface=interface,
        window_seconds=window_seconds,
        bpf_filter=bpf_filter,
    )

    worker = Thread(
        target=_analysis_worker,
        args=(
            work_queue,
            stop_event,
            manager,
            keep_pcaps,
            stats,
            store,
            session_id,
            interface,
        ),
        name="ai-ids-analysis-worker",
        daemon=False,
    )
    worker.start()

    print("=" * 72)
    print("AI-IDS LIVE NETWORK MONITOR — STEP 8 NOTIFICATION MODE")
    print("=" * 72)
    print(f"Session ID      : {session_id}")
    print(f"Interface       : {interface}")
    print(f"Capture window  : {window_seconds:.1f} seconds")
    print(f"Alert cooldown  : {cooldown_seconds:.1f} seconds")
    print(f"BPF filter      : {bpf_filter or 'None'}")
    print(f"Queue size      : {'unbounded' if queue_size == 0 else queue_size}")
    print(f"Notifications   : {', '.join(channels)}")
    print(f"Event database  : {store.db_path}")
    print("Architecture    : capture -> analysis -> notify -> SQLite")
    print("Stop            : Ctrl+C")

    sequence = 0
    session_status = "COMPLETED"

    try:
        while max_windows is None or sequence < max_windows:
            sequence += 1
            print(f"\n[Capture] Window {sequence}: capturing traffic...")

            result = capture_window(
                interface=interface,
                duration_seconds=window_seconds,
                bpf_filter=bpf_filter,
            )

            stats.windows_captured += 1
            stats.packets_captured += result.packet_count

            window = make_window(
                result.pcap_path,
                result.packet_count,
                sequence,
            )

            print(
                f"[Capture] Window {sequence}: "
                f"{window.packet_count} packet(s) captured."
            )

            if window.packet_count == 0:
                stats.windows_skipped_empty += 1
                print(
                    f"[Capture] Window {sequence}: "
                    "idle window; nothing to analyze."
                )
                continue

            if queue_size and work_queue.full():
                print(
                    f"[Capture] Window {sequence}: analysis queue is full; "
                    "waiting so evidence is not dropped..."
                )

            work_queue.put(window)
            stats.windows_enqueued += 1

            print(
                f"[Capture] Window {sequence}: queued for analysis "
                f"(pending={work_queue.qsize()})."
            )

    except KeyboardInterrupt:
        session_status = "STOPPED"
        print("\n[Monitor] Stop requested by user.")
    except Exception:
        session_status = "ERROR"
        raise
    finally:
        print("\n[Monitor] Capture stopped. Waiting for queued analysis...")
        work_queue.join()
        stop_event.set()
        worker.join(timeout=10.0)
        store.finish_session(session_id, status=session_status)

        overview = store.overview()

        print("\n" + "=" * 72)
        print("LIVE MONITOR SUMMARY")
        print("=" * 72)
        print(f"Windows captured       : {stats.windows_captured}")
        print(f"Windows queued         : {stats.windows_enqueued}")
        print(f"Windows analyzed       : {stats.windows_analyzed}")
        print(f"Idle windows skipped   : {stats.windows_skipped_empty}")
        print(f"Flowless windows       : {stats.windows_skipped_no_flows}")
        print(f"Analysis errors        : {stats.analysis_errors}")
        print(f"Persistence errors     : {stats.persistence_errors}")
        print(f"Notification failures  : {stats.notification_failures}")
        print(f"Packets captured       : {stats.packets_captured}")
        print(f"Alerts emitted         : {stats.alerts_emitted}")
        print(f"Stored windows (all)   : {overview['total_windows']}")
        print(f"Stored alerts (all)    : {overview['total_alerts']}")
        print(f"Event database         : {store.db_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI-IDS persistent live network monitor with notifications"
    )
    parser.add_argument("--interface", "-i", help="Network interface to monitor")
    parser.add_argument(
        "--window", type=float, default=5.0,
        help="Capture window in seconds (default: 5)",
    )
    parser.add_argument(
        "--cooldown", type=float, default=60.0,
        help="Duplicate-alert cooldown in seconds",
    )
    parser.add_argument(
        "--filter", dest="bpf_filter",
        help="Optional BPF capture filter, e.g. 'tcp or udp'",
    )
    parser.add_argument(
        "--keep-pcaps", action="store_true",
        help="Keep generated live PCAP windows",
    )
    parser.add_argument(
        "--max-windows", type=int,
        help="Stop capture after N windows and finish queued analyses",
    )
    parser.add_argument(
        "--queue-size", type=int, default=0,
        help="Maximum pending analysis windows; 0 means unbounded",
    )
    parser.add_argument(
        "--event-db", default=str(DEFAULT_EVENT_DB),
        help="SQLite live-event database path",
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List capture interfaces and exit",
    )
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
        queue_size=args.queue_size,
        event_db=args.event_db,
    )


if __name__ == "__main__":
    main()
