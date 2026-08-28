"""
Behavior-based detection engine for AI-IDS.

Detects suspicious behavior that may span multiple network flows.
This complements the ML-based CIC-IDS2017 classifier.
"""

from collections import defaultdict
from datetime import datetime

import pandas as pd


def detect_port_scans(
    flow_df: pd.DataFrame,
    min_unique_ports: int = 10,
):
    """
    Detect possible port scanning behavior.

    A source is considered suspicious when it contacts
    many unique destination ports on the same target.

    Parameters
    ----------
    flow_df : pandas.DataFrame
        Raw CICFlowMeter output containing:
        src_ip, dst_ip, src_port, dst_port, protocol, timestamp

    min_unique_ports : int
        Minimum number of unique destination ports required
        before generating a PortScan alert.

    Returns
    -------
    list[dict]
        Behavioral alerts.
    """

    required = {
        "src_ip",
        "dst_ip",
        "dst_port",
    }

    missing = required - set(flow_df.columns)

    if missing:
        raise ValueError(
            f"Missing required flow columns: {sorted(missing)}"
        )

    alerts = []

    # Clean relevant columns
    df = flow_df.copy()

    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)

    df["dst_port"] = pd.to_numeric(
        df["dst_port"],
        errors="coerce",
    )

    df = df.dropna(
        subset=["dst_port"]
    )

    # Group traffic:
    # attacker/source -> target
    grouped = df.groupby(
        ["src_ip", "dst_ip"],
        dropna=False,
    )

    for (src_ip, dst_ip), group in grouped:

        ports = sorted(
            group["dst_port"]
            .dropna()
            .astype(int)
            .unique()
            .tolist()
        )

        unique_ports = len(ports)
        total_flows = len(group)

        if unique_ports < min_unique_ports:
            continue

        # Determine severity
        if unique_ports >= 100:
            severity = "CRITICAL"

        elif unique_ports >= 50:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        # Protocol information
        protocols = []

        if "protocol" in group.columns:

            protocols = sorted(
                group["protocol"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

        # Timestamp information
        first_seen = "Unknown"
        last_seen = "Unknown"

        if "timestamp" in group.columns:

            timestamps = pd.to_datetime(
                group["timestamp"],
                errors="coerce",
            ).dropna()

            if not timestamps.empty:

                first_seen = str(
                    timestamps.min()
                )

                last_seen = str(
                    timestamps.max()
                )

        alerts.append(
            {
                "detection_engine": "Behavioral IDS",
                "attack_type": "PortScan",
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "unique_ports": unique_ports,
                "total_flows": total_flows,
                "ports": ports,
                "protocols": protocols,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "severity": severity,
                "status": "ALERT",
                "reason": (
                    f"{src_ip} contacted "
                    f"{unique_ports} unique ports "
                    f"on {dst_ip}"
                ),
            }
        )

    return alerts


def detect_dos_ddos(
    flow_df: pd.DataFrame,
    min_total_flows: int = 100,
    min_sources: int = 3,
    min_flows_per_source: int = 20,
):
    """
    Detect high-volume DoS / DDoS behavior.

    DDoS:
        Multiple sources generate many flows toward the
        same destination IP + destination port.

    DoS:
        A single source generates an unusually large
        number of flows toward one destination service.
    """

    required = {
        "src_ip",
        "dst_ip",
        "dst_port",
    }

    missing = required - set(flow_df.columns)

    if missing:
        raise ValueError(
            f"Missing required flow columns: {sorted(missing)}"
        )

    df = flow_df.copy()

    df["src_ip"] = (
        df["src_ip"]
        .astype(str)
        .str.strip()
    )

    df["dst_ip"] = (
        df["dst_ip"]
        .astype(str)
        .str.strip()
    )

    df["dst_port"] = pd.to_numeric(
        df["dst_port"],
        errors="coerce",
    )

    df = df.dropna(
        subset=["dst_port"]
    )

    alerts = []

    # =====================================================
    # GROUP BY TARGET SERVICE
    # =====================================================

    grouped = df.groupby(
        [
            "dst_ip",
            "dst_port",
        ],
        dropna=False,
    )

    for (
        target_ip,
        target_port
    ), group in grouped:

        total_flows = len(group)

        if total_flows < min_total_flows:
            continue

        # -------------------------------------------------
        # Count traffic contributed by each source
        # -------------------------------------------------

        source_counts = (
            group["src_ip"]
            .value_counts()
        )

        active_sources = source_counts[
            source_counts
            >= min_flows_per_source
        ]

        source_count = len(
            active_sources
        )

        # -------------------------------------------------
        # Time information
        # -------------------------------------------------

        first_seen = "Unknown"
        last_seen = "Unknown"
        observed_window_seconds = None

        if "timestamp" in group.columns:

            timestamps = pd.to_datetime(
                group["timestamp"],
                errors="coerce",
            ).dropna()

            if not timestamps.empty:

                first_time = timestamps.min()
                last_time = timestamps.max()

                first_seen = str(
                    first_time
                )

                last_seen = str(
                    last_time
                )

                observed_window_seconds = (
                    last_time
                    - first_time
                ).total_seconds()

        # =================================================
        # DDoS — multiple high-volume sources
        # =================================================

        if source_count >= min_sources:

            if total_flows >= 250:
                severity = "CRITICAL"

            elif total_flows >= 100:
                severity = "HIGH"

            else:
                severity = "MEDIUM"

            attackers = (
                active_sources
                .index
                .astype(str)
                .tolist()
            )

            source_flow_counts = {
                str(ip): int(count)
                for ip, count
                in active_sources.items()
            }

            alerts.append(
                {
                    "detection_engine":
                        "Behavioral IDS",

                    "attack_type":
                        "DDoS",

                    "source_ip":
                        ", ".join(attackers),

                    "source_ips":
                        attackers,

                    "target_ip":
                        str(target_ip),

                    "target_port":
                        int(target_port),

                    "source_count":
                        source_count,

                    "total_flows":
                        total_flows,

                    "source_flow_counts":
                        source_flow_counts,

                    "first_seen":
                        first_seen,

                    "last_seen":
                        last_seen,

                    "observed_window_seconds":
                        observed_window_seconds,

                    "severity":
                        severity,

                    "status":
                        "ALERT",

                    "reason": (
                        f"{source_count} high-volume "
                        f"sources generated "
                        f"{total_flows} flows toward "
                        f"{target_ip}:{int(target_port)}"
                    ),
                }
            )

            # Do not also generate a single-source DoS
            # alert for the same target group.
            continue

        # =================================================
        # DoS — one dominant high-volume source
        # =================================================

        if not source_counts.empty:

            dominant_source = str(
                source_counts.index[0]
            )

            dominant_flows = int(
                source_counts.iloc[0]
            )

            if dominant_flows >= min_total_flows:

                severity = (
                    "CRITICAL"
                    if dominant_flows >= 250
                    else "HIGH"
                )

                alerts.append(
                    {
                        "detection_engine":
                            "Behavioral IDS",

                        "attack_type":
                            "DoS",

                        "source_ip":
                            dominant_source,

                        "source_ips":
                            [dominant_source],

                        "target_ip":
                            str(target_ip),

                        "target_port":
                            int(target_port),

                        "source_count":
                            1,

                        "total_flows":
                            dominant_flows,

                        "first_seen":
                            first_seen,

                        "last_seen":
                            last_seen,

                        "observed_window_seconds":
                            observed_window_seconds,

                        "severity":
                            severity,

                        "status":
                            "ALERT",

                        "reason": (
                            f"{dominant_source} generated "
                            f"{dominant_flows} flows toward "
                            f"{target_ip}:{int(target_port)}"
                        ),
                    }
                )

    return alerts


def detect_brute_force(
    flow_df: pd.DataFrame,
    min_attempts: int = 20,
    service_ports=None,
):
    """
    Detect repeated connection attempts that may indicate
    SSH or FTP brute-force activity.

    Detection idea:
        same source IP
        -> same target IP
        -> authentication service port
        -> many separate flows
    """

    if service_ports is None:
        service_ports = {
            21: "FTP",
            22: "SSH",
        }

    required_columns = {
        "src_ip",
        "dst_ip",
        "dst_port",
    }

    missing = (
        required_columns
        - set(flow_df.columns)
    )

    if missing:
        raise ValueError(
            f"Missing required flow columns: "
            f"{sorted(missing)}"
        )

    df = flow_df.copy()

    # =====================================================
    # CLEAN FIELDS
    # =====================================================

    df["src_ip"] = (
        df["src_ip"]
        .astype(str)
        .str.strip()
    )

    df["dst_ip"] = (
        df["dst_ip"]
        .astype(str)
        .str.strip()
    )

    df["dst_port"] = pd.to_numeric(
        df["dst_port"],
        errors="coerce",
    )

    df = df.dropna(
        subset=["dst_port"]
    )

    df["dst_port"] = (
        df["dst_port"]
        .astype(int)
    )

    # =====================================================
    # ONLY AUTHENTICATION SERVICES
    # =====================================================

    auth_flows = df[
        df["dst_port"].isin(
            service_ports.keys()
        )
    ]

    alerts = []

    if auth_flows.empty:
        return alerts

    # =====================================================
    # GROUP CONNECTION ATTEMPTS
    # =====================================================

    grouped = auth_flows.groupby(
        [
            "src_ip",
            "dst_ip",
            "dst_port",
        ]
    )

    for (
        source_ip,
        target_ip,
        target_port,
    ), group in grouped:

        attempts = len(group)

        if attempts < min_attempts:
            continue

        service = service_ports.get(
            int(target_port),
            "Unknown",
        )

        # =================================================
        # TIME INFORMATION
        # =================================================

        first_seen = "Unknown"
        last_seen = "Unknown"
        observed_window_seconds = None

        if "timestamp" in group.columns:

            timestamps = pd.to_datetime(
                group["timestamp"],
                errors="coerce",
            ).dropna()

            if not timestamps.empty:

                first_time = timestamps.min()
                last_time = timestamps.max()

                first_seen = str(
                    first_time
                )

                last_seen = str(
                    last_time
                )

                observed_window_seconds = (
                    last_time
                    - first_time
                ).total_seconds()

        # =================================================
        # SEVERITY
        # =================================================

        if attempts >= 100:

            severity = "CRITICAL"

        elif attempts >= 50:

            severity = "HIGH"

        else:

            severity = "MEDIUM"

        # =================================================
        # SOURCE PORT INFORMATION
        # =================================================

        unique_source_ports = 0

        if "src_port" in group.columns:

            unique_source_ports = int(
                group[
                    "src_port"
                ]
                .nunique()
            )

        # =================================================
        # ALERT
        # =================================================

        alerts.append(
            {
                "detection_engine":
                    "Behavioral IDS",

                "attack_type":
                    f"{service} Brute Force",

                "source_ip":
                    str(source_ip),

                "target_ip":
                    str(target_ip),

                "target_port":
                    int(target_port),

                "target_service":
                    service,

                "total_attempts":
                    int(attempts),

                "total_flows":
                    int(attempts),

                "unique_source_ports":
                    unique_source_ports,

                "first_seen":
                    first_seen,

                "last_seen":
                    last_seen,

                "observed_window_seconds":
                    observed_window_seconds,

                "severity":
                    severity,

                "status":
                    "ALERT",

                "reason": (
                    f"{source_ip} generated "
                    f"{attempts} connection attempts "
                    f"toward {target_ip}:"
                    f"{int(target_port)} "
                    f"({service})"
                ),
            }
        )

    return alerts


def detect_slow_http(
    flow_df: pd.DataFrame,
    min_suspicious_flows: int = 15,
    min_flow_duration: float = 5.0,
    max_packets_per_flow: int = 10,
    http_ports=None,
):
    """
    Detect Slowloris / Slow HTTP-style behavior.

    Heuristic:
    - same source -> same HTTP target
    - multiple long-lived flows
    - low packet count per flow
    - HTTP-related destination port

    flow_duration is expected in seconds for the 
    python cicflowmeter implementation used by this project.
    """

    if http_ports is None:
        http_ports = {
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-ALT",
        }

    required = {
        "src_ip",
        "dst_ip",
        "dst_port",
        "flow_duration",
        "tot_fwd_pkts",
        "tot_bwd_pkts",
    }

    missing = required - set(
        flow_df.columns
    )

    if missing:
        raise ValueError(
            f"Missing required flow columns: "
            f"{sorted(missing)}"
        )

    df = flow_df.copy()

    df["src_ip"] = (
        df["src_ip"]
        .astype(str)
        .str.strip()
    )

    df["dst_ip"] = (
        df["dst_ip"]
        .astype(str)
        .str.strip()
    )

    df["dst_port"] = pd.to_numeric(
        df["dst_port"],
        errors="coerce",
    )

    df["flow_duration"] = pd.to_numeric(
        df["flow_duration"],
        errors="coerce",
    )

    df["tot_fwd_pkts"] = pd.to_numeric(
        df["tot_fwd_pkts"],
        errors="coerce",
    ).fillna(0)

    df["tot_bwd_pkts"] = pd.to_numeric(
        df["tot_bwd_pkts"],
        errors="coerce",
    ).fillna(0)

    df = df.dropna(
        subset=[
            "dst_port",
            "flow_duration",
        ]
    )

    df["dst_port"] = (
        df["dst_port"]
        .astype(int)
    )

    df["total_packets"] = (
        df["tot_fwd_pkts"]
        + df["tot_bwd_pkts"]
    )

    # =====================================================
    # SLOW HTTP CANDIDATES
    # =====================================================

    candidates = df[
        (
            df["dst_port"].isin(
                http_ports.keys()
            )
        )
        &
        (
            df["flow_duration"]
            >= min_flow_duration
        )
        &
        (
            df["total_packets"]
            <= max_packets_per_flow
        )
    ]

    alerts = []

    if candidates.empty:
        return alerts

    grouped = candidates.groupby(
        [
            "src_ip",
            "dst_ip",
            "dst_port",
        ]
    )

    for (
        source_ip,
        target_ip,
        target_port,
    ), group in grouped:

        suspicious_flows = len(
            group
        )

        if (
            suspicious_flows
            < min_suspicious_flows
        ):
            continue

        service = http_ports.get(
            int(target_port),
            "HTTP",
        )

        avg_duration = float(
            group[
                "flow_duration"
            ].mean()
        )

        max_duration = float(
            group[
                "flow_duration"
            ].max()
        )

        avg_packets = float(
            group[
                "total_packets"
            ].mean()
        )

        first_seen = "Unknown"
        last_seen = "Unknown"
        observed_window_seconds = None

        if "timestamp" in group.columns:

            timestamps = pd.to_datetime(
                group["timestamp"],
                errors="coerce",
            ).dropna()

            if not timestamps.empty:

                first_time = timestamps.min()
                last_time = timestamps.max()

                first_seen = str(
                    first_time
                )

                last_seen = str(
                    last_time
                )

                observed_window_seconds = (
                    last_time
                    - first_time
                ).total_seconds()

        if suspicious_flows >= 50:

            severity = "CRITICAL"

        elif suspicious_flows >= 30:

            severity = "HIGH"

        else:

            severity = "MEDIUM"

        alerts.append(
            {
                "detection_engine":
                    "Behavioral IDS",

                "attack_type":
                    "Slow HTTP",

                "source_ip":
                    str(source_ip),

                "target_ip":
                    str(target_ip),

                "target_port":
                    int(target_port),

                "target_service":
                    service,

                "suspicious_flows":
                    int(suspicious_flows),

                "total_flows":
                    int(suspicious_flows),

                "average_flow_duration":
                    avg_duration,

                "max_flow_duration":
                    max_duration,

                "average_packets_per_flow":
                    avg_packets,

                "first_seen":
                    first_seen,

                "last_seen":
                    last_seen,

                "observed_window_seconds":
                    observed_window_seconds,

                "severity":
                    severity,

                "status":
                    "ALERT",

                "reason": (
                    f"{source_ip} maintained "
                    f"{suspicious_flows} long-lived "
                    f"low-packet connections toward "
                    f"{target_ip}:{int(target_port)} "
                    f"({service})"
                ),
            }
        )

    return alerts


def analyze_behavior(
    flow_df: pd.DataFrame,
):
    """
    Run all behavioral IDS detectors.
    """

    alerts = []

    # =====================================================
    # PORT SCAN
    # =====================================================

    alerts.extend(
        detect_port_scans(
            flow_df,
            min_unique_ports=10,
        )
    )

    # =====================================================
    # DoS / DDoS
    # =====================================================

    alerts.extend(
        detect_dos_ddos(
            flow_df,
            min_total_flows=100,
            min_sources=3,
            min_flows_per_source=20,
        )
    )

    # =====================================================
    # SSH / FTP BRUTE FORCE
    # =====================================================

    alerts.extend(
        detect_brute_force(
            flow_df,
            min_attempts=20,
        )
    )

    # =====================================================
    # SLOW HTTP / SLOWLORIS
    # =====================================================

    alerts.extend(
        detect_slow_http(
            flow_df,
            min_suspicious_flows=15,
            min_flow_duration=5.0,
            max_packets_per_flow=10,
        )
    )

    return alerts


if __name__ == "__main__":

    from pathlib import Path
    import sys
    import pprint

    PROJECT_ROOT = (
        Path(__file__).resolve().parent.parent
    )

    if len(sys.argv) < 2:

        print(
            "Usage:\n"
            "python src/behavior_detector.py "
            "<flow_csv>"
        )

        sys.exit(1)

    flow_file = Path(sys.argv[1])

    if not flow_file.is_absolute():
        flow_file = (
            PROJECT_ROOT / flow_file
        ).resolve()

    if not flow_file.exists():

        raise FileNotFoundError(
            f"Flow CSV not found:\n{flow_file}"
        )

    df = pd.read_csv(
        flow_file,
        low_memory=False,
    )

    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
    )

    print("=" * 65)
    print("AI-IDS BEHAVIORAL DETECTION")
    print("=" * 65)

    print(
        f"Flows loaded: {len(df):,}"
    )

    alerts = analyze_behavior(df)

    print(
        f"Behavioral alerts: {len(alerts)}"
    )

    print()

    if alerts:

        for alert in alerts:

            pprint.pp(alert)

            print("-" * 65)

    else:

        print(
            "No suspicious behavioral patterns detected."
        )
