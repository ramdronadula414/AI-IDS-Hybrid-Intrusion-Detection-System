"""
AI-IDS Web Attack Detector

Detects suspicious HTTP request payload patterns such as:
- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)

This module is intended for defensive IDS analysis of
authorized PCAP captures.
"""

from pathlib import Path
from urllib.parse import unquote_plus
import re

from scapy.all import rdpcap, TCP, Raw, IP


# =========================================================
# SIGNATURE PATTERNS
# =========================================================

XSS_PATTERNS = [
    r"<script\b",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<img\b[^>]*onerror",
    r"<svg\b[^>]*onload",
    r"document\.cookie",
    r"alert\s*\(",
]


SQLI_PATTERNS = [
    r"\bunion\s+select\b",
    r"\bor\s+1\s*=\s*1\b",
    r"\band\s+1\s*=\s*1\b",
    r"'\s*or\s*'",
    r"--\s*$",
    r";\s*drop\s+table\b",
    r"\binformation_schema\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
]


# =========================================================
# PAYLOAD NORMALIZATION
# =========================================================

def normalize_payload(payload: str) -> str:
    """
    Normalize HTTP payload text so encoded attack strings
    can be inspected more reliably.
    """

    text = str(payload)

    try:
        text = unquote_plus(text)
    except Exception:
        pass

    return text.lower()


# =========================================================
# PATTERN MATCHING
# =========================================================

def find_matches(text, patterns):
    matches = []

    for pattern in patterns:

        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            matches.append(pattern)

    return matches


# =========================================================
# DETECT WEB ATTACKS IN PCAP
# =========================================================

def detect_web_attacks(
    pcap_file,
    web_ports=None,
):
    """
    Inspect TCP payloads in a PCAP and detect suspicious
    HTTP-level XSS / SQL Injection patterns.
    """

    if web_ports is None:
        web_ports = {
            80,
            8080,
            8000,
        }

    pcap_file = Path(
        pcap_file
    )

    if not pcap_file.exists():
        raise FileNotFoundError(
            f"PCAP not found: {pcap_file}"
        )

    packets = rdpcap(
        str(pcap_file)
    )

    alerts = []

    for packet_number, packet in enumerate(
        packets,
        start=1,
    ):

        if IP not in packet:
            continue

        if TCP not in packet:
            continue

        if Raw not in packet:
            continue

        tcp = packet[TCP]

        if int(tcp.dport) not in web_ports:
            continue

        raw_bytes = bytes(
            packet[Raw].load
        )

        try:
            payload = raw_bytes.decode(
                "utf-8",
                errors="ignore",
            )
        except Exception:
            continue

        if not payload:
            continue

        normalized = normalize_payload(
            payload
        )

        # -------------------------------------------------
        # Only inspect likely HTTP requests
        # -------------------------------------------------

        http_methods = (
            "get ",
            "post ",
            "put ",
            "delete ",
            "patch ",
            "head ",
        )

        if not normalized.startswith(
            http_methods
        ):
            continue

        source_ip = packet[IP].src
        target_ip = packet[IP].dst

        source_port = int(
            tcp.sport
        )

        target_port = int(
            tcp.dport
        )

        # =================================================
        # XSS
        # =================================================

        xss_matches = find_matches(
            normalized,
            XSS_PATTERNS,
        )

        if xss_matches:

            alerts.append({
                "detection_engine":
                    "Payload Inspection",

                "attack_type":
                    "Web Attack - XSS",

                "source_ip":
                    source_ip,

                "target_ip":
                    target_ip,

                "source_port":
                    source_port,

                "target_port":
                    target_port,

                "packet_number":
                    packet_number,

                "matched_patterns":
                    xss_matches,

                "severity":
                    "HIGH",

                "status":
                    "ALERT",

                "reason": (
                    f"Suspicious XSS indicators "
                    f"detected in HTTP request from "
                    f"{source_ip} to "
                    f"{target_ip}:{target_port}"
                ),
            })

        # =================================================
        # SQL INJECTION
        # =================================================

        sqli_matches = find_matches(
            normalized,
            SQLI_PATTERNS,
        )

        if sqli_matches:

            alerts.append({
                "detection_engine":
                    "Payload Inspection",

                "attack_type":
                    "Web Attack - SQL Injection",

                "source_ip":
                    source_ip,

                "target_ip":
                    target_ip,

                "source_port":
                    source_port,

                "target_port":
                    target_port,

                "packet_number":
                    packet_number,

                "matched_patterns":
                    sqli_matches,

                "severity":
                    "CRITICAL",

                "status":
                    "ALERT",

                "reason": (
                    f"Suspicious SQL injection "
                    f"indicators detected in HTTP "
                    f"request from {source_ip} to "
                    f"{target_ip}:{target_port}"
                ),
            })

    return alerts


# =========================================================
# COMMAND-LINE TEST
# =========================================================

def main():

    import sys
    import pprint

    if len(sys.argv) < 2:

        print(
            "Usage:\n"
            "python src/web_attack_detector.py "
            "\"data/raw/test_web_attacks.pcap\""
        )

        sys.exit(1)

    alerts = detect_web_attacks(
        sys.argv[1]
    )

    print("=" * 65)
    print("AI-IDS WEB ATTACK DETECTION")
    print("=" * 65)

    print(
        f"Alerts detected: "
        f"{len(alerts)}"
    )

    if alerts:

        for alert in alerts:

            pprint.pp(
                alert
            )

            print(
                "-" * 65
            )

    else:

        print(
            "No suspicious web attack "
            "patterns detected."
        )


if __name__ == "__main__":
    main()
