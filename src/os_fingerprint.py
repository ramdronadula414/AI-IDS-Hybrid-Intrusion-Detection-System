"""
Passive OS Fingerprinting for AI-IDS

Uses packet metadata from PCAP files to estimate the
likely operating-system family of each source IP.

This is heuristic only and must not be treated as
definitive OS identification.
"""

from collections import defaultdict, Counter
from pathlib import Path

from scapy.all import rdpcap, IP, TCP


# =========================================================
# TTL-BASED OS ESTIMATION
# =========================================================

def estimate_os_from_ttl(ttl):
    """
    Estimate likely OS family from observed TTL.

    Because TTL is reduced by routers, we map the observed
    value to the nearest common initial TTL family.
    """

    try:
        ttl = int(ttl)
    except (TypeError, ValueError):

        return {
            "os": "Unknown",
            "confidence": "Unknown",
            "initial_ttl_guess": None,
            "evidence": "TTL unavailable",
        }

    # -----------------------------------------------------
    # Estimate original TTL family
    # -----------------------------------------------------

    if ttl <= 32:
        initial_ttl = 32

    elif ttl <= 64:
        initial_ttl = 64

    elif ttl <= 128:
        initial_ttl = 128

    else:
        initial_ttl = 255

    # -----------------------------------------------------
    # OS-family guess
    # -----------------------------------------------------

    if initial_ttl == 64:

        os_guess = "Linux / Unix-like / macOS"

        confidence = "Low"

    elif initial_ttl == 128:

        os_guess = "Windows-like"

        confidence = "Low"

    elif initial_ttl == 255:

        os_guess = "Network device / Unix-like appliance"

        confidence = "Low"

    else:

        os_guess = "Unknown / Legacy system"

        confidence = "Low"

    return {
        "os": os_guess,
        "confidence": confidence,
        "initial_ttl_guess": initial_ttl,
        "observed_ttl": ttl,
        "evidence": (
            f"Observed TTL {ttl}; "
            f"nearest common initial TTL {initial_ttl}"
        ),
    }


# =========================================================
# PCAP FINGERPRINT EXTRACTION
# =========================================================

def fingerprint_pcap(pcap_file):
    """
    Analyze packets in a PCAP and build one passive
    fingerprint per observed source IP.
    """

    pcap_path = Path(
        pcap_file
    )

    if not pcap_path.exists():

        raise FileNotFoundError(
            f"PCAP file not found:\n{pcap_path}"
        )

    packets = rdpcap(
        str(pcap_path)
    )

    hosts = defaultdict(
        lambda: {
            "ttls": [],
            "tcp_windows": [],
            "tcp_options": [],
            "packet_count": 0,
        }
    )

    # -----------------------------------------------------
    # Collect packet characteristics
    # -----------------------------------------------------

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src

        hosts[source_ip][
            "packet_count"
        ] += 1

        hosts[source_ip][
            "ttls"
        ].append(
            int(packet[IP].ttl)
        )

        if TCP in packet:

            hosts[source_ip][
                "tcp_windows"
            ].append(
                int(packet[TCP].window)
            )

            hosts[source_ip][
                "tcp_options"
            ].append(
                packet[TCP].options
            )

    # -----------------------------------------------------
    # Build one fingerprint per source IP
    # -----------------------------------------------------

    results = {}

    for source_ip, data in hosts.items():

        if not data["ttls"]:

            continue

        # Most common observed TTL
        ttl_counter = Counter(
            data["ttls"]
        )

        common_ttl = ttl_counter.most_common(
            1
        )[0][0]

        os_result = estimate_os_from_ttl(
            common_ttl
        )

        # Most common TCP window
        common_window = None

        if data["tcp_windows"]:

            common_window = Counter(
                data["tcp_windows"]
            ).most_common(
                1
            )[0][0]

        results[source_ip] = {
            "source_ip": source_ip,

            "estimated_os": os_result[
                "os"
            ],

            "confidence": os_result[
                "confidence"
            ],

            "observed_ttl": os_result.get(
                "observed_ttl"
            ),

            "initial_ttl_guess": os_result[
                "initial_ttl_guess"
            ],

            "tcp_window": common_window,

            "packet_count": data[
                "packet_count"
            ],

            "evidence": os_result[
                "evidence"
            ],

            "method": (
                "Passive TTL/TCP fingerprint"
            ),
        }

    return results


# =========================================================
# COMMAND-LINE TEST
# =========================================================

if __name__ == "__main__":

    import sys
    import pprint

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            'python src\\os_fingerprint.py '
            '"data\\raw\\test_traffic.pcap"'
        )

        sys.exit(1)

    fingerprints = fingerprint_pcap(
        sys.argv[1]
    )

    pprint.pp(
        fingerprints
    )