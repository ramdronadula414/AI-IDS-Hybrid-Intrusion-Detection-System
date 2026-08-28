"""
Create a controlled port-scan-style PCAP for AI-IDS testing.

This does NOT send packets over the network.
It only creates an offline PCAP file.

Source:
    192.168.1.50

Target:
    192.168.1.100

Ports:
    20-100
"""

from pathlib import Path
import time

from scapy.all import (
    Ether,
    IP,
    TCP,
    wrpcap,
)


# =========================================================
# PATHS
# =========================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "test_portscan.pcap"
)


# =========================================================
# TEST NETWORK
# =========================================================

SOURCE_IP = "192.168.1.50"
TARGET_IP = "192.168.1.100"

SOURCE_MAC = "02:00:00:00:50:01"
TARGET_MAC = "02:00:00:00:50:02"


# =========================================================
# PACKET CREATION
# =========================================================

packets = []

base_time = time.time()

packet_index = 0


# ---------------------------------------------------------
# Simulated SYN scan
# ---------------------------------------------------------

for destination_port in range(20, 101):

    source_port = (
        40000
        + destination_port
    )

    packet = (
        Ether(
            src=SOURCE_MAC,
            dst=TARGET_MAC,
        )
        /
        IP(
            src=SOURCE_IP,
            dst=TARGET_IP,

            # Used later by passive OS fingerprinting
            ttl=64,
        )
        /
        TCP(
            sport=source_port,
            dport=destination_port,

            # SYN packet
            flags="S",

            seq=1000 + packet_index,

            window=64240,

            options=[
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (123456, 0)),
                ("NOP", None),
                ("WScale", 7),
            ],
        )
    )

    # Give packets slightly different timestamps
    packet.time = (
        base_time
        + packet_index * 0.002
    )

    packets.append(
        packet
    )

    packet_index += 1


# ---------------------------------------------------------
# Add several repeated probe flows
# ---------------------------------------------------------

common_ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    443,
    445,
    3389,
    8080,
]

for repeat in range(4):

    for destination_port in common_ports:

        source_port = (
            50000
            + repeat * 100
            + destination_port % 100
        )

        packet = (
            Ether(
                src=SOURCE_MAC,
                dst=TARGET_MAC,
            )
            /
            IP(
                src=SOURCE_IP,
                dst=TARGET_IP,
                ttl=64,
            )
            /
            TCP(
                sport=source_port,
                dport=destination_port,
                flags="S",
                seq=5000 + packet_index,
                window=64240,
                options=[
                    ("MSS", 1460),
                    ("SAckOK", b""),
                    ("WScale", 7),
                ],
            )
        )

        packet.time = (
            base_time
            + packet_index * 0.002
        )

        packets.append(
            packet
        )

        packet_index += 1


# =========================================================
# SAVE PCAP
# =========================================================

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

wrpcap(
    str(OUTPUT_FILE),
    packets
)


# =========================================================
# SUMMARY
# =========================================================

print("=" * 60)
print("CONTROLLED PORT-SCAN PCAP CREATED")
print("=" * 60)

print(
    f"Output: {OUTPUT_FILE}"
)

print(
    f"Source IP: {SOURCE_IP}"
)

print(
    f"Target IP: {TARGET_IP}"
)

print(
    f"Packets: {len(packets)}"
)

print(
    "TTL: 64"
)

print(
    "Traffic: TCP SYN probes"
)

print(
    "Purpose: AI-IDS pipeline testing only"
)