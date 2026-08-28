"""
Create a controlled PCAP containing repeated SSH and FTP
connection attempts for AI-IDS brute-force detection testing.

This does NOT contact a real target.
It only writes synthetic packets into a PCAP file.
"""

from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap
import random
import time


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "test_bruteforce.pcap"
)


ATTACKER_IP = "192.168.56.10"
TARGET_IP = "192.168.56.20"

TTL = 64

packets = []

base_time = time.time()


def add_connection_attempts(
    target_port,
    attempts,
    start_source_port,
):
    """
    Generate repeated TCP SYN attempts toward one service.
    """

    global packets

    for i in range(attempts):

        src_port = (
            start_source_port
            + i
        )

        packet = (
            Ether()
            / IP(
                src=ATTACKER_IP,
                dst=TARGET_IP,
                ttl=TTL,
            )
            / TCP(
                sport=src_port,
                dport=target_port,
                flags="S",
                seq=random.randint(
                    1000,
                    999999,
                ),
                window=64240,
                options=[
                    ("MSS", 1460),
                    ("SAckOK", b""),
                    ("NOP", None),
                    ("WScale", 7),
                ],
            )
        )

        packet.time = (
            base_time
            + (i * 0.02)
        )

        packets.append(
            packet
        )


# =========================================================
# SSH BRUTE-FORCE STYLE TRAFFIC
# =========================================================

add_connection_attempts(
    target_port=22,
    attempts=60,
    start_source_port=40000,
)


# =========================================================
# FTP BRUTE-FORCE STYLE TRAFFIC
# =========================================================

add_connection_attempts(
    target_port=21,
    attempts=35,
    start_source_port=50000,
)


# =========================================================
# SAVE PCAP
# =========================================================

wrpcap(
    str(OUTPUT_FILE),
    packets,
)


print("=" * 60)
print("CONTROLLED BRUTE-FORCE TEST PCAP CREATED")
print("=" * 60)

print(
    f"Output: {OUTPUT_FILE}"
)

print(
    f"Source IP: {ATTACKER_IP}"
)

print(
    f"Target IP: {TARGET_IP}"
)

print(
    "SSH attempts: 60"
)

print(
    "FTP attempts: 35"
)

print(
    f"Packets: {len(packets)}"
)

print(
    f"TTL: {TTL}"
)

print(
    "Purpose: AI-IDS brute-force detection testing only"
)
