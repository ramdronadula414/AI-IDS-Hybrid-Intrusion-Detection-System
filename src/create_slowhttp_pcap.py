"""
Create a controlled PCAP containing long-lived,
low-packet HTTP connections for Slow HTTP detection testing.

This does not contact any real host.
"""

from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "test_slowhttp.pcap"

SOURCE_IP = "192.168.56.30"
TARGET_IP = "192.168.56.40"
TARGET_PORT = 80

FLOW_COUNT = 25
TTL = 64

packets = []

base_time = time.time()

for i in range(FLOW_COUNT):

    src_port = 45000 + i

    start_time = base_time + (i * 0.10)

    # SYN
    syn = (
        Ether()
        / IP(
            src=SOURCE_IP,
            dst=TARGET_IP,
            ttl=TTL,
        )
        / TCP(
            sport=src_port,
            dport=TARGET_PORT,
            flags="S",
            seq=1000 + i,
            window=64240,
        )
    )

    syn.time = start_time

    # SYN-ACK
    syn_ack = (
        Ether()
        / IP(
            src=TARGET_IP,
            dst=SOURCE_IP,
            ttl=64,
        )
        / TCP(
            sport=TARGET_PORT,
            dport=src_port,
            flags="SA",
            seq=2000 + i,
            ack=1001 + i,
            window=64240,
        )
    )

    syn_ack.time = start_time + 0.01

    # small HTTP fragment after a long delay
    slow_packet = (
        Ether()
        / IP(
            src=SOURCE_IP,
            dst=TARGET_IP,
            ttl=TTL,
        )
        / TCP(
            sport=src_port,
            dport=TARGET_PORT,
            flags="PA",
            seq=1001 + i,
            ack=2001 + i,
            window=64240,
        )
        / b"GET / HTTP/1.1\r\nHost: test\r\n"
    )

    # 8 seconds later -> long-lived flow
    slow_packet.time = start_time + 8.0

    packets.extend(
        [
            syn,
            syn_ack,
            slow_packet,
        ]
    )

wrpcap(
    str(OUTPUT_FILE),
    packets,
)

print("=" * 60)
print("CONTROLLED SLOW HTTP TEST PCAP CREATED")
print("=" * 60)

print(f"Output: {OUTPUT_FILE}")
print(f"Source IP: {SOURCE_IP}")
print(f"Target IP: {TARGET_IP}:{TARGET_PORT}")
print(f"Connections: {FLOW_COUNT}")
print(f"Packets: {len(packets)}")
print("Approx flow duration: 8 seconds")
print("Purpose: AI-IDS Slow HTTP detection testing only")
