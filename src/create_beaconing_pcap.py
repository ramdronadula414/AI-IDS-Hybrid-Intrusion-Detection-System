"""
Create a controlled synthetic PCAP containing
periodic outbound connections for Bot / C2 beaconing testing.

No real host is contacted.
"""

from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap
import time


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "test_beaconing.pcap"


SOURCE_IP = "192.168.56.70"
TARGET_IP = "192.168.56.80"
TARGET_PORT = 443

CONNECTION_COUNT = 20
BEACON_INTERVAL = 5.0
TTL = 64

packets = []

base_time = time.time()


for i in range(CONNECTION_COUNT):

    source_port = 47000 + i

    packet = (
        Ether()
        / IP(
            src=SOURCE_IP,
            dst=TARGET_IP,
            ttl=TTL,
        )
        / TCP(
            sport=source_port,
            dport=TARGET_PORT,
            flags="S",
            seq=1000 + i,
            window=64240,
        )
    )

    packet.time = (
        base_time
        + (i * BEACON_INTERVAL)
    )

    packets.append(packet)


wrpcap(
    str(OUTPUT_FILE),
    packets,
)


print("=" * 60)
print("CONTROLLED BOT / C2 BEACONING PCAP CREATED")
print("=" * 60)

print(f"Output: {OUTPUT_FILE}")
print(f"Source IP: {SOURCE_IP}")
print(f"Target IP: {TARGET_IP}:{TARGET_PORT}")
print(f"Connections: {CONNECTION_COUNT}")
print(f"Interval: {BEACON_INTERVAL} seconds")
print(f"Packets: {len(packets)}")
print(f"TTL: {TTL}")
print("Purpose: AI-IDS beaconing detection testing only")
