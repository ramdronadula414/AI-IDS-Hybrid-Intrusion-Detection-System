"""
Create a controlled PCAP containing synthetic HTTP requests
for XSS and SQL Injection detection testing.

No real host is contacted.
"""

from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap
import time


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "test_web_attacks.pcap"


SOURCE_IP = "192.168.56.50"
TARGET_IP = "192.168.56.60"
TARGET_PORT = 80
TTL = 64

packets = []

base_time = time.time()


def add_http_request(
    source_port,
    payload,
    offset,
):

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
            flags="PA",
            seq=1000,
            ack=1,
            window=64240,
        )
        / Raw(
            load=payload.encode("utf-8")
        )
    )

    packet.time = base_time + offset

    packets.append(packet)


# =========================================================
# NORMAL HTTP REQUEST
# =========================================================

add_http_request(
    source_port=41000,
    payload=(
        "GET /index.html HTTP/1.1\r\n"
        "Host: test.local\r\n"
        "User-Agent: AI-IDS-Test\r\n"
        "\r\n"
    ),
    offset=0.0,
)


# =========================================================
# XSS-STYLE TEST REQUEST
# =========================================================

add_http_request(
    source_port=41001,
    payload=(
        "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E "
        "HTTP/1.1\r\n"
        "Host: test.local\r\n"
        "User-Agent: AI-IDS-Test\r\n"
        "\r\n"
    ),
    offset=0.5,
)


# =========================================================
# SQL-INJECTION-STYLE TEST REQUEST
# =========================================================

add_http_request(
    source_port=41002,
    payload=(
        "GET /login?username=admin&password=%27%20OR%201%3D1-- "
        "HTTP/1.1\r\n"
        "Host: test.local\r\n"
        "User-Agent: AI-IDS-Test\r\n"
        "\r\n"
    ),
    offset=1.0,
)


# =========================================================
# SAVE PCAP
# =========================================================

wrpcap(
    str(OUTPUT_FILE),
    packets,
)


print("=" * 60)
print("CONTROLLED WEB ATTACK TEST PCAP CREATED")
print("=" * 60)

print(f"Output: {OUTPUT_FILE}")
print(f"Source IP: {SOURCE_IP}")
print(f"Target IP: {TARGET_IP}:{TARGET_PORT}")
print("Normal HTTP requests: 1")
print("XSS-style requests: 1")
print("SQLi-style requests: 1")
print(f"Packets: {len(packets)}")
print("Purpose: AI-IDS payload detection testing only")
