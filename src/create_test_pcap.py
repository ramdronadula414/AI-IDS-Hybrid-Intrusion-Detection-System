from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "test_traffic.pcap"
)


packets = []


# =========================================================
# TCP FLOWS
# =========================================================

for i in range(10):

    src_port = 5000 + i

    # Client -> server SYN
    packets.append(
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        /
        IP(
            src="192.168.1.10",
            dst="192.168.1.20",
        )
        /
        TCP(
            sport=src_port,
            dport=80,
            flags="S",
            seq=1000 + i,
        )
    )

    # Server -> client SYN/ACK
    packets.append(
        Ether(
            src="02:00:00:00:00:02",
            dst="02:00:00:00:00:01",
        )
        /
        IP(
            src="192.168.1.20",
            dst="192.168.1.10",
        )
        /
        TCP(
            sport=80,
            dport=src_port,
            flags="SA",
            seq=2000 + i,
            ack=1001 + i,
        )
    )

    # Client -> server ACK + payload
    packets.append(
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        /
        IP(
            src="192.168.1.10",
            dst="192.168.1.20",
        )
        /
        TCP(
            sport=src_port,
            dport=80,
            flags="PA",
            seq=1001 + i,
            ack=2001 + i,
        )
        /
        Raw(
            load=b"AI-IDS test HTTP payload"
        )
    )

    # Server -> client response
    packets.append(
        Ether(
            src="02:00:00:00:00:02",
            dst="02:00:00:00:00:01",
        )
        /
        IP(
            src="192.168.1.20",
            dst="192.168.1.10",
        )
        /
        TCP(
            sport=80,
            dport=src_port,
            flags="PA",
            seq=2001 + i,
            ack=1025 + i,
        )
        /
        Raw(
            load=b"AI-IDS test response"
        )
    )


# =========================================================
# UDP FLOWS
# =========================================================

for i in range(10):

    src_port = 6000 + i

    # Client -> server
    packets.append(
        Ether(
            src="02:00:00:00:00:03",
            dst="02:00:00:00:00:04",
        )
        /
        IP(
            src="192.168.1.30",
            dst="192.168.1.40",
        )
        /
        UDP(
            sport=src_port,
            dport=53,
        )
        /
        Raw(
            load=b"AI-IDS UDP request"
        )
    )

    # Server -> client
    packets.append(
        Ether(
            src="02:00:00:00:00:04",
            dst="02:00:00:00:00:03",
        )
        /
        IP(
            src="192.168.1.40",
            dst="192.168.1.30",
        )
        /
        UDP(
            sport=53,
            dport=src_port,
        )
        /
        Raw(
            load=b"AI-IDS UDP response"
        )
    )


# =========================================================
# WRITE PCAP
# =========================================================

OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True
)

wrpcap(
    str(OUTPUT),
    packets
)

print("Test PCAP created:")
print(OUTPUT)

print("Packets:", len(packets))