"""
Threat Intelligence Enrichment

Provides:
- IP classification
- Source/destination information
- Ports
- Protocol
- Private/public determination
- Basic service identification
"""

import ipaddress
import socket
from pathlib import Path

try:
    import geoip2.database
except ImportError:
    geoip2 = None


PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

CITY_DB = (
    PROJECT_ROOT
    / "data"
    / "geoip"
    / "GeoLite2-City.mmdb"
)

ASN_DB = (
    PROJECT_ROOT
    / "data"
    / "geoip"
    / "GeoLite2-ASN.mmdb"
)


COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternative",
}


def analyze_ip(ip_string):
    """Classify an IP address safely."""

    try:
        ip = ipaddress.ip_address(
            str(ip_string)
        )
    except ValueError:

        return {
            "ip": str(ip_string),
            "valid": False,
            "scope": "Invalid",
            "is_private": False,
            "is_global": False,
        }

    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    for network in documentation_networks:

        if ip in network:

            return {
                "ip": str(ip),
                "valid": True,
                "scope": "Documentation / Reserved Network",
                "is_private": False,
                "is_global": False,
            }

    if ip.is_loopback:
        scope = "Loopback"

    elif ip.is_private:
        scope = "Private Network"

    elif ip.is_multicast:
        scope = "Multicast"

    elif ip.is_link_local:
        scope = "Link Local"

    elif ip.is_global:
        scope = "Public Internet"

    else:
        scope = "Reserved / Special"

    return {
        "ip": str(ip),
        "valid": True,
        "scope": scope,
        "is_private": ip.is_private,
        "is_global": ip.is_global,
    }


def identify_service(port):
    """Identify likely service using destination port."""

    try:
        port = int(port)
    except (ValueError, TypeError):
        return "Unknown"

    if port in COMMON_PORTS:
        return COMMON_PORTS[port]

    try:
        return socket.getservbyport(
            port
        )
    except Exception:
        return "Unknown"


def enrich_flow(flow):
    """
    Create complete threat context from one flow.
    """

    src_ip = flow.get(
        "src_ip",
        "Unknown"
    )

    dst_ip = flow.get(
        "dst_ip",
        "Unknown"
    )

    src_port = flow.get(
        "src_port",
        "Unknown"
    )

    dst_port = flow.get(
        "dst_port",
        "Unknown"
    )

    protocol = flow.get(
        "protocol",
        "Unknown"
    )

    timestamp = flow.get(
        "timestamp",
        "Unknown"
    )

    source_ip_info = analyze_ip(
        src_ip
    )

    destination_ip_info = analyze_ip(
        dst_ip
    )

    source_geolocation = geolocate_ip(
        src_ip
    )

    destination_geolocation = geolocate_ip(
        dst_ip
    )

    source_asn_info = lookup_asn(
        src_ip
    )

    destination_asn_info = lookup_asn(
        dst_ip
    )

    return {
        # Source / suspected attacker
        "source_ip": src_ip,
        "source_ip_info": source_ip_info,
        "source_geolocation": source_geolocation,
        "source_asn_info": source_asn_info,

        # Destination / target
        "destination_ip": dst_ip,
        "destination_ip_info": destination_ip_info,
        "destination_geolocation": destination_geolocation,
        "destination_asn_info": destination_asn_info,

        # Network context
        "source_port": src_port,
        "destination_port": dst_port,

        "target_service": identify_service(
            dst_port
        ),

        "protocol": protocol,
        "timestamp": timestamp,
    }

def geolocate_ip(ip_string):
    """Look up city-level GeoIP data for a public IP address."""

    ip_info = analyze_ip(
        ip_string
    )

    if not ip_info["valid"]:

        return {
            "available": False,
            "reason": "Invalid IP",
        }

    if ip_info.get("scope") == "Documentation / Reserved Network":

        return {
            "available": False,
            "reason": "Documentation / Reserved Network",
        }

    if not ip_info["is_global"]:

        return {
            "available": False,
            "reason": ip_info["scope"],
        }

    if geoip2 is None:

        return {
            "available": False,
            "reason": "geoip2 library not installed",
        }

    if not CITY_DB.exists():

        return {
            "available": False,
            "reason": "GeoLite2 City database unavailable",
        }

    try:

        with geoip2.database.Reader(
            str(CITY_DB)
        ) as reader:

            record = reader.city(
                ip_string
            )

            return {
                "available": True,

                "country": (
                    record.country.name
                    or "Unknown"
                ),

                "country_code": (
                    record.country.iso_code
                    or "Unknown"
                ),

                "region": (
                    record.subdivisions.most_specific.name
                    or "Unknown"
                ),

                "city": (
                    record.city.name
                    or "Unknown"
                ),

                "latitude": (
                    record.location.latitude
                ),

                "longitude": (
                    record.location.longitude
                ),
            }

    except Exception as exc:

        return {
            "available": False,
            "reason": str(exc),
        }


def lookup_asn(ip_string):
    """Look up the owning ASN / organization for a public IP address."""

    ip_info = analyze_ip(
        ip_string
    )

    if ip_info.get("scope") == "Documentation / Reserved Network":

        return {
            "available": False,
            "reason": "Documentation / Reserved Network",
        }

    if not ip_info["is_global"]:

        return {
            "available": False,
            "reason": ip_info["scope"],
        }

    if geoip2 is None:

        return {
            "available": False,
            "reason": "geoip2 library not installed",
        }

    if not ASN_DB.exists():

        return {
            "available": False,
            "reason": "GeoLite2 ASN database unavailable",
        }

    try:

        with geoip2.database.Reader(
            str(ASN_DB)
        ) as reader:

            record = reader.asn(
                ip_string
            )

            return {
                "available": True,

                "asn": (
                    record.autonomous_system_number
                ),

                "organization": (
                    record.autonomous_system_organization
                    or "Unknown"
                ),
            }

    except Exception as exc:

        return {
            "available": False,
            "reason": str(exc),
        }