"""
AI-IDS PCAP Pipeline

This module connects:
- PCAP processing
- ML prediction
- Behavioral detection
- Threat intelligence
- Passive OS fingerprinting
"""

from pathlib import Path
import sys
import json
import pandas as pd


# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# IMPORT PROJECT MODULES
# =========================================================

from src.pcap_processor import process_pcap
from src.predict import predict
from src.behavior_detector import analyze_behavior
from src.threat_intelligence import enrich_flow
from src.os_fingerprint import fingerprint_pcap
from src.correlation_engine import correlate_detection
from src.web_attack_detector import detect_web_attacks


# =========================================================
# MAIN
# =========================================================

def analyze_pcap(pcap_file):

    pcap_file = Path(pcap_file)

    if not pcap_file.is_absolute():
        pcap_file = (
            PROJECT_ROOT
            / pcap_file
        ).resolve()

    if not pcap_file.exists():
        raise FileNotFoundError(
            f"PCAP file not found:\n{pcap_file}"
        )

    print("=" * 70)
    print("AI-IDS PCAP PIPELINE")
    print("=" * 70)

    print(
        f"Input PCAP: {pcap_file}"
    )

    # =====================================================
    # STEP 1 — PROCESS PCAP
    # =====================================================

    print("\n[1/5] Processing PCAP...")

    model_feature_file = process_pcap(
        pcap_file
    )

    model_feature_file = Path(
        model_feature_file
    )

    # -----------------------------------------------------
    # Locate raw CICFlowMeter CSV
    # -----------------------------------------------------

    raw_flow_file = (
        model_feature_file.parent
        / model_feature_file.name.replace(
            "_model_features.csv",
            ".csv"
        )
    )

    if not raw_flow_file.exists():
        raise FileNotFoundError(
            f"Raw flow file not found:\n"
            f"{raw_flow_file}"
        )

    # -----------------------------------------------------
    # Load raw metadata flows
    # -----------------------------------------------------

    raw_flows = pd.read_csv(
        raw_flow_file,
        low_memory=False
    )

    raw_flows.columns = (
        raw_flows.columns
        .astype(str)
        .str.strip()
    )

    # -----------------------------------------------------
    # Load 78 ML features
    # -----------------------------------------------------

    model_features = pd.read_csv(
        model_feature_file,
        low_memory=False
    )

    print(
        f"Raw flows loaded: {len(raw_flows):,}"
    )

    print(
        f"Model feature rows: {len(model_features):,}"
    )

    print(
        f"Model features: {len(model_features.columns)}"
    )

    # -----------------------------------------------------
    # Row alignment check
    # -----------------------------------------------------

    if len(raw_flows) != len(model_features):

        raise ValueError(
            "Raw flow rows and ML feature rows "
            "do not match."
        )

    # =====================================================
    # STEP 2 — XGBOOST ML IDS
    # =====================================================

    print("\n[2/5] Running XGBoost ML IDS...")

    ml_results = predict(
        model_features
    )

    ml_attack_count = int(
        (
            ml_results[
                "Binary Prediction"
            ]
            == "ATTACK"
        ).sum()
    )

    ml_benign_count = (
        len(ml_results)
        - ml_attack_count
    )

    print(
        f"ML flows analyzed: {len(ml_results):,}"
    )

    print(
        f"ML benign: {ml_benign_count:,}"
    )

    print(
        f"ML attacks: {ml_attack_count:,}"
    )

    if ml_attack_count > 0:

        ml_attacks = ml_results[
            ml_results[
                "Binary Prediction"
            ]
            == "ATTACK"
        ]

        print(
            "\nML detected attack types:"
        )

        print(
            ml_attacks[
                "Attack Type"
            ]
            .value_counts()
            .to_string()
        )

    else:

        print(
            "No attacks detected by ML model."
        )

    # =====================================================
    # STEP 3 — BEHAVIORAL IDS
    # =====================================================

    print(
        "\n[3/5] Running Behavioral IDS..."
    )

    behavior_alerts = analyze_behavior(
        raw_flows
    )
    # =====================================================
    # PASSIVE OS FINGERPRINTING
    # =====================================================

    os_fingerprints = fingerprint_pcap(
        str(pcap_file)
    )

    print(
        f"Behavioral alerts detected: "
        f"{len(behavior_alerts)}"
    )

    if behavior_alerts:

        print(
            "\nDetected behavioral threats:"
        )

        for alert in behavior_alerts:

            source_ip = str(
                alert["source_ip"]
            )

            target_ip = str(
                alert["target_ip"]
            )

            source_ips = alert.get(
                "source_ips",
                []
            )

            if not source_ips:
                source_ips = [
                    source_ip
                ]

            attack_type = alert.get(
                "attack_type",
                "Unknown"
            )

            # =================================================
            # SOURCE ENRICHMENT (PortScan / Brute Force /
            # Slow HTTP: single source)
            # =================================================

            if attack_type in {
                "PortScan",
                "SSH Brute Force",
                "FTP Brute Force",
                "Slow HTTP",
            }:

                os_info = os_fingerprints.get(
                    source_ip,
                    {}
                )

                sample_flow = {
                    "src_ip": source_ip,
                    "dst_ip": target_ip,
                    "src_port": "Unknown",
                    "dst_port": "Unknown",

                    "protocol": (
                        alert["protocols"][0]
                        if alert.get("protocols")
                        else "Unknown"
                    ),

                    "timestamp": alert.get(
                        "first_seen",
                        "Unknown"
                    ),
                }

                threat_info = enrich_flow(
                    sample_flow
                )

                source_geo = threat_info.get(
                    "source_geolocation",
                    {}
                )

                source_asn = threat_info.get(
                    "source_asn_info",
                    {}
                )

                source_scope = (
                    threat_info
                    .get(
                        "source_ip_info",
                        {}
                    )
                    .get(
                        "scope",
                        "Unknown"
                    )
                )

            # =================================================
            # SOURCE ENRICHMENT (DoS/DDoS: per attacker)
            # =================================================

            elif attack_type in {
                "DoS",
                "DDoS",
            }:

                attacker_details = []

                flow_counts = alert.get(
                    "source_flow_counts",
                    {}
                )

                for attacker_ip in source_ips:

                    attacker_ip = str(
                        attacker_ip
                    )

                    attacker_os_info = os_fingerprints.get(
                        attacker_ip,
                        {}
                    )

                    attacker_threat_info = enrich_flow({
                        "src_ip": attacker_ip,
                        "dst_ip": target_ip,
                        "src_port": "Unknown",
                        "dst_port": alert.get(
                            "target_port",
                            "Unknown"
                        ),
                        "protocol": "6",
                        "timestamp": alert.get(
                            "first_seen",
                            "Unknown"
                        ),
                    })

                    attacker_geo = attacker_threat_info.get(
                        "source_geolocation",
                        {}
                    )

                    attacker_asn = attacker_threat_info.get(
                        "source_asn_info",
                        {}
                    )

                    attacker_ip_info = attacker_threat_info.get(
                        "source_ip_info",
                        {}
                    )

                    attacker_details.append({
                        "ip": attacker_ip,

                        "flows": flow_counts.get(
                            attacker_ip,
                            0
                        ),

                        "scope": attacker_ip_info.get(
                            "scope",
                            "Unknown"
                        ),

                        "estimated_os": attacker_os_info.get(
                            "estimated_os",
                            "Unknown"
                        ),

                        "os_confidence": attacker_os_info.get(
                            "confidence",
                            "Unknown"
                        ),

                        "ttl": attacker_os_info.get(
                            "observed_ttl",
                            "Unknown"
                        ),

                        "tcp_window": attacker_os_info.get(
                            "tcp_window",
                            "Unknown"
                        ),

                        "country": attacker_geo.get(
                            "country",
                            attacker_geo.get(
                                "reason",
                                "Unknown"
                            )
                        ),

                        "region": attacker_geo.get(
                            "region",
                            "Unknown"
                        ),

                        "city": attacker_geo.get(
                            "city",
                            "Unknown"
                        ),

                        "asn": attacker_asn.get(
                            "asn"
                        ),

                        "organization": attacker_asn.get(
                            "organization",
                            attacker_asn.get(
                                "reason",
                                "Unavailable"
                            )
                        ),
                    })

            # =================================================
            # PRINT ALERT
            # =================================================

            print(
                "\n" + "-" * 60
            )

            print(
                f"Severity: "
                f"{alert.get('severity', 'Unknown')}"
            )

            print(
                f"Attack Type: "
                f"{attack_type}"
            )

            print(
                f"Detection Engine: "
                f"{alert.get('detection_engine', 'Unknown')}"
            )

            print(
                f"Source IP: "
                f"{source_ip}"
            )

            print(
                f"Target IP: "
                f"{target_ip}"
            )

            # =================================================
            # PORTSCAN-SPECIFIC DETAILS
            # =================================================

            if attack_type == "PortScan":

                print(
                    f"Unique Ports: "
                    f"{alert.get('unique_ports', 0)}"
                )

                print(
                    f"Total Flows: "
                    f"{alert.get('total_flows', 0)}"
                )

                protocols = alert.get(
                    "protocols",
                    []
                )

                print(
                    f"Protocols: "
                    f"{', '.join(protocols) if protocols else 'Unknown'}"
                )

            # =================================================
            # BRUTE FORCE-SPECIFIC DETAILS
            # =================================================

            elif attack_type in {
                "SSH Brute Force",
                "FTP Brute Force",
            }:

                print(
                    f"Target Port: "
                    f"{alert.get('target_port', 'Unknown')}"
                )

                print(
                    f"Target Service: "
                    f"{alert.get('target_service', 'Unknown')}"
                )

                print(
                    f"Total Attempts: "
                    f"{alert.get('total_attempts', 0)}"
                )

                print(
                    f"Unique Source Ports: "
                    f"{alert.get('unique_source_ports', 0)}"
                )

                window = alert.get(
                    "observed_window_seconds"
                )

                print(
                    f"Observed Window: "
                    f"{window if window is not None else 'Unknown'} seconds"
                )

            # =================================================
            # SLOW HTTP-SPECIFIC DETAILS
            # =================================================

            elif attack_type == "Slow HTTP":

                print(
                    f"Target Port: "
                    f"{alert.get('target_port', 'Unknown')}"
                )

                print(
                    f"Target Service: "
                    f"{alert.get('target_service', 'Unknown')}"
                )

                print(
                    f"Suspicious Flows: "
                    f"{alert.get('suspicious_flows', 0)}"
                )

                print(
                    f"Average Flow Duration: "
                    f"{alert.get('average_flow_duration', 'Unknown')} seconds"
                )

                print(
                    f"Maximum Flow Duration: "
                    f"{alert.get('max_flow_duration', 'Unknown')} seconds"
                )

                print(
                    f"Average Packets / Flow: "
                    f"{alert.get('average_packets_per_flow', 'Unknown')}"
                )

                window = alert.get(
                    "observed_window_seconds"
                )

                print(
                    f"Observed Window: "
                    f"{window if window is not None else 'Unknown'} seconds"
                )

            # =================================================
            # DOS / DDOS-SPECIFIC DETAILS
            # =================================================

            elif attack_type in {
                "DoS",
                "DDoS",
            }:

                print(
                    f"Target Port: "
                    f"{alert.get('target_port', 'Unknown')}"
                )

                print(
                    f"Source Count: "
                    f"{alert.get('source_count', 1)}"
                )

                print(
                    f"Total Flows: "
                    f"{alert.get('total_flows', 0)}"
                )

                source_counts = alert.get(
                    "source_flow_counts",
                    {}
                )

                if source_counts:

                    print(
                        "Source Flow Counts:"
                    )

                    for ip, count in source_counts.items():

                        print(
                            f"  {ip}: {count}"
                        )

                print(
                    "Attacker Intelligence:"
                )

                for attacker in attacker_details:

                    print(
                        f"\n  IP: {attacker['ip']}"
                    )

                    print(
                        f"  Flows: {attacker['flows']}"
                    )

                    print(
                        f"  Scope: {attacker['scope']}"
                    )

                    print(
                        f"  Estimated OS: "
                        f"{attacker['estimated_os']}"
                    )

                    print(
                        f"  OS Confidence: "
                        f"{attacker['os_confidence']}"
                    )

                    print(
                        f"  TTL: {attacker['ttl']}"
                    )

                    print(
                        f"  TCP Window: "
                        f"{attacker['tcp_window']}"
                    )

                    print(
                        f"  Country: "
                        f"{attacker['country']}"
                    )

                    print(
                        f"  Region: "
                        f"{attacker['region']}"
                    )

                    print(
                        f"  City: "
                        f"{attacker['city']}"
                    )

                    print(
                        f"  ASN: "
                        f"{attacker['asn']}"
                    )

                    print(
                        f"  Organization: "
                        f"{attacker['organization']}"
                    )

            print(
                f"First Seen: "
                f"{alert.get('first_seen', 'Unknown')}"
            )

            print(
                f"Last Seen: "
                f"{alert.get('last_seen', 'Unknown')}"
            )

            print(
                f"Reason: "
                f"{alert.get('reason', 'Unknown')}"
            )

            # =================================================
            # SOURCE NETWORK INTELLIGENCE (PortScan / Brute
            # Force / Slow HTTP only — DoS/DDoS attacker
            # details were already printed above via the
            # per-attacker Attacker Intelligence loop; the old
            # combined-IP enrichment no longer runs for those
            # attack types)
            # =================================================

            if attack_type in {
                "PortScan",
                "SSH Brute Force",
                "FTP Brute Force",
                "Slow HTTP",
            }:

                print(
                    f"Source Scope: "
                    f"{source_scope}"
                )

                print(
                    f"Estimated Source OS: "
                    f"{os_info.get('estimated_os', 'Unknown')}"
                )

                print(
                    f"OS Confidence: "
                    f"{os_info.get('confidence', 'Unknown')}"
                )

                print(
                    f"Observed TTL: "
                    f"{os_info.get('observed_ttl', 'Unknown')}"
                )

                print(
                    f"TCP Window: "
                    f"{os_info.get('tcp_window', 'Unknown')}"
                )

                # =============================================
                # GEOLOCATION
                # =============================================

                print(
                    f"Source Country: "
                    f"{source_geo.get('country', source_geo.get('reason', 'Unknown'))}"
                )

                print(
                    f"Source Region: "
                    f"{source_geo.get('region', 'Unknown')}"
                )

                print(
                    f"Source City: "
                    f"{source_geo.get('city', 'Unknown')}"
                )

                print(
                    f"Source Latitude: "
                    f"{source_geo.get('latitude', 'Unavailable')}"
                )

                print(
                    f"Source Longitude: "
                    f"{source_geo.get('longitude', 'Unavailable')}"
                )

                # =============================================
                # ASN / ORGANIZATION
                # =============================================

                print(
                    f"Source ASN: "
                    f"{source_asn.get('asn', 'Unavailable')}"
                )

                print(
                    f"Source Organization: "
                    f"{source_asn.get('organization', source_asn.get('reason', 'Unavailable'))}"
                )

    else:

        print(
            "No suspicious behavioral "
            "patterns detected."
        )

    # =====================================================
    # STEP 4 — WEB PAYLOAD INSPECTION
    # =====================================================

    print("\n[4/5] Running Web Payload Inspection...")

    web_alerts = detect_web_attacks(
        pcap_file
    )

    print(
        f"Web payload alerts detected: "
        f"{len(web_alerts)}"
    )

    if web_alerts:

        print(
            "\nDetected web attack threats:"
        )

        for alert in web_alerts:

            print(
                "\n" + "-" * 60
            )

            print(
                f"Severity: "
                f"{alert.get('severity', 'Unknown')}"
            )

            print(
                f"Attack Type: "
                f"{alert.get('attack_type', 'Unknown')}"
            )

            print(
                f"Detection Engine: "
                f"{alert.get('detection_engine', 'Unknown')}"
            )

            print(
                f"Source IP: "
                f"{alert.get('source_ip', 'Unknown')}"
            )

            print(
                f"Target IP: "
                f"{alert.get('target_ip', 'Unknown')}"
            )

            print(
                f"Source Port: "
                f"{alert.get('source_port', 'Unknown')}"
            )

            print(
                f"Target Port: "
                f"{alert.get('target_port', 'Unknown')}"
            )

            print(
                f"Packet Number: "
                f"{alert.get('packet_number', 'Unknown')}"
            )

            print(
                "Matched Indicators: "
                + ", ".join(
                    alert.get(
                        "matched_patterns",
                        []
                    )
                )
            )

            print(
                f"Reason: "
                f"{alert.get('reason', 'Unknown')}"
            )

    else:

        print(
            "No web payload threats detected."
        )

    # =====================================================
    # STEP 5 — CORRELATION ENGINE
    # =====================================================

    print("\n[5/5] Correlating detection results...")

    final_result = correlate_detection(
        ml_results,
        behavior_alerts,
        web_alerts,
    )

    # =====================================================
    # BUILD DETAILED ALERT LIST
    # =====================================================

    detailed_alerts = []

    for alert in behavior_alerts:

        attack_type = alert.get(
            "attack_type",
            "Unknown"
        )

        target_ip = str(
            alert.get(
                "target_ip",
                "Unknown"
            )
        )

        alert_record = {
            "attack_type": attack_type,
            "severity": alert.get(
                "severity",
                "Unknown"
            ),
            "detection_engine": alert.get(
                "detection_engine",
                "Behavioral IDS"
            ),
            "target_ip": target_ip,
            "target_port": alert.get(
                "target_port"
            ),
            "total_flows": alert.get(
                "total_flows",
                0
            ),
            "first_seen": alert.get(
                "first_seen"
            ),
            "last_seen": alert.get(
                "last_seen"
            ),
            "reason": alert.get(
                "reason",
                "Unknown"
            ),
        }

        # =================================================
        # PORTSCAN DETAILS
        # =================================================

        if attack_type == "PortScan":

            source_ip = str(
                alert.get(
                    "source_ip",
                    "Unknown"
                )
            )

            os_info = os_fingerprints.get(
                source_ip,
                {}
            )

            threat_info = enrich_flow({
                "src_ip": source_ip,
                "dst_ip": target_ip,
                "src_port": "Unknown",
                "dst_port": "Unknown",
                "protocol": (
                    alert.get(
                        "protocols",
                        ["Unknown"]
                    )[0]
                    if alert.get("protocols")
                    else "Unknown"
                ),
                "timestamp": alert.get(
                    "first_seen",
                    "Unknown"
                ),
            })

            source_geo = threat_info.get(
                "source_geolocation",
                {}
            )

            source_asn = threat_info.get(
                "source_asn_info",
                {}
            )

            source_ip_info = threat_info.get(
                "source_ip_info",
                {}
            )

            alert_record.update({
                "source_ip": source_ip,

                "unique_ports": alert.get(
                    "unique_ports",
                    0
                ),

                "ports": alert.get(
                    "ports",
                    []
                ),

                "protocols": alert.get(
                    "protocols",
                    []
                ),

                "source_scope": source_ip_info.get(
                    "scope",
                    "Unknown"
                ),

                "estimated_os": os_info.get(
                    "estimated_os",
                    "Unknown"
                ),

                "os_confidence": os_info.get(
                    "confidence",
                    "Unknown"
                ),

                "observed_ttl": os_info.get(
                    "observed_ttl"
                ),

                "tcp_window": os_info.get(
                    "tcp_window"
                ),

                "country": source_geo.get(
                    "country",
                    source_geo.get(
                        "reason",
                        "Unknown"
                    )
                ),

                "region": source_geo.get(
                    "region",
                    "Unknown"
                ),

                "city": source_geo.get(
                    "city",
                    "Unknown"
                ),

                "asn": source_asn.get(
                    "asn"
                ),

                "organization": source_asn.get(
                    "organization",
                    source_asn.get(
                        "reason",
                        "Unavailable"
                    )
                ),
            })

        # =================================================
        # BRUTE FORCE DETAILS
        # =================================================

        elif attack_type in {
            "SSH Brute Force",
            "FTP Brute Force",
        }:

            source_ip = str(
                alert.get(
                    "source_ip",
                    "Unknown"
                )
            )

            os_info = os_fingerprints.get(
                source_ip,
                {}
            )

            threat_info = enrich_flow({
                "src_ip": source_ip,
                "dst_ip": target_ip,
                "src_port": "Unknown",
                "dst_port": alert.get(
                    "target_port",
                    "Unknown"
                ),
                "protocol": "6",
                "timestamp": alert.get(
                    "first_seen",
                    "Unknown"
                ),
            })

            source_geo = threat_info.get(
                "source_geolocation",
                {}
            )

            source_asn = threat_info.get(
                "source_asn_info",
                {}
            )

            source_ip_info = threat_info.get(
                "source_ip_info",
                {}
            )

            alert_record.update({
                "source_ip":
                    source_ip,

                "target_port":
                    alert.get(
                        "target_port"
                    ),

                "target_service":
                    alert.get(
                        "target_service",
                        "Unknown"
                    ),

                "total_attempts":
                    alert.get(
                        "total_attempts",
                        0
                    ),

                "unique_source_ports":
                    alert.get(
                        "unique_source_ports",
                        0
                    ),

                "observed_window_seconds":
                    alert.get(
                        "observed_window_seconds"
                    ),

                "source_scope":
                    source_ip_info.get(
                        "scope",
                        "Unknown"
                    ),

                "estimated_os":
                    os_info.get(
                        "estimated_os",
                        "Unknown"
                    ),

                "os_confidence":
                    os_info.get(
                        "confidence",
                        "Unknown"
                    ),

                "observed_ttl":
                    os_info.get(
                        "observed_ttl"
                    ),

                "tcp_window":
                    os_info.get(
                        "tcp_window"
                    ),

                "country":
                    source_geo.get(
                        "country",
                        source_geo.get(
                            "reason",
                            "Unknown"
                        )
                    ),

                "region":
                    source_geo.get(
                        "region",
                        "Unknown"
                    ),

                "city":
                    source_geo.get(
                        "city",
                        "Unknown"
                    ),

                "asn":
                    source_asn.get(
                        "asn"
                    ),

                "organization":
                    source_asn.get(
                        "organization",
                        source_asn.get(
                            "reason",
                            "Unavailable"
                        )
                    ),
            })

        # =================================================
        # SLOW HTTP DETAILS
        # =================================================

        elif attack_type == "Slow HTTP":

            source_ip = str(
                alert.get(
                    "source_ip",
                    "Unknown"
                )
            )

            os_info = os_fingerprints.get(
                source_ip,
                {}
            )

            threat_info = enrich_flow({
                "src_ip": source_ip,
                "dst_ip": target_ip,
                "src_port": "Unknown",
                "dst_port": alert.get(
                    "target_port",
                    "Unknown"
                ),
                "protocol": "6",
                "timestamp": alert.get(
                    "first_seen",
                    "Unknown"
                ),
            })

            source_geo = threat_info.get(
                "source_geolocation",
                {}
            )

            source_asn = threat_info.get(
                "source_asn_info",
                {}
            )

            source_ip_info = threat_info.get(
                "source_ip_info",
                {}
            )

            alert_record.update({

                "source_ip":
                    source_ip,

                "target_port":
                    alert.get(
                        "target_port"
                    ),

                "target_service":
                    alert.get(
                        "target_service",
                        "Unknown"
                    ),

                "suspicious_flows":
                    alert.get(
                        "suspicious_flows",
                        0
                    ),

                "average_flow_duration":
                    alert.get(
                        "average_flow_duration"
                    ),

                "max_flow_duration":
                    alert.get(
                        "max_flow_duration"
                    ),

                "average_packets_per_flow":
                    alert.get(
                        "average_packets_per_flow"
                    ),

                "observed_window_seconds":
                    alert.get(
                        "observed_window_seconds"
                    ),

                "source_scope":
                    source_ip_info.get(
                        "scope",
                        "Unknown"
                    ),

                "estimated_os":
                    os_info.get(
                        "estimated_os",
                        "Unknown"
                    ),

                "os_confidence":
                    os_info.get(
                        "confidence",
                        "Unknown"
                    ),

                "observed_ttl":
                    os_info.get(
                        "observed_ttl"
                    ),

                "tcp_window":
                    os_info.get(
                        "tcp_window"
                    ),

                "country":
                    source_geo.get(
                        "country",
                        source_geo.get(
                            "reason",
                            "Unknown"
                        )
                    ),

                "region":
                    source_geo.get(
                        "region",
                        "Unknown"
                    ),

                "city":
                    source_geo.get(
                        "city",
                        "Unknown"
                    ),

                "asn":
                    source_asn.get(
                        "asn"
                    ),

                "organization":
                    source_asn.get(
                        "organization",
                        source_asn.get(
                            "reason",
                            "Unavailable"
                        )
                    ),
            })

        # =================================================
        # DOS / DDOS DETAILS
        # =================================================

        elif attack_type in {
            "DoS",
            "DDoS",
        }:

            attackers = []

            source_ips = alert.get(
                "source_ips",
                []
            )

            if not source_ips:

                source_ips = [
                    str(
                        alert.get(
                            "source_ip",
                            "Unknown"
                        )
                    )
                ]

            source_flow_counts = alert.get(
                "source_flow_counts",
                {}
            )

            for attacker_ip in source_ips:

                attacker_ip = str(
                    attacker_ip
                )

                os_info = os_fingerprints.get(
                    attacker_ip,
                    {}
                )

                threat_info = enrich_flow({
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": "Unknown",
                    "dst_port": alert.get(
                        "target_port",
                        "Unknown"
                    ),
                    "protocol": "6",
                    "timestamp": alert.get(
                        "first_seen",
                        "Unknown"
                    ),
                })

                geo = threat_info.get(
                    "source_geolocation",
                    {}
                )

                asn = threat_info.get(
                    "source_asn_info",
                    {}
                )

                ip_info = threat_info.get(
                    "source_ip_info",
                    {}
                )

                attackers.append({
                    "ip": attacker_ip,

                    "flows": source_flow_counts.get(
                        attacker_ip,
                        0
                    ),

                    "scope": ip_info.get(
                        "scope",
                        "Unknown"
                    ),

                    "estimated_os": os_info.get(
                        "estimated_os",
                        "Unknown"
                    ),

                    "os_confidence": os_info.get(
                        "confidence",
                        "Unknown"
                    ),

                    "observed_ttl": os_info.get(
                        "observed_ttl"
                    ),

                    "tcp_window": os_info.get(
                        "tcp_window"
                    ),

                    "country": geo.get(
                        "country",
                        geo.get(
                            "reason",
                            "Unknown"
                        )
                    ),

                    "region": geo.get(
                        "region",
                        "Unknown"
                    ),

                    "city": geo.get(
                        "city",
                        "Unknown"
                    ),

                    "asn": asn.get(
                        "asn"
                    ),

                    "organization": asn.get(
                        "organization",
                        asn.get(
                            "reason",
                            "Unavailable"
                        )
                    ),
                })

            alert_record.update({
                "source_count": alert.get(
                    "source_count",
                    len(attackers)
                ),

                "source_flow_counts": source_flow_counts,

                "attackers": attackers,

                "observed_window_seconds": alert.get(
                    "observed_window_seconds"
                ),
            })

        detailed_alerts.append(
            alert_record
        )

    for alert in web_alerts:

        detailed_alerts.append({
            "attack_type":
                alert.get(
                    "attack_type",
                    "Unknown"
                ),

            "severity":
                alert.get(
                    "severity",
                    "Unknown"
                ),

            "detection_engine":
                alert.get(
                    "detection_engine",
                    "Payload Inspection"
                ),

            "source_ip":
                alert.get(
                    "source_ip",
                    "Unknown"
                ),

            "target_ip":
                alert.get(
                    "target_ip",
                    "Unknown"
                ),

            "source_port":
                alert.get(
                    "source_port"
                ),

            "target_port":
                alert.get(
                    "target_port"
                ),

            "packet_number":
                alert.get(
                    "packet_number"
                ),

            "matched_patterns":
                alert.get(
                    "matched_patterns",
                    []
                ),

            "reason":
                alert.get(
                    "reason",
                    "Unknown"
                ),
        })

    # =====================================================
    # BUILD STRUCTURED SECURITY REPORT
    # =====================================================

    security_report = {
        "final_decision": final_result["final_decision"],
        "attack_type": final_result["attack_type"],
        "severity": final_result["severity"],
        "detection_source": final_result["detection_source"],

        "ml_attack_flows": final_result["ml_attack_count"],
        "behavioral_alerts": final_result["behavioral_alert_count"],

        "web_alerts": final_result.get(
            "web_alert_count",
            0
        ),

        "reason": final_result["reason"],

        "source_ip": None,
        "target_ip": None,

        "unique_ports": None,
        "total_flows": len(raw_flows),
        "ports": [],

        "first_seen": None,
        "last_seen": None,

        "estimated_source_os": "Unknown",
        "os_confidence": "Unknown",
        "observed_ttl": None,
        "tcp_window": None,

        "source_scope": "Unknown",

        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",

        "latitude": None,
        "longitude": None,

        "asn": None,
        "organization": "Unknown",

        "alerts": [],
    }

    security_report["alerts"] = detailed_alerts

    # =====================================================
    # ADD BEHAVIORAL ALERT DETAILS
    # =====================================================

    if behavior_alerts:

        primary_alert = behavior_alerts[0]

        source_ip = str(
            primary_alert["source_ip"]
        )

        target_ip = str(
            primary_alert["target_ip"]
        )

        os_info = os_fingerprints.get(
            source_ip,
            {}
        )

        sample_flow = {
            "src_ip": source_ip,
            "dst_ip": target_ip,
            "src_port": "Unknown",
            "dst_port": "Unknown",
            "protocol": (
                primary_alert["protocols"][0]
                if primary_alert.get("protocols")
                else "Unknown"
            ),
            "timestamp": primary_alert.get(
                "first_seen",
                "Unknown"
            ),
        }

        threat_info = enrich_flow(
            sample_flow
        )

        source_geo = threat_info.get(
            "source_geolocation",
            {}
        )

        source_asn = threat_info.get(
            "source_asn_info",
            {}
        )

        source_scope = (
            threat_info
            .get("source_ip_info", {})
            .get("scope", "Unknown")
        )

        security_report.update({
            "source_ip": source_ip,
            "target_ip": target_ip,

            "unique_ports": primary_alert.get(
                "unique_ports"
            ),

            "ports": primary_alert.get(
                "ports",
                []
            ),

            "first_seen": primary_alert.get(
                "first_seen"
            ),

            "last_seen": primary_alert.get(
                "last_seen"
            ),

            "estimated_source_os": os_info.get(
                "estimated_os",
                "Unknown"
            ),

            "os_confidence": os_info.get(
                "confidence",
                "Unknown"
            ),

            "observed_ttl": os_info.get(
                "observed_ttl"
            ),

            "tcp_window": os_info.get(
                "tcp_window"
            ),

            "source_scope": source_scope,

            "country": source_geo.get(
                "country",
                source_geo.get(
                    "reason",
                    "Unknown"
                )
            ),

            "region": source_geo.get(
                "region",
                "Unknown"
            ),

            "city": source_geo.get(
                "city",
                "Unknown"
            ),

            "latitude": source_geo.get(
                "latitude"
            ),

            "longitude": source_geo.get(
                "longitude"
            ),

            "asn": source_asn.get(
                "asn"
            ),

            "organization": source_asn.get(
                "organization",
                source_asn.get(
                    "reason",
                    "Unknown"
                )
            ),
        })

    print("\n" + "=" * 70)
    print("FINAL AI-IDS SECURITY DECISION")
    print("=" * 70)

    print(
        f"Final Decision: "
        f"{final_result['final_decision']}"
    )

    print(
        f"Attack Type: "
        f"{final_result['attack_type']}"
    )

    print(
        f"Severity: "
        f"{final_result['severity']}"
    )

    print(
        f"Detection Source: "
        f"{final_result['detection_source']}"
    )

    print(
        f"ML Attack Flows: "
        f"{final_result['ml_attack_count']}"
    )

    print(
        f"Behavioral Alerts: "
        f"{final_result['behavioral_alert_count']}"
    )

    print(
        f"Reason: "
        f"{final_result['reason']}"
    )

    # =====================================================
    # SAVE JSON REPORT
    # =====================================================

    report_dir = (
        PROJECT_ROOT
        / "data"
        / "processed"
        / "security_reports"
    )

    report_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    json_report_file = (
        report_dir
        / f"{pcap_file.stem}_security_report.json"
    )

    with open(
        json_report_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            security_report,
            file,
            indent=4
        )

    # =====================================================
    # SAVE CSV REPORT
    # =====================================================

    csv_report_file = (
        report_dir
        / f"{pcap_file.stem}_security_report.csv"
    )

    csv_report = security_report.copy()

    csv_report["ports"] = ",".join(
        str(port)
        for port in csv_report["ports"]
    )

    pd.DataFrame(
        [csv_report]
    ).to_csv(
        csv_report_file,
        index=False
    )

    print("\n" + "=" * 70)
    print("SECURITY REPORT SAVED")
    print("=" * 70)

    print(
        f"JSON: {json_report_file}"
    )

    print(
        f"CSV : {csv_report_file}"
    )

    return security_report


def main():

    if len(sys.argv) < 2:
        print(
            "Usage:\n"
            "python src\\pcap_pipeline.py "
            "\"data\\raw\\test_portscan.pcap\""
        )
        sys.exit(1)

    analyze_pcap(
        sys.argv[1]
    )


if __name__ == "__main__":
    main()
