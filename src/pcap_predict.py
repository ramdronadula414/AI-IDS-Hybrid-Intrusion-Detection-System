"""
AI-IDS PCAP Prediction Engine

Pipeline:
PCAP
 -> CICFlowMeter
 -> 78 CIC-IDS2017 features
 -> XGBoost prediction
 -> Network metadata
 -> GeoIP / ASN
 -> OS fingerprinting
 -> Final enriched IDS report
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from src.predict import predict
from src.pcap_processor import process_pcap
from src.threat_intelligence import enrich_flow
from src.os_fingerprint import fingerprint_pcap


def main():

    # ---------------------------------------------------------
    # 1. Get PCAP from command line
    # ---------------------------------------------------------

    if len(sys.argv) < 2:
        print(
            "\nUsage:\n"
            "python src\\pcap_predict.py <pcap_file>\n\n"
            "Example:\n"
            "python src\\pcap_predict.py data\\raw\\test_portscan.pcap"
        )
        sys.exit(1)

    pcap_file = Path(sys.argv[1])

    if not pcap_file.is_absolute():
        pcap_file = PROJECT_ROOT / pcap_file

    pcap_file = pcap_file.resolve()

    if not pcap_file.exists():
        raise FileNotFoundError(
            f"PCAP file not found:\n{pcap_file}"
        )

    print("=" * 75)
    print("AI-IDS PCAP SECURITY ANALYZER")
    print("=" * 75)

    print(f"PCAP: {pcap_file}")

    # ---------------------------------------------------------
    # 2. Process PCAP
    # ---------------------------------------------------------

    print("\n[1/5] Extracting network flows...")

    model_feature_file = process_pcap(pcap_file)

    model_feature_file = Path(model_feature_file)

    # CICFlowMeter raw metadata file
    raw_flow_file = (
        model_feature_file.parent
        / model_feature_file.name.replace(
            "_model_features.csv",
            ".csv"
        )
    )

    if not raw_flow_file.exists():
        raise FileNotFoundError(
            f"Raw flow metadata file not found:\n"
            f"{raw_flow_file}"
        )

    # ---------------------------------------------------------
    # 3. Load model features
    # ---------------------------------------------------------

    print("\n[2/5] Loading ML features...")

    features_df = pd.read_csv(
        model_feature_file,
        low_memory=False
    )

    metadata_df = pd.read_csv(
        raw_flow_file,
        low_memory=False
    )

    metadata_df.columns = (
        metadata_df.columns
        .astype(str)
        .str.strip()
    )

    print(f"Flows: {len(features_df):,}")
    print(f"Model features: {len(features_df.columns)}")
    print(f"Metadata rows: {len(metadata_df):,}")

    # ---------------------------------------------------------
    # 4. Machine-learning prediction
    # ---------------------------------------------------------

    print("\n[3/5] Running AI intrusion detection...")

    predictions = predict(features_df)

    # ---------------------------------------------------------
    # 5. OS fingerprinting
    # ---------------------------------------------------------

    print("\n[4/5] Performing passive OS fingerprinting...")

    os_results = fingerprint_pcap(str(pcap_file))

    # ---------------------------------------------------------
    # 6. Threat intelligence
    # ---------------------------------------------------------

    print("\n[5/5] Enriching network intelligence...")

    enriched_rows = []

    count = min(
        len(metadata_df),
        len(predictions)
    )

    for i in range(count):

        flow = metadata_df.iloc[i].to_dict()

        intelligence = enrich_flow(flow)

        src_ip = str(
            intelligence.get(
                "source_ip",
                flow.get("src_ip", "Unknown")
            )
        )

        os_info = os_results.get(
            src_ip,
            {}
        )

        src_geo = intelligence.get(
            "source_geolocation",
            {}
        )

        dst_geo = intelligence.get(
            "destination_geolocation",
            {}
        )

        src_asn = intelligence.get(
            "source_asn_info",
            {}
        )

        dst_asn = intelligence.get(
            "destination_asn_info",
            {}
        )

        src_ip_info = intelligence.get(
            "source_ip_info",
            {}
        )

        dst_ip_info = intelligence.get(
            "destination_ip_info",
            {}
        )

        row = {

            # ---------------- OS ----------------

            "Estimated Source OS":
                os_info.get(
                    "estimated_os",
                    "Unknown"
                ),

            "OS Confidence":
                os_info.get(
                    "confidence",
                    "Unknown"
                ),

            "Observed TTL":
                os_info.get(
                    "observed_ttl"
                ),

            "Initial TTL Guess":
                os_info.get(
                    "initial_ttl_guess"
                ),

            "TCP Window":
                os_info.get(
                    "tcp_window"
                ),

            "OS Fingerprint Method":
                os_info.get(
                    "method",
                    "Unknown"
                ),

            "OS Evidence":
                os_info.get(
                    "evidence",
                    "Unknown"
                ),

            # ---------------- Network ----------------

            "Source IP":
                intelligence.get(
                    "source_ip",
                    "Unknown"
                ),

            "Source Port":
                intelligence.get(
                    "source_port",
                    "Unknown"
                ),

            "Source Scope":
                src_ip_info.get(
                    "scope",
                    "Unknown"
                ),

            "Destination IP":
                intelligence.get(
                    "destination_ip",
                    "Unknown"
                ),

            "Target Port":
                intelligence.get(
                    "destination_port",
                    "Unknown"
                ),

            "Target Service":
                intelligence.get(
                    "target_service",
                    "Unknown"
                ),

            "Destination Scope":
                dst_ip_info.get(
                    "scope",
                    "Unknown"
                ),

            "Protocol":
                intelligence.get(
                    "protocol",
                    "Unknown"
                ),

            "Timestamp":
                intelligence.get(
                    "timestamp",
                    "Unknown"
                ),

            # ---------------- Source GeoIP ----------------

            "Source Country":
                src_geo.get(
                    "country",
                    src_geo.get(
                        "reason",
                        "Unknown"
                    )
                ),

            "Source Region":
                src_geo.get(
                    "region",
                    "Unknown"
                ),

            "Source City":
                src_geo.get(
                    "city",
                    "Unknown"
                ),

            "Source Latitude":
                src_geo.get(
                    "latitude"
                ),

            "Source Longitude":
                src_geo.get(
                    "longitude"
                ),

            # ---------------- Source ASN ----------------

            "Source ASN":
                src_asn.get(
                    "asn"
                ),

            "Source Organization":
                src_asn.get(
                    "organization",
                    src_asn.get(
                        "reason",
                        "Unknown"
                    )
                ),

            # ---------------- Destination GeoIP ----------------

            "Destination Country":
                dst_geo.get(
                    "country",
                    dst_geo.get(
                        "reason",
                        "Unknown"
                    )
                ),

            "Destination Region":
                dst_geo.get(
                    "region",
                    "Unknown"
                ),

            "Destination City":
                dst_geo.get(
                    "city",
                    "Unknown"
                ),

            "Destination Latitude":
                dst_geo.get(
                    "latitude"
                ),

            "Destination Longitude":
                dst_geo.get(
                    "longitude"
                ),

            # ---------------- Destination ASN ----------------

            "Destination ASN":
                dst_asn.get(
                    "asn"
                ),

            "Destination Organization":
                dst_asn.get(
                    "organization",
                    dst_asn.get(
                        "reason",
                        "Unknown"
                    )
                ),
        }

        enriched_rows.append(row)

    intelligence_df = pd.DataFrame(
        enriched_rows
    )

    # ---------------------------------------------------------
    # 7. Combine intelligence + AI predictions
    # ---------------------------------------------------------

    final_results = pd.concat(
        [
            intelligence_df.reset_index(drop=True),
            predictions.iloc[:count].reset_index(drop=True),
        ],
        axis=1
    )

    # ---------------------------------------------------------
    # 8. Display
    # ---------------------------------------------------------

    print("\n" + "=" * 75)
    print("AI-IDS SECURITY RESULTS")
    print("=" * 75)

    display_columns = [

        "Source IP",
        "Destination IP",
        "Target Port",
        "Target Service",

        "Estimated Source OS",
        "OS Confidence",

        "Source Country",
        "Source Organization",

        "Binary Prediction",
        "Binary Confidence",

        "Attack Type",
        "Attack Confidence",

        "Status"
    ]

    existing_columns = [
        column
        for column in display_columns
        if column in final_results.columns
    ]

    print(
        final_results[
            existing_columns
        ].to_string(index=False)
    )

    # ---------------------------------------------------------
    # 9. Summary
    # ---------------------------------------------------------

    print("\n" + "=" * 75)
    print("SECURITY SUMMARY")
    print("=" * 75)

    total_flows = len(final_results)

    attack_count = (
        final_results[
            "Binary Prediction"
        ]
        .eq("ATTACK")
        .sum()
    )

    benign_count = (
        final_results[
            "Binary Prediction"
        ]
        .eq("BENIGN")
        .sum()
    )

    print(f"Total flows : {total_flows}")
    print(f"Benign      : {benign_count}")
    print(f"Attacks     : {attack_count}")

    if attack_count > 0:

        print("\nDetected attack types:")

        attacks = (
            final_results.loc[
                final_results[
                    "Binary Prediction"
                ] == "ATTACK",
                "Attack Type"
            ]
            .value_counts()
        )

        print(
            attacks.to_string()
        )

    # ---------------------------------------------------------
    # 10. Save report
    # ---------------------------------------------------------

    output_file = (
        model_feature_file.parent
        / f"{pcap_file.stem}_security_report.csv"
    )

    final_results.to_csv(
        output_file,
        index=False
    )

    print("\n" + "=" * 75)
    print("REPORT SAVED")
    print("=" * 75)

    print(output_file)


if __name__ == "__main__":
    main()