"""
PCAP Processor for AI-IDS

Pipeline:

    PCAP / PCAPNG
          ↓
    Python CICFlowMeter
          ↓
    Raw flow CSV
          ↓
    CIC-IDS2017 feature adapter
          ↓
    78 model features
          ↓
    Binary / Multiclass XGBoost
"""

from pathlib import Path
import shutil
import subprocess

import pandas as pd


# =========================================================
# PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

PCAP_OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "pcap_flows"
)

PCAP_OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# CONFIGURATION
# =========================================================

SUPPORTED_EXTENSIONS = {
    ".pcap",
    ".pcapng",
}

CICFLOWMETER_COMMAND = "cicflowmeter"

FLOW_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
]


# =========================================================
# MODEL FEATURE MAPPING
# =========================================================

FEATURE_MAP = {
    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration",

    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",

    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",

    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",

    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",

    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",

    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",

    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",

    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",

    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",

    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",

    "Fwd Header Length": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",

    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",

    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",

    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",

    "CWE Flag Count": "cwr_flag_count",
    "ECE Flag Count": "ece_flag_cnt",

    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",

    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",

    # The original CIC-IDS2017 CSV contains
    # "Fwd Header Length.1". The Python extractor
    # provides one fwd_header_len value, so we
    # intentionally map the same value to both.
    "Fwd Header Length.1": "fwd_header_len",

    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",

    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",

    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",

    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",

    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",

    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",

    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}


# =========================================================
# VALIDATE PCAP
# =========================================================

def validate_pcap(pcap_file):

    path = Path(pcap_file)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found:\n{path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a file:\n{path}"
        )

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            "Unsupported capture format. "
            "Use .pcap or .pcapng."
        )

    if path.stat().st_size == 0:
        raise ValueError(
            "The PCAP file is empty."
        )

    return path.resolve()


# =========================================================
# FIND CICFLOWMETER
# =========================================================

def find_cicflowmeter():

    command = shutil.which(
        CICFLOWMETER_COMMAND
    )

    if command:
        return command

    raise FileNotFoundError(
        "CICFlowMeter was not found in PATH.\n\n"
        "Verify that this works in CMD:\n"
        "cicflowmeter --help"
    )


# =========================================================
# CONVERT PCAP → FLOW CSV
# =========================================================

def convert_pcap_to_raw_csv(
    pcap_file,
    output_csv=None
):

    pcap_path = validate_pcap(
        pcap_file
    )

    cicflowmeter = find_cicflowmeter()

    if output_csv is None:

        output_csv = (
            PCAP_OUTPUT_DIR
            / f"{pcap_path.stem}_flows.csv"
        )

    output_csv = Path(
        output_csv
    )

    output_csv.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    command = [
        cicflowmeter,
        "-f",
        str(pcap_path),
        "-c",
        str(output_csv),
    ]

    print("=" * 65)
    print("PCAP → FLOW CSV")
    print("=" * 65)

    print(
        f"Input : {pcap_path}"
    )

    print(
        f"Output: {output_csv}"
    )

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=1800
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "CICFlowMeter exceeded the "
            "30-minute processing limit."
        )

    if process.returncode != 0:

        error = (
            process.stderr.strip()
            or process.stdout.strip()
            or "Unknown CICFlowMeter error."
        )

        raise RuntimeError(
            "CICFlowMeter failed:\n\n"
            + error
        )

    if not output_csv.exists():

        raise RuntimeError(
            "CICFlowMeter finished but did not "
            f"create:\n{output_csv}"
        )

    print(
        "\n✓ Flow CSV generated successfully."
    )

    return output_csv.resolve()


# =========================================================
# ADAPT FLOW CSV → 78 MODEL FEATURES
# =========================================================

def convert_to_model_features(
    raw_csv,
    output_csv=None
):

    raw_csv = Path(
        raw_csv
    )

    if not raw_csv.exists():
        raise FileNotFoundError(
            f"Flow CSV not found:\n{raw_csv}"
        )

    if output_csv is None:

        output_csv = (
            raw_csv.parent
            / f"{raw_csv.stem}_model_features.csv"
        )

    print("\n" + "=" * 65)
    print("FLOW CSV → 78 MODEL FEATURES")
    print("=" * 65)

    df = pd.read_csv(
        raw_csv,
        low_memory=False
    )

    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
    )

    print(
        f"Raw flow rows: {len(df):,}"
    )

    print(
        f"Raw columns: {len(df.columns)}"
    )

    # -----------------------------------------------------
    # Check required source columns
    # -----------------------------------------------------

    source_columns = set(
        FEATURE_MAP.values()
    )

    missing_sources = sorted(
        source_columns.difference(
            df.columns
        )
    )

    if missing_sources:

        raise ValueError(
            "The generated flow CSV is missing "
            "required CICFlowMeter fields:\n\n"
            + "\n".join(missing_sources)
        )

    # -----------------------------------------------------
    # Build exact model feature order
    # -----------------------------------------------------

    model_df = pd.DataFrame(
        index=df.index
    )

    for model_feature, source_feature in (
        FEATURE_MAP.items()
    ):

        model_df[model_feature] = df[
            source_feature
        ]

    # -----------------------------------------------------
    # Numeric conversion
    # -----------------------------------------------------

    for column in model_df.columns:

        model_df[column] = pd.to_numeric(
            model_df[column],
            errors="coerce"
        )

    # -----------------------------------------------------
    # Replace invalid values
    # -----------------------------------------------------

    model_df.replace(
        [float("inf"), float("-inf")],
        pd.NA,
        inplace=True
    )

    # Use numeric median for each feature.
    # This is only for PCAP inference. It does
    # NOT alter your training data.
    for column in model_df.columns:

        model_df[column] = model_df[
            column
        ].fillna(
            model_df[column].median()
        )

        model_df[column] = (
            model_df[column].fillna(0)
        )

    # -----------------------------------------------------
    # Ensure exactly 78 columns
    # -----------------------------------------------------

    if len(model_df.columns) != 78:

        raise RuntimeError(
            "Feature adapter produced "
            f"{len(model_df.columns)} columns; "
            "expected 78."
        )

    model_df.to_csv(
        output_csv,
        index=False
    )

    print(
        f"✓ Model feature CSV created:"
    )

    print(
        output_csv
    )

    print(
        f"Rows: {len(model_df):,}"
    )

    print(
        f"Columns: {len(model_df.columns)}"
    )

    return output_csv.resolve()


# =========================================================
# COMPLETE PCAP PIPELINE
# =========================================================

def process_pcap(pcap_file):

    raw_csv = convert_pcap_to_raw_csv(
        pcap_file
    )

    model_csv = convert_to_model_features(
        raw_csv
    )

    return model_csv


# =========================================================
# COMMAND LINE
# =========================================================

if __name__ == "__main__":

    import sys

    print("=" * 65)
    print("AI-IDS PCAP PROCESSOR")
    print("=" * 65)

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            'python src\\pcap_processor.py '
            '"path\\to\\capture.pcap"'
        )

        sys.exit(1)

    try:

        result = process_pcap(
            sys.argv[1]
        )

        print(
            "\n✓ PCAP processing completed."
        )

        print(
            f"Model-ready CSV:\n{result}"
        )

    except Exception as exc:

        print(
            "\n✗ PCAP processing failed:"
        )

        print(
            str(exc)
        )

        sys.exit(1)