"""
AI-IDS Prediction Engine

Pipeline:

    Network Flow Features
            |
            v
      Binary XGBoost
            |
       +----+----+
       |         |
    BENIGN     ATTACK
                  |
                  v
          Multiclass XGBoost
                  |
                  v
         Attack Type + Confidence

The model expects the 78 CIC-IDS2017 numerical features.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# =========================================================
# Project paths
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BINARY_MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "xgboost_binary_ids.joblib"
)

MULTICLASS_MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "multiclass"
    / "xgboost_multiclass_ids.joblib"
)

LABEL_ENCODER_FILE = (
    PROJECT_ROOT
    / "models"
    / "multiclass"
    / "label_encoder.joblib"
)


# =========================================================
# Expected CIC-IDS2017 features
# =========================================================

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


# =========================================================
# Load models
# =========================================================

def load_models():
    """Load the trained binary and multiclass models."""

    if not BINARY_MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Binary model not found:\n{BINARY_MODEL_FILE}"
        )

    if not MULTICLASS_MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Multiclass model not found:\n{MULTICLASS_MODEL_FILE}"
        )

    if not LABEL_ENCODER_FILE.exists():
        raise FileNotFoundError(
            f"Label encoder not found:\n{LABEL_ENCODER_FILE}"
        )

    binary_model = joblib.load(
        BINARY_MODEL_FILE
    )

    multiclass_model = joblib.load(
        MULTICLASS_MODEL_FILE
    )

    label_encoder = joblib.load(
        LABEL_ENCODER_FILE
    )

    return (
        binary_model,
        multiclass_model,
        label_encoder
    )


# =========================================================
# Prepare input features
# =========================================================

def prepare_features(data):
    """
    Convert input data into the exact 78-feature format
    expected by the trained models.

    Parameters
    ----------
    data : pandas.DataFrame or dict

    Returns
    -------
    pandas.DataFrame
    """

    # -----------------------------------------------------
    # Convert dictionary to DataFrame
    # -----------------------------------------------------

    if isinstance(data, dict):
        data = pd.DataFrame([data])

    elif isinstance(data, pd.Series):
        data = data.to_frame().T

    elif not isinstance(data, pd.DataFrame):
        raise TypeError(
            "Input must be a pandas DataFrame, Series, or dictionary."
        )

    data = data.copy()

    # -----------------------------------------------------
    # Strip accidental spaces
    # -----------------------------------------------------

    data.columns = data.columns.astype(str).str.strip()

    # -----------------------------------------------------
    # Check missing feature columns
    # -----------------------------------------------------

    missing_features = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in data.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing required CIC-IDS2017 features:\n"
            + "\n".join(missing_features)
        )

    # -----------------------------------------------------
    # Keep only the 78 model features
    # -----------------------------------------------------

    X = data[
        FEATURE_COLUMNS
    ].copy()

    # -----------------------------------------------------
    # Convert to numeric
    # -----------------------------------------------------

    for column in FEATURE_COLUMNS:
        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    # -----------------------------------------------------
    # Replace invalid values
    # -----------------------------------------------------

    X.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # The training pipeline removed invalid values, but the
    # inference engine needs to handle them gracefully.
    X.fillna(
        0,
        inplace=True
    )

    return X


# =========================================================
# Predict one or more network flows
# =========================================================

def predict(data):
    """
    Run the complete AI-IDS prediction pipeline.

    Returns a DataFrame containing:

        Binary Prediction
        Binary Confidence
        Attack Type
        Attack Confidence
        Status
    """

    (
        binary_model,
        multiclass_model,
        label_encoder
    ) = load_models()

    X = prepare_features(data)

    # -----------------------------------------------------
    # Binary detection
    # -----------------------------------------------------

    binary_probabilities = (
        binary_model.predict_proba(X)[:, 1]
    )

    binary_predictions = (
        binary_probabilities >= 0.50
    ).astype(np.int8)

    # -----------------------------------------------------
    # Prepare result
    # -----------------------------------------------------

    results = []

    # -----------------------------------------------------
    # Process each network flow
    # -----------------------------------------------------

    for index in range(len(X)):

        attack_probability = float(
            binary_probabilities[index]
        )

        is_attack = bool(
            binary_predictions[index]
        )

        # -------------------------------------------------
        # BENIGN
        # -------------------------------------------------

        if not is_attack:

            results.append({
                "Binary Prediction": "BENIGN",
                "Binary Confidence": round(
                    (1.0 - attack_probability) * 100,
                    2
                ),
                "Attack Type": "None",
                "Attack Confidence": 0.0,
                "Status": "NORMAL"
            })

            continue

        # -------------------------------------------------
        # ATTACK
        # -------------------------------------------------

        multiclass_probabilities = (
            multiclass_model.predict_proba(
                X.iloc[[index]]
            )[0]
        )

        attack_class_index = int(
            np.argmax(
                multiclass_probabilities
            )
        )

        attack_label = label_encoder.inverse_transform(
            [attack_class_index]
        )[0]

        attack_confidence = float(
            multiclass_probabilities[
                attack_class_index
            ]
        )

        results.append({
            "Binary Prediction": "ATTACK",
            "Binary Confidence": round(
                attack_probability * 100,
                2
            ),
            "Attack Type": attack_label,
            "Attack Confidence": round(
                attack_confidence * 100,
                2
            ),
            "Status": "ALERT"
        })

    return pd.DataFrame(results)


# =========================================================
# Test using an existing CIC-IDS2017 CSV
# =========================================================

def test_with_csv(csv_file, number_of_rows=10):
    """
    Test the prediction engine using rows from a CIC-IDS2017 CSV.
    """

    csv_path = Path(csv_file)

    if not csv_path.exists():
        raise FileNotFoundError(
            f"CSV file not found:\n{csv_path}"
        )

    print(
        f"Loading first {number_of_rows} rows..."
    )

    df = pd.read_csv(
        csv_path,
        nrows=number_of_rows,
        low_memory=False
    )

    # Remove spaces from column names
    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
    )

    # Preserve original labels when available
    original_labels = None

    if "Label" in df.columns:
        original_labels = df["Label"].astype(str)

    predictions = predict(df)

    # -----------------------------------------------------
    # Add original labels for testing
    # -----------------------------------------------------

    if original_labels is not None:

        predictions.insert(
            0,
            "Actual Label",
            original_labels.values
        )

    return predictions


# =========================================================
# Direct command-line test
# =========================================================

if __name__ == "__main__":

    print("=" * 65)
    print("AI-IDS PREDICTION ENGINE TEST")
    print("=" * 65)

    sample_file = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "Wednesday-workingHours.pcap_ISCX.csv"
    )

    results = test_with_csv(
        sample_file,
        number_of_rows=20
    )

    print("\nPrediction results:")
    print(
        results.to_string(
            index=False
        )
    )