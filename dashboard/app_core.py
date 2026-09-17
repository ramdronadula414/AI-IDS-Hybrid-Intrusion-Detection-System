"""
AI-IDS Security Center
Premium Streamlit dashboard for the CIC-IDS2017 AI-based IDS.

Run:
    streamlit run dashboard/app.py
"""

from pathlib import Path
from datetime import datetime
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
import streamlit as st

from src.predict import (
    FEATURE_COLUMNS,
    prepare_features,
)

from src.pcap_processor import (
    process_pcap,
)

from src.pcap_pipeline import analyze_pcap
# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="AI-IDS Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# PATHS
# =========================================================

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

EVALUATION_DIR = (
    PROJECT_ROOT
    / "models"
    / "evaluation"
)

COMPARISON_DIR = (
    PROJECT_ROOT
    / "models"
    / "comparison"
)

MULTICLASS_RESULTS_DIR = (
    PROJECT_ROOT
    / "models"
    / "multiclass"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown(
    """
    <style>

    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600&display=swap');

    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* -----------------------------
       Global
    ----------------------------- */

    .stApp {
        background:
            radial-gradient(
                ellipse 900px 600px at 8% -5%,
                rgba(45, 212, 255, 0.14),
                transparent 55%
            ),
            radial-gradient(
                ellipse 900px 700px at 95% 0%,
                rgba(16, 220, 150, 0.12),
                transparent 55%
            ),
            radial-gradient(
                ellipse 1200px 800px at 50% 110%,
                rgba(20, 184, 166, 0.10),
                transparent 60%
            ),
            linear-gradient(180deg, #050d16 0%, #071620 55%, #050f18 100%);
        color: #e9f4f6;
    }

    /* Main container */

    .block-container {
        padding-top: 1.4rem;
        padding-bottom: 2.5rem;
        max-width: 1600px;
    }

    h1, h2, h3, h4, h5, h6 {
        color: #eaf9f4;
        font-weight: 800;
    }

    p, span, label, div {
        letter-spacing: 0.1px;
    }

    /* Scrollbar */

    ::-webkit-scrollbar {
        width: 9px;
        height: 9px;
    }

    ::-webkit-scrollbar-track {
        background: transparent;
    }

    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #1fb6d8, #16d1a0);
        border-radius: 999px;
    }

    /* Sidebar */

    section[data-testid="stSidebar"] {
        background:
            linear-gradient(
                180deg,
                #04101a 0%,
                #061a26 55%,
                #051620 100%
            );
        border-right: 1px solid rgba(38, 214, 191, 0.14);
    }

    section[data-testid="stSidebar"] > div {
        padding-top: 1.6rem;
    }

    /* Radio nav in sidebar */

    section[data-testid="stSidebar"] [role="radiogroup"] label {
        border-radius: 12px;
        padding: 9px 12px;
        margin-bottom: 4px;
        transition: background 0.15s ease, border-color 0.15s ease;
        border: 1px solid transparent;
    }

    section[data-testid="stSidebar"] [role="radiogroup"] label:hover {
        background: rgba(45, 212, 255, 0.07);
        border-color: rgba(45, 212, 255, 0.18);
    }

    /* Hide Streamlit menu */

    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    /* Keep header transparent (not hidden) so the sidebar
       collapse/expand arrow — which lives inside this element —
       stays visible and clickable. */

    header[data-testid="stHeader"] {
        background: transparent;
        box-shadow: none;
    }

    [data-testid="collapsedControl"] {
        visibility: visible !important;
        display: flex !important;
        color: #6fe8ff !important;
    }

    [data-testid="collapsedControl"] svg {
        fill: #6fe8ff !important;
    }

    /* -----------------------------
       Brand
    ----------------------------- */

    .brand {
        display: flex;
        align-items: center;
        gap: 13px;
        margin-bottom: 26px;
        padding-bottom: 20px;
        border-bottom: 1px solid rgba(45, 212, 255, 0.12);
    }

    .brand-icon {
        width: 50px;
        height: 50px;
        border-radius: 15px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 25px;
        background:
            linear-gradient(
                135deg,
                rgba(45, 212, 255, 0.30),
                rgba(16, 220, 150, 0.22)
            );
        border: 1px solid rgba(56, 224, 200, 0.38);
        box-shadow:
            0 0 30px rgba(30, 210, 190, 0.20),
            inset 0 1px 0 rgba(255,255,255,0.12);
    }

    .brand-title {
        font-size: 19px;
        font-weight: 900;
        letter-spacing: 0.3px;
        background: linear-gradient(90deg, #6fe8ff, #4dffbe);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    .brand-subtitle {
        font-size: 11px;
        color: #7fa3ab;
        margin-top: 3px;
        font-weight: 500;
    }

    /* -----------------------------
       Header
    ----------------------------- */

    .top-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 20px 24px;
        margin-bottom: 24px;
        border-radius: 20px;
        background:
            linear-gradient(
                120deg,
                rgba(8, 28, 38, 0.92),
                rgba(6, 22, 30, 0.88)
            );
        border: 1px solid rgba(45, 212, 255, 0.16);
        box-shadow:
            0 14px 40px rgba(0, 0, 0, 0.28),
            inset 0 1px 0 rgba(255,255,255,0.04);
        backdrop-filter: blur(12px);
    }

    .header-title {
        font-size: 31px;
        font-weight: 900;
        letter-spacing: -0.6px;
        background: linear-gradient(100deg, #7fefff 0%, #4defb0 55%, #34d9c4 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    .header-subtitle {
        color: #86a6ae;
        margin-top: 5px;
        font-size: 13px;
        font-weight: 500;
    }

    .online-badge {
        padding: 9px 16px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 800;
        color: #4dffc2;
        background: rgba(16, 220, 150, 0.09);
        border: 1px solid rgba(16, 220, 150, 0.30);
        box-shadow: 0 0 22px rgba(16, 220, 150, 0.14);
        letter-spacing: 0.4px;
    }

    /* -----------------------------
       KPI Cards
    ----------------------------- */

    .metric-card {
        position: relative;
        padding: 22px;
        min-height: 140px;
        border-radius: 20px;
        background:
            linear-gradient(
                150deg,
                rgba(10, 30, 42, 0.92),
                rgba(6, 20, 28, 0.94)
            );
        border: 1px solid rgba(90, 190, 200, 0.14);
        box-shadow:
            inset 0 1px 0 rgba(255,255,255,0.03),
            0 14px 34px rgba(0,0,0,0.22);
        transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
        overflow: hidden;
    }

    .metric-card:hover {
        transform: translateY(-3px);
        border-color: rgba(80, 220, 210, 0.32);
        box-shadow:
            inset 0 1px 0 rgba(255,255,255,0.04),
            0 18px 40px rgba(0,0,0,0.30);
    }

    .metric-label {
        color: #7fa0a8;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1.1px;
        font-weight: 700;
    }

    .metric-value {
        margin-top: 13px;
        font-size: 32px;
        font-weight: 900;
        letter-spacing: -1px;
        color: #f1fbf8;
    }

    .metric-note {
        margin-top: 9px;
        color: #7f9ba3;
        font-size: 11px;
        font-weight: 500;
    }

    .metric-accent-blue {
        border-top: 3px solid #2dd4ff;
        box-shadow: inset 0 3px 0 -2px rgba(45,212,255,0.6), 0 14px 34px rgba(0,0,0,0.22);
    }

    .metric-accent-green {
        border-top: 3px solid #22e0a8;
        box-shadow: inset 0 3px 0 -2px rgba(34,224,168,0.6), 0 14px 34px rgba(0,0,0,0.22);
    }

    .metric-accent-red {
        border-top: 3px solid #ff5f75;
        box-shadow: inset 0 3px 0 -2px rgba(255,95,117,0.55), 0 14px 34px rgba(0,0,0,0.22);
    }

    .metric-accent-purple {
        border-top: 3px solid #3fd6c8;
        box-shadow: inset 0 3px 0 -2px rgba(63,214,200,0.55), 0 14px 34px rgba(0,0,0,0.22);
    }

    /* -----------------------------
       Panels
    ----------------------------- */

    .panel {
        padding: 22px;
        margin-top: 18px;
        border-radius: 20px;
        background:
            linear-gradient(
                150deg,
                rgba(9, 27, 38, 0.92),
                rgba(6, 18, 26, 0.94)
            );
        border: 1px solid rgba(80, 190, 195, 0.13);
        box-shadow: 0 14px 36px rgba(0,0,0,0.20);
    }

    .panel-title {
        font-size: 16px;
        font-weight: 800;
        margin-bottom: 4px;
        color: #eafaf6;
    }

    .panel-subtitle {
        font-size: 11.5px;
        color: #7c9aa2;
        margin-bottom: 16px;
        font-weight: 500;
    }

    /* -----------------------------
       Alert cards
    ----------------------------- */

    .alert-card {
        padding: 14px 16px;
        margin-bottom: 10px;
        border-radius: 14px;
        background: rgba(45, 212, 255, 0.025);
        border: 1px solid rgba(120, 210, 210, 0.08);
        transition: background 0.15s ease;
    }

    .alert-card:hover {
        background: rgba(45, 212, 255, 0.045);
    }

    .alert-critical {
        border-left: 4px solid #ff4f67;
    }

    .alert-high {
        border-left: 4px solid #ff9f43;
    }

    .alert-medium {
        border-left: 4px solid #f5d76e;
    }

    .alert-normal {
        border-left: 4px solid #22e0a8;
    }

    .alert-label {
        font-weight: 800;
        font-size: 13px;
        color: #eafaf6;
    }

    .alert-meta {
        color: #7c95a0;
        font-size: 10.5px;
        margin-top: 4px;
        font-weight: 500;
    }

    /* -----------------------------
       Status
    ----------------------------- */

    .status-box {
        padding: 15px;
        border-radius: 15px;
        background:
            linear-gradient(
                120deg,
                rgba(16, 220, 150, 0.06),
                rgba(45, 212, 255, 0.03)
            );
        border: 1px solid rgba(34, 224, 168, 0.18);
    }

    .status-title {
        font-size: 12px;
        font-weight: 800;
        color: #eafaf6;
    }

    .status-text {
        color: #82a0a8;
        font-size: 11px;
        margin-top: 6px;
        font-weight: 500;
    }

    /* -----------------------------
       Prediction result
    ----------------------------- */

    .result-normal {
        padding: 26px;
        border-radius: 20px;
        background:
            linear-gradient(
                135deg,
                rgba(16, 220, 150, 0.11),
                rgba(45, 212, 255, 0.04)
            );
        border: 1px solid rgba(34, 224, 168, 0.28);
        box-shadow: 0 16px 40px rgba(16, 180, 130, 0.08);
    }

    .result-alert {
        padding: 26px;
        border-radius: 20px;
        background:
            linear-gradient(
                135deg,
                rgba(255,70,95,0.12),
                rgba(130,20,45,0.03)
            );
        border: 1px solid rgba(255,75,100,0.26);
        box-shadow: 0 16px 40px rgba(200, 40, 65, 0.08);
    }

    .result-status {
        font-size: 12px;
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 1.6px;
    }

    .result-main {
        font-size: 30px;
        font-weight: 900;
        margin-top: 9px;
        color: #f2fbf8;
    }

    .result-confidence {
        margin-top: 9px;
        color: #93b2b8;
        font-size: 12px;
        font-weight: 500;
    }

    /* -----------------------------
       Sidebar information
    ----------------------------- */

    .sidebar-box {
        margin-top: 20px;
        padding: 16px;
        border-radius: 15px;
        background: linear-gradient(150deg, rgba(45,212,255,0.05), rgba(16,220,150,0.03));
        border: 1px solid rgba(80, 200, 200, 0.14);
    }

    .sidebar-small {
        color: #82a3ab;
        font-size: 10.5px;
        line-height: 1.65;
        font-weight: 500;
    }

    .sidebar-small b {
        color: #6fe8d0;
        letter-spacing: 0.4px;
    }

    /* -----------------------------
       Buttons
    ----------------------------- */

    .stButton > button {
        border-radius: 13px;
        border: 1px solid rgba(45, 212, 255, 0.28);
        background:
            linear-gradient(
                135deg,
                rgba(45, 190, 255, 0.20),
                rgba(16, 220, 150, 0.12)
            );
        color: #f0fbfc;
        font-weight: 750;
        min-height: 44px;
        transition: all 0.18s ease;
    }

    .stButton > button:hover {
        border-color: rgba(56, 230, 210, 0.55);
        background:
            linear-gradient(
                135deg,
                rgba(45, 190, 255, 0.30),
                rgba(16, 220, 150, 0.20)
            );
        color: white;
        box-shadow: 0 0 24px rgba(45, 212, 255, 0.18);
    }

    .stDownloadButton > button {
        border-radius: 13px;
        border: 1px solid rgba(34, 224, 168, 0.32);
        background: linear-gradient(135deg, rgba(34,224,168,0.18), rgba(45,212,255,0.10));
        color: #f0fbfc;
        font-weight: 750;
        transition: all 0.18s ease;
    }

    .stDownloadButton > button:hover {
        border-color: rgba(34, 224, 168, 0.6);
        box-shadow: 0 0 24px rgba(34, 224, 168, 0.18);
    }

    /* File uploader */

    [data-testid="stFileUploader"] {
        background: rgba(45, 212, 255, 0.02);
        border-radius: 15px;
        border: 1px solid rgba(80, 190, 195, 0.14);
        padding: 6px;
    }

    /* Selectboxes */

    div[data-baseweb="select"] > div {
        background-color: #071b28;
        border-color: rgba(80, 190, 195, 0.20);
        border-radius: 11px;
    }

    /* Tabs */

    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 11px 11px 0 0;
        color: #82a3ab;
        font-weight: 600;
    }

    .stTabs [aria-selected="true"] {
        color: #4defb0 !important;
        border-bottom: 2px solid #2dd4ff !important;
    }

    /* Metrics (native st.metric) */

    [data-testid="stMetric"] {
        background: linear-gradient(150deg, rgba(10,30,42,0.9), rgba(6,20,28,0.92));
        border: 1px solid rgba(90, 190, 200, 0.14);
        border-radius: 16px;
        padding: 14px 16px;
    }

    /* Progress */

    .stProgress > div > div > div {
        border-radius: 999px;
        background: linear-gradient(90deg, #2dd4ff, #22e0a8);
    }

    /* DataFrames */

    [data-testid="stDataFrame"] {
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid rgba(80, 190, 195, 0.14);
    }

    /* Expander */

    .streamlit-expanderHeader {
        border-radius: 12px;
        background: rgba(45, 212, 255, 0.04);
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# HELPERS
# =========================================================

def safe_model_load():
    """Load dashboard models safely."""

    missing = []

    for path in [
        BINARY_MODEL_FILE,
        MULTICLASS_MODEL_FILE,
        LABEL_ENCODER_FILE,
    ]:
        if not path.exists():
            missing.append(str(path))

    if missing:
        return None, None, None, missing

    binary_model = joblib.load(BINARY_MODEL_FILE)
    multiclass_model = joblib.load(MULTICLASS_MODEL_FILE)
    label_encoder = joblib.load(LABEL_ENCODER_FILE)

    return binary_model, multiclass_model, label_encoder, []


@st.cache_resource
def get_models():
    return safe_model_load()


@st.cache_data
def load_csv_sample(path, nrows=5000):
    return pd.read_csv(
        path,
        nrows=nrows,
        low_memory=False
    )
def find_flow_samples(path, sample_type, chunk_size=100000):
    """
    Find a representative benign or attack flow from a
    CIC-IDS2017 CSV without loading the entire file.
    """

    for chunk in pd.read_csv(
        path,
        chunksize=chunk_size,
        low_memory=False
    ):

        chunk.columns = (
            chunk.columns
            .astype(str)
            .str.strip()
        )

        if "Label" not in chunk.columns:
            continue

        labels = (
            chunk["Label"]
            .astype(str)
            .str.strip()
        )

        if sample_type == "Random attack":

            candidates = chunk[
                labels != "BENIGN"
            ]

        elif sample_type == "Benign flow":

            candidates = chunk[
                labels == "BENIGN"
            ]

        else:

            candidates = chunk

        if not candidates.empty:

            return candidates.sample(
                1,
                random_state=42
            )

    return None

def normalize_label(label):
    """
    Clean some common encoding artifacts in CIC-IDS2017 labels
    for display purposes.
    """

    if pd.isna(label):
        return "Unknown"

    text = str(label)

    replacements = {
        "Web Attack   Brute Force": "Web Attack - Brute Force",
        "Web Attack   XSS": "Web Attack - XSS",
        "Web Attack   Sql Injection": "Web Attack - SQL Injection",
        "Web Attack â€“ Brute Force": "Web Attack - Brute Force",
        "Web Attack â€“ XSS": "Web Attack - XSS",
        "Web Attack â€“ Sql Injection": "Web Attack - SQL Injection",
    }

    return replacements.get(text, text)


def run_predictions(df, binary_model, multiclass_model, encoder):
    """Run two-stage IDS inference."""

    X = prepare_features(df)

    # Binary stage
    binary_prob = binary_model.predict_proba(X)[:, 1]

    binary_pred = (
        binary_prob >= 0.50
    ).astype(np.int8)

    # Multiclass probabilities only where needed
    multiclass_pred = np.full(
        len(df),
        -1,
        dtype=np.int32
    )

    multiclass_conf = np.zeros(
        len(df),
        dtype=float
    )

    attack_mask = binary_pred == 1

    if attack_mask.any():
        attack_X = X.loc[attack_mask]

        probabilities = (
            multiclass_model
            .predict_proba(attack_X)
        )

        multiclass_indices = np.argmax(
            probabilities,
            axis=1
        )

        multiclass_pred[attack_mask] = (
            multiclass_indices
        )

        multiclass_conf[attack_mask] = (
            probabilities[
                np.arange(len(probabilities)),
                multiclass_indices
            ]
        )

    # Convert class IDs to labels
    attack_types = []

    for class_id in multiclass_pred:
        if class_id == -1:
            attack_types.append("None")
        else:
            label = encoder.inverse_transform(
                [class_id]
            )[0]

            attack_types.append(
                normalize_label(label)
            )

    result = pd.DataFrame({
        "Binary Prediction": np.where(
            binary_pred == 1,
            "ATTACK",
            "BENIGN"
        ),
        "Binary Confidence (%)": np.where(
            binary_pred == 1,
            binary_prob * 100,
            (1 - binary_prob) * 100
        ),
        "Attack Type": attack_types,
        "Attack Confidence (%)": multiclass_conf * 100,
        "Status": np.where(
            binary_pred == 1,
            "ALERT",
            "NORMAL"
        ),
    })

    return result


def severity_from_attack(label):
    """Assign a simple dashboard severity."""

    text = str(label).lower()

    if text == "none":
        return "NORMAL"

    critical_terms = [
        "heartbleed",
        "infiltration",
        "sql injection",
    ]

    high_terms = [
        "ddos",
        "dos hulk",
        "bot",
        "brute force",
    ]

    if any(term in text for term in critical_terms):
        return "CRITICAL"

    if any(term in text for term in high_terms):
        return "HIGH"

    return "MEDIUM"


def render_metric(
    label,
    value,
    note,
    accent
):
    st.markdown(
        f"""
        <div class="metric-card {accent}">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_security_alert(alert, alert_number):
    """Render one behavioral security alert."""

    attack_type = alert.get(
        "attack_type",
        "Unknown"
    )

    severity = alert.get(
        "severity",
        "Unknown"
    )

    target_ip = alert.get(
        "target_ip",
        "Unknown"
    )

    target_port = alert.get(
        "target_port"
    )

    severity_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }.get(
        severity,
        "⚪"
    )

    title = (
        f"{severity_icon} Alert {alert_number} — "
        f"{attack_type} [{severity}]"
    )

    with st.expander(
        title,
        expanded=True,
    ):

        # =================================================
        # COMMON ALERT INFORMATION
        # =================================================

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.metric(
                "Attack Type",
                attack_type,
            )

        with c2:
            st.metric(
                "Severity",
                severity,
            )

        with c3:
            st.metric(
                "Target IP",
                target_ip,
            )

        with c4:
            st.metric(
                "Total Flows",
                alert.get(
                    "total_flows",
                    0
                ),
            )

        # =================================================
        # PORTSCAN
        # =================================================

        if attack_type == "PortScan":

            st.markdown(
                "#### Port Scan Investigation"
            )

            p1, p2, p3, p4 = st.columns(4)

            with p1:
                st.metric(
                    "Source IP",
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),
                )

            with p2:
                st.metric(
                    "Unique Ports",
                    alert.get(
                        "unique_ports",
                        0
                    ),
                )

            with p3:
                st.metric(
                    "Estimated OS",
                    alert.get(
                        "estimated_os",
                        "Unknown"
                    ),
                )

            with p4:
                st.metric(
                    "OS Confidence",
                    alert.get(
                        "os_confidence",
                        "Unknown"
                    ),
                )

            st.markdown(
                "##### Source Intelligence"
            )

            source_info = pd.DataFrame({
                "Field": [
                    "Network Scope",
                    "Observed TTL",
                    "TCP Window",
                    "Country",
                    "Region",
                    "City",
                    "ASN",
                    "Organization",
                    "First Seen",
                    "Last Seen",
                ],

                "Value": [
                    alert.get(
                        "source_scope",
                        "Unknown"
                    ),

                    alert.get(
                        "observed_ttl",
                        "Unknown"
                    ),

                    alert.get(
                        "tcp_window",
                        "Unknown"
                    ),

                    alert.get(
                        "country",
                        "Unknown"
                    ),

                    alert.get(
                        "region",
                        "Unknown"
                    ),

                    alert.get(
                        "city",
                        "Unknown"
                    ),

                    (
                        alert.get("asn")
                        if alert.get("asn") is not None
                        else "Unavailable"
                    ),

                    alert.get(
                        "organization",
                        "Unknown"
                    ),

                    alert.get(
                        "first_seen",
                        "Unknown"
                    ),

                    alert.get(
                        "last_seen",
                        "Unknown"
                    ),
                ]
            })

            st.dataframe(
                source_info,
                use_container_width=True,
                hide_index=True,
            )

            ports = alert.get(
                "ports",
                []
            )

            if ports:

                st.markdown(
                    "##### Ports Probed"
                )

                st.code(
                    ", ".join(
                        str(port)
                        for port in ports
                    ),
                    language=None,
                )

        # =================================================
        # DOS / DDOS
        # =================================================

        elif attack_type in {
            "DoS",
            "DDoS",
        }:

            st.markdown(
                f"#### {attack_type} Investigation"
            )

            d1, d2, d3, d4 = st.columns(4)

            with d1:
                st.metric(
                    "Target",
                    (
                        f"{target_ip}:{target_port}"
                        if target_port is not None
                        else target_ip
                    ),
                )

            with d2:
                st.metric(
                    "Attack Sources",
                    alert.get(
                        "source_count",
                        1
                    ),
                )

            with d3:
                st.metric(
                    "Total Flows",
                    alert.get(
                        "total_flows",
                        0
                    ),
                )

            with d4:
                window = alert.get(
                    "observed_window_seconds"
                )

                st.metric(
                    "Observed Window",
                    (
                        f"{window:.3f}s"
                        if isinstance(
                            window,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            attackers = alert.get(
                "attackers",
                []
            )

            if attackers:

                st.markdown(
                    "##### Attacker Intelligence"
                )

                attacker_rows = []

                for attacker in attackers:

                    attacker_rows.append({
                        "Source IP":
                            attacker.get(
                                "ip",
                                "Unknown"
                            ),

                        "Flows":
                            attacker.get(
                                "flows",
                                0
                            ),

                        "Scope":
                            attacker.get(
                                "scope",
                                "Unknown"
                            ),

                        "Estimated OS":
                            attacker.get(
                                "estimated_os",
                                "Unknown"
                            ),

                        "OS Confidence":
                            attacker.get(
                                "os_confidence",
                                "Unknown"
                            ),

                        "TTL":
                            attacker.get(
                                "observed_ttl",
                                "Unknown"
                            ),

                        "TCP Window":
                            attacker.get(
                                "tcp_window",
                                "Unknown"
                            ),

                        "Country":
                            attacker.get(
                                "country",
                                "Unknown"
                            ),

                        "ASN":
                            (
                                attacker.get("asn")
                                if attacker.get("asn")
                                is not None
                                else "Unavailable"
                            ),

                        "Organization":
                            attacker.get(
                                "organization",
                                "Unknown"
                            ),
                    })

                attacker_df = pd.DataFrame(
                    attacker_rows
                )

                st.dataframe(
                    attacker_df,
                    use_container_width=True,
                    hide_index=True,
                )

        # =================================================
        # BRUTE FORCE
        # =================================================

        elif attack_type in {
            "SSH Brute Force",
            "FTP Brute Force",
        }:

            st.markdown(
                f"#### {attack_type} Investigation"
            )

            b1, b2, b3, b4 = st.columns(4)

            with b1:
                st.metric(
                    "Source IP",
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),
                )

            with b2:
                st.metric(
                    "Target Service",
                    alert.get(
                        "target_service",
                        "Unknown"
                    ),
                )

            with b3:
                st.metric(
                    "Target Port",
                    alert.get(
                        "target_port",
                        "Unknown"
                    ),
                )

            with b4:
                st.metric(
                    "Total Attempts",
                    alert.get(
                        "total_attempts",
                        0
                    ),
                )

            b5, b6, b7, b8 = st.columns(4)

            with b5:
                st.metric(
                    "Unique Source Ports",
                    alert.get(
                        "unique_source_ports",
                        0
                    ),
                )

            with b6:
                window = alert.get(
                    "observed_window_seconds"
                )

                st.metric(
                    "Observed Window",
                    (
                        f"{window:.2f}s"
                        if isinstance(
                            window,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with b7:
                st.metric(
                    "Estimated OS",
                    alert.get(
                        "estimated_os",
                        "Unknown"
                    ),
                )

            with b8:
                st.metric(
                    "OS Confidence",
                    alert.get(
                        "os_confidence",
                        "Unknown"
                    ),
                )

            st.markdown(
                "##### Source Intelligence"
            )

            brute_source_info = pd.DataFrame({
                "Field": [
                    "Source IP",
                    "Target IP",
                    "Target Service",
                    "Network Scope",
                    "Observed TTL",
                    "TCP Window",
                    "Country",
                    "Region",
                    "City",
                    "ASN",
                    "Organization",
                    "First Seen",
                    "Last Seen",
                ],

                "Value": [
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),

                    alert.get(
                        "target_ip",
                        "Unknown"
                    ),

                    alert.get(
                        "target_service",
                        "Unknown"
                    ),

                    alert.get(
                        "source_scope",
                        "Unknown"
                    ),

                    alert.get(
                        "observed_ttl",
                        "Unknown"
                    ),

                    alert.get(
                        "tcp_window",
                        "Unknown"
                    ),

                    alert.get(
                        "country",
                        "Unknown"
                    ),

                    alert.get(
                        "region",
                        "Unknown"
                    ),

                    alert.get(
                        "city",
                        "Unknown"
                    ),

                    (
                        alert.get("asn")
                        if alert.get("asn") is not None
                        else "Unavailable"
                    ),

                    alert.get(
                        "organization",
                        "Unknown"
                    ),

                    alert.get(
                        "first_seen",
                        "Unknown"
                    ),

                    alert.get(
                        "last_seen",
                        "Unknown"
                    ),
                ]
            })

            st.dataframe(
                brute_source_info,
                use_container_width=True,
                hide_index=True,
            )

        # =================================================
        # SLOW HTTP
        # =================================================

        elif attack_type == "Slow HTTP":

            st.markdown(
                "#### Slow HTTP Investigation"
            )

            s1, s2, s3, s4 = st.columns(4)

            with s1:
                st.metric(
                    "Source IP",
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),
                )

            with s2:
                st.metric(
                    "Target",
                    (
                        f"{target_ip}:{target_port}"
                        if target_port is not None
                        else target_ip
                    ),
                )

            with s3:
                st.metric(
                    "Target Service",
                    alert.get(
                        "target_service",
                        "HTTP"
                    ),
                )

            with s4:
                st.metric(
                    "Suspicious Flows",
                    alert.get(
                        "suspicious_flows",
                        0
                    ),
                )

            s5, s6, s7, s8 = st.columns(4)

            with s5:
                duration = alert.get(
                    "average_flow_duration"
                )

                st.metric(
                    "Avg Flow Duration",
                    (
                        f"{duration:.2f}s"
                        if isinstance(
                            duration,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with s6:
                maximum = alert.get(
                    "max_flow_duration"
                )

                st.metric(
                    "Max Flow Duration",
                    (
                        f"{maximum:.2f}s"
                        if isinstance(
                            maximum,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with s7:
                packets = alert.get(
                    "average_packets_per_flow"
                )

                st.metric(
                    "Avg Packets / Flow",
                    (
                        f"{packets:.2f}"
                        if isinstance(
                            packets,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with s8:
                window = alert.get(
                    "observed_window_seconds"
                )

                st.metric(
                    "Observed Window",
                    (
                        f"{window:.2f}s"
                        if isinstance(
                            window,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            st.markdown(
                "##### Source Intelligence"
            )

            slow_http_info = pd.DataFrame({
                "Field": [
                    "Source IP",
                    "Target IP",
                    "Target Port",
                    "Target Service",
                    "Network Scope",
                    "Estimated OS",
                    "OS Confidence",
                    "Observed TTL",
                    "TCP Window",
                    "Country",
                    "Region",
                    "City",
                    "ASN",
                    "Organization",
                    "First Seen",
                    "Last Seen",
                ],

                "Value": [
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),

                    alert.get(
                        "target_ip",
                        "Unknown"
                    ),

                    alert.get(
                        "target_port",
                        "Unknown"
                    ),

                    alert.get(
                        "target_service",
                        "HTTP"
                    ),

                    alert.get(
                        "source_scope",
                        "Unknown"
                    ),

                    alert.get(
                        "estimated_os",
                        "Unknown"
                    ),

                    alert.get(
                        "os_confidence",
                        "Unknown"
                    ),

                    alert.get(
                        "observed_ttl",
                        "Unknown"
                    ),

                    alert.get(
                        "tcp_window",
                        "Unknown"
                    ),

                    alert.get(
                        "country",
                        "Unknown"
                    ),

                    alert.get(
                        "region",
                        "Unknown"
                    ),

                    alert.get(
                        "city",
                        "Unknown"
                    ),

                    (
                        alert.get("asn")
                        if alert.get("asn") is not None
                        else "Unavailable"
                    ),

                    alert.get(
                        "organization",
                        "Unknown"
                    ),

                    alert.get(
                        "first_seen",
                        "Unknown"
                    ),

                    alert.get(
                        "last_seen",
                        "Unknown"
                    ),
                ]
            })

            st.dataframe(
                slow_http_info,
                use_container_width=True,
                hide_index=True,
            )

        # =================================================
        # WEB ATTACKS
        # =================================================

        elif attack_type in {
            "Web Attack - XSS",
            "Web Attack - SQL Injection",
        }:

            st.markdown(
                "#### Web Attack Investigation"
            )

            w1, w2, w3, w4 = st.columns(4)

            with w1:
                st.metric(
                    "Source IP",
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),
                )

            with w2:
                st.metric(
                    "Target IP",
                    alert.get(
                        "target_ip",
                        "Unknown"
                    ),
                )

            with w3:
                st.metric(
                    "Target Port",
                    alert.get(
                        "target_port",
                        "Unknown"
                    ),
                )

            with w4:
                st.metric(
                    "Packet Number",
                    alert.get(
                        "packet_number",
                        "Unknown"
                    ),
                )

            # =============================================
            # CONNECTION DETAILS
            # =============================================

            st.markdown(
                "##### Network Context"
            )

            network_info = pd.DataFrame({
                "Field": [
                    "Attack Type",
                    "Detection Engine",
                    "Source IP",
                    "Source Port",
                    "Target IP",
                    "Target Port",
                    "Severity",
                ],

                "Value": [
                    attack_type,

                    alert.get(
                        "detection_engine",
                        "Payload Inspection"
                    ),

                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),

                    alert.get(
                        "source_port",
                        "Unknown"
                    ),

                    alert.get(
                        "target_ip",
                        "Unknown"
                    ),

                    alert.get(
                        "target_port",
                        "Unknown"
                    ),

                    severity,
                ],
            })

            st.dataframe(
                network_info,
                use_container_width=True,
                hide_index=True,
            )

            # =============================================
            # PAYLOAD INDICATORS
            # =============================================

            matched_patterns = alert.get(
                "matched_patterns",
                []
            )

            st.markdown(
                "##### Detected Payload Indicators"
            )

            if matched_patterns:

                indicator_df = pd.DataFrame({
                    "Indicator": matched_patterns
                })

                st.dataframe(
                    indicator_df,
                    use_container_width=True,
                    hide_index=True,
                )

            else:

                st.info(
                    "No individual payload indicators "
                    "were recorded."
                )

            # =============================================
            # ATTACK-SPECIFIC EXPLANATION
            # =============================================

            if attack_type == "Web Attack - XSS":

                st.warning(
                    "The HTTP request contains patterns "
                    "associated with Cross-Site Scripting "
                    "(XSS). Payload inspection detected "
                    "script-related indicators in the request."
                )

            elif attack_type == "Web Attack - SQL Injection":

                st.error(
                    "The HTTP request contains patterns "
                    "associated with SQL Injection. "
                    "Payload inspection detected SQL-control "
                    "indicators in the request."
                )

        # =================================================
        # BOT / C2 BEACONING
        # =================================================

        elif attack_type == "Bot / C2 Beaconing":

            st.markdown(
                "#### Bot / C2 Beaconing Investigation"
            )

            b1, b2, b3, b4 = st.columns(4)

            with b1:
                st.metric(
                    "Source IP",
                    alert.get(
                        "source_ip",
                        "Unknown"
                    ),
                )

            with b2:
                st.metric(
                    "Target",
                    (
                        f"{target_ip}:{target_port}"
                        if target_port is not None
                        else target_ip
                    ),
                )

            with b3:
                st.metric(
                    "Connections",
                    alert.get(
                        "total_connections",
                        0
                    ),
                )

            with b4:
                st.metric(
                    "Severity",
                    severity,
                )

            b5, b6, b7, b8 = st.columns(4)

            with b5:
                interval = alert.get(
                    "average_interval_seconds"
                )

                st.metric(
                    "Avg Interval",
                    (
                        f"{interval:.2f}s"
                        if isinstance(
                            interval,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with b6:
                std_interval = alert.get(
                    "interval_std_seconds"
                )

                st.metric(
                    "Interval Std Dev",
                    (
                        f"{std_interval:.3f}s"
                        if isinstance(
                            std_interval,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with b7:
                cv = alert.get(
                    "interval_cv"
                )

                st.metric(
                    "Timing CV",
                    (
                        f"{cv:.4f}"
                        if isinstance(
                            cv,
                            (int, float)
                        )
                        else "Unknown"
                    ),
                )

            with b8:
                st.metric(
                    "Estimated OS",
                    alert.get(
                        "estimated_os",
                        "Unknown"
                    ),
                )

            st.markdown(
                "##### Source Intelligence"
            )

            beacon_info = pd.DataFrame({
                "Field": [
                    "Source IP",
                    "Target IP",
                    "Target Port",
                    "Network Scope",
                    "Estimated OS",
                    "OS Confidence",
                    "Observed TTL",
                    "TCP Window",
                    "Country",
                    "Region",
                    "City",
                    "ASN",
                    "Organization",
                    "First Seen",
                    "Last Seen",
                ],

                "Value": [
                    alert.get("source_ip", "Unknown"),
                    alert.get("target_ip", "Unknown"),
                    alert.get("target_port", "Unknown"),
                    alert.get("source_scope", "Unknown"),
                    alert.get("estimated_os", "Unknown"),
                    alert.get("os_confidence", "Unknown"),
                    alert.get("observed_ttl", "Unknown"),
                    alert.get("tcp_window", "Unknown"),
                    alert.get("country", "Unknown"),
                    alert.get("region", "Unknown"),
                    alert.get("city", "Unknown"),
                    (
                        alert.get("asn")
                        if alert.get("asn") is not None
                        else "Unavailable"
                    ),
                    alert.get("organization", "Unknown"),
                    alert.get("first_seen", "Unknown"),
                    alert.get("last_seen", "Unknown"),
                ],
            })

            st.dataframe(
                beacon_info,
                use_container_width=True,
                hide_index=True,
            )

            st.info(
                "Regular outbound connection timing was "
                "observed. A very low timing coefficient "
                "of variation can indicate automated "
                "bot or command-and-control beaconing."
            )

        # =================================================
        # EVIDENCE
        # =================================================

        st.markdown(
            "##### Detection Evidence"
        )

        st.warning(
            alert.get(
                "reason",
                "No evidence description available."
            )
        )

        st.caption(
            f"First seen: "
            f"{alert.get('first_seen', 'Unknown')}  •  "
            f"Last seen: "
            f"{alert.get('last_seen', 'Unknown')}  •  "
            f"Engine: "
            f"{alert.get('detection_engine', 'Unknown')}"
        )




# =========================================================
# LOAD MODELS
# =========================================================

(
    binary_model,
    multiclass_model,
    label_encoder,
    model_errors,
) = get_models()


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown(
        """
        <div class="brand">
            <div class="brand-icon">🛡️</div>
            <div>
                <div class="brand-title">AI-IDS</div>
                <div class="brand-subtitle">
                    Intelligent Threat Detection
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Navigation",
        [
            "Security Dashboard",
            "Traffic Analyzer",
            "Batch Detection",
            "Model Performance",
        ],
        label_visibility="collapsed",
    )

    st.markdown(
        """
        <div class="sidebar-box">
            <div class="sidebar-small">
                <b>ENGINE</b><br>
                Binary XGBoost + Multiclass XGBoost
                <br><br>
                <b>DATASET</b><br>
                CIC-IDS2017
                <br><br>
                <b>FEATURES</b><br>
                78 network-flow features
                <br><br>
                <b>MODE</b><br>
                Two-stage intrusion detection
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if model_errors:
        st.error(
            "Required models are missing."
        )

        with st.expander(
            "Missing files"
        ):
            for error in model_errors:
                st.code(error)


# =========================================================
# HEADER
# =========================================================

# =========================================================
# HEADER
# =========================================================

current_time = datetime.now().strftime(
    "%d %b %Y • %H:%M:%S"
)

header_left, header_right = st.columns(
    [4, 1],
    vertical_alignment="center"
)

with header_left:
    st.markdown(
        """
        <div class="header-title">
            AI-IDS Security Center
        </div>
        <div class="header-subtitle">
            AI-powered network intrusion detection and
            attack classification
        </div>
        """,
        unsafe_allow_html=True,
    )

with header_right:
    st.markdown(
        f"""
        <div style="
            text-align:right;
            padding-top:8px;
        ">
            <div class="online-badge">
                ● SYSTEM ONLINE
            </div>
            <div style="
                color:#71869f;
                font-size:10px;
                margin-top:7px;
            ">
                {current_time}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =========================================================
# MODEL AVAILABILITY
# =========================================================

if model_errors:
    st.warning(
        "The dashboard cannot perform predictions until all "
        "trained models are available."
    )


# =========================================================
# PAGE 1: SECURITY DASHBOARD
# =========================================================

if page == "Security Dashboard":

    st.markdown(
        "### Security Overview"
    )

    # -----------------------------------------------------
    # Dashboard stats
    # -----------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        render_metric(
            "Detection Engine",
            "ONLINE",
            "Binary + multiclass pipeline",
            "metric-accent-green",
        )

    with col2:
        render_metric(
            "Primary Model",
            "XGBoost",
            "Binary F1: 99.76%",
            "metric-accent-blue",
        )

    with col3:
        render_metric(
            "Binary Detection",
            "99.92%",
            "Held-out test accuracy",
            "metric-accent-purple",
        )

    with col4:
        render_metric(
            "Multiclass F1",
            "92.82%",
            "Macro F1 across 15 classes",
            "metric-accent-red",
        )

    # -----------------------------------------------------
    # Main panels
    # -----------------------------------------------------

    left, right = st.columns(
        [1.45, 1]
    )

    with left:

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    AI Detection Pipeline
                </div>
                <div class="panel-subtitle">
                    Two-stage threat classification architecture
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        pipeline_df = pd.DataFrame({
            "Stage": [
                "Network Flow",
                "Feature Processing",
                "Binary XGBoost",
                "Multiclass XGBoost",
                "Final Verdict",
            ],
            "Function": [
                "Raw flow / CICFlowMeter features",
                "78 numerical features",
                "Benign vs Attack",
                "Specific attack classification",
                "Alert + confidence",
            ],
            "Status": [
                "READY",
                "READY",
                "ACTIVE",
                "ACTIVE",
                "READY",
            ],
        })

        st.dataframe(
            pipeline_df,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown(
            """
            <div class="status-box">
                <div class="status-title">
                    ● Detection pipeline healthy
                </div>
                <div class="status-text">
                    Binary and multiclass XGBoost models are
                    available for inference.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    Threat Intelligence
                </div>
                <div class="panel-subtitle">
                    Classes monitored by the multiclass model
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if label_encoder is not None:

            classes = [
                normalize_label(x)
                for x in label_encoder.classes_
            ]

            for label in classes:

                if label == "BENIGN":
                    continue

                severity = severity_from_attack(
                    label
                )

                severity_class = {
                    "CRITICAL": "alert-critical",
                    "HIGH": "alert-high",
                    "MEDIUM": "alert-medium",
                    "NORMAL": "alert-normal",
                }.get(
                    severity,
                    "alert-medium"
                )

                st.markdown(
                    f"""
                    <div class="alert-card {severity_class}">
                        <div class="alert-label">
                            {severity} • {label}
                        </div>
                        <div class="alert-meta">
                            Active detection class
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


## =========================================================
# PAGE 2: TRAFFIC ANALYZER
# =========================================================

elif page == "Traffic Analyzer":

    st.markdown("### Traffic Analyzer")

    st.caption(
        "Analyze CICFlowMeter-compatible CSV files or "
        "Wireshark PCAP/PCAPNG captures."
    )

    if model_errors:
        st.error(
            "Required AI models are not available."
        )
        st.stop()

    input_type = st.radio(
        "Choose traffic input",
        [
            "CIC-IDS2017 Sample",
            "Upload CSV",
            "Upload PCAP / PCAPNG",
        ],
        horizontal=True,
    )

    # =====================================================
    # BUILT-IN DATASET
    # =====================================================

    if input_type == "CIC-IDS2017 Sample":

        source_file = st.selectbox(
            "Dataset",
            [
                "Wednesday-workingHours.pcap_ISCX.csv",
                "Tuesday-WorkingHours.pcap_ISCX.csv",
                "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                "Friday-WorkingHours-Morning.pcap_ISCX.csv",
                "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
                "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                "Monday-WorkingHours.pcap_ISCX.csv",
            ],
        )

        sample_type = st.radio(
            "Traffic type",
            [
                "Random flow",
                "Benign flow",
                "Random attack",
            ],
            horizontal=True,
        )

        source_path = (
            PROJECT_ROOT
            / "data"
            / "raw"
            / source_file
        )

        if (
            sample_type == "Random attack"
            and "Monday" in source_file
        ):
            st.warning(
                "Monday contains benign traffic only. "
                "Select another dataset for attack testing."
            )
            st.stop()

        if st.button(
            "Load Flow",
            use_container_width=True,
        ):

            selected_flow = find_flow_samples(
                source_path,
                sample_type,
            )

            if selected_flow is None:

                st.error(
                    "No matching flow found."
                )

            else:

                st.session_state[
                    "selected_flow"
                ] = selected_flow

        selected_flow = st.session_state.get(
            "selected_flow"
        )

        if selected_flow is not None:

            actual_label = "Unknown"

            if "Label" in selected_flow.columns:

                actual_label = normalize_label(
                    selected_flow.iloc[0]["Label"]
                )

            st.markdown(
                "#### Selected Flow"
            )

            a, b, c = st.columns(3)

            with a:
                st.metric(
                    "Dataset",
                    source_file.replace(
                        ".pcap_ISCX.csv",
                        ""
                    ),
                )

            with b:
                st.metric(
                    "Ground Truth",
                    actual_label,
                )

            with c:

                traffic_type = (
                    "NORMAL"
                    if actual_label == "BENIGN"
                    else "ATTACK"
                )

                st.metric(
                    "Traffic Type",
                    traffic_type,
                )

            if st.button(
                "🔍 Analyze Flow",
                use_container_width=True,
            ):

                result = run_predictions(
                    selected_flow,
                    binary_model,
                    multiclass_model,
                    label_encoder,
                ).iloc[0]

                is_attack = (
                    result["Binary Prediction"]
                    == "ATTACK"
                )

                if is_attack:

                    st.error(
                        f"🚨 ATTACK DETECTED — "
                        f"{result['Attack Type']}"
                    )

                else:

                    st.success(
                        "✓ BENIGN TRAFFIC"
                    )

                r1, r2, r3 = st.columns(3)

                with r1:
                    st.metric(
                        "Verdict",
                        result["Binary Prediction"],
                    )

                with r2:
                    st.metric(
                        "Binary Confidence",
                        f"{result['Binary Confidence (%)']:.2f}%",
                    )

                with r3:
                    st.metric(
                        "Attack Type",
                        result["Attack Type"],
                    )

                verification = pd.DataFrame({
                    "Field": [
                        "Ground Truth",
                        "AI Prediction",
                        "Binary Confidence",
                        "Attack Confidence",
                        "Status",
                    ],
                    "Value": [
                        actual_label,
                        (
                            result["Attack Type"]
                            if is_attack
                            else "BENIGN"
                        ),
                        f"{result['Binary Confidence (%)']:.2f}%",
                        f"{result['Attack Confidence (%)']:.2f}%",
                        result["Status"],
                    ],
                })

                st.markdown(
                    "#### Prediction Verification"
                )

                st.dataframe(
                    verification,
                    use_container_width=True,
                    hide_index=True,
                )

    # =====================================================
    # USER CSV
    # =====================================================

    elif input_type == "Upload CSV":

        uploaded_csv = st.file_uploader(
            "Upload CICFlowMeter-compatible CSV",
            type=["csv"],
            key="traffic_csv",
        )

        if uploaded_csv is not None:

            try:

                df = pd.read_csv(
                    uploaded_csv,
                    low_memory=False,
                )

                df.columns = (
                    df.columns
                    .astype(str)
                    .str.strip()
                )

                st.success(
                    f"CSV loaded: {len(df):,} rows, "
                    f"{len(df.columns)} columns"
                )

                if len(df) > 100_000:

                    st.warning(
                        "Only the first 100,000 flows "
                        "will be analyzed."
                    )

                    df = df.head(
                        100_000
                    )

                if st.button(
                    "🚨 Analyze CSV",
                    use_container_width=True,
                    key="analyze_csv",
                ):

                    with st.spinner(
                        "Running AI-IDS..."
                    ):

                        results = run_predictions(
                            df,
                            binary_model,
                            multiclass_model,
                            label_encoder,
                        )

                    attacks = int(
                        (
                            results[
                                "Binary Prediction"
                            ]
                            == "ATTACK"
                        ).sum()
                    )

                    benign = (
                        len(results) - attacks
                    )

                    c1, c2, c3 = st.columns(3)

                    with c1:
                        st.metric(
                            "Flows",
                            f"{len(results):,}",
                        )

                    with c2:
                        st.metric(
                            "Benign",
                            f"{benign:,}",
                        )

                    with c3:
                        st.metric(
                            "Threats",
                            f"{attacks:,}",
                        )

                    st.dataframe(
                        results,
                        use_container_width=True,
                        hide_index=True,
                    )

                    output = pd.concat(
                        [
                            df.reset_index(drop=True),
                            results.reset_index(drop=True),
                        ],
                        axis=1,
                    )

                    csv_data = output.to_csv(
                        index=False
                    ).encode("utf-8")

                    st.download_button(
                        "⬇️ Download Results",
                        data=csv_data,
                        file_name=(
                            "ai_ids_csv_results.csv"
                        ),
                        mime="text/csv",
                        use_container_width=True,
                    )

            except Exception as exc:

                st.error(
                    f"CSV processing failed:\n{exc}"
                )

    # =====================================================
    # USER PCAP
    # =====================================================

    elif input_type == "Upload PCAP / PCAPNG":

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    PCAP Threat Investigation
                </div>
                <div class="panel-subtitle">
                    Upload a Wireshark PCAP / PCAPNG capture.
                    The complete AI-IDS pipeline will perform
                    flow extraction, XGBoost detection,
                    behavioral analysis, OS fingerprinting,
                    GeoIP / ASN enrichment and final
                    threat correlation.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        uploaded_pcap = st.file_uploader(
            "Upload PCAP / PCAPNG",
            type=[
                "pcap",
                "pcapng",
            ],
            key="traffic_pcap",
        )

        if uploaded_pcap is not None:

            st.info(
                f"File: {uploaded_pcap.name} • "
                f"Size: "
                f"{uploaded_pcap.size / (1024 * 1024):.2f} MB"
            )

            # =================================================
            # ANALYZE BUTTON
            # =================================================

            if st.button(
                "⚡ Run Complete AI-IDS Analysis",
                use_container_width=True,
                key="process_complete_pcap",
            ):

                temp_dir = Path(
                    tempfile.mkdtemp(
                        prefix="ai_ids_"
                    )
                )

                input_path = (
                    temp_dir
                    / uploaded_pcap.name
                )

                try:

                    # -----------------------------------------
                    # Save uploaded PCAP temporarily
                    # -----------------------------------------

                    input_path.write_bytes(
                        uploaded_pcap.getbuffer()
                    )

                    # -----------------------------------------
                    # Run complete pipeline
                    # -----------------------------------------

                    with st.status(
                        "Running complete AI-IDS pipeline...",
                        expanded=True,
                    ) as status:

                        st.write(
                            "✓ Upload received"
                        )

                        st.write(
                            "⏳ Extracting CICFlowMeter flows..."
                        )

                        st.write(
                            "⏳ Running XGBoost ML detection..."
                        )

                        st.write(
                            "⏳ Running behavioral IDS..."
                        )

                        st.write(
                            "⏳ Performing passive OS fingerprinting..."
                        )

                        st.write(
                            "⏳ Looking up GeoIP and ASN intelligence..."
                        )

                        st.write(
                            "⏳ Correlating security evidence..."
                        )

                        report = analyze_pcap(
                            input_path
                        )

                        status.update(
                            label=(
                                "✓ Complete AI-IDS analysis finished"
                            ),
                            state="complete",
                            expanded=False,
                        )

                    # Keep report after Streamlit reruns
                    st.session_state[
                        "pcap_security_report"
                    ] = report

                    st.session_state[
                        "pcap_original_name"
                    ] = uploaded_pcap.name

                except Exception as exc:

                    st.error(
                        "PCAP analysis failed."
                    )

                    st.code(
                        str(exc)
                    )

                finally:

                    import shutil

                    shutil.rmtree(
                        temp_dir,
                        ignore_errors=True,
                    )

            # =================================================
            # LOAD STORED REPORT
            # =================================================

            report = st.session_state.get(
                "pcap_security_report"
            )

            if report:

                st.markdown("---")

                st.markdown(
                    "## 🛡️ Threat Investigation"
                )

                # =================================================
                # FINAL ALERT
                # =================================================

                final_decision = report.get(
                    "final_decision",
                    "UNKNOWN"
                )

                severity = report.get(
                    "severity",
                    "UNKNOWN"
                )

                attack_type = report.get(
                    "attack_type",
                    "Unknown"
                )

                if final_decision == "ATTACK":

                    st.error(
                        f"🚨 {severity} THREAT DETECTED — "
                        f"{attack_type}"
                    )

                else:

                    st.success(
                        "✓ No malicious activity detected"
                    )

                # =================================================
                # PRIMARY METRICS
                # =================================================

                c1, c2, c3, c4 = st.columns(4)

                with c1:

                    accent = (
                        "metric-accent-red"
                        if final_decision == "ATTACK"
                        else "metric-accent-green"
                    )

                    render_metric(
                        "Final Decision",
                        final_decision,
                        "Correlated IDS verdict",
                        accent,
                    )

                with c2:

                    render_metric(
                        "Attack Type",
                        attack_type,
                        "Identified threat",
                        "metric-accent-red",
                    )

                with c3:

                    render_metric(
                        "Severity",
                        severity,
                        "Overall risk level",
                        "metric-accent-purple",
                    )

                with c4:

                    render_metric(
                        "Detection Source",
                        report.get(
                            "detection_source",
                            "Unknown"
                        ),
                        "Engine producing alert",
                        "metric-accent-blue",
                    )

                # =================================================
                # DETAILED SECURITY ALERTS
                # =================================================

                alerts = report.get(
                    "alerts",
                    []
                )

                st.markdown(
                    "### Detected Security Events"
                )

                if alerts:

                    st.caption(
                        f"{len(alerts)} correlated security "
                        f"event(s) detected in this capture."
                    )

                    # Summary table
                    alert_summary_rows = []

                    for index, alert in enumerate(
                        alerts,
                        start=1,
                    ):

                        attack_type_item = alert.get(
                            "attack_type",
                            "Unknown"
                        )

                        target = alert.get(
                            "target_ip",
                            "Unknown"
                        )

                        target_port_item = alert.get(
                            "target_port"
                        )

                        if target_port_item is not None:
                            target = (
                                f"{target}:"
                                f"{target_port_item}"
                            )

                        if attack_type_item in {
                            "PortScan",
                            "SSH Brute Force",
                            "FTP Brute Force",
                            "Slow HTTP",
                            "Web Attack - XSS",
                            "Web Attack - SQL Injection",
                            "Bot / C2 Beaconing",
                        }:

                            source_description = alert.get(
                                "source_ip",
                                "Unknown"
                            )

                        elif attack_type_item in {
                            "DoS",
                            "DDoS",
                        }:

                            source_description = (
                                f"{alert.get('source_count', 1)} sources"
                            )

                        else:

                            source_description = alert.get(
                                "source_ip",
                                "Unknown"
                            )

                        alert_summary_rows.append({
                            "#": index,
                            "Severity": alert.get(
                                "severity",
                                "Unknown"
                            ),
                            "Attack": attack_type_item,
                            "Source": source_description,
                            "Target": target,
                            "Flows": alert.get(
                                "total_flows",
                                0
                            ),
                        })

                    summary_df = pd.DataFrame(
                        alert_summary_rows
                    )

                    st.dataframe(
                        summary_df,
                        use_container_width=True,
                        hide_index=True,
                    )

                    st.markdown(
                        "### Threat Investigation Details"
                    )

                    for index, alert in enumerate(
                        alerts,
                        start=1,
                    ):

                        render_security_alert(
                            alert,
                            index,
                        )

                else:

                    st.success(
                        "No detailed behavioral security "
                        "alerts were generated."
                    )

                # =================================================
                # DETECTION ENGINE COMPARISON
                # =================================================

                st.markdown(
                    "### Detection Engine Correlation"
                )

                engine_results = pd.DataFrame(
                    {
                        "Detection Engine": [
                            "XGBoost ML IDS",
                            "Behavioral IDS",
                            "Payload Inspection",
                            "Correlation Engine",
                        ],

                        "Result": [
                            (
                                f"{report.get('ml_attack_flows', 0)} "
                                "malicious flow(s)"
                            ),

                            (
                                f"{report.get('behavioral_alerts', 0)} "
                                "alert(s)"
                            ),

                            (
                                f"{report.get('web_alerts', 0)} "
                                "web payload alert(s)"
                            ),

                            final_decision,
                        ],

                        "Interpretation": [
                            (
                                "Individual flow classification"
                            ),

                            (
                                "Cross-flow behavior analysis"
                            ),

                            (
                                "HTTP payload inspection"
                            ),

                            (
                                "Final security decision"
                            ),
                        ],
                    }
                )

                st.dataframe(
                    engine_results,
                    use_container_width=True,
                    hide_index=True,
                )

                # =================================================
                # CORRELATION EXPLANATION
                # =================================================

                st.markdown(
                    "### Security Analysis"
                )

                st.info(
                    report.get(
                        "reason",
                        "No correlation explanation available."
                    )
                )

                # =================================================
                # DOWNLOAD FINAL REPORT
                # =================================================

                st.markdown(
                    "### Export Investigation"
                )

                import json

                report_json = json.dumps(
                    report,
                    indent=4,
                ).encode(
                    "utf-8"
                )

                download_name = (
                    Path(
                        st.session_state.get(
                            "pcap_original_name",
                            "capture.pcap"
                        )
                    ).stem
                    + "_security_report.json"
                )

                st.download_button(
                    "⬇️ Download Security Report",
                    data=report_json,
                    file_name=download_name,
                    mime="application/json",
                    use_container_width=True,
                )
# =========================================================
# PAGE 3: BATCH DETECTION
# =========================================================

elif page == "Batch Detection":

    st.markdown(
        "### Batch Traffic Detection"
    )

    st.caption(
        "Upload a CICFlowMeter/CIC-IDS2017 CSV and classify "
        "network flows in batches."
    )

    if model_errors:
        st.stop()

    uploaded = st.file_uploader(
        "Upload network-flow CSV",
        type=["csv"],
    )

    if uploaded is not None:

        try:

            df = pd.read_csv(
                uploaded,
                low_memory=False
            )

            df.columns = (
                df.columns
                .astype(str)
                .str.strip()
            )

            st.info(
                f"Loaded {len(df):,} rows and "
                f"{len(df.columns):,} columns."
            )

            if len(df) > 100_000:

                st.warning(
                    "For dashboard responsiveness, only the "
                    "first 100,000 flows will be analyzed."
                )

                df = df.head(
                    100_000
                )

            if st.button(
                "🚨 Analyze Uploaded Traffic",
                use_container_width=True,
            ):

                with st.spinner(
                    "Running AI intrusion detection..."
                ):

                    result = run_predictions(
                        df,
                        binary_model,
                        multiclass_model,
                        label_encoder,
                    )

                combined = pd.concat(
                    [
                        df.reset_index(drop=True),
                        result.reset_index(drop=True),
                    ],
                    axis=1,
                )

                total = len(
                    combined
                )

                attacks = int(
                    (
                        combined[
                            "Binary Prediction"
                        ]
                        == "ATTACK"
                    ).sum()
                )

                benign = (
                    total - attacks
                )

                attack_rate = (
                    attacks / total * 100
                    if total
                    else 0
                )

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    render_metric(
                        "Flows Analyzed",
                        f"{total:,}",
                        "Current batch",
                        "metric-accent-blue",
                    )

                with col2:
                    render_metric(
                        "Benign",
                        f"{benign:,}",
                        "Normal flows",
                        "metric-accent-green",
                    )

                with col3:
                    render_metric(
                        "Threats",
                        f"{attacks:,}",
                        "Detected attacks",
                        "metric-accent-red",
                    )

                with col4:
                    render_metric(
                        "Threat Rate",
                        f"{attack_rate:.2f}%",
                        "Attack share",
                        "metric-accent-purple",
                    )

                # -----------------------------------------
                # Attack distribution
                # -----------------------------------------

                attack_only = combined[
                    combined[
                        "Binary Prediction"
                    ] == "ATTACK"
                ].copy()

                if not attack_only.empty:

                    st.markdown(
                        """
                        <div class="panel">
                            <div class="panel-title">
                                Detected Threat Distribution
                            </div>
                            <div class="panel-subtitle">
                                Attack classes identified by the
                                multiclass model
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    distribution = (
                        attack_only[
                            "Attack Type"
                        ]
                        .value_counts()
                        .rename_axis(
                            "Attack Type"
                        )
                        .reset_index(
                            name="Count"
                        )
                    )

                    st.bar_chart(
                        distribution.set_index(
                            "Attack Type"
                        )
                    )

                # -----------------------------------------
                # Prediction table
                # -----------------------------------------

                st.markdown(
                    """
                    <div class="panel">
                        <div class="panel-title">
                            Prediction Results
                        </div>
                        <div class="panel-subtitle">
                            AI-generated verdicts and confidence
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                table_columns = [
                    "Binary Prediction",
                    "Binary Confidence (%)",
                    "Attack Type",
                    "Attack Confidence (%)",
                    "Status",
                ]

                st.dataframe(
                    combined[
                        table_columns
                    ].head(1000),
                    use_container_width=True,
                    hide_index=True,
                )

                # -----------------------------------------
                # Download
                # -----------------------------------------

                csv_output = combined.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "⬇️ Download Detection Results",
                    data=csv_output,
                    file_name="ai_ids_detection_results.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

        except Exception as exc:

            st.error(
                f"Unable to analyze the uploaded CSV: {exc}"
            )


# =========================================================
# PAGE 4: MODEL PERFORMANCE
# =========================================================

elif page == "Model Performance":

    st.markdown(
        "### Model Performance"
    )

    st.caption(
        "Performance measured on the held-out test sets used "
        "during model development."
    )

    # -----------------------------------------------------
    # Binary model comparison
    # -----------------------------------------------------

    comparison_file = (
        COMPARISON_DIR
        / "binary_model_comparison.csv"
    )

    if comparison_file.exists():

        comparison = pd.read_csv(
            comparison_file
        )

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    Binary Model Comparison
                </div>
                <div class="panel-subtitle">
                    Same binary test split across all baseline models
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        display_comparison = comparison.copy()

        for column in [
            "accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "pr_auc",
        ]:

            if column in display_comparison:
                display_comparison[column] = (
                    display_comparison[column] * 100
                ).round(3)

        st.dataframe(
            display_comparison,
            use_container_width=True,
            hide_index=True,
        )

        chart_data = comparison.set_index(
            "model"
        )[
            [
                "precision",
                "recall",
                "f1",
                "roc_auc",
                "pr_auc",
            ]
        ].copy()

        chart_data.columns = [
            "Precision",
            "Recall",
            "F1",
            "ROC-AUC",
            "PR-AUC",
        ]

        st.bar_chart(
            chart_data
        )

    # -----------------------------------------------------
    # Binary evaluation assets
    # -----------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        confusion_path = (
            EVALUATION_DIR
            / "confusion_matrix.png"
        )

        if confusion_path.exists():

            st.markdown(
                """
                <div class="panel">
                    <div class="panel-title">
                        Binary Confusion Matrix
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.image(
                str(confusion_path),
                use_container_width=True,
            )

    with col2:

        roc_path = (
            EVALUATION_DIR
            / "roc_curve.png"
        )

        if roc_path.exists():

            st.markdown(
                """
                <div class="panel">
                    <div class="panel-title">
                        ROC Curve
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.image(
                str(roc_path),
                use_container_width=True,
            )

    # -----------------------------------------------------
    # Precision recall
    # -----------------------------------------------------

    pr_path = (
        EVALUATION_DIR
        / "precision_recall_curve.png"
    )

    if pr_path.exists():

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    Precision-Recall Curve
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.image(
            str(pr_path),
            use_container_width=True,
        )

    # -----------------------------------------------------
    # Feature importance
    # -----------------------------------------------------

    feature_file = (
        EVALUATION_DIR
        / "feature_importance.csv"
    )

    if feature_file.exists():

        features = pd.read_csv(
            feature_file
        ).head(20)

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    Top XGBoost Features
                </div>
                <div class="panel-subtitle">
                    Model-derived feature importance
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.bar_chart(
            features.set_index(
                "Feature"
            )["Importance"]
        )

    # -----------------------------------------------------
    # Multiclass
    # -----------------------------------------------------

    multiclass_report_file = (
        MULTICLASS_RESULTS_DIR
        / "per_class_metrics.csv"
    )

    if multiclass_report_file.exists():

        st.markdown(
            """
            <div class="panel">
                <div class="panel-title">
                    Multiclass Detection Performance
                </div>
                <div class="panel-subtitle">
                    Per-class metrics for the 15-class IDS
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        multiclass = pd.read_csv(
            multiclass_report_file
        )

        multiclass["Label"] = (
            multiclass["Label"]
            .apply(normalize_label)
        )

        for column in [
            "Precision",
            "Recall",
            "F1",
        ]:

            multiclass[column] = (
                multiclass[column] * 100
            ).round(2)

        st.dataframe(
            multiclass,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown(
            """
            <div class="status-box">
                <div class="status-title">
                    Evaluation note
                </div>
                <div class="status-text">
                    Rare classes such as Heartbleed, Infiltration,
                    and SQL Injection have very small test support.
                    Their metrics should therefore be interpreted
                    cautiously.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <div style="
        text-align:center;
        margin-top:35px;
        color:#52677f;
        font-size:10px;
    ">
        AI-IDS Security Center • CIC-IDS2017 •
        XGBoost-powered Network Intrusion Detection
    </div>
    """,
    unsafe_allow_html=True,
)
