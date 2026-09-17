"""AI-IDS Streamlit UI shell.

This module keeps the existing dashboard implementation intact in
``app_core.py`` and applies presentation-only navigation and copy changes
before executing it. Detection models, pipeline functions, thresholds,
reports and backend behavior remain unchanged.
"""

from pathlib import Path
import streamlit as st

_CORE_PATH = Path(__file__).with_name("app_core.py")
_source = _CORE_PATH.read_text(encoding="utf-8")

# ---------------------------------------------------------------------
# Presentation-only copy changes
# ---------------------------------------------------------------------
_source = _source.replace(
    "Premium Streamlit dashboard for the CIC-IDS2017 AI-based IDS.",
    "Premium Streamlit dashboard for the Hybrid AI-based Intrusion Detection System.",
)

_source = _source.replace(
    """                <b>DATASET</b><br>\n                CIC-IDS2017\n                <br><br>\n                <b>FEATURES</b><br>""",
    """                <b>DETECTION LAYERS</b><br>\n                ML Detection · Behavioral IDS · Payload Inspection · Correlation\n                <br><br>\n                <b>FEATURES</b><br>""",
)
_source = _source.replace(
    "Two-stage intrusion detection",
    "Hybrid intrusion detection",
)
_source = _source.replace(
    """            AI-powered network intrusion detection and\n            attack classification""",
    """            Security-first hybrid intrusion detection with\n            PCAP analysis, behavioral detection and payload inspection""",
)
_source = _source.replace(
    """        AI-IDS Security Center • CIC-IDS2017 •\n        XGBoost-powered Network Intrusion Detection""",
    """        AI-IDS Security Center • Hybrid Intrusion Detection •\n        PCAP-first Security Analysis""",
)

# Make the analyzer page title reflect the sidebar choice while leaving
# the existing PCAP/CSV processing code untouched.
_source = _source.replace(
    '''elif page == "Traffic Analyzer":\n\n    st.markdown("### Traffic Analyzer")\n\n    st.caption(\n        "Analyze CICFlowMeter-compatible CSV files or "\n        "Wireshark PCAP/PCAPNG captures."\n    )''',
    '''elif page == "Traffic Analyzer":\n\n    if st.session_state.get("_ai_ids_input_mode") == "Upload PCAP / PCAPNG":\n        st.markdown("### PCAP Analyzer")\n        st.caption(\n            "Primary analysis workflow — upload a Wireshark PCAP/PCAPNG capture "\n            "and run the complete hybrid AI-IDS pipeline."\n        )\n    else:\n        st.markdown("### CSV Analyzer")\n        st.caption(\n            "Analyze external CICFlowMeter-compatible network-flow CSV files. "\n            "No local CIC-IDS2017 dataset is required."\n        )''',
)

# Batch mode remains available but no longer implies a local CIC dataset.
_source = _source.replace(
    '"Upload a CICFlowMeter/CIC-IDS2017 CSV and classify "',
    '"Upload a CICFlowMeter-compatible CSV and classify "',
)

# ---------------------------------------------------------------------
# Navigation adapter
# ---------------------------------------------------------------------
_original_radio = st.radio

_NAV_ITEMS = {
    "🛡️  Security Dashboard": "Security Dashboard",
    "📦  PCAP Analyzer": "Traffic Analyzer",
    "📄  CSV Analyzer": "Traffic Analyzer",
    "🗂️  Batch Detection": "Batch Detection",
    "📈  Model Performance": "Model Performance",
}


def _navigation_radio(label, options, *args, **kwargs):
    options = list(options)

    if label == "Navigation" and "Traffic Analyzer" in options:
        selected = _original_radio(
            label,
            list(_NAV_ITEMS.keys()),
            *args,
            **kwargs,
        )

        if "PCAP Analyzer" in selected:
            st.session_state["_ai_ids_input_mode"] = "Upload PCAP / PCAPNG"
        elif "CSV Analyzer" in selected:
            st.session_state["_ai_ids_input_mode"] = "Upload CSV"
        else:
            st.session_state.pop("_ai_ids_input_mode", None)

        return _NAV_ITEMS[selected]

    if label == "Choose traffic input":
        forced_mode = st.session_state.get("_ai_ids_input_mode")
        if forced_mode in {"Upload PCAP / PCAPNG", "Upload CSV"}:
            # Do not render a second radio control. The sidebar card already
            # selected the analyzer workflow.
            return forced_mode

        # Defensive fallback: dataset-backed sample analysis is intentionally
        # removed from the user interface for portable deployments.
        portable_options = [
            item
            for item in ["Upload PCAP / PCAPNG", "Upload CSV"]
            if item in options
        ]
        return _original_radio(
            label,
            portable_options,
            *args,
            **kwargs,
        )

    return _original_radio(label, options, *args, **kwargs)


st.radio = _navigation_radio

# Execute the original dashboard implementation unchanged apart from the
# presentation-only source copy replacements above.
exec(compile(_source, str(_CORE_PATH), "exec"), globals())

# ---------------------------------------------------------------------
# UI overlay — loaded last so it cleanly overrides Streamlit defaults.
# ---------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* Sidebar card navigation */
    section[data-testid="stSidebar"] [role="radiogroup"] {
        gap: 10px !important;
    }

    section[data-testid="stSidebar"] [role="radiogroup"] label {
        min-height: 54px !important;
        padding: 13px 14px !important;
        margin-bottom: 2px !important;
        border-radius: 14px !important;
        border: 1px solid rgba(84, 195, 210, 0.14) !important;
        background: linear-gradient(145deg, rgba(10, 31, 43, 0.94), rgba(6, 23, 34, 0.96)) !important;
        box-shadow: 0 8px 22px rgba(0, 0, 0, 0.14) !important;
        transition: transform .18s ease, border-color .18s ease, background .18s ease, box-shadow .18s ease !important;
    }

    section[data-testid="stSidebar"] [role="radiogroup"] label > div:first-child {
        display: none !important;
    }

    section[data-testid="stSidebar"] [role="radiogroup"] label p {
        color: #eafafd !important;
        font-size: 13px !important;
        font-weight: 800 !important;
        letter-spacing: .1px !important;
    }

    section[data-testid="stSidebar"] [role="radiogroup"] label:hover {
        transform: translateY(-1px) !important;
        border-color: rgba(51, 223, 232, 0.40) !important;
        background: linear-gradient(145deg, rgba(12, 44, 58, 0.97), rgba(7, 31, 43, 0.98)) !important;
        box-shadow: 0 0 22px rgba(38, 217, 226, 0.09) !important;
    }

    section[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
        border-color: rgba(45, 232, 231, 0.95) !important;
        background: linear-gradient(135deg, rgba(13, 73, 85, 0.98), rgba(7, 43, 54, 0.98)) !important;
        box-shadow: 0 0 25px rgba(45, 232, 231, 0.15), inset 0 0 18px rgba(32, 227, 212, 0.05) !important;
    }

    /* Stronger security-center surfaces */
    .stApp {
        background:
            radial-gradient(ellipse 900px 600px at 8% -5%, rgba(36, 206, 255, 0.12), transparent 55%),
            radial-gradient(ellipse 900px 700px at 96% 0%, rgba(24, 224, 178, 0.10), transparent 55%),
            linear-gradient(180deg, #030e17 0%, #061723 55%, #041019 100%) !important;
    }

    .metric-card,
    [data-testid="stMetric"] {
        border-color: rgba(83, 197, 207, 0.16) !important;
        box-shadow: 0 14px 34px rgba(0, 0, 0, 0.24) !important;
    }

    [data-testid="stFileUploader"] {
        border: 1px dashed rgba(45, 226, 232, 0.38) !important;
        border-radius: 16px !important;
        background: linear-gradient(145deg, rgba(8, 31, 43, 0.92), rgba(6, 22, 31, 0.96)) !important;
        padding: 10px !important;
    }

    [data-testid="stFileUploaderDropzone"] {
        background: transparent !important;
        border: none !important;
    }

    .stButton > button,
    .stDownloadButton > button {
        min-height: 45px !important;
        border-radius: 13px !important;
        font-weight: 800 !important;
    }

    @media (max-width: 1000px) {
        .block-container {
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }
        .header-title { font-size: 26px !important; }
        .metric-value { font-size: 27px !important; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)
