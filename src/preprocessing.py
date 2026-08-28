"""
CIC-IDS2017 preprocessing pipeline.

Converts the raw CIC-IDS2017 CSV files into a cleaned dataset
with both:
    1. Original multiclass Label
    2. Binary target: BENIGN vs ATTACK
"""

from pathlib import Path
import pandas as pd
import numpy as np


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

OUTPUT_FILE = PROCESSED_DIR / "cicids2017_clean.csv"


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

CHUNK_SIZE = 100_000

DROP_DUPLICATES = True


# ---------------------------------------------------------
# Load and clean one chunk
# ---------------------------------------------------------

def clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """
    Clean one chunk of CIC-IDS2017 data.
    """

    # Remove spaces around column names
    chunk.columns = chunk.columns.str.strip()

    # Replace positive/negative infinity with NaN
    chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Remove rows with missing values
    chunk.dropna(inplace=True)

    # Remove duplicate rows inside the chunk
    if DROP_DUPLICATES:
        chunk.drop_duplicates(inplace=True)

    # Create binary target
    chunk["BinaryLabel"] = (
        chunk["Label"]
        .astype(str)
        .str.strip()
        .ne("BENIGN")
        .astype(np.int8)
    )

    return chunk


# ---------------------------------------------------------
# Process all CSV files
# ---------------------------------------------------------

def process_dataset() -> None:
    """
    Process all CIC-IDS2017 CSV files chunk-by-chunk.
    """

    if not RAW_DIR.exists():
        raise FileNotFoundError(
            f"Raw dataset directory not found: {RAW_DIR}"
        )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(RAW_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in: {RAW_DIR}"
        )

    print("=" * 60)
    print("CIC-IDS2017 PREPROCESSING")
    print("=" * 60)

    print(f"Raw directory:       {RAW_DIR}")
    print(f"Output file:         {OUTPUT_FILE}")
    print(f"CSV files found:     {len(csv_files)}")
    print()

    first_write = True

    total_before = 0
    total_after = 0

    for csv_file in csv_files:

        print(f"Processing: {csv_file.name}")

        for chunk in pd.read_csv(
            csv_file,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ):

            before = len(chunk)
            total_before += before

            chunk = clean_chunk(chunk)

            after = len(chunk)
            total_after += after

            if after == 0:
                continue

            chunk.to_csv(
                OUTPUT_FILE,
                mode="w" if first_write else "a",
                header=first_write,
                index=False
            )

            first_write = False

        print("  Completed.")

    print()
    print("=" * 60)
    print("PREPROCESSING COMPLETE")
    print("=" * 60)

    print(f"Rows before cleaning: {total_before:,}")
    print(f"Rows after cleaning:  {total_after:,}")
    print(f"Rows removed:        {total_before - total_after:,}")

    if total_before > 0:
        retained = total_after / total_before * 100
        print(f"Rows retained:        {retained:.2f}%")

    print()
    print(f"Saved to:")
    print(OUTPUT_FILE)


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    process_dataset()