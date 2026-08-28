"""
Prepare CIC-IDS2017 data for multiclass classification.

Creates stratified:
    train.csv
    validation.csv
    test.csv

Target:
    Label

The original binary target is retained.
"""

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cicids2017_clean.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "multiclass"
)


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

RANDOM_STATE = 42

TRAIN_SIZE = 0.70
VALIDATION_SIZE = 0.15
TEST_SIZE = 0.15


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 65)
    print("CIC-IDS2017 MULTICLASS PREPARATION")
    print("=" * 65)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found:\n{INPUT_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("\nLoading cleaned dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(f"Rows loaded: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    # -----------------------------------------------------
    # Clean labels
    # -----------------------------------------------------

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    print("\nOriginal class distribution:")
    print(
        df["Label"]
        .value_counts()
        .to_string()
    )

    # -----------------------------------------------------
    # First split: train vs temporary
    # -----------------------------------------------------

    train_df, temp_df = train_test_split(
        df,
        train_size=TRAIN_SIZE,
        stratify=df["Label"],
        random_state=RANDOM_STATE
    )

    # -----------------------------------------------------
    # Second split: validation vs test
    #
    # temp = 30%
    # validation should be 15% overall
    # test should be 15% overall
    #
    # Therefore split temp 50/50.
    # -----------------------------------------------------

    validation_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        stratify=temp_df["Label"],
        random_state=RANDOM_STATE
    )

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    train_file = OUTPUT_DIR / "train.csv"
    validation_file = OUTPUT_DIR / "validation.csv"
    test_file = OUTPUT_DIR / "test.csv"

    train_df.to_csv(
        train_file,
        index=False
    )

    validation_df.to_csv(
        validation_file,
        index=False
    )

    test_df.to_csv(
        test_file,
        index=False
    )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print("\n" + "=" * 65)
    print("MULTICLASS SPLIT COMPLETE")
    print("=" * 65)

    print(f"Training:   {len(train_df):,}")
    print(f"Validation: {len(validation_df):,}")
    print(f"Test:       {len(test_df):,}")

    for name, dataset in [
        ("TRAIN", train_df),
        ("VALIDATION", validation_df),
        ("TEST", test_df),
    ]:

        print("\n" + "-" * 65)
        print(name)
        print("-" * 65)

        print(
            dataset["Label"]
            .value_counts()
            .sort_index()
            .to_string()
        )

    print("\nFiles created:")
    print(train_file)
    print(validation_file)
    print(test_file)


if __name__ == "__main__":
    main()