"""
Prepare CIC-IDS2017 data for binary IDS training.

Tasks:
1. Remove exact duplicate rows globally.
2. Create deterministic train/validation/test splits.
3. Preserve the original Label.
4. Use BinaryLabel as the prediction target.
"""

from pathlib import Path
import hashlib

import pandas as pd


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

OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "splits"


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

CHUNK_SIZE = 100_000

# 70% train, 15% validation, 15% test
TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15

RANDOM_SEED = 42


# ---------------------------------------------------------
# Stable row hash
# ---------------------------------------------------------

def row_hash(row: tuple) -> str:
    """
    Create a deterministic hash for a complete row.
    """

    text = "|".join(map(str, row))

    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found:\n{INPUT_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    train_file = OUTPUT_DIR / "train.csv"
    validation_file = OUTPUT_DIR / "validation.csv"
    test_file = OUTPUT_DIR / "test.csv"

    # Remove previously generated files
    for file in [train_file, validation_file, test_file]:
        if file.exists():
            file.unlink()

    print("=" * 60)
    print("CIC-IDS2017 DATA PREPARATION")
    print("=" * 60)

    print(f"Input: {INPUT_FILE}")
    print(f"Output directory: {OUTPUT_DIR}")
    print()

    seen_hashes = set()

    total_rows = 0
    duplicate_rows = 0

    train_rows = 0
    validation_rows = 0
    test_rows = 0

    first_train = True
    first_validation = True
    first_test = True

    # Deterministic random generator
    rng = pd.Series(range(CHUNK_SIZE)).sample(
        frac=1,
        random_state=RANDOM_SEED
    )

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            INPUT_FILE,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ),
        start=1
    ):

        print(f"Processing chunk {chunk_number}...")

        total_rows += len(chunk)

        # -------------------------------------------------
        # Global duplicate removal
        # -------------------------------------------------

        hashes = []

        for row in chunk.itertuples(index=False, name=None):
            hashes.append(row_hash(row))

        keep_mask = []

        for h in hashes:

            if h in seen_hashes:
                keep_mask.append(False)
                duplicate_rows += 1
            else:
                seen_hashes.add(h)
                keep_mask.append(True)

        chunk = chunk.loc[keep_mask].copy()

        if chunk.empty:
            continue

        # -------------------------------------------------
        # Deterministic random split
        # -------------------------------------------------

        random_values = pd.Series(
            range(len(chunk)),
            index=chunk.index
        ).sample(
            frac=1,
            random_state=RANDOM_SEED + chunk_number
        )

        shuffled_indices = random_values.index

        chunk = chunk.loc[shuffled_indices]

        # 70 / 15 / 15 split
        n = len(chunk)

        train_end = int(n * TRAIN_RATIO)

        validation_end = train_end + int(
            n * VALIDATION_RATIO
        )

        train_chunk = chunk.iloc[:train_end]

        validation_chunk = chunk.iloc[
            train_end:validation_end
        ]

        test_chunk = chunk.iloc[
            validation_end:
        ]

        # -------------------------------------------------
        # Write files
        # -------------------------------------------------

        train_chunk.to_csv(
            train_file,
            mode="w" if first_train else "a",
            header=first_train,
            index=False
        )

        validation_chunk.to_csv(
            validation_file,
            mode="w" if first_validation else "a",
            header=first_validation,
            index=False
        )

        test_chunk.to_csv(
            test_file,
            mode="w" if first_test else "a",
            header=first_test,
            index=False
        )

        first_train = False
        first_validation = False
        first_test = False

        train_rows += len(train_chunk)
        validation_rows += len(validation_chunk)
        test_rows += len(test_chunk)

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print()
    print("=" * 60)
    print("DATA PREPARATION COMPLETE")
    print("=" * 60)

    print(f"Rows processed:       {total_rows:,}")
    print(f"Global duplicates:    {duplicate_rows:,}")
    print()

    print(f"Training rows:        {train_rows:,}")
    print(f"Validation rows:      {validation_rows:,}")
    print(f"Test rows:            {test_rows:,}")
    print()

    print("Files:")
    print(train_file)
    print(validation_file)
    print(test_file)


if __name__ == "__main__":
    main()