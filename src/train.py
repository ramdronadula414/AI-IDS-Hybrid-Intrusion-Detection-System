"""
Binary CIC-IDS2017 IDS using XGBoost.

Target:
    BENIGN = 0
    ATTACK = 1
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    average_precision_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

from xgboost import XGBClassifier


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data" / "processed" / "splits"
MODEL_DIR = PROJECT_ROOT / "models"

TRAIN_FILE = DATA_DIR / "train.csv"
VALIDATION_FILE = DATA_DIR / "validation.csv"
TEST_FILE = DATA_DIR / "test.csv"

MODEL_FILE = MODEL_DIR / "xgboost_binary_ids.joblib"


# ---------------------------------------------------------
# Settings
# ---------------------------------------------------------

CHUNK_SIZE = 100_000
RANDOM_STATE = 42


# ---------------------------------------------------------
# Load CSV
# ---------------------------------------------------------

def load_data(path: Path) -> pd.DataFrame:
    """
    Load a split CSV file.
    """

    print(f"Loading: {path.name}")

    chunks = []

    for chunk in pd.read_csv(
        path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):
        chunks.append(chunk)

    df = pd.concat(chunks, ignore_index=True)

    print(f"Rows loaded: {len(df):,}")

    return df


# ---------------------------------------------------------
# Prepare features
# ---------------------------------------------------------

def prepare_features(df: pd.DataFrame):
    """
    Separate features from targets and make all features numeric.
    """

    # Original target is retained for reporting
    labels = df["Label"].astype(str)

    # Binary target
    y = df["BinaryLabel"].astype(np.int8)

    # Remove both target columns
    X = df.drop(
        columns=["Label", "BinaryLabel"]
    ).copy()

    # Convert everything to numeric
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Replace invalid values
    X.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # Fill remaining missing values
    X.fillna(
        0,
        inplace=True
    )

    return X, y, labels


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 60)
    print("BINARY AI-IDS - XGBOOST")
    print("=" * 60)

    # -----------------------------------------------------
    # Load datasets
    # -----------------------------------------------------

    train_df = load_data(TRAIN_FILE)
    validation_df = load_data(VALIDATION_FILE)
    test_df = load_data(TEST_FILE)

    # -----------------------------------------------------
    # Prepare features
    # -----------------------------------------------------

    print("\nPreparing features...")

    X_train, y_train, _ = prepare_features(train_df)
    X_val, y_val, _ = prepare_features(validation_df)
    X_test, y_test, test_labels = prepare_features(test_df)

    print("Features:", X_train.shape[1])

    # -----------------------------------------------------
    # Class imbalance
    # -----------------------------------------------------

    negative = int((y_train == 0).sum())
    positive = int((y_train == 1).sum())

    scale_pos_weight = negative / positive

    print("\nClass distribution:")
    print("BENIGN:", f"{negative:,}")
    print("ATTACK:", f"{positive:,}")
    print(
        "scale_pos_weight:",
        round(scale_pos_weight, 4)
    )

    # -----------------------------------------------------
    # XGBoost model
    # -----------------------------------------------------

    print("\nTraining XGBoost...")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.10,
        subsample=0.80,
        colsample_bytree=0.80,

        objective="binary:logistic",

        eval_metric="logloss",

        scale_pos_weight=scale_pos_weight,

        random_state=RANDOM_STATE,

        n_jobs=-1,

        tree_method="hist"
    )

    model.fit(
        X_train,
        y_train,

        eval_set=[
            (X_val, y_val)
        ],

        verbose=True
    )

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("VALIDATION RESULTS")
    print("=" * 60)

    val_prob = model.predict_proba(X_val)[:, 1]

    val_pred = (
        val_prob >= 0.50
    ).astype(np.int8)

    print(
        "Accuracy:",
        round(
            accuracy_score(y_val, val_pred),
            4
        )
    )

    print(
        "Precision:",
        round(
            precision_score(
                y_val,
                val_pred,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                y_val,
                val_pred,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1:",
        round(
            f1_score(
                y_val,
                val_pred,
                zero_division=0
            ),
            4
        )
    )

    print(
        "ROC-AUC:",
        round(
            roc_auc_score(
                y_val,
                val_prob
            ),
            4
        )
    )

    print(
        "PR-AUC:",
        round(
            average_precision_score(
                y_val,
                val_prob
            ),
            4
        )
    )

    print("\nClassification report:")

    print(
        classification_report(
            y_val,
            val_pred,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )

    # -----------------------------------------------------
    # Test
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)

    test_prob = model.predict_proba(
        X_test
    )[:, 1]

    test_pred = (
        test_prob >= 0.50
    ).astype(np.int8)

    print(
        "Accuracy:",
        round(
            accuracy_score(
                y_test,
                test_pred
            ),
            4
        )
    )

    print(
        "Precision:",
        round(
            precision_score(
                y_test,
                test_pred,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                y_test,
                test_pred,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1:",
        round(
            f1_score(
                y_test,
                test_pred,
                zero_division=0
            ),
            4
        )
    )

    print(
        "ROC-AUC:",
        round(
            roc_auc_score(
                y_test,
                test_prob
            ),
            4
        )
    )

    print(
        "PR-AUC:",
        round(
            average_precision_score(
                y_test,
                test_prob
            ),
            4
        )
    )

    print("\nConfusion matrix:")

    print(
        confusion_matrix(
            y_test,
            test_pred
        )
    )

    print("\nClassification report:")

    print(
        classification_report(
            y_test,
            test_pred,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )

    # -----------------------------------------------------
    # Save model
    # -----------------------------------------------------

    joblib.dump(
        model,
        MODEL_FILE
    )

    print("\n" + "=" * 60)
    print("MODEL SAVED")
    print("=" * 60)

    print(MODEL_FILE)


if __name__ == "__main__":
    main()