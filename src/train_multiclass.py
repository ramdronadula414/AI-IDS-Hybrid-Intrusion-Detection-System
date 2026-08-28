"""
CIC-IDS2017 Multiclass XGBoost IDS

Predicts the original CIC-IDS2017 attack class.

Outputs:
    - Accuracy
    - Macro Precision / Recall / F1
    - Weighted Precision / Recall / F1
    - Confusion matrix
    - Per-class classification report
    - Saved XGBoost model
    - Label encoder
"""

from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "multiclass"
)

MODEL_DIR = (
    PROJECT_ROOT
    / "models"
    / "multiclass"
)

TRAIN_FILE = DATA_DIR / "train.csv"
VALIDATION_FILE = DATA_DIR / "validation.csv"
TEST_FILE = DATA_DIR / "test.csv"

MODEL_FILE = (
    MODEL_DIR
    / "xgboost_multiclass_ids.joblib"
)

ENCODER_FILE = (
    MODEL_DIR
    / "label_encoder.joblib"
)

RANDOM_STATE = 42


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

def load_dataset(path):

    print(f"Loading {path.name}...")

    df = pd.read_csv(
        path,
        low_memory=False
    )

    labels = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    X = df.drop(
        columns=["Label", "BinaryLabel"],
        errors="ignore"
    ).copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    X.fillna(
        0,
        inplace=True
    )

    print(
        f"Rows: {len(df):,}, "
        f"Features: {X.shape[1]}"
    )

    return X, labels


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 65)
    print("CIC-IDS2017 MULTICLASS XGBOOST")
    print("=" * 65)

    # -----------------------------------------------------
    # Load data
    # -----------------------------------------------------

    X_train, labels_train = load_dataset(
        TRAIN_FILE
    )

    X_val, labels_val = load_dataset(
        VALIDATION_FILE
    )

    X_test, labels_test = load_dataset(
        TEST_FILE
    )

    # -----------------------------------------------------
    # Encode labels
    # -----------------------------------------------------

    encoder = LabelEncoder()

    y_train = encoder.fit_transform(
        labels_train
    )

    y_val = encoder.transform(
        labels_val
    )

    y_test = encoder.transform(
        labels_test
    )

    num_classes = len(
        encoder.classes_
    )

    print("\nClasses:")
    for i, label in enumerate(
        encoder.classes_
    ):
        print(
            f"{i:2d}: {label}"
        )

    print(
        f"\nNumber of classes: {num_classes}"
    )

    # -----------------------------------------------------
    # Class distribution
    # -----------------------------------------------------

    print("\nTraining class distribution:")

    train_counts = pd.Series(
        labels_train
    ).value_counts()

    print(
        train_counts.to_string()
    )

    # -----------------------------------------------------
    # Model
    # -----------------------------------------------------

    print("\nTraining XGBoost...")

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.10,
        subsample=0.80,
        colsample_bytree=0.80,

        objective="multi:softprob",

        num_class=num_classes,

        eval_metric="mlogloss",

        random_state=RANDOM_STATE,

        n_jobs=-1,

        tree_method="hist"
    )

    start = time.time()

    model.fit(
        X_train,
        y_train,
        eval_set=[
            (X_val, y_val)
        ],
        verbose=True
    )

    training_time = time.time() - start

    print(
        f"\nTraining time: "
        f"{training_time:.2f} seconds"
    )

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    print("\nGenerating test predictions...")

    probabilities = model.predict_proba(
        X_test
    )

    predictions = np.argmax(
        probabilities,
        axis=1
    )

    # -----------------------------------------------------
    # Overall metrics
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            y_test,
            predictions,
            average="macro",
            zero_division=0
        )
    )

    weighted_precision, weighted_recall, weighted_f1, _ = (
        precision_recall_fscore_support(
            y_test,
            predictions,
            average="weighted",
            zero_division=0
        )
    )

    print("\n" + "=" * 65)
    print("MULTICLASS TEST RESULTS")
    print("=" * 65)

    print(
        f"Accuracy:           {accuracy:.6f}"
    )

    print(
        f"Macro Precision:    {macro_precision:.6f}"
    )

    print(
        f"Macro Recall:       {macro_recall:.6f}"
    )

    print(
        f"Macro F1:           {macro_f1:.6f}"
    )

    print(
        f"Weighted Precision: {weighted_precision:.6f}"
    )

    print(
        f"Weighted Recall:    {weighted_recall:.6f}"
    )

    print(
        f"Weighted F1:        {weighted_f1:.6f}"
    )

    # -----------------------------------------------------
    # Classification report
    # -----------------------------------------------------

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=encoder.classes_,
            zero_division=0
        )
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=encoder.classes_,
        output_dict=True,
        zero_division=0
    )

    report_df = pd.DataFrame(
        report
    ).transpose()

    report_df.to_csv(
        MODEL_DIR
        / "multiclass_classification_report.csv"
    )

    # -----------------------------------------------------
    # Confusion matrix
    # -----------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions
    )

    print("\nConfusion Matrix:")
    print(cm)

    cm_df = pd.DataFrame(
        cm,
        index=encoder.classes_,
        columns=encoder.classes_
    )

    cm_df.to_csv(
        MODEL_DIR
        / "multiclass_confusion_matrix.csv"
    )

    # -----------------------------------------------------
    # Per-class summary
    # -----------------------------------------------------

    per_class_precision, per_class_recall, per_class_f1, support = (
        precision_recall_fscore_support(
            y_test,
            predictions,
            labels=np.arange(num_classes),
            zero_division=0
        )
    )

    per_class = pd.DataFrame({
        "Label": encoder.classes_,
        "Precision": per_class_precision,
        "Recall": per_class_recall,
        "F1": per_class_f1,
        "Support": support
    })

    per_class.to_csv(
        MODEL_DIR
        / "per_class_metrics.csv",
        index=False
    )

    print("\nPer-class results:")
    print(
        per_class.to_string(index=False)
    )

    # -----------------------------------------------------
    # Save model + encoder
    # -----------------------------------------------------

    joblib.dump(
        model,
        MODEL_FILE
    )

    joblib.dump(
        encoder,
        ENCODER_FILE
    )

    print("\n" + "=" * 65)
    print("MODEL SAVED")
    print("=" * 65)

    print(
        f"Model:   {MODEL_FILE}"
    )

    print(
        f"Encoder: {ENCODER_FILE}"
    )


if __name__ == "__main__":
    main()