"""
Optimize the CIC-IDS2017 multiclass XGBoost model.

Goals:
    - Reduce overfitting with early stopping.
    - Improve minority-class detection.
    - Preserve strong performance on major classes.
    - Select the model using validation data only.

Final evaluation is performed once on the untouched test set.
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
    / "multiclass_optimized"
)

TRAIN_FILE = DATA_DIR / "train.csv"
VALIDATION_FILE = DATA_DIR / "validation.csv"
TEST_FILE = DATA_DIR / "test.csv"

MODEL_FILE = (
    MODEL_DIR
    / "xgboost_multiclass_optimized.joblib"
)

ENCODER_FILE = (
    MODEL_DIR
    / "label_encoder.joblib"
)

RESULTS_FILE = (
    MODEL_DIR
    / "optimization_results.txt"
)

RANDOM_STATE = 42


# ---------------------------------------------------------
# Load data
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

    return X, labels


# ---------------------------------------------------------
# Build controlled class weights
# ---------------------------------------------------------

def build_class_weights(labels, max_weight=20.0):

    counts = labels.value_counts()

    max_count = counts.max()

    # Square-root weighting is deliberately less aggressive
    # than inverse-frequency weighting.
    weights = np.sqrt(
        max_count / counts
    )

    # Prevent tiny classes from dominating training.
    weights = weights.clip(
        upper=max_weight
    )

    print("\nClass weights:")

    for label in sorted(weights.index):
        print(
            f"{label:35s} "
            f"count={counts[label]:8,d} "
            f"weight={weights[label]:.3f}"
        )

    return weights


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 70)
    print("OPTIMIZED CIC-IDS2017 MULTICLASS XGBOOST")
    print("=" * 70)

    # -----------------------------------------------------
    # Load datasets
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

    print(
        f"\nNumber of classes: {num_classes}"
    )

    for i, label in enumerate(
        encoder.classes_
    ):
        print(
            f"{i:2d}: {label}"
        )

    # -----------------------------------------------------
    # Class weights
    # -----------------------------------------------------

    class_weights = build_class_weights(
        labels_train,
        max_weight=20.0
    )

    train_weights = (
        labels_train.map(
            class_weights
        ).to_numpy()
    )

    validation_weights = (
        labels_val.map(
            class_weights
        ).to_numpy()
    )

    # -----------------------------------------------------
    # Optimized XGBoost
    # -----------------------------------------------------

    print("\nTraining optimized model...")

    model = xgb.XGBClassifier(

        n_estimators=600,

        max_depth=6,

        learning_rate=0.05,

        min_child_weight=2,

        subsample=0.85,

        colsample_bytree=0.85,

        gamma=0.05,

        reg_alpha=0.1,

        reg_lambda=2.0,

        objective="multi:softprob",

        num_class=num_classes,

        eval_metric="mlogloss",

        early_stopping_rounds=40,

        random_state=RANDOM_STATE,

        n_jobs=-1,

        tree_method="hist"
    )

    start = time.time()

    model.fit(
        X_train,
        y_train,

        sample_weight=train_weights,

        eval_set=[
            (X_val, y_val)
        ],

        sample_weight_eval_set=[
            validation_weights
        ],

        verbose=True
    )

    training_time = time.time() - start

    print(
        f"\nTraining time: "
        f"{training_time:.2f} seconds"
    )

    print(
        "\nBest iteration:",
        model.best_iteration
    )

    print(
        "Best validation score:",
        model.best_score
    )

    # -----------------------------------------------------
    # Validation evaluation
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    val_probabilities = model.predict_proba(
        X_val
    )

    val_predictions = np.argmax(
        val_probabilities,
        axis=1
    )

    val_accuracy = accuracy_score(
        y_val,
        val_predictions
    )

    val_macro_precision, val_macro_recall, val_macro_f1, _ = (
        precision_recall_fscore_support(
            y_val,
            val_predictions,
            average="macro",
            zero_division=0
        )
    )

    val_weighted_precision, val_weighted_recall, val_weighted_f1, _ = (
        precision_recall_fscore_support(
            y_val,
            val_predictions,
            average="weighted",
            zero_division=0
        )
    )

    print(
        f"Accuracy:           {val_accuracy:.6f}"
    )

    print(
        f"Macro Precision:    {val_macro_precision:.6f}"
    )

    print(
        f"Macro Recall:       {val_macro_recall:.6f}"
    )

    print(
        f"Macro F1:           {val_macro_f1:.6f}"
    )

    print(
        f"Weighted F1:        {val_weighted_f1:.6f}"
    )

    # -----------------------------------------------------
    # Final test evaluation
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL TEST RESULTS")
    print("=" * 70)

    test_probabilities = model.predict_proba(
        X_test
    )

    test_predictions = np.argmax(
        test_probabilities,
        axis=1
    )

    accuracy = accuracy_score(
        y_test,
        test_predictions
    )

    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            y_test,
            test_predictions,
            average="macro",
            zero_division=0
        )
    )

    weighted_precision, weighted_recall, weighted_f1, _ = (
        precision_recall_fscore_support(
            y_test,
            test_predictions,
            average="weighted",
            zero_division=0
        )
    )

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

    report_text = classification_report(
        y_test,
        test_predictions,
        target_names=encoder.classes_,
        zero_division=0
    )

    print(report_text)

    report = classification_report(
        y_test,
        test_predictions,
        target_names=encoder.classes_,
        output_dict=True,
        zero_division=0
    )

    report_df = pd.DataFrame(
        report
    ).transpose()

    report_df.to_csv(
        MODEL_DIR
        / "classification_report.csv"
    )

    # -----------------------------------------------------
    # Per-class metrics
    # -----------------------------------------------------

    per_precision, per_recall, per_f1, support = (
        precision_recall_fscore_support(
            y_test,
            test_predictions,
            labels=np.arange(num_classes),
            zero_division=0
        )
    )

    per_class = pd.DataFrame({
        "Label": encoder.classes_,
        "Precision": per_precision,
        "Recall": per_recall,
        "F1": per_f1,
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
    # Confusion matrix
    # -----------------------------------------------------

    cm = confusion_matrix(
        y_test,
        test_predictions
    )

    cm_df = pd.DataFrame(
        cm,
        index=encoder.classes_,
        columns=encoder.classes_
    )

    cm_df.to_csv(
        MODEL_DIR
        / "confusion_matrix.csv"
    )

    # -----------------------------------------------------
    # Save model and encoder
    # -----------------------------------------------------

    joblib.dump(
        model,
        MODEL_FILE
    )

    joblib.dump(
        encoder,
        ENCODER_FILE
    )

    # -----------------------------------------------------
    # Save summary
    # -----------------------------------------------------

    with open(
        RESULTS_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "Optimized CIC-IDS2017 Multiclass XGBoost\n"
        )

        f.write(
            f"Training time: {training_time:.2f} seconds\n"
        )

        f.write(
            f"Best iteration: {model.best_iteration}\n"
        )

        f.write(
            f"Best validation mlogloss: {model.best_score}\n\n"
        )

        f.write(
            f"Test Accuracy: {accuracy:.6f}\n"
        )

        f.write(
            f"Test Macro Precision: {macro_precision:.6f}\n"
        )

        f.write(
            f"Test Macro Recall: {macro_recall:.6f}\n"
        )

        f.write(
            f"Test Macro F1: {macro_f1:.6f}\n"
        )

        f.write(
            f"Test Weighted Precision: {weighted_precision:.6f}\n"
        )

        f.write(
            f"Test Weighted Recall: {weighted_recall:.6f}\n"
        )

        f.write(
            f"Test Weighted F1: {weighted_f1:.6f}\n"
        )

    print("\n" + "=" * 70)
    print("OPTIMIZED MODEL SAVED")
    print("=" * 70)

    print(
        "Model:",
        MODEL_FILE
    )

    print(
        "Encoder:",
        ENCODER_FILE
    )

    print(
        "Results:",
        MODEL_DIR
    )


if __name__ == "__main__":
    main()