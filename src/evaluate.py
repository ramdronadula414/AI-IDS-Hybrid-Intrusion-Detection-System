"""
Evaluate the trained binary AI-IDS model.

Generates:
1. Classification metrics
2. Confusion matrix
3. ROC curve
4. Precision-Recall curve
5. Per-attack detection performance
6. Feature importance
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve,
)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TEST_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "splits"
    / "test.csv"
)

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "xgboost_binary_ids.joblib"
)

RESULTS_DIR = (
    PROJECT_ROOT
    / "models"
    / "evaluation"
)


# ---------------------------------------------------------
# Load test data
# ---------------------------------------------------------

def load_test_data():
    print("Loading test data...")

    df = pd.read_csv(
        TEST_FILE,
        low_memory=False
    )

    labels = df["Label"].astype(str)

    y = df["BinaryLabel"].astype(np.int8)

    X = df.drop(
        columns=["Label", "BinaryLabel"]
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

    return X, y, labels


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 60)
    print("AI-IDS MODEL EVALUATION")
    print("=" * 60)

    # -----------------------------------------------------
    # Load model
    # -----------------------------------------------------

    print("\nLoading model...")

    model = joblib.load(
        MODEL_FILE
    )

    # -----------------------------------------------------
    # Load test dataset
    # -----------------------------------------------------

    X_test, y_test, attack_labels = load_test_data()

    # -----------------------------------------------------
    # Predictions
    # -----------------------------------------------------

    print("Generating predictions...")

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    predictions = (
        probabilities >= 0.50
    ).astype(np.int8)

    # -----------------------------------------------------
    # Overall metrics
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    pr_auc = average_precision_score(
        y_test,
        probabilities
    )

    print("\n" + "=" * 60)
    print("OVERALL TEST METRICS")
    print("=" * 60)

    print(f"Accuracy : {accuracy:.6f}")
    print(f"Precision: {precision:.6f}")
    print(f"Recall   : {recall:.6f}")
    print(f"F1-score : {f1:.6f}")
    print(f"ROC-AUC  : {roc_auc:.6f}")
    print(f"PR-AUC   : {pr_auc:.6f}")

    # -----------------------------------------------------
    # Classification report
    # -----------------------------------------------------

    report = classification_report(
        y_test,
        predictions,
        target_names=[
            "BENIGN",
            "ATTACK"
        ],
        output_dict=True,
        zero_division=0
    )

    report_df = pd.DataFrame(report).transpose()

    report_df.to_csv(
        RESULTS_DIR / "classification_report.csv"
    )

    print("\nClassification report saved.")

    # -----------------------------------------------------
    # Confusion matrix
    # -----------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions
    )

    print("\nConfusion Matrix:")
    print(cm)

    fig, ax = plt.subplots(
        figsize=(7, 6)
    )

    ax.imshow(cm)

    ax.set_title(
        "Binary AI-IDS Confusion Matrix"
    )

    ax.set_xlabel(
        "Predicted"
    )

    ax.set_ylabel(
        "Actual"
    )

    ax.set_xticks(
        [0, 1],
        ["BENIGN", "ATTACK"]
    )

    ax.set_yticks(
        [0, 1],
        ["BENIGN", "ATTACK"]
    )

    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                f"{cm[i, j]:,}",
                ha="center",
                va="center"
            )

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "confusion_matrix.png",
        dpi=200
    )

    plt.close()

    # -----------------------------------------------------
    # ROC curve
    # -----------------------------------------------------

    fpr, tpr, _ = roc_curve(
        y_test,
        probabilities
    )

    plt.figure(
        figsize=(8, 6)
    )

    plt.plot(
        fpr,
        tpr,
        label=f"XGBoost (AUC = {roc_auc:.4f})"
    )

    plt.plot(
        [0, 1],
        [0, 1],
        linestyle="--"
    )

    plt.xlabel(
        "False Positive Rate"
    )

    plt.ylabel(
        "True Positive Rate"
    )

    plt.title(
        "ROC Curve - Binary AI-IDS"
    )

    plt.legend()

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "roc_curve.png",
        dpi=200
    )

    plt.close()

    # -----------------------------------------------------
    # Precision-Recall curve
    # -----------------------------------------------------

    precision_curve, recall_curve, _ = (
        precision_recall_curve(
            y_test,
            probabilities
        )
    )

    plt.figure(
        figsize=(8, 6)
    )

    plt.plot(
        recall_curve,
        precision_curve,
        label=f"PR-AUC = {pr_auc:.4f}"
    )

    plt.xlabel(
        "Recall"
    )

    plt.ylabel(
        "Precision"
    )

    plt.title(
        "Precision-Recall Curve - Binary AI-IDS"
    )

    plt.legend()

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "precision_recall_curve.png",
        dpi=200
    )

    plt.close()

    # -----------------------------------------------------
    # Per-attack performance
    # -----------------------------------------------------

    test_results = pd.DataFrame({
        "Label": attack_labels,
        "Actual": y_test,
        "Predicted": predictions
    })

    attack_results = []

    for label in sorted(
        test_results["Label"].unique()
    ):

        subset = test_results[
            test_results["Label"] == label
        ]

        if label == "BENIGN":
            actual = np.zeros(
                len(subset),
                dtype=np.int8
            )
        else:
            actual = np.ones(
                len(subset),
                dtype=np.int8
            )

        predicted = subset["Predicted"].to_numpy()

        attack_results.append({
            "Label": label,
            "Samples": len(subset),
            "Detected": int(
                np.sum(predicted == 1)
            ),
            "Missed": int(
                np.sum(predicted == 0)
            ),
            "Detection_Rate": (
                np.mean(predicted == 1)
            )
        })

    attack_df = pd.DataFrame(
        attack_results
    )

    attack_df.to_csv(
        RESULTS_DIR / "per_attack_detection.csv",
        index=False
    )

    print("\nPer-attack detection:")
    print(
        attack_df.to_string(
            index=False
        )
    )

    # -----------------------------------------------------
    # Feature importance
    # -----------------------------------------------------

    feature_importance = pd.DataFrame({
        "Feature": X_test.columns,
        "Importance": model.feature_importances_
    }).sort_values(
        "Importance",
        ascending=False
    )

    feature_importance.to_csv(
        RESULTS_DIR / "feature_importance.csv",
        index=False
    )

    top_features = feature_importance.head(20)

    plt.figure(
        figsize=(10, 8)
    )

    plt.barh(
        top_features["Feature"][::-1],
        top_features["Importance"][::-1]
    )

    plt.xlabel(
        "Importance"
    )

    plt.ylabel(
        "Feature"
    )

    plt.title(
        "Top 20 XGBoost Features"
    )

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "feature_importance.png",
        dpi=200
    )

    plt.close()

    # -----------------------------------------------------
    # Save predictions
    # -----------------------------------------------------

    test_results["Probability"] = probabilities

    test_results.to_csv(
        RESULTS_DIR / "test_predictions.csv",
        index=False
    )

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)

    print(f"Results saved to:\n{RESULTS_DIR}")


if __name__ == "__main__":
    main()