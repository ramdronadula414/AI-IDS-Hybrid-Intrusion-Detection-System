"""
AI-IDS Model Comparison

Binary classification:
    BENIGN = 0
    ATTACK = 1

Models:
    1. Logistic Regression
    2. Decision Tree
    3. Random Forest
    4. XGBoost

All models use the same train/validation/test splits.
"""

from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
)

from xgboost import XGBClassifier


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data" / "processed" / "splits"
MODEL_DIR = PROJECT_ROOT / "models" / "comparison"

TRAIN_FILE = DATA_DIR / "train.csv"
VALIDATION_FILE = DATA_DIR / "validation.csv"
TEST_FILE = DATA_DIR / "test.csv"

RANDOM_STATE = 42


# ---------------------------------------------------------
# Load and prepare data
# ---------------------------------------------------------

def load_dataset(path):
    print(f"Loading {path.name}...")

    df = pd.read_csv(
        path,
        low_memory=False
    )

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

    X.fillna(0, inplace=True)

    return X, y


# ---------------------------------------------------------
# Evaluate model
# ---------------------------------------------------------

def evaluate_model(name, model, X, y):

    start = time.time()

    probabilities = model.predict_proba(X)[:, 1]

    predictions = (
        probabilities >= 0.50
    ).astype(np.int8)

    inference_time = time.time() - start

    results = {
        "model": name,
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(
            y,
            predictions,
            zero_division=0
        ),
        "recall": recall_score(
            y,
            predictions,
            zero_division=0
        ),
        "f1": f1_score(
            y,
            predictions,
            zero_division=0
        ),
        "roc_auc": roc_auc_score(
            y,
            probabilities
        ),
        "pr_auc": average_precision_score(
            y,
            probabilities
        ),
        "inference_seconds": inference_time,
    }

    return results


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 65)
    print("AI-IDS BINARY MODEL COMPARISON")
    print("=" * 65)

    # -----------------------------------------------------
    # Load data
    # -----------------------------------------------------

    X_train, y_train = load_dataset(TRAIN_FILE)
    X_val, y_val = load_dataset(VALIDATION_FILE)
    X_test, y_test = load_dataset(TEST_FILE)

    print()
    print("Training shape:", X_train.shape)
    print("Validation shape:", X_val.shape)
    print("Test shape:", X_test.shape)

    # -----------------------------------------------------
    # Class imbalance
    # -----------------------------------------------------

    benign = int((y_train == 0).sum())
    attack = int((y_train == 1).sum())

    scale_pos_weight = benign / attack

    print()
    print("BENIGN:", f"{benign:,}")
    print("ATTACK:", f"{attack:,}")
    print(
        "scale_pos_weight:",
        round(scale_pos_weight, 4)
    )

    # -----------------------------------------------------
    # Models
    # -----------------------------------------------------

    models = {

        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ),

        "Decision Tree": DecisionTreeClassifier(
            max_depth=20,
            class_weight="balanced",
            random_state=RANDOM_STATE
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=150,
            class_weight="balanced",
            n_jobs=-1,
            random_state=RANDOM_STATE
        ),

        "XGBoost": XGBClassifier(
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
    }

    results = []

    # -----------------------------------------------------
    # Train and evaluate
    # -----------------------------------------------------

    for name, model in models.items():

        print()
        print("=" * 65)
        print(f"TRAINING: {name}")
        print("=" * 65)

        start = time.time()

        if name == "XGBoost":

            model.fit(
                X_train,
                y_train,
                eval_set=[
                    (X_val, y_val)
                ],
                verbose=False
            )

        else:

            model.fit(
                X_train,
                y_train
            )

        training_time = time.time() - start

        metrics = evaluate_model(
            name,
            model,
            X_test,
            y_test
        )

        metrics["training_seconds"] = training_time

        results.append(metrics)

        filename = (
            name.lower()
            .replace(" ", "_")
            + "_binary.joblib"
        )

        model_path = MODEL_DIR / filename

        joblib.dump(
            model,
            model_path
        )

        print(
            f"Training time: "
            f"{training_time:.2f} sec"
        )

        print(
            f"Accuracy:  "
            f"{metrics['accuracy']:.6f}"
        )

        print(
            f"Precision: "
            f"{metrics['precision']:.6f}"
        )

        print(
            f"Recall:    "
            f"{metrics['recall']:.6f}"
        )

        print(
            f"F1:        "
            f"{metrics['f1']:.6f}"
        )

        print(
            f"ROC-AUC:   "
            f"{metrics['roc_auc']:.6f}"
        )

        print(
            f"PR-AUC:    "
            f"{metrics['pr_auc']:.6f}"
        )

    # -----------------------------------------------------
    # Comparison table
    # -----------------------------------------------------

    results_df = pd.DataFrame(results)

    results_df = results_df.sort_values(
        "f1",
        ascending=False
    )

    print()
    print("=" * 65)
    print("MODEL COMPARISON")
    print("=" * 65)

    print(
        results_df[
            [
                "model",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "roc_auc",
                "pr_auc",
                "training_seconds",
                "inference_seconds",
            ]
        ].to_string(index=False)
    )

    # -----------------------------------------------------
    # Save results
    # -----------------------------------------------------

    results_df.to_csv(
        MODEL_DIR / "binary_model_comparison.csv",
        index=False
    )

    with open(
        MODEL_DIR / "binary_model_comparison.json",
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            results,
            f,
            indent=2
        )

    best = results_df.iloc[0]

    print()
    print("=" * 65)
    print("BEST MODEL BY F1")
    print("=" * 65)

    print(
        best["model"],
        f"(F1 = {best['f1']:.6f})"
    )

    print()
    print(
        "Results saved to:",
        MODEL_DIR
    )


if __name__ == "__main__":
    main()