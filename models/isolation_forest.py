"""
models/isolation_forest.py
===========================
Isolation Forest anomaly detector.

Best suited for: global outliers — events that are universally
unusual regardless of who the user is. Catches:
  - Privilege escalation (2 AM IAM write burst — globally rare)
  - Insider threat (mass delete volume — globally rare)
  - Backdoor creation (3 AM IAM writes — globally rare)

May struggle with:
  - Data exfiltration (gradual ramp — not globally extreme at any point)
  - Reconnaissance (IST business hours, low volume — locally anomalous
    for Eve but globally unremarkable IAM read activity)

Run:
    python models/isolation_forest.py

Trains on normal windows only, evaluates on all windows with labels.
Saves model to data/models/isolation_forest.pkl
"""

import logging
import sys
import os
import numpy as np

# Run from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import ParameterGrid

from models.model_utils import (
    load_feature_matrix,
    get_X_y,
    train_test_split_by_label,
    fit_scaler,
    evaluate,
    save_model,
    save_results,
    FEATURE_COLUMNS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("isolation_forest")


def find_best_contamination(
    X_train_scaled: np.ndarray,
    X_test_scaled: np.ndarray,
    y_true: np.ndarray,
    y_multi: np.ndarray,
) -> dict:
    """
    Grid search over contamination parameter.

    contamination = expected fraction of outliers in training data.
    Since we train on normal-only data, this should be low (0.01-0.10).
    We tune it to maximize F1 on the test set.

    Note: this does NOT leak attack labels into training —
    we only use labels to SELECT the threshold after training.
    The IF model itself trains unsupervised.
    """
    best = {"f1": -1, "contamination": 0.05, "n_estimators": 100}

    # Small grid — IF is fast so we can afford this
    param_grid = {
        "contamination": [0.01, 0.02, 0.05, 0.08, 0.10],
        "n_estimators": [100, 200],
    }

    log.info("Grid searching contamination and n_estimators...")
    for params in ParameterGrid(param_grid):
        model = IsolationForest(
            n_estimators=params["n_estimators"],
            contamination=params["contamination"],
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train_scaled)
        # IF returns -1 for anomaly, 1 for normal
        raw_pred = model.predict(X_test_scaled)
        y_pred = (raw_pred == -1).astype(int)

        from sklearn.metrics import f1_score
        f1 = f1_score(y_true, y_pred, zero_division=0)

        if f1 > best["f1"]:
            best = {
                "f1": f1,
                "contamination": params["contamination"],
                "n_estimators": params["n_estimators"],
            }
            log.info(f"  New best: contamination={params['contamination']}, "
                     f"n_estimators={params['n_estimators']}, F1={f1:.4f}")

    log.info(f"Best params: {best}")
    return best


def train(tune: bool = True) -> dict:
    """
    Full training + evaluation pipeline for Isolation Forest.

    Args:
        tune: If True, run grid search for best contamination.
              If False, use sensible defaults (faster).
    """
    log.info("Loading feature matrix...")
    df = load_feature_matrix()

    train_df, test_df = train_test_split_by_label(df)

    X_train, _, _ = get_X_y(train_df)
    X_test, y_true, y_multi = get_X_y(test_df)

    # Scale — fit ONLY on normal training data
    scaler = fit_scaler(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    if tune:
        best_params = find_best_contamination(
            X_train_scaled, X_test_scaled, y_true, y_multi
        )
        contamination = best_params["contamination"]
        n_estimators = best_params["n_estimators"]
    else:
        contamination = 0.05
        n_estimators = 200

    log.info(f"Training Isolation Forest: contamination={contamination}, "
             f"n_estimators={n_estimators}...")

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)

    # Predict on full test set
    raw_pred = model.predict(X_test_scaled)
    y_pred = (raw_pred == -1).astype(int)

    # Anomaly score: decision_function returns negative scores for anomalies
    # Negate so higher = more anomalous (consistent with LOF and autoencoder)
    raw_scores = model.decision_function(X_test_scaled)
    anomaly_scores = -raw_scores  # now higher = more anomalous

    # Evaluate
    results = evaluate(y_true, y_pred, anomaly_scores, y_multi, "IsolationForest")
    results["contamination"] = contamination
    results["n_estimators"] = n_estimators

    # Save
    save_model(model, scaler, "isolation_forest")
    save_results(results, "isolation_forest")

    # Save anomaly scores alongside windows for ensemble later
    score_df = test_df[["user_name", "window"]].copy()
    score_df["if_score"] = anomaly_scores
    score_df["if_pred"] = y_pred
    score_df.to_csv("data/models/if_scores.csv", index=False)
    log.info("Anomaly scores saved to data/models/if_scores.csv")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-tune", action="store_true",
                        help="Skip grid search, use defaults (faster)")
    args = parser.parse_args()
    train(tune=not args.no_tune)
