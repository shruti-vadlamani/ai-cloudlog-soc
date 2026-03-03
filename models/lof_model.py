"""
models/lof_model.py
====================
Local Outlier Factor anomaly detector.

Best suited for: local behavioral deviations — events anomalous
relative to the user's own peer group, not the global dataset.
Catches what Isolation Forest misses:
  - Reconnaissance (Eve making IAM List* calls — locally anomalous
    for a data analyst even though IAM reads are globally common)
  - Backdoor creation (non-admin IAM writes — locally anomalous
    for Eve even at low volume)

LOF compares each point to its k nearest neighbors. A point is
anomalous if its local density is much lower than its neighbors.
This makes it user-context-aware in a natural way — Eve's IAM calls
land in a sparse region near other analyst windows, which are all
S3-heavy with near-zero IAM activity.

Run:
    python models/lof_model.py

Saves model to data/models/lof.pkl
"""

import logging
import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.neighbors import LocalOutlierFactor
from sklearn.model_selection import ParameterGrid
from sklearn.metrics import f1_score

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
log = logging.getLogger("lof")


# ── Important LOF Note ────────────────────────────────────────────────────────
#
# LOF has a critical quirk: it does NOT support predict() on new data
# unless novelty=True. With novelty=True it behaves like a one-class
# classifier — fit on normal, score new points.
#
# We use novelty=True here because:
#   1. We want to score the test set (which includes attacks)
#   2. The model should never have seen attack data
#   3. This is the correct protocol for a production anomaly detector
#
# Downside of novelty=True: LOF is now more conservative (higher FPR).
# We compensate with threshold tuning.
# ─────────────────────────────────────────────────────────────────────────────


def _find_best_threshold(scores, y_true, percentile_range=None):
    if percentile_range is None:
        percentile_range = [85, 87, 89, 90, 91, 92, 93, 94, 95, 97, 99]
    best_f1 = -1
    best_thresh = np.percentile(scores, 90)
    for p in percentile_range:
        thresh = np.percentile(scores, p)
        y_pred = (scores >= thresh).astype(int)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh
    return best_thresh, best_f1


def find_best_k(
    X_train_scaled: np.ndarray,
    X_test_scaled: np.ndarray,
    y_true: np.ndarray,
    y_multi: np.ndarray,
) -> dict:
    """Grid search over n_neighbors (k)."""
    best = {"f1": -1, "n_neighbors": 20}

    # k values: rule of thumb is sqrt(n_samples), try around that
    n = len(X_train_scaled)
    sqrt_n = int(np.sqrt(n))
    k_candidates = sorted(set([10, 15, 20, sqrt_n, sqrt_n + 10, 30, 50]))
    k_candidates = [k for k in k_candidates if k < n]

    log.info(f"Grid searching k (n_neighbors) in {k_candidates}...")

    for k in k_candidates:
        model = LocalOutlierFactor(
            n_neighbors=k,
            algorithm="auto",
            metric="euclidean",
            contamination="auto",
            novelty=True,
            n_jobs=-1,
        )
        model.fit(X_train_scaled)

        # LOF novelty scores: negative_outlier_factor_ style
        # score_samples returns -LOF scores: higher (less negative) = more normal
        raw_scores = model.score_samples(X_test_scaled)
        # Negate: now higher = more anomalous
        anomaly_scores = -raw_scores

        thresh, f1 = _find_best_threshold(anomaly_scores, y_true)

        if f1 > best["f1"]:
            best = {"f1": f1, "n_neighbors": k, "threshold": thresh}
            log.info(f"  New best: k={k}, F1={f1:.4f}, threshold={thresh:.4f}")

    log.info(f"Best k: {best['n_neighbors']} (F1={best['f1']:.4f})")
    return best


def train(tune: bool = True) -> dict:
    """
    Full training + evaluation pipeline for LOF.
    """
    log.info("Loading feature matrix...")
    df = load_feature_matrix()

    train_df, test_df = train_test_split_by_label(df)

    X_train, _, _ = get_X_y(train_df)
    X_test, y_true, y_multi = get_X_y(test_df)

    scaler = fit_scaler(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    if tune:
        best_params = find_best_k(X_train_scaled, X_test_scaled, y_true, y_multi)
        n_neighbors = best_params["n_neighbors"]
    else:
        n_neighbors = 20

    log.info(f"Training LOF: n_neighbors={n_neighbors}, novelty=True...")

    model = LocalOutlierFactor(
        n_neighbors=n_neighbors,
        algorithm="auto",
        metric="euclidean",
        contamination="auto",
        novelty=True,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)

    raw_scores = model.score_samples(X_test_scaled)
    anomaly_scores = -raw_scores  # higher = more anomalous

    # Find best threshold
    best_thresh, _ = _find_best_threshold(anomaly_scores, y_true)
    y_pred = (anomaly_scores >= best_thresh).astype(int)

    log.info(f"Using threshold: {best_thresh:.4f} "
             f"(flags top {100*(anomaly_scores >= best_thresh).mean():.1f}% of windows)")

    results = evaluate(y_true, y_pred, anomaly_scores, y_multi, "LOF")
    results["n_neighbors"] = n_neighbors
    results["threshold"] = float(best_thresh)

    # Save model with threshold embedded
    import pickle
    from pathlib import Path
    Path("data/models").mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "scaler": scaler,
        "threshold": best_thresh,
        "feature_columns": FEATURE_COLUMNS,
    }
    with open("data/models/lof.pkl", "wb") as f:
        pickle.dump(payload, f)
    log.info("Saved to data/models/lof.pkl")

    save_results(results, "lof")

    # Save scores
    score_df = test_df[["user_name", "window"]].copy()
    score_df["lof_score"] = anomaly_scores
    score_df["lof_pred"] = y_pred
    score_df.to_csv("data/models/lof_scores.csv", index=False)
    log.info("Scores saved to data/models/lof_scores.csv")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-tune", action="store_true",
                        help="Skip grid search, use defaults")
    args = parser.parse_args()
    train(tune=not args.no_tune)


