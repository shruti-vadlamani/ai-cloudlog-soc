"""
models/model_utils.py
======================
Shared utilities for all models:
  - Loading the feature matrix
  - Train/test splitting (normal-only train, all for eval)
  - StandardScaler fitting and persistence
  - Evaluation metrics (precision, recall, F1, ROC-AUC per attack type)
  - Saving/loading models

Anomaly detection evaluation strategy:
  - Train ONLY on normal windows (unsupervised — models never see attack labels)
  - Evaluate on the FULL dataset using ground truth labels
  - Report per-attack-type detection rates so you can see which scenarios
    each model catches and which it misses
"""

import json
import logging
import os
import pickle
from pathlib import Path
from typing import Tuple, Dict, List

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

log = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "total_events", "iam_events", "s3_events", "write_events",
    "s3_get_events", "s3_delete_events", "iam_write_events",
    "iam_list_events", "error_events", "bytes_out_total",
    "unique_resources", "unique_ips", "unique_event_types",
    "iam_ratio", "s3_ratio", "write_ratio", "error_rate",
    "iam_write_ratio", "delete_ratio", "after_hours_ratio",
    "total_events_zscore", "iam_events_zscore", "s3_events_zscore",
    "s3_get_events_zscore", "s3_delete_events_zscore",
    "iam_write_events_zscore", "iam_list_events_zscore", "bytes_out_zscore",
    "h1_total_events", "h1_iam_events", "h1_s3_events",
    "h1_s3_get_events", "h1_s3_delete_events", "h1_iam_write_events",
    "h1_iam_list_events", "h1_error_events", "h1_write_ratio",
    "s3_get_slope_3d", "s3_get_pct_change_1d",
    "window_hour", "window_day_of_week", "window_is_weekend",
    "window_is_business_hours",
]

ATTACK_NAMES = {
    0: "normal",
    1: "privilege_escalation",
    2: "data_exfiltration",
    3: "insider_threat",
    4: "reconnaissance",
    5: "backdoor_creation",
}


# ── Data Loading ──────────────────────────────────────────────────────────────

def load_feature_matrix(features_dir: str = "data/features") -> pd.DataFrame:
    """Load feature matrix from Parquet or CSV.gz fallback."""
    parquet_path = Path(features_dir) / "feature_matrix.parquet"
    csv_path = Path(features_dir) / "feature_matrix.csv.gz"

    if parquet_path.exists():
        try:
            df = pd.read_parquet(parquet_path)
            log.info(f"Loaded feature matrix: {df.shape} from {parquet_path}")
            return df
        except Exception:
            pass

    if csv_path.exists():
        df = pd.read_csv(csv_path, compression="gzip")
        # Parse window column back to datetime if needed
        if "window" in df.columns:
            df["window"] = pd.to_datetime(df["window"], utc=True)
        log.info(f"Loaded feature matrix: {df.shape} from {csv_path}")
        return df

    raise FileNotFoundError(
        f"Feature matrix not found in {features_dir}. "
        "Run: python run_pipeline.py --stage features"
    )


def get_X_y(
    df: pd.DataFrame,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Extract feature array X, binary labels y, and multiclass labels y_multi.

    Returns:
        X         — shape (n, 43), float64, all windows
        y         — shape (n,), binary int (0=normal, 1=attack)
        y_multi   — shape (n,), int (0-5, attack type)
    """
    X = df[FEATURE_COLUMNS].values.astype(np.float64)
    y = df["is_attack"].astype(int).values if "is_attack" in df.columns else np.zeros(len(df), dtype=int)
    y_multi = df["attack_id"].astype(int).values if "attack_id" in df.columns else np.zeros(len(df), dtype=int)
    return X, y, y_multi


def train_test_split_by_label(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split for unsupervised anomaly detection:
      - train_df: ONLY normal windows (models trained blind to attacks)
      - test_df:  ALL windows (used for evaluation with ground truth)

    This is the correct evaluation protocol for anomaly detection.
    Do NOT use sklearn train_test_split here — that would leak attack
    information into training for unsupervised models.
    """
    if "is_attack" in df.columns:
        train_df = df[~df["is_attack"]].copy()
        test_df = df.copy()
    else:
        # No labels — treat everything as normal (real AWS mode)
        train_df = df.copy()
        test_df = df.copy()

    log.info(f"Train (normal only): {len(train_df)} windows")
    log.info(f"Test  (all):         {len(test_df)} windows "
             f"({test_df['is_attack'].sum() if 'is_attack' in test_df.columns else 0} attacks)")
    return train_df, test_df


# ── Scaling ───────────────────────────────────────────────────────────────────

def fit_scaler(X_train: np.ndarray) -> StandardScaler:
    """Fit StandardScaler on normal training data only."""
    scaler = StandardScaler()
    scaler.fit(X_train)
    return scaler


# ── Model Persistence ─────────────────────────────────────────────────────────

def save_model(model, scaler: StandardScaler, model_name: str, models_dir: str = "data/models") -> str:
    """Save model + scaler as pickle."""
    Path(models_dir).mkdir(parents=True, exist_ok=True)
    payload = {"model": model, "scaler": scaler, "feature_columns": FEATURE_COLUMNS}
    out_path = str(Path(models_dir) / f"{model_name}.pkl")
    with open(out_path, "wb") as f:
        pickle.dump(payload, f)
    size_kb = Path(out_path).stat().st_size / 1024
    log.info(f"Saved {model_name} to {out_path} ({size_kb:.1f} KB)")
    return out_path


def load_model(model_name: str, models_dir: str = "data/models") -> Tuple:
    """Load model + scaler. Returns (model, scaler, feature_columns)."""
    path = Path(models_dir) / f"{model_name}.pkl"
    if not path.exists():
        raise FileNotFoundError(f"Model not found: {path}")
    with open(path, "rb") as f:
        payload = pickle.load(f)
    return payload["model"], payload["scaler"], payload["feature_columns"]


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray,
    y_multi: np.ndarray,
    model_name: str,
) -> Dict:
    """
    Full evaluation report for an anomaly detection model.

    Args:
        y_true:    Binary ground truth (0=normal, 1=attack)
        y_pred:    Binary predictions (0=normal, 1=attack)
        scores:    Continuous anomaly scores (higher = more anomalous)
        y_multi:   Multi-class ground truth (0-5)
        model_name: Label for printing

    Returns:
        Dict with all metrics
    """
    # Guard: if only one class in predictions, ROC-AUC is undefined
    try:
        auc = roc_auc_score(y_true, scores)
    except ValueError:
        auc = float("nan")

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    # Per-attack-type detection rate
    per_attack = {}
    for attack_id, attack_name in ATTACK_NAMES.items():
        if attack_id == 0:
            continue
        mask = y_multi == attack_id
        if mask.sum() == 0:
            continue
        detected = y_pred[mask].sum()
        total = mask.sum()
        per_attack[attack_name] = {
            "total_windows": int(total),
            "detected": int(detected),
            "detection_rate": float(detected / total),
        }

    results = {
        "model": model_name,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4) if not np.isnan(auc) else None,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0,
        "per_attack_detection": per_attack,
    }

    _print_results(results)
    return results


def _print_results(r: Dict) -> None:
    w = 52
    print("\n" + "=" * w)
    print(f"  MODEL: {r['model']}")
    print("=" * w)
    print(f"  Precision:          {r['precision']:.4f}")
    print(f"  Recall:             {r['recall']:.4f}")
    print(f"  F1 Score:           {r['f1']:.4f}")
    print(f"  ROC-AUC:            {r['roc_auc']}")
    print(f"  True Positives:     {r['true_positives']}")
    print(f"  False Positives:    {r['false_positives']}")
    print(f"  False Negatives:    {r['false_negatives']}")
    print(f"  False Positive Rate:{r['false_positive_rate']:.4f}")
    print(f"\n  Per-Attack Detection Rates:")
    for name, stats in r.get("per_attack_detection", {}).items():
        bar_len = int(stats["detection_rate"] * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"    {name:<25} [{bar}] {stats['detection_rate']*100:.0f}%"
              f"  ({stats['detected']}/{stats['total_windows']} windows)")
    print("=" * w + "\n")


def save_results(results: Dict, model_name: str, results_dir: str = "data/results") -> str:
    """Save evaluation results as JSON."""
    Path(results_dir).mkdir(parents=True, exist_ok=True)
    out_path = str(Path(results_dir) / f"{model_name}_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log.info(f"Results saved to {out_path}")
    return out_path


def compare_models(results_dir: str = "data/results") -> None:
    """Print a side-by-side comparison of all trained models."""
    result_files = list(Path(results_dir).glob("*_results.json"))
    if not result_files:
        print("No results found. Train models first.")
        return

    all_results = []
    for f in result_files:
        with open(f) as fh:
            all_results.append(json.load(fh))

    print("\n" + "=" * 70)
    print("MODEL COMPARISON SUMMARY")
    print("=" * 70)
    header = f"{'Model':<25} {'Precision':>9} {'Recall':>7} {'F1':>7} {'AUC':>7} {'FPR':>7}"
    print(header)
    print("-" * 70)
    for r in sorted(all_results, key=lambda x: x.get("f1", 0), reverse=True):
        print(
            f"  {r['model']:<23} "
            f"{r['precision']:>9.4f} "
            f"{r['recall']:>7.4f} "
            f"{r['f1']:>7.4f} "
            f"{str(r['roc_auc']):>7} "
            f"{r['false_positive_rate']:>7.4f}"
        )
    print("=" * 70 + "\n")
