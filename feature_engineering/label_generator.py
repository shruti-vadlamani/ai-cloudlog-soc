"""
feature_engineering/label_generator.py
=========================================
Generates and saves ground truth label files from the attack manifest.

Two output formats:
  1. Per-event labels (JSONL) — for fine-grained analysis
  2. Per-window labels (CSV) — for ML evaluation metrics
"""

import json
import logging
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)


def _write_df(df: pd.DataFrame, output_path: str) -> None:
    """Write DataFrame as parquet if pyarrow available, else csv.gz."""
    try:
        import pyarrow
        df.to_parquet(output_path, engine="pyarrow", index=False)
        log.info(f"Saved to {output_path}: {df.shape}")
    except ImportError:
        csv_path = str(output_path).replace(".parquet", ".csv.gz")
        df.to_csv(csv_path, index=False, compression="gzip")
        log.info(f"Saved to {csv_path} (pyarrow not available): {df.shape}")


def save_window_labels(feature_df: pd.DataFrame, output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    label_cols = ["user_name", "window", "is_attack", "attack_id", "attack_name"]
    available = [c for c in label_cols if c in feature_df.columns]
    labels = feature_df[available].copy()
    labels.to_csv(output_path, index=False)
    n_attack = labels["is_attack"].sum() if "is_attack" in labels else 0
    log.info(f"Window labels saved to {output_path}: "
             f"{n_attack} attack windows / {len(labels)} total")


def save_feature_matrix(feature_df: pd.DataFrame, output_path: str) -> None:
    """Save the complete feature matrix (including labels)."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    _write_df(feature_df, output_path)


def print_label_summary(feature_df: pd.DataFrame) -> None:
    if "attack_id" not in feature_df.columns:
        print("No labels found in feature DataFrame.")
        return

    print("\n" + "="*55)
    print("ATTACK LABEL DISTRIBUTION IN FEATURE MATRIX")
    print("="*55)
    breakdown = (
        feature_df.groupby(["attack_id", "attack_name"])
        .size()
        .reset_index(name="window_count")
    )
    for _, row in breakdown.iterrows():
        label = f"[{row['attack_id']}] {row['attack_name']}"
        print(f"  {label:<35} {row['window_count']:>5} windows")
    print("="*55)
    total = len(feature_df)
    n_attack = (feature_df["attack_id"] > 0).sum()
    print(f"  Attack rate: {100*n_attack/total:.2f}% of windows")
    print("="*55 + "\n")
