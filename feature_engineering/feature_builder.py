"""
feature_engineering/feature_builder.py
========================================
Combines window features, user baselines, and daily slopes into
the final feature matrix consumed by ML models.

For each (user, 5-minute window) row, we produce:
  - Raw counts from the 5-min window
  - Derived ratios
  - Z-scores relative to that user's baseline (key for LOF + IF)
  - 1-hour window context (events in the surrounding hour)
  - Daily slope features (for exfiltration detection)
  - Temporal features (hour, day_of_week, is_weekend, etc.)

Final matrix: float64 columns only (ML-ready).
No NaN values (filled with 0 or user mean).
"""

import logging
import numpy as np
import pandas as pd
from typing import Optional

log = logging.getLogger(__name__)

# Columns used in the final feature matrix (in order)
# These are the features your models train on
FEATURE_COLUMNS = [
    # Raw counts (5-min window)
    "total_events",
    "iam_events",
    "s3_events",
    "write_events",
    "s3_get_events",
    "s3_delete_events",
    "iam_write_events",
    "iam_list_events",
    "error_events",
    "bytes_out_total",
    "unique_resources",
    "unique_ips",
    "unique_event_types",

    # Ratios (5-min window)
    "iam_ratio",
    "s3_ratio",
    "write_ratio",
    "error_rate",
    "iam_write_ratio",
    "delete_ratio",
    "after_hours_ratio",

    # Z-scores vs user baseline
    "total_events_zscore",
    "iam_events_zscore",
    "s3_events_zscore",
    "s3_get_events_zscore",
    "s3_delete_events_zscore",
    "iam_write_events_zscore",
    "iam_list_events_zscore",
    "bytes_out_zscore",

    # 1-hour context window
    "h1_total_events",
    "h1_iam_events",
    "h1_s3_events",
    "h1_s3_get_events",
    "h1_s3_delete_events",
    "h1_iam_write_events",
    "h1_iam_list_events",
    "h1_error_events",
    "h1_write_ratio",

    # Daily slope features
    "s3_get_slope_3d",
    "s3_get_pct_change_1d",

    # Temporal features
    "window_hour",
    "window_day_of_week",
    "window_is_weekend",
    "window_is_business_hours",
]


def _zscore(value: float, mean: float, std: float) -> float:
    """Compute z-score, clipped to [-10, 10]."""
    if std == 0:
        return 0.0
    return float(np.clip((value - mean) / std, -10, 10))


def build_feature_matrix(
    w5: pd.DataFrame,
    w60: pd.DataFrame,
    daily: pd.DataFrame,
    baselines: pd.DataFrame,
) -> pd.DataFrame:
    """
    Build the final ML feature matrix from window aggregations.

    Args:
        w5: 5-minute window DataFrame from window_aggregator
        w60: 1-hour window DataFrame from window_aggregator
        daily: Daily slope DataFrame from window_aggregator
        baselines: Per-user baseline DataFrame from window_aggregator

    Returns:
        DataFrame with FEATURE_COLUMNS plus metadata columns:
        (user_name, window, window_date) for joining with labels
    """
    log.info("Building feature matrix...")

    # ── Step 1: Start with 5-min windows as base ──
    feat = w5.copy()
    feat["window_date"] = feat["window"].dt.date.astype(str)

    # ── Step 2: Add z-scores relative to user baseline ──
    baseline_lookup = baselines.set_index("user_name")

    zscore_pairs = [
        ("total_events", "total_events"),
        ("iam_events", "iam_events"),
        ("s3_events", "s3_events"),
        ("s3_get_events", "s3_get_events"),
        ("s3_delete_events", "s3_delete_events"),
        ("iam_write_events", "iam_write_events"),
        ("iam_list_events", "iam_list_events"),
        ("bytes_out_total", "bytes_out_total"),
    ]

    for feat_col, baseline_col in zscore_pairs:
        zscores = []
        for _, row in feat.iterrows():
            user = row["user_name"]
            if user in baseline_lookup.index:
                mean = baseline_lookup.loc[user, f"{baseline_col}_mean"]
                std = baseline_lookup.loc[user, f"{baseline_col}_std"]
                zscores.append(_zscore(row[feat_col], mean, std))
            else:
                zscores.append(0.0)
        # Column name: feat_col + _zscore, but bytes_out_total → bytes_out_zscore
        out_col = f"{feat_col}_zscore".replace("bytes_out_total_zscore", "bytes_out_zscore")
        feat[out_col] = zscores

    # ── Step 3: Join 1-hour context window features ──
    # For each 5-min window, find the 1-hour window that contains it
    # The 1-hour window key is floored to the hour
    w60_lookup = w60.copy()
    w60_lookup["hour_key"] = w60_lookup["window"].dt.floor("h")
    w60_lookup = w60_lookup.rename(columns={
        "total_events": "h1_total_events",
        "iam_events": "h1_iam_events",
        "s3_events": "h1_s3_events",
        "s3_get_events": "h1_s3_get_events",
        "s3_delete_events": "h1_s3_delete_events",
        "iam_write_events": "h1_iam_write_events",
        "iam_list_events": "h1_iam_list_events",
        "error_events": "h1_error_events",
        "write_ratio": "h1_write_ratio",
    })
    h1_cols = [
        "user_name", "hour_key",
        "h1_total_events", "h1_iam_events", "h1_s3_events",
        "h1_s3_get_events", "h1_s3_delete_events", "h1_iam_write_events",
        "h1_iam_list_events", "h1_error_events", "h1_write_ratio"
    ]
    w60_lookup = w60_lookup[h1_cols]

    feat["hour_key"] = feat["window"].dt.floor("h")
    feat = feat.merge(w60_lookup, on=["user_name", "hour_key"], how="left")

    # ── Step 4: Join daily slope features ──
    daily_lookup = daily[["user_name", "event_date", "s3_get_slope_3d", "s3_get_pct_change_1d"]].copy()
    daily_lookup["event_date"] = daily_lookup["event_date"].dt.strftime("%Y-%m-%d")
    feat = feat.merge(daily_lookup, left_on=["user_name", "window_date"], right_on=["user_name", "event_date"], how="left")

    # ── Step 5: Cast boolean temporal features to int ──
    feat["window_is_weekend"] = feat["window_is_weekend"].astype(int)
    feat["window_is_business_hours"] = feat["window_is_business_hours"].astype(int)

    # ── Step 6: Fill NaN (missing joins) with 0 ──
    # Only fill columns that actually exist
    available_feat_cols = [c for c in FEATURE_COLUMNS if c in feat.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in feat.columns]
    if missing:
        for col in missing:
            feat[col] = 0.0
    feat[FEATURE_COLUMNS] = feat[FEATURE_COLUMNS].fillna(0.0)

    # ── Step 7: Select and order output ──
    meta_cols = ["user_name", "window", "window_date"]
    output = feat[meta_cols + FEATURE_COLUMNS].copy()

    # Final type enforcement — all feature cols must be float64
    for col in FEATURE_COLUMNS:
        output[col] = output[col].astype(float)

    log.info(f"Feature matrix: {output.shape[0]} rows × {len(FEATURE_COLUMNS)} features")
    return output


def add_labels_to_features(
    feature_df: pd.DataFrame,
    normalized_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Add attack labels to the feature matrix.

    Strategy: a feature window is labeled as an attack if ANY event
    in that window is an attack event. We propagate the attack_id
    of the first (most severe) attack found in the window.

    Args:
        feature_df: Output of build_feature_matrix
        normalized_df: Normalized events with is_attack, attack_id columns

    Returns:
        feature_df with added columns: is_attack, attack_id, attack_name
    """
    if "is_attack" not in normalized_df.columns:
        log.warning("normalized_df has no is_attack column. Adding zero labels.")
        feature_df["is_attack"] = False
        feature_df["attack_id"] = 0
        feature_df["attack_name"] = "normal"
        return feature_df

    # Build window-level attack labels
    attack_events = normalized_df[normalized_df["is_attack"]].copy()
    if len(attack_events) == 0:
        feature_df["is_attack"] = False
        feature_df["attack_id"] = 0
        feature_df["attack_name"] = "normal"
        return feature_df

    # Floor attack event times to 5-minute windows — must match window_aggregator floor
    attack_events["window"] = attack_events["eventTime"].dt.floor("5min")

    window_labels = (
        attack_events.groupby(["user_name", "window"])
        .agg(
            attack_id=("attack_id", "first"),
            attack_name=("attack_name", "first"),
        )
        .reset_index()
    )
    window_labels["is_attack"] = True

    # Merge
    feature_df = feature_df.merge(
        window_labels,
        on=["user_name", "window"],
        how="left"
    )
    feature_df["is_attack"] = feature_df["is_attack"].fillna(False)
    feature_df["attack_id"] = feature_df["attack_id"].fillna(0).astype(int)
    feature_df["attack_name"] = feature_df["attack_name"].fillna("normal")

    n_attack_windows = feature_df["is_attack"].sum()
    n_total = len(feature_df)
    log.info(f"Labeled {n_attack_windows}/{n_total} windows as attacks "
             f"({100*n_attack_windows/n_total:.1f}%)")

    return feature_df
