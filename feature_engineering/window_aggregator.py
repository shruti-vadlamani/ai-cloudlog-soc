"""
feature_engineering/window_aggregator.py
=========================================
Computes rolling window features over the normalized event stream.

Two window sizes (matching your multi-window ML approach):
  - 5-minute windows: catch bursts (privilege escalation, backdoor)
  - 1-hour windows: catch short-term pattern shifts
  - Daily (24h): catch volume trends (data exfiltration slope)

For each window, features are computed PER USER (not globally).
This is critical — a spike for eve-analyst means something different
than the same count for dave-admin.

Output: One row per (user, window_end_time) with feature columns.
This is the matrix your ML models train on.
"""

import logging
from typing import Optional

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)


def _floor_to_window(dt_series: pd.Series, window_minutes: int) -> pd.Series:
    """Floor timestamps to the nearest window boundary."""
    return dt_series.dt.floor(f"{window_minutes}min")


def compute_per_user_window_counts(
    df: pd.DataFrame,
    window_minutes: int
) -> pd.DataFrame:
    """
    For each (user, time_window) bucket, count events by type.
    Returns a wide DataFrame with one row per (user, window).
    """
    df = df.copy()
    df["window"] = _floor_to_window(df["eventTime"], window_minutes)

    # Base count columns
    df["is_iam_event"] = df["service"] == "iam"
    df["is_s3_event"] = df["service"] == "s3"
    df["is_write_event"] = ~df["is_read_only"]
    df["is_s3_write"] = df["is_s3_event"] & df["is_write_event"]
    df["is_s3_delete"] = df["eventName"].str.contains("Delete", na=False)
    df["is_iam_write"] = df["is_iam_event"] & df["is_write_event"]
    df["is_iam_list"] = df["eventName"].str.startswith("List", na=False) & df["is_iam_event"]
    df["is_s3_get"] = df["eventName"] == "GetObject"
    df["is_error_event"] = df["is_error"]
    df["is_after_hours"] = ~df["is_business_hours"]

    group = df.groupby(["user_name", "window"])

    agg = group.agg(
        total_events=("eventID", "count"),
        iam_events=("is_iam_event", "sum"),
        s3_events=("is_s3_event", "sum"),
        write_events=("is_write_event", "sum"),
        s3_write_events=("is_s3_write", "sum"),
        s3_delete_events=("is_s3_delete", "sum"),
        iam_write_events=("is_iam_write", "sum"),
        iam_list_events=("is_iam_list", "sum"),
        s3_get_events=("is_s3_get", "sum"),
        error_events=("is_error_event", "sum"),
        after_hours_events=("is_after_hours", "sum"),
        unique_resources=("request_bucket_name", "nunique"),
        unique_ips=("sourceIPAddress", "nunique"),
        unique_event_types=("eventName", "nunique"),
        bytes_out_total=("bytes_transferred_out", "sum"),
        bytes_out_max=("bytes_transferred_out", "max"),
    ).reset_index()

    # Derived ratios (safe division)
    def safe_ratio(a, b):
        return np.where(b > 0, a / b, 0.0)

    agg["iam_ratio"] = safe_ratio(agg["iam_events"], agg["total_events"])
    agg["s3_ratio"] = safe_ratio(agg["s3_events"], agg["total_events"])
    agg["write_ratio"] = safe_ratio(agg["write_events"], agg["total_events"])
    agg["error_rate"] = safe_ratio(agg["error_events"], agg["total_events"])
    agg["iam_write_ratio"] = safe_ratio(agg["iam_write_events"], agg["total_events"])
    agg["delete_ratio"] = safe_ratio(agg["s3_delete_events"], agg["total_events"])
    agg["after_hours_ratio"] = safe_ratio(agg["after_hours_events"], agg["total_events"])

    # Add window metadata
    agg["window_minutes"] = window_minutes
    agg["window_hour"] = agg["window"].dt.hour
    agg["window_day_of_week"] = agg["window"].dt.dayofweek
    agg["window_is_weekend"] = agg["window_day_of_week"] >= 5
    agg["window_is_business_hours"] = (
        (agg["window_hour"] >= 9) & (agg["window_hour"] < 18) & (~agg["window_is_weekend"])
    )

    return agg


def compute_user_baselines(df_5min: pd.DataFrame) -> pd.DataFrame:
    """
    Compute per-user baseline statistics from their normal 5-minute windows.
    Used for z-score normalization in feature builder.

    Returns one row per user with mean and std for each count feature.
    """
    count_cols = [
        "total_events", "iam_events", "s3_events", "write_events",
        "s3_get_events", "s3_delete_events", "iam_write_events",
        "iam_list_events", "error_events", "bytes_out_total"
    ]

    baselines = []
    for user, group in df_5min.groupby("user_name"):
        row = {"user_name": user}
        for col in count_cols:
            vals = group[col].values
            row[f"{col}_mean"] = np.mean(vals)
            row[f"{col}_std"] = np.std(vals) + 1e-8  # Avoid div-by-zero
            row[f"{col}_p95"] = np.percentile(vals, 95)
            row[f"{col}_max"] = np.max(vals)
        baselines.append(row)

    return pd.DataFrame(baselines)


def compute_daily_slope_features(df: pd.DataFrame, days: int = 3) -> pd.DataFrame:
    """
    Compute per-user daily slopes over a rolling N-day window.
    This is the key feature for detecting gradual data exfiltration.

    For each day D and user U, computes:
      - s3_get_slope_3d: linear regression slope of daily GetObject counts
        over the 3 days ending at D
      - s3_get_pct_change_1d: % change from yesterday to today

    Returns one row per (user, date).
    """
    df = df.copy()
    df["event_date"] = df["eventTime"].dt.date

    # Daily GetObject counts per user
    daily = (
        df[df["eventName"] == "GetObject"]
        .groupby(["user_name", "event_date"])
        .size()
        .reset_index(name="daily_s3_gets")
    )
    daily["event_date"] = pd.to_datetime(daily["event_date"])

    # Fill missing days with 0
    users = daily["user_name"].unique()
    dates = pd.date_range(df["eventTime"].dt.date.min(), df["eventTime"].dt.date.max(), freq="D")
    full_index = pd.MultiIndex.from_product([users, dates], names=["user_name", "event_date"])
    daily = daily.set_index(["user_name", "event_date"]).reindex(full_index, fill_value=0).reset_index()

    results = []
    for user, group in daily.groupby("user_name"):
        group = group.sort_values("event_date").copy()
        counts = group["daily_s3_gets"].values
        n = len(counts)

        slopes = []
        pct_changes = []

        for i in range(n):
            if i < days - 1:
                slopes.append(np.nan)
            else:
                window = counts[i - days + 1 : i + 1]
                x = np.arange(len(window))
                if window.std() > 0:
                    slope = np.polyfit(x, window, 1)[0]
                else:
                    slope = 0.0
                slopes.append(slope)

            if i == 0 or counts[i - 1] == 0:
                pct_changes.append(0.0)
            else:
                pct_changes.append((counts[i] - counts[i - 1]) / counts[i - 1])

        group["s3_get_slope_3d"] = slopes
        group["s3_get_pct_change_1d"] = pct_changes
        results.append(group)

    return pd.concat(results, ignore_index=True)


def compute_all_windows(df: pd.DataFrame) -> dict:
    """
    Master function: compute all window aggregations.

    Returns dict with keys:
        'w5'     -> 5-minute window DataFrame
        'w60'    -> 1-hour window DataFrame
        'daily'  -> daily slope DataFrame
        'baselines' -> per-user baseline stats
    """
    log.info("Computing 5-minute window features...")
    w5 = compute_per_user_window_counts(df, window_minutes=5)

    log.info("Computing 1-hour window features...")
    w60 = compute_per_user_window_counts(df, window_minutes=60)

    log.info("Computing daily slope features...")
    daily = compute_daily_slope_features(df)

    log.info("Computing user baselines...")
    baselines = compute_user_baselines(w5)

    log.info(
        f"Windows computed: "
        f"5min={len(w5)} rows, "
        f"1hr={len(w60)} rows, "
        f"daily={len(daily)} rows, "
        f"baselines={len(baselines)} users"
    )

    return {
        "w5": w5,
        "w60": w60,
        "daily": daily,
        "baselines": baselines,
    }
