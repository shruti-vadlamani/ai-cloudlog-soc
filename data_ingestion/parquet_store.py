"""
data_ingestion/parquet_store.py
================================
Handles reading and writing normalized event DataFrames as Parquet files.

Why Parquet:
  - Columnar format: feature engineering reads only needed columns
  - Preserves dtypes (datetime, bool, int) — no CSV type loss
  - Fast for analytical queries (10x+ faster than CSV for aggregations)
  - Native pandas/pyarrow support
  - When you move to real AWS, these can live in S3 and be queried
    with Athena or Glue — zero format change

File layout:
  data/normalized/
    events.parquet          — full normalized event table
    events_with_labels.parquet — events joined with attack labels
"""

import logging
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)


def _has_pyarrow() -> bool:
    try:
        import pyarrow
        return True
    except ImportError:
        return False


def write_parquet(df: pd.DataFrame, output_path: str, partition_by_date: bool = False) -> None:
    """
    Write normalized DataFrame to Parquet.

    Args:
        df: Normalized events DataFrame
        output_path: Full path to output file (e.g., data/normalized/events.parquet)
        partition_by_date: If True, partition by event_date column (good for large datasets)
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if _has_pyarrow():
        if partition_by_date and "event_date" in df.columns:
            partition_dir = path.parent / path.stem
            df.to_parquet(str(partition_dir), partition_cols=["event_date"], engine="pyarrow", index=False)
            log.info(f"Written partitioned Parquet to {partition_dir}/")
        else:
            df.to_parquet(output_path, engine="pyarrow", index=False)
            size_mb = path.stat().st_size / (1024 * 1024)
            log.info(f"Written {len(df):,} rows to {output_path} ({size_mb:.2f} MB)")
    else:
        # Fallback: write as compressed CSV (install pyarrow for production)
        csv_path = str(output_path).replace(".parquet", ".csv.gz")
        df.to_csv(csv_path, index=False, compression="gzip")
        size_mb = Path(csv_path).stat().st_size / (1024 * 1024)
        log.warning(f"pyarrow not installed — written as CSV.gz: {csv_path} ({size_mb:.2f} MB)")
        log.warning("Install pyarrow for Parquet: pip install pyarrow")


def read_parquet(input_path: str) -> pd.DataFrame:
    """
    Read normalized events from Parquet (or CSV.gz fallback).
    Restores all dtypes correctly.
    """
    path = Path(input_path)

    # Try parquet first, then csv.gz fallback
    if path.exists() and _has_pyarrow():
        df = pd.read_parquet(input_path, engine="pyarrow")
    else:
        csv_path = str(input_path).replace(".parquet", ".csv.gz")
        if Path(csv_path).exists():
            df = pd.read_csv(csv_path, compression="gzip")
        elif path.exists():
            df = pd.read_parquet(input_path)
        else:
            raise FileNotFoundError(f"Neither {input_path} nor {csv_path} found")

    # Ensure eventTime is timezone-aware UTC
    if "eventTime" in df.columns:
        if not pd.api.types.is_datetime64_any_dtype(df["eventTime"]):
            df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True)
        elif df["eventTime"].dt.tz is None:
            df["eventTime"] = df["eventTime"].dt.tz_localize("UTC")

    log.info(f"Loaded {len(df):,} rows from {input_path}")
    return df


def read_parquet_for_date_range(
    input_path: str,
    start_date: str,
    end_date: str
) -> pd.DataFrame:
    """
    Read only rows within a date range.
    Efficient for filtering large datasets.

    Args:
        input_path: Path to parquet file or directory
        start_date: 'YYYY-MM-DD'
        end_date: 'YYYY-MM-DD'
    """
    df = read_parquet(input_path)
    mask = (df["event_date"] >= start_date) & (df["event_date"] <= end_date)
    filtered = df[mask].copy()
    log.info(f"Filtered to {len(filtered):,} rows for {start_date} to {end_date}")
    return filtered
