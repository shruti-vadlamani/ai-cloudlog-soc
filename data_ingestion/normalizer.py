"""
data_ingestion/normalizer.py
=============================
Flattens nested CloudTrail JSON events into flat pandas DataFrames.

CloudTrail events have deeply nested structures (userIdentity,
requestParameters, responseElements, sessionContext). This module
extracts every field that matters for feature engineering and
ML training into a flat, typed row.

Output columns (guaranteed to exist, NaN if absent in source):
  eventID, eventTime, eventName, eventSource, awsRegion,
  sourceIPAddress, userAgent,
  user_type, user_name, user_arn, user_account_id, user_access_key_id,
  user_mfa_authenticated,
  session_issuer_type, session_issuer_username,
  request_bucket_name, request_key, request_prefix,
  response_error_code, error_message,
  is_read_only, is_management_event,
  bytes_transferred_out,
  event_hour, event_day_of_week, event_date, event_minute_of_day
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import pandas as pd
import numpy as np

log = logging.getLogger(__name__)


def _safe_get(d: dict, *keys, default=None):
    """Safely navigate nested dict."""
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is None:
            return default
    return current


def flatten_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten a single CloudTrail event dict into a flat record.
    All nested fields are extracted to top-level columns.
    """
    uid = event.get("userIdentity", {})
    session = uid.get("sessionContext", {})
    session_issuer = session.get("sessionIssuer", {})
    session_attrs = session.get("attributes", {})
    req = event.get("requestParameters") or {}
    resp = event.get("responseElements") or {}
    additional = event.get("additionalEventData") or {}

    # Parse eventTime to datetime
    event_time_str = event.get("eventTime", "")
    try:
        event_time = datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        event_time = None

    # Extract S3-specific request fields
    bucket_name = (
        req.get("bucketName")
        or req.get("bucket")
        or _safe_get(req, "createBucketConfiguration", "locationConstraint")
    )
    object_key = req.get("key") or req.get("objectKey")
    prefix = req.get("prefix")

    # User agent classification
    user_agent = event.get("userAgent", "")
    ua_category = _classify_user_agent(user_agent)

    # IP classification
    source_ip = event.get("sourceIPAddress", "")
    is_internal_ip = source_ip.startswith("10.") or source_ip.startswith("172.") or source_ip.startswith("192.168.")

    record = {
        # Core event fields
        "eventID": event.get("eventID"),
        "eventTime": event_time,
        "eventTime_str": event_time_str,
        "eventName": event.get("eventName"),
        "eventSource": event.get("eventSource"),
        "awsRegion": event.get("awsRegion"),
        "eventType": event.get("eventType"),

        # Network
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "ua_category": ua_category,           # 'cli', 'sdk', 'console', 'service', 'other'
        "is_internal_ip": is_internal_ip,

        # User identity
        "user_type": uid.get("type"),
        "user_name": uid.get("userName") or (
            uid.get("principalId", "").split(":")[-1]
            if uid.get("type") == "AssumedRole"
            else uid.get("principalId")
        ),
        "user_arn": uid.get("arn"),
        "user_account_id": uid.get("accountId"),
        "user_access_key_id": uid.get("accessKeyId"),
        "user_mfa_authenticated": (
            session_attrs.get("mfaAuthenticated", "false") == "true"
        ),

        # Session / assumed role
        "session_issuer_type": session_issuer.get("type"),
        "session_issuer_username": session_issuer.get("userName"),

        # Request parameters (S3-specific)
        "request_bucket_name": bucket_name,
        "request_key": object_key,
        "request_prefix": prefix,

        # Error info
        "error_code": event.get("errorCode"),
        "error_message": event.get("errorMessage"),
        "is_error": event.get("errorCode") is not None,

        # Event metadata
        "is_read_only": event.get("readOnly", True),
        "is_management_event": event.get("managementEvent", False),

        # Transfer data (S3 data events)
        "bytes_transferred_out": additional.get("byteTransferredOut", 0),
        "bytes_transferred_in": additional.get("byteTransferredIn", 0),

        # Derived temporal features (set after eventTime is parsed)
        "event_hour": event_time.hour if event_time else None,
        "event_day_of_week": event_time.weekday() if event_time else None,  # 0=Mon
        "event_date": event_time.date().isoformat() if event_time else None,
        "event_minute_of_day": (
            event_time.hour * 60 + event_time.minute if event_time else None
        ),
        "is_weekend": (event_time.weekday() >= 5) if event_time else None,
        "is_business_hours": (
            9 <= event_time.hour < 18 and event_time.weekday() < 5
        ) if event_time else None,

        # Service shortname (s3, iam, lambda, ec2, etc.)
        "service": _extract_service(event.get("eventSource", "")),
    }

    return record


def _classify_user_agent(user_agent: str) -> str:
    """Classify user agent into coarse categories."""
    ua = user_agent.lower()
    if "aws-cli" in ua:
        return "cli"
    elif "boto3" in ua or "botocore" in ua:
        return "sdk"
    elif "mozilla" in ua or "chrome" in ua or "safari" in ua or "signin.amazonaws" in ua:
        return "console"
    elif "aws-internal" in ua or "elasticloadbalancing" in ua or "lambda" in ua:
        return "service"
    else:
        return "other"


def _extract_service(event_source: str) -> str:
    """Extract short service name from eventSource."""
    # e.g. 's3.amazonaws.com' -> 's3'
    # 'iam.amazonaws.com' -> 'iam'
    # 'monitoring.amazonaws.com' -> 'cloudwatch'
    mapping = {
        "monitoring.amazonaws.com": "cloudwatch",
        "sts.amazonaws.com": "iam",   # AssumeRole attributed to iam for feature purposes
    }
    if event_source in mapping:
        return mapping[event_source]
    return event_source.split(".")[0]


def normalize_events(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Normalize a list of raw CloudTrail event dicts into a clean DataFrame.

    Returns a typed DataFrame with consistent columns, sorted by eventTime.
    """
    if not events:
        log.warning("normalize_events called with empty event list")
        return pd.DataFrame()

    log.info(f"Normalizing {len(events)} events...")
    records = [flatten_event(e) for e in events]
    df = pd.DataFrame(records)

    # Type enforcement
    df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True)
    df["event_hour"] = df["event_hour"].astype("Int64")
    df["event_day_of_week"] = df["event_day_of_week"].astype("Int64")
    df["event_minute_of_day"] = df["event_minute_of_day"].astype("Int64")
    df["bytes_transferred_out"] = df["bytes_transferred_out"].fillna(0).astype(float)
    df["bytes_transferred_in"] = df["bytes_transferred_in"].fillna(0).astype(float)
    df["is_error"] = df["is_error"].fillna(False).astype(bool)
    df["is_read_only"] = df["is_read_only"].fillna(True).astype(bool)
    df["is_management_event"] = df["is_management_event"].fillna(False).astype(bool)
    df["is_weekend"] = df["is_weekend"].fillna(False).astype(bool)
    df["is_business_hours"] = df["is_business_hours"].fillna(False).astype(bool)
    df["is_internal_ip"] = df["is_internal_ip"].fillna(False).astype(bool)
    df["user_mfa_authenticated"] = df["user_mfa_authenticated"].fillna(False).astype(bool)

    # Sort by time
    df = df.sort_values("eventTime").reset_index(drop=True)

    log.info(f"Normalized DataFrame: {df.shape[0]} rows × {df.shape[1]} columns")
    log.info(f"Date range: {df['eventTime'].min()} → {df['eventTime'].max()}")
    log.info(f"Users: {df['user_name'].nunique()} unique")
    log.info(f"Event types: {df['eventName'].nunique()} unique")

    return df


def add_attack_labels(df: pd.DataFrame, label_jsonl_path: str) -> pd.DataFrame:
    """
    Join attack labels from the ground truth JSONL file onto the
    normalized DataFrame. Adds columns:
      - is_attack (bool)
      - attack_id (int, 0 = normal)
      - attack_name (str, 'normal' for non-attacks)
    """
    import json
    from pathlib import Path

    df = df.copy()
    df["is_attack"] = False
    df["attack_id"] = 0
    df["attack_name"] = "normal"

    label_path = Path(label_jsonl_path)
    if not label_path.exists():
        log.warning(f"Label file not found: {label_jsonl_path}. Skipping label join.")
        return df

    labels = []
    with open(label_path) as f:
        for line in f:
            line = line.strip()
            if line:
                labels.append(json.loads(line))

    label_df = pd.DataFrame(labels)[["eventID", "attack_id", "attack_name"]].copy()
    label_df["is_attack"] = True

    # Merge on eventID
    df = df.merge(
        label_df,
        on="eventID",
        how="left",
        suffixes=("", "_label")
    )

    # Resolve merged columns
    df["is_attack"] = df["is_attack_label"].fillna(False)
    df["attack_id"] = df["attack_id_label"].fillna(0).astype(int)
    df["attack_name"] = df["attack_name_label"].fillna("normal")

    # Drop temporary merge columns
    drop_cols = [c for c in df.columns if c.endswith("_label")]
    df = df.drop(columns=drop_cols)

    n_attack = df["is_attack"].sum()
    log.info(f"Labels joined: {n_attack} attack events, {len(df) - n_attack} normal events")
    return df
