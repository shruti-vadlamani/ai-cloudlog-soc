"""
aws_connector/s3_cloudtrail_reader.py
=======================================
Drop-in replacement for data_ingestion/log_reader.py that reads
CloudTrail logs directly from a real AWS S3 bucket.

Usage:
    from aws_connector.s3_cloudtrail_reader import load_all_events_from_s3

    events = load_all_events_from_s3(
        bucket="your-cloudtrail-bucket",
        prefix="AWSLogs/911234567890/CloudTrail/ap-south-1/",
        start_date="2026-02-15",
        end_date="2026-03-01",
        profile_name="default"  # AWS CLI profile
    )

All downstream code (normalizer, feature_builder, models) works
identically on this output as on simulated data.

Prerequisites:
    pip install boto3
    aws configure  (or set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars)
    Your IAM user needs: s3:GetObject, s3:ListBucket on the CloudTrail bucket
"""

import gzip
import io
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)


def _date_prefixes(
    base_prefix: str,
    start_date: str,
    end_date: str
) -> List[str]:
    """
    Generate per-day S3 prefixes for the date range.
    CloudTrail path: .../YYYY/MM/DD/
    """
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    prefixes = []
    current = start
    while current <= end:
        prefixes.append(f"{base_prefix}{current.strftime('%Y/%m/%d/')}")
        current += timedelta(days=1)
    return prefixes


def load_all_events_from_s3(
    bucket: str,
    prefix: str,
    start_date: str,
    end_date: str,
    profile_name: Optional[str] = None,
    max_files: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Load all CloudTrail events from a real S3 bucket for a date range.

    Args:
        bucket: S3 bucket name (e.g. 'your-cloudtrail-logs-bucket')
        prefix: S3 key prefix (e.g. 'AWSLogs/123456789/CloudTrail/ap-south-1/')
        start_date: 'YYYY-MM-DD'
        end_date: 'YYYY-MM-DD'
        profile_name: AWS CLI profile name (optional, uses default if None)
        max_files: Optional limit for debugging

    Returns:
        Flat list of CloudTrail event dicts — identical format to
        data_ingestion/log_reader.py output.
    """
    try:
        import boto3
        import botocore
    except ImportError:
        raise ImportError("boto3 required: pip install boto3")

    session = boto3.Session(profile_name=profile_name)
    s3 = session.client("s3")

    all_events = []
    file_count = 0

    date_prefixes = _date_prefixes(prefix, start_date, end_date)

    for day_prefix in date_prefixes:
        log.info(f"Listing s3://{bucket}/{day_prefix}")

        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=day_prefix)

        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json.gz"):
                    continue

                try:
                    response = s3.get_object(Bucket=bucket, Key=key)
                    compressed = response["Body"].read()
                    with gzip.open(io.BytesIO(compressed), "rb") as f:
                        content = json.loads(f.read().decode("utf-8"))
                    events = content.get("Records", [])
                    all_events.extend(events)
                    file_count += 1
                    log.debug(f"  Read {len(events)} events from {key}")
                except Exception as e:
                    log.warning(f"  Failed to read {key}: {e}")

                if max_files and file_count >= max_files:
                    log.info(f"Stopped at max_files={max_files}")
                    all_events.sort(key=lambda e: e.get("eventTime", ""))
                    return all_events

    all_events.sort(key=lambda e: e.get("eventTime", ""))
    log.info(f"Loaded {len(all_events)} events from {file_count} S3 files")
    return all_events


def get_cloudtrail_bucket_for_account(
    account_id: str,
    region: str = "ap-south-1",
    profile_name: Optional[str] = None,
) -> Optional[str]:
    """
    Auto-detect the CloudTrail S3 bucket for a given account
    by querying the CloudTrail API.

    Useful for the demo: run this first to find your bucket,
    then pass it to load_all_events_from_s3.
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 required: pip install boto3")

    session = boto3.Session(profile_name=profile_name, region_name=region)
    ct = session.client("cloudtrail")

    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        for trail in trails:
            if trail.get("HomeRegion") == region:
                bucket = trail.get("S3BucketName")
                prefix = trail.get("S3KeyPrefix", "")
                log.info(f"Found CloudTrail bucket: {bucket}, prefix: {prefix}")
                return bucket, prefix
    except Exception as e:
        log.error(f"Failed to describe trails: {e}")

    return None, None
