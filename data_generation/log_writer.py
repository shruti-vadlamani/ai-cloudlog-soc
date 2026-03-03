"""
log_writer.py
=============
Writes CloudTrail events to gzipped JSON files, organized in the
exact S3 folder hierarchy that real AWS CloudTrail uses:

  AWSLogs/<account_id>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/
    <account>_CloudTrail_<region>_<YYYYMMDDTHHmmssZ>_<uid>.json.gz

Each file covers a ~15-minute window, exactly as AWS produces.
This means when you switch to a real AWS account, your downstream
pipeline reads from S3 with zero changes to the file format.
"""

import gzip
import json
import os
import uuid
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict
from pathlib import Path

log = logging.getLogger(__name__)


def _window_key(event_time_str: str, window_minutes: int = 15) -> str:
    """
    Bucket an ISO8601 event time string into a 15-minute window key.
    Returns a string like '2026-02-17T02:00:00Z' (start of window).
    """
    dt = datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    # Floor to nearest window_minutes
    floored_minute = (dt.minute // window_minutes) * window_minutes
    window_start = dt.replace(minute=floored_minute, second=0, microsecond=0)
    return window_start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cloudtrail_filename(account_id: str, region: str, window_start: datetime) -> str:
    """
    Generate a CloudTrail-format filename.
    Real format: <accountID>_CloudTrail_<region>_<YYYYMMDDTHHmmssZ>_<uid>.json.gz
    """
    timestamp_str = window_start.strftime("%Y%m%dT%H%M%SZ")
    uid = str(uuid.uuid4())[:8].upper()
    return f"{account_id}_CloudTrail_{region}_{timestamp_str}_{uid}.json.gz"


def _output_path(base_dir: str, account_id: str, region: str, window_start: datetime) -> Path:
    """
    Build the full output path mirroring CloudTrail's S3 structure.
    """
    date_path = window_start.strftime("%Y/%m/%d")
    dir_path = Path(base_dir) / "AWSLogs" / account_id / "CloudTrail" / region / date_path
    dir_path.mkdir(parents=True, exist_ok=True)
    filename = _cloudtrail_filename(account_id, region, window_start)
    return dir_path / filename


def write_cloudtrail_logs(
    events: List[dict],
    config: dict,
    window_minutes: int = 15
) -> List[str]:
    """
    Group events by 15-minute window and write each group as a
    gzipped JSON file in the CloudTrail directory hierarchy.

    Returns list of written file paths.
    """
    account_id = config["aws"]["account_id"]
    region = config["aws"]["region"]
    base_dir = config["output"]["raw_log_dir"]

    # Group events by window
    windowed: Dict[str, List[dict]] = defaultdict(list)
    for event in events:
        key = _window_key(event["eventTime"], window_minutes)
        windowed[key].append(event)

    log.info(f"Writing {len(windowed)} CloudTrail log files ({len(events)} total events)")

    written_paths = []
    for window_key_str, window_events in sorted(windowed.items()):
        window_start = datetime.strptime(window_key_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

        # CloudTrail JSON wrapper: {"Records": [...]}
        payload = {"Records": window_events}
        payload_bytes = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")

        out_path = _output_path(base_dir, account_id, region, window_start)

        with gzip.open(str(out_path), "wb") as f:
            f.write(payload_bytes)

        written_paths.append(str(out_path))

    log.info(f"Wrote {len(written_paths)} log files to {base_dir}/AWSLogs/")
    return written_paths


def write_attack_manifest(manifest: dict, output_path: str) -> None:
    """Write the ground truth attack manifest as pretty JSON."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    log.info(f"Attack manifest written to {output_path}")


def write_label_jsonl(labels: List[dict], output_path: str) -> None:
    """
    Write per-event ground truth labels as newline-delimited JSON.
    One line per attack event: {eventID, eventTime, attack_id, attack_name, ...}
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for entry in labels:
            f.write(json.dumps(entry, default=str) + "\n")
    log.info(f"Label JSONL written to {output_path} ({len(labels)} attack events)")


def summarize_output(events: List[dict], written_paths: List[str]) -> None:
    """Print a human-readable summary of the generated dataset."""
    from collections import Counter

    event_names = Counter(e["eventName"] for e in events)
    usernames = Counter(e["userIdentity"].get("userName", "unknown") for e in events)
    sources = Counter(e["eventSource"] for e in events)

    print("\n" + "="*60)
    print("CLOUDTRAIL LOG GENERATION SUMMARY")
    print("="*60)
    print(f"Total events:      {len(events):,}")
    print(f"Total log files:   {len(written_paths):,}")
    print(f"\nTop event names:")
    for name, count in event_names.most_common(10):
        print(f"  {name:<45} {count:>5}")
    print(f"\nEvents per user:")
    for user, count in usernames.most_common():
        print(f"  {user:<30} {count:>5}")
    print(f"\nEvents per service:")
    for src, count in sources.most_common():
        print(f"  {src:<40} {count:>5}")
    print("="*60 + "\n")
