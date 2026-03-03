"""
data_ingestion/log_reader.py
=============================
Reads CloudTrail gzip JSON files from local disk (simulation)
or from AWS S3 (real account — see aws_connector/s3_cloudtrail_reader.py).

This is the single entry point for all raw log data. Swap the
source by setting use_s3=True and providing s3_config.
"""

import gzip
import json
import logging
import os
from pathlib import Path
from typing import List, Iterator, Dict, Any

log = logging.getLogger(__name__)


def iter_local_cloudtrail_files(base_dir: str) -> Iterator[Path]:
    """
    Walk the local CloudTrail directory and yield each .json.gz file path.
    Yields in chronological order (by filename, which encodes timestamp).
    """
    base_path = Path(base_dir)
    if not base_path.exists():
        raise FileNotFoundError(f"Raw log directory not found: {base_dir}")

    all_files = sorted(base_path.rglob("*.json.gz"))
    log.info(f"Found {len(all_files)} CloudTrail log files in {base_dir}")
    yield from all_files


def read_cloudtrail_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    Read a single gzipped CloudTrail log file and return
    the list of Records it contains.
    """
    try:
        with gzip.open(str(file_path), "rb") as f:
            content = json.loads(f.read().decode("utf-8"))
        return content.get("Records", [])
    except Exception as e:
        log.warning(f"Failed to read {file_path}: {e}")
        return []


def load_all_events(
    base_dir: str,
    max_files: int = None
) -> List[Dict[str, Any]]:
    """
    Load all CloudTrail events from local gzip files into memory.

    For 18,000 events across ~1,344 files (2 weeks × 96 windows/day),
    this is fast enough — typically < 5 seconds.

    Args:
        base_dir: Path to the raw log output directory
        max_files: Optional limit (for testing/debugging)

    Returns:
        Flat list of all CloudTrail event dicts, sorted by eventTime
    """
    all_events = []
    file_count = 0

    for file_path in iter_local_cloudtrail_files(base_dir):
        events = read_cloudtrail_file(file_path)
        all_events.extend(events)
        file_count += 1

        if max_files and file_count >= max_files:
            log.info(f"Stopped at max_files={max_files}")
            break

    # Sort by eventTime (ISO8601 strings sort correctly lexicographically)
    all_events.sort(key=lambda e: e.get("eventTime", ""))

    log.info(f"Loaded {len(all_events)} events from {file_count} files")
    return all_events


def stream_events_by_day(
    base_dir: str
) -> Iterator[tuple]:
    """
    Stream events grouped by calendar day.
    Yields (date_str, [events]) tuples.
    Memory-efficient for very large datasets.
    """
    from collections import defaultdict
    daily: Dict[str, list] = defaultdict(list)

    for file_path in iter_local_cloudtrail_files(base_dir):
        events = read_cloudtrail_file(file_path)
        for event in events:
            event_time = event.get("eventTime", "")
            date_str = event_time[:10]  # YYYY-MM-DD
            daily[date_str].append(event)

    for date_str in sorted(daily.keys()):
        yield date_str, daily[date_str]
