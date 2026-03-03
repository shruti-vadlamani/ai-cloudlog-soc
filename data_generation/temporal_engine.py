"""
temporal_engine.py
==================
Generates realistic timestamps for a 2-week simulation window.

Business logic modeled on:
- Indian Standard Time (IST = UTC+5:30)
- Typical software company in India work patterns
- CI/CD bots running around the clock
- Human users clustered in IST business hours
"""

import random
import numpy as np
from datetime import datetime, timedelta, timezone
from typing import List, Tuple
import yaml


IST_OFFSET = timedelta(hours=5, minutes=30)
IST = timezone(IST_OFFSET)


def load_config(config_path: str = "config/simulation_config.yaml") -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def ist_to_utc(dt: datetime) -> datetime:
    """Convert naive IST datetime to UTC-aware datetime."""
    ist_aware = dt.replace(tzinfo=IST)
    return ist_aware.astimezone(timezone.utc)


def utc_now_ist() -> datetime:
    return datetime.now(IST)


class TemporalEngine:
    """
    Generates event timestamps distributed realistically
    across the 2-week simulation window.

    Usage:
        engine = TemporalEngine(config)
        timestamps = engine.generate_timestamps(n=18000)
        # Returns list of UTC-aware datetime objects
    """

    def __init__(self, config: dict):
        self.config = config
        sim = config["simulation"]

        # Parse date range
        self.start_ist = datetime.strptime(
            sim["start_date"], "%Y-%m-%d"
        ).replace(hour=0, minute=0, second=0, tzinfo=IST)

        self.end_ist = datetime.strptime(
            sim["end_date"], "%Y-%m-%d"
        ).replace(hour=23, minute=59, second=59, tzinfo=IST)

        self.total_seconds = (self.end_ist - self.start_ist).total_seconds()

        # Load weight tables
        temporal = config["temporal"]
        self.hourly_weights = {
            int(k): float(v)
            for k, v in temporal["hourly_weights"].items()
        }
        self.daily_weights = {
            int(k): float(v)
            for k, v in temporal["daily_weights"].items()
        }

    def _weight_for_datetime(self, dt: datetime) -> float:
        """Combined weight for a given datetime (IST)."""
        hour_w = self.hourly_weights.get(dt.hour, 0.05)
        day_w = self.daily_weights.get(dt.weekday(), 1.0)
        return hour_w * day_w

    def generate_timestamps(
        self,
        n: int,
        persona_name: str = None,
        working_hours: Tuple[int, int] = None
    ) -> List[datetime]:
        """
        Generate n timestamps (UTC-aware) distributed across the window.

        If working_hours is provided, strongly biases toward those hours
        but still allows a small fraction outside (overtime, checking in).

        For cicd-bot (persona_name == 'cicd-service-account'),
        uses uniform distribution weighted only by daily pattern.
        """
        timestamps = []
        is_bot = (persona_name == "cicd-service-account")

        # Build a discretized weight array over every minute in the window
        # For performance, we sample from weighted minutes
        total_minutes = int(self.total_seconds / 60)

        # Sample candidate minutes
        # Use rejection sampling with weight proportional to temporal pattern
        attempts = 0
        max_weight = max(self.hourly_weights.values()) * max(self.daily_weights.values())

        while len(timestamps) < n and attempts < n * 20:
            attempts += 1
            # Pick a random second in the window
            random_second = random.uniform(0, self.total_seconds)
            candidate = self.start_ist + timedelta(seconds=random_second)

            # For bot: weight only by day, allow all hours
            if is_bot:
                weight = self.daily_weights.get(candidate.weekday(), 1.0) * 0.5
                threshold = max(self.daily_weights.values()) * 0.5
                if random.random() < (weight / threshold):
                    timestamps.append(candidate.astimezone(timezone.utc))
                continue

            # For humans: weight by hour and day
            weight = self._weight_for_datetime(candidate)

            # If working hours specified, outside-hours events are rare (5%)
            if working_hours:
                start_h, end_h = working_hours
                if not (start_h <= candidate.hour < end_h):
                    # Only 5% chance of accepting outside working hours
                    if random.random() > 0.05:
                        continue
                    weight *= 0.1  # Reduce weight for off-hours

            # Acceptance probability
            if random.random() < (weight / max_weight):
                timestamps.append(candidate.astimezone(timezone.utc))

        timestamps.sort()
        return timestamps[:n]

    def generate_burst(
        self,
        center_ist: datetime,
        n: int,
        spread_seconds: int = 300
    ) -> List[datetime]:
        """
        Generate n timestamps clustered around a center time.
        Used for attack scenario bursts. Spread follows log-normal.
        """
        if center_ist.tzinfo is None:
            center_ist = center_ist.replace(tzinfo=IST)
        center_utc = center_ist.astimezone(timezone.utc)

        timestamps = []
        for _ in range(n):
            # Log-normal offset: most events close to center, some scattered
            offset_sign = random.choice([-1, 1])
            offset = abs(np.random.lognormal(mean=3, sigma=1.5))
            offset = min(offset, spread_seconds)
            ts = center_utc + timedelta(seconds=offset_sign * offset)
            timestamps.append(ts)

        timestamps.sort()
        return timestamps

    def spread_across_window(
        self,
        start_ist: datetime,
        end_ist: datetime,
        n: int,
        business_hours_only: bool = True
    ) -> List[datetime]:
        """
        Spread n events across a multi-day window with realistic daily patterns.
        Used for gradual attacks (exfiltration, reconnaissance).
        """
        if start_ist.tzinfo is None:
            start_ist = start_ist.replace(tzinfo=IST)
        if end_ist.tzinfo is None:
            end_ist = end_ist.replace(tzinfo=IST)

        window_seconds = (end_ist - start_ist).total_seconds()
        timestamps = []
        attempts = 0

        while len(timestamps) < n and attempts < n * 30:
            attempts += 1
            random_second = random.uniform(0, window_seconds)
            candidate = start_ist + timedelta(seconds=random_second)

            if business_hours_only and not (9 <= candidate.hour < 18):
                continue

            weight = self._weight_for_datetime(candidate)
            max_w = max(self.hourly_weights.values()) * max(self.daily_weights.values())

            if random.random() < (weight / max_w):
                timestamps.append(candidate.astimezone(timezone.utc))

        timestamps.sort()
        return timestamps[:n]

    def parse_attack_datetime(self, dt_str: str) -> datetime:
        """Parse IST datetime string from config into UTC-aware datetime."""
        naive = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        ist_aware = naive.replace(tzinfo=IST)
        return ist_aware.astimezone(timezone.utc)


def get_engine(config_path: str = "config/simulation_config.yaml") -> TemporalEngine:
    config = load_config(config_path)
    return TemporalEngine(config)
