"""
backend/services/alert_service.py
===================================
Service layer for alert data loading and processing
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.models.schemas import Alert, AlertList, OverviewStats, ModelPerformance

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
ALERTS_PATH = PROJECT_ROOT / "data" / "results" / "ensemble_alerts.csv"
RESULTS_PATH = PROJECT_ROOT / "data" / "results"


class AlertService:
    """Service for loading and querying alert data"""

    def __init__(self):
        self.alerts_df: Optional[pd.DataFrame] = None
        self.load_alerts()

    def load_alerts(self):
        """Load ensemble alerts CSV"""
        if not ALERTS_PATH.exists():
            log.warning(f"Alerts file not found: {ALERTS_PATH}")
            log.warning("Run: python run_models.py")
            self.alerts_df = pd.DataFrame()
            return

        try:
            self.alerts_df = pd.read_csv(ALERTS_PATH)
            self.alerts_df["window"] = pd.to_datetime(self.alerts_df["window"], utc=True)
            log.info(f"Loaded {len(self.alerts_df)} alerts")
        except Exception as e:
            log.error(f"Failed to load alerts: {e}")
            self.alerts_df = pd.DataFrame()

    def get_alerts(
        self,
        page: int = 1,
        page_size: int = 50,
        user_name: Optional[str] = None,
        attack_name: Optional[str] = None,
        min_score: Optional[float] = None,
        is_attack: Optional[bool] = None,
        sort_by: str = "ensemble_score",
        sort_order: str = "desc",
    ) -> AlertList:
        """
        Get paginated alerts with filtering.

        Args:
            page: Page number (1-indexed)
            page_size: Number of alerts per page
            user_name: Filter by user
            attack_name: Filter by attack type
            min_score: Minimum ensemble score
            is_attack: Filter by ground truth label
            sort_by: Column to sort by
            sort_order: 'asc' or 'desc'
        """
        if self.alerts_df is None or len(self.alerts_df) == 0:
            return AlertList(total=0, page=page, page_size=page_size, alerts=[])

        df = self.alerts_df.copy()

        # Apply filters
        if user_name:
            df = df[df["user_name"].str.contains(user_name, case=False, na=False)]
        if attack_name:
            df = df[df["attack_name"] == attack_name]
        if min_score is not None:
            df = df[df["ensemble_score"] >= min_score]
        if is_attack is not None:
            df = df[df["is_attack"] == is_attack]

        # Sort
        ascending = sort_order == "asc"
        df = df.sort_values(by=sort_by, ascending=ascending)

        # Paginate
        total = len(df)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_df = df.iloc[start_idx:end_idx]

        # Convert to Alert models
        alerts = []
        for _, row in page_df.iterrows():
            alert = Alert(
                user_name=row["user_name"],
                window=row["window"],
                ensemble_score=float(row["ensemble_score"]),
                if_norm=float(row["if_norm"]),
                lof_norm=float(row["lof_norm"]),
                ae_norm=float(row["ae_norm"]),
                vote_count=int(row["vote_count"]),
                attack_name=row["attack_name"],
                is_attack=bool(row["is_attack"]),
            )
            alerts.append(alert)

        return AlertList(
            total=total,
            page=page,
            page_size=page_size,
            alerts=alerts,
        )

    def get_alert_by_window(self, user_name: str, window: datetime) -> Optional[Alert]:
        """Get specific alert by user and window"""
        if self.alerts_df is None or len(self.alerts_df) == 0:
            return None

        mask = (self.alerts_df["user_name"] == user_name) & (
            self.alerts_df["window"] == window
        )
        matches = self.alerts_df[mask]

        if len(matches) == 0:
            return None

        row = matches.iloc[0]
        return Alert(
            user_name=row["user_name"],
            window=row["window"],
            ensemble_score=float(row["ensemble_score"]),
            if_norm=float(row["if_norm"]),
            lof_norm=float(row["lof_norm"]),
            ae_norm=float(row["ae_norm"]),
            vote_count=int(row["vote_count"]),
            attack_name=row["attack_name"],
            is_attack=bool(row["is_attack"]),
        )

    def get_overview_stats(self) -> OverviewStats:
        """Compute dashboard statistics"""
        if self.alerts_df is None or len(self.alerts_df) == 0:
            return OverviewStats(
                total_alerts=0,
                high_severity_count=0,
                medium_severity_count=0,
                low_severity_count=0,
                unique_users_affected=0,
                attack_types={},
                alerts_by_date=[],
                top_users=[],
            )

        df = self.alerts_df

        # Severity thresholds
        high = df[df["ensemble_score"] >= 0.7]
        medium = df[(df["ensemble_score"] >= 0.3) & (df["ensemble_score"] < 0.7)]
        low = df[df["ensemble_score"] < 0.3]

        # Attack type distribution
        attack_types = df["attack_name"].value_counts().to_dict()

        # Alerts by date
        df["date"] = pd.to_datetime(df["window"]).dt.date
        alerts_by_date = (
            df.groupby("date")
            .size()
            .reset_index(name="count")
            .sort_values("date")
        )
        alerts_by_date["date"] = alerts_by_date["date"].astype(str)
        alerts_by_date_list = alerts_by_date.to_dict("records")

        # Top users by alert count
        top_users = (
            df.groupby("user_name")
            .agg(
                alert_count=("user_name", "size"),
                avg_score=("ensemble_score", "mean"),
                max_score=("ensemble_score", "max"),
            )
            .reset_index()
            .sort_values("alert_count", ascending=False)
            .head(10)
        )
        top_users["avg_score"] = top_users["avg_score"].round(3)
        top_users["max_score"] = top_users["max_score"].round(3)
        top_users_list = top_users.to_dict("records")
        
        # Rename column for response
        for user in top_users_list:
            user["user"] = user.pop("user_name")

        return OverviewStats(
            total_alerts=len(df),
            high_severity_count=len(high),
            medium_severity_count=len(medium),
            low_severity_count=len(low),
            unique_users_affected=df["user_name"].nunique(),
            attack_types=attack_types,
            alerts_by_date=alerts_by_date_list,
            top_users=top_users_list,
        )

    def get_model_performance(self) -> List[ModelPerformance]:
        """Load model performance metrics from results JSON files"""
        models = ["ensemble", "isolation_forest", "lof", "autoencoder"]
        performance = []

        for model_name in models:
            result_file = RESULTS_PATH / f"{model_name}_results.json"
            if not result_file.exists():
                continue

            try:
                with open(result_file, "r") as f:
                    data = json.load(f)

                metrics = data.get("metrics", {})
                perf = ModelPerformance(
                    model_name=model_name,
                    precision=metrics.get("precision", 0.0),
                    recall=metrics.get("recall", 0.0),
                    f1_score=metrics.get("f1", 0.0),
                    true_positives=metrics.get("true_positives", 0),
                    false_positives=metrics.get("false_positives", 0),
                    false_negatives=metrics.get("false_negatives", 0),
                )
                performance.append(perf)
            except Exception as e:
                log.warning(f"Failed to load {model_name} metrics: {e}")

        return performance

    def get_unique_users(self) -> List[str]:
        """Get list of unique users in alerts"""
        if self.alerts_df is None or len(self.alerts_df) == 0:
            return []
        return sorted(self.alerts_df["user_name"].unique().tolist())

    def get_unique_attack_types(self) -> List[str]:
        """Get list of unique attack types"""
        if self.alerts_df is None or len(self.alerts_df) == 0:
            return []
        return sorted(self.alerts_df["attack_name"].unique().tolist())


# Singleton instance
_alert_service = None


def get_alert_service() -> AlertService:
    """Get or create AlertService singleton"""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertService()
    return _alert_service
