"""
backend/api/stats.py
=====================
API endpoints for statistics and metrics
"""

from typing import List
from fastapi import APIRouter, Depends

from backend.models.schemas import OverviewStats, ModelPerformance
from backend.services.alert_service import get_alert_service, AlertService

router = APIRouter()


@router.get("/overview", response_model=OverviewStats)
def get_overview_statistics(
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Get high-level dashboard statistics.

    Returns:
    - Total alerts count
    - Severity distribution (high/medium/low)
    - Unique users affected
    - Attack type distribution
    - Alert timeline
    - Top users by alert count
    """
    return alert_service.get_overview_stats()


@router.get("/models", response_model=List[ModelPerformance])
def get_model_performance(
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Get ML model performance metrics.

    Returns precision, recall, F1-score, and confusion matrix
    values for each detection model:
    - Ensemble
    - Isolation Forest
    - Local Outlier Factor (LOF)
    - Autoencoder
    """
    return alert_service.get_model_performance()


@router.get("/severity-distribution", response_model=dict)
def get_severity_distribution(
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Get alert severity distribution.

    Severity levels:
    - High: ensemble_score >= 0.7
    - Medium: 0.3 <= ensemble_score < 0.7
    - Low: ensemble_score < 0.3
    """
    stats = alert_service.get_overview_stats()
    return {
        "high": stats.high_severity_count,
        "medium": stats.medium_severity_count,
        "low": stats.low_severity_count,
    }


@router.get("/attack-distribution", response_model=dict)
def get_attack_distribution(
    alert_service: AlertService = Depends(get_alert_service),
):
    """Get distribution of attack types"""
    stats = alert_service.get_overview_stats()
    return stats.attack_types
