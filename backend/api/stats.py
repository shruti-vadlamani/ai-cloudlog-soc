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


@router.get("/filter-options", response_model=dict)
def get_filter_options(
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Get available options for filter dropdowns.
    
    Returns:
    - attack_types: List of all attack types in the database
    - mitre_techniques: List of all MITRE technique IDs
    - users: List of all unique users
    """
    stats = alert_service.get_overview_stats()
    attack_types = list(stats.attack_types.keys()) if stats.attack_types else []
    
    # Load MITRE techniques from knowledge base
    import json
    from pathlib import Path
    mitre_techniques = []
    try:
        kb_path = Path(__file__).parent.parent.parent / "knowledge_base" / "mitre_techniques.json"
        if kb_path.exists():
            with open(kb_path, "r") as f:
                techniques = json.load(f)
                mitre_techniques = [
                    {"id": t.get("technique_id"), "name": t.get("name")}
                    for t in techniques
                ]
    except Exception as e:
        print(f"Error loading MITRE techniques: {e}")
    
    # Get all unique users
    users = alert_service.get_unique_users()
    
    return {
        "attack_types": sorted(attack_types),
        "mitre_techniques": mitre_techniques,
        "users": sorted(users) if users else [],
    }
