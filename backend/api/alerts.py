"""
backend/api/alerts.py
======================
API endpoints for alert management
"""

from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Depends

from backend.models.schemas import Alert, AlertList, EnrichedAlert
from backend.services.alert_service import get_alert_service, AlertService
from backend.services.rag_service import get_rag_service, RAGService

router = APIRouter()


@router.get("/", response_model=AlertList)
def get_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    user_name: Optional[str] = Query(None, description="Filter by user"),
    attack_name: Optional[str] = Query(None, description="Filter by attack type"),
    min_score: Optional[float] = Query(None, ge=0, le=1, description="Minimum ensemble score"),
    is_attack: Optional[bool] = Query(None, description="Filter by ground truth"),
    sort_by: str = Query("ensemble_score", description="Sort column"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Get paginated list of alerts with filtering and sorting.

    Example queries:
    - `/api/alerts?page=1&page_size=20` - First 20 alerts
    - `/api/alerts?user_name=bob-devops` - Alerts for specific user
    - `/api/alerts?min_score=0.7` - High severity alerts (>= 0.7)
    - `/api/alerts?is_attack=true` - Only confirmed attacks
    - `/api/alerts?attack_name=insider_threat` - Specific attack type
    """
    return alert_service.get_alerts(
        page=page,
        page_size=page_size,
        user_name=user_name,
        attack_name=attack_name,
        min_score=min_score,
        is_attack=is_attack,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/filters", response_model=dict)
def get_filter_options(
    alert_service: AlertService = Depends(get_alert_service),
):
    """Get available filter options (users, attack types, etc.)"""
    return {
        "users": alert_service.get_unique_users(),
        "attack_types": alert_service.get_unique_attack_types(),
    }


@router.get("/{user_name}/{window}", response_model=EnrichedAlert)
def get_alert_details(
    user_name: str,
    window: str,
    alert_service: AlertService = Depends(get_alert_service),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Get enriched alert details with full RAG context.

    Returns MITRE techniques, detection patterns, playbooks,
    similar incidents, and behavioral context.

    Example:
    `/api/alerts/bob-devops/2026-02-27T11:35:00+00:00`
    """
    try:
        # Parse window timestamp
        window_dt = datetime.fromisoformat(window.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp format. Use ISO 8601 format.")

    # Get base alert
    alert = alert_service.get_alert_by_window(user_name, window_dt)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Enrich with RAG context
    enriched = rag_service.enrich_alert(alert)
    return enriched


@router.get("/summary/timeline", response_model=List[dict])
def get_alert_timeline(
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Get alert timeline for visualization.
    Returns alert counts grouped by date.
    """
    stats = alert_service.get_overview_stats()
    return stats.alerts_by_date


@router.get("/summary/top-users", response_model=List[dict])
def get_top_users(
    limit: int = Query(10, ge=1, le=50),
    alert_service: AlertService = Depends(get_alert_service),
):
    """Get users with most alerts"""
    stats = alert_service.get_overview_stats()
    return stats.top_users[:limit]
