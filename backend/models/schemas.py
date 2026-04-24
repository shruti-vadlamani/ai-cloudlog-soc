"""
backend/models/schemas.py
==========================
Pydantic models for FastAPI request/response validation
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ── Alert Models ───────────────────────────────────────────────────────────

class Alert(BaseModel):
    """Single alert from ensemble detector"""
    user_name: str
    window: datetime
    ensemble_score: float
    if_norm: float
    lof_norm: float
    ae_norm: float
    vote_count: int
    attack_name: str
    is_attack: bool

    class Config:
        json_schema_extra = {
            "example": {
                "user_name": "bob-devops",
                "window": "2026-02-27T11:35:00+00:00",
                "ensemble_score": 0.8219,
                "if_norm": 0.4929,
                "lof_norm": 1.0,
                "ae_norm": 0.9981,
                "vote_count": 2,
                "attack_name": "insider_threat",
                "is_attack": True
            }
        }


class AlertList(BaseModel):
    """Paginated list of alerts"""
    total: int
    page: int
    page_size: int
    alerts: List[Alert]


class EnrichedAlert(BaseModel):
    """Alert with full RAG enrichment context"""
    alert: Alert
    detection: Dict[str, Any]  # MITRE techniques, patterns, playbooks
    rag_retrieval: Dict[str, Any]  # Similar incidents, threat intel
    behavioral_context: Dict[str, Any]  # Feature values, raw events
    llm_analysis: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "alert": {
                    "user_name": "bob-devops",
                    "window": "2026-02-27T11:35:00+00:00",
                    "ensemble_score": 0.8219,
                    "if_norm": 0.4929,
                    "lof_norm": 1.0,
                    "ae_norm": 0.9981,
                    "vote_count": 2,
                    "attack_name": "insider_threat",
                    "is_attack": True
                },
                "detection": {
                    "techniques": ["T1078", "T1530"],
                    "matched_patterns": ["Unusual IAM Role Assumption"],
                    "primary_playbooks": ["IR-IAM-001"]
                },
                "rag_retrieval": {
                    "similar_past_incidents": []
                },
                "behavioral_context": {
                    "total_events": 3,
                    "iam_write_events": 1
                }
            }
        }


# ── Statistics Models ──────────────────────────────────────────────────────

class OverviewStats(BaseModel):
    """High-level SOC dashboard statistics"""
    total_alerts: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    unique_users_affected: int
    attack_types: Dict[str, int]
    alerts_by_date: List[Dict[str, Any]]
    top_users: List[Dict[str, Any]]

    class Config:
        json_schema_extra = {
            "example": {
                "total_alerts": 235,
                "high_severity_count": 15,
                "medium_severity_count": 45,
                "low_severity_count": 175,
                "unique_users_affected": 4,
                "attack_types": {
                    "insider_threat": 6,
                    "data_exfiltration": 12,
                    "privilege_escalation": 1
                },
                "alerts_by_date": [
                    {"date": "2026-02-27", "count": 6}
                ],
                "top_users": [
                    {"user": "bob-devops", "alert_count": 6, "avg_score": 0.75}
                ]
            }
        }


class ModelPerformance(BaseModel):
    """ML model performance metrics"""
    model_name: str
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    false_positives: int
    false_negatives: int


# ── RAG Query Models ───────────────────────────────────────────────────────

class RAGQueryRequest(BaseModel):
    """Request body for RAG knowledge base queries"""
    query: str = Field(..., min_length=3, max_length=500)
    max_results: int = Field(default=5, ge=1, le=20)
    collection: Optional[str] = Field(default=None, description="behavioral_incidents or threat_intelligence")
    use_llm: bool = Field(default=True, description="Use LLM to synthesize results into explanation")

    class Config:
        json_schema_extra = {
            "example": {
                "query": "What are indicators of privilege escalation in AWS?",
                "max_results": 5,
                "collection": "threat_intelligence",
                "use_llm": True
            }
        }


class RAGQueryResult(BaseModel):
    """Single result from RAG query"""
    content: str
    metadata: Dict[str, Any]
    similarity: float


class RAGQueryResponse(BaseModel):
    """Response from RAG query"""
    query: str
    results: List[RAGQueryResult]
    collection: str
    explanation: Optional[str] = None  # LLM-generated synthesis of results


# ── Playbook Models ────────────────────────────────────────────────────────

class PlaybookStep(BaseModel):
    """Single containment/investigation step"""
    action: str
    cli: Optional[str] = None
    notes: Optional[str] = None


class Playbook(BaseModel):
    """Incident response playbook"""
    playbook_id: str
    name: str
    description: str
    severity: str
    triage_questions: List[str]
    investigation_steps: List[PlaybookStep]
    containment_steps: List[PlaybookStep]
    techniques_covered: List[str]


class PlaybookList(BaseModel):
    """List of available playbooks"""
    playbooks: List[Playbook]
    total: int
