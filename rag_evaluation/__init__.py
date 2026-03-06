"""
RAG Evaluation Module
=====================
Comprehensive evaluation framework for RAG-based SOC systems.

Modules:
  - metrics: Retrieval, generation, and RAG metrics
  - security_metrics: SOC-specific metrics
  - utils: Helper functions for data loading and aggregation
  - plots: Visualization utilities
  - evaluation_rag: Main evaluation pipeline
"""

__version__ = "1.0.0"
__author__ = "SOC Evaluation Team"

from rag_evaluation.metrics import (
    precision_at_k,
    recall_at_k,
    mean_reciprocal_rank,
    ndcg_at_k,
    faithfulness_score,
    answer_relevance,
    context_utilization,
    context_precision,
    context_recall,
)

from rag_evaluation.security_metrics import (
    incident_classification_accuracy,
    playbook_recommendation_accuracy,
    analyst_time_reduction,
)

from rag_evaluation.utils import (
    load_alerts_csv,
    load_incident_reports,
    extract_playbooks_from_report,
    extract_mitre_techniques,
    aggregate_metrics,
)

__all__ = [
    # Retrieval metrics
    "precision_at_k",
    "recall_at_k",
    "mean_reciprocal_rank",
    "ndcg_at_k",
    # Generation metrics
    "faithfulness_score",
    "answer_relevance",
    "context_utilization",
    # RAG metrics
    "context_precision",
    "context_recall",
    # Security metrics
    "incident_classification_accuracy",
    "playbook_recommendation_accuracy",
    "analyst_time_reduction",
    # Utilities
    "load_alerts_csv",
    "load_incident_reports",
    "extract_playbooks_from_report",
    "extract_mitre_techniques",
    "aggregate_metrics",
]
