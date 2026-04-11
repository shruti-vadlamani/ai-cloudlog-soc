"""
rag_evaluation/utils.py
=======================
Utility functions for data loading, parsing, and metric aggregation.
"""

import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

log = logging.getLogger("rag_evaluation.utils")

PROJECT_ROOT = Path(__file__).parent.parent


def load_alerts_csv(csv_path: Optional[str] = None) -> pd.DataFrame:
    """
    Load ensemble alerts CSV.
    
    Args:
        csv_path: Path to CSV file. Defaults to data/results/ensemble_alerts.csv
        
    Returns:
        DataFrame with alerts data
    """
    if csv_path is None:
        csv_path = PROJECT_ROOT / "data" / "results" / "ensemble_alerts.csv"
    
    csv_path = Path(csv_path)
    if not csv_path.exists():
        log.warning(f"Alerts CSV not found: {csv_path}")
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    log.info(f"Loaded {len(df)} alerts from {csv_path}")
    return df


def load_incident_reports(
    report_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Load all incident reports from directory.
    
    Args:
        report_dir: Directory containing incident_report_*.txt files.
                   Defaults to data/results/
        
    Returns:
        List of dictionaries with report metadata and content
    """
    if report_dir is None:
        report_dir = PROJECT_ROOT / "data" / "results"
    
    report_dir = Path(report_dir)
    if not report_dir.exists():
        log.warning(f"Report directory not found: {report_dir}")
        return []
    
    reports = []
    for report_file in sorted(report_dir.glob("incident_report_*.txt")):
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Parse timestamp from filename
            match = re.search(r"incident_report_(\d{8}_\d{6})", report_file.name)
            timestamp = match.group(1) if match else None
            
            reports.append({
                "file": report_file.name,
                "path": str(report_file),
                "timestamp": timestamp,
                "content": content,
            })
        except Exception as e:
            log.error(f"Error loading report {report_file}: {e}")
    
    log.info(f"Loaded {len(reports)} incident reports")
    return reports


def extract_playbooks_from_report(report_content: str) -> List[str]:
    """
    Extract playbook IDs from incident report text.

    Matches the IR-* format used throughout the system
    (e.g. IR-IAM-001, IR-DESTRUCT-001, IR-S3-002).

    Returns:
        List of unique playbook IDs
    """
    # Primary format used in this system: IR-<SERVICE>-<NUM>
    matches = re.findall(r"\bIR-[A-Z]+-\d+\b", report_content)
    return list(set(matches))


def extract_mitre_techniques(report_content: str) -> List[str]:
    """
    Extract MITRE ATT&CK technique IDs from incident report.
    
    Args:
        report_content: Full text of incident report
        
    Returns:
        List of MITRE technique IDs (e.g., T1098, T1133)
    """
    techniques = []
    
    # Match MITRE technique format: T followed by 4 digits
    pattern = r"\bT\d{4}\b"
    matches = re.findall(pattern, report_content)
    techniques.extend(matches)
    
    return list(set(techniques))  # Remove duplicates


def extract_severity_from_report(report_content: str) -> Optional[str]:
    """
    Extract incident severity level from report.
    
    Args:
        report_content: Full text of incident report
        
    Returns:
        Severity level (CRITICAL, HIGH, MEDIUM, LOW) or None
    """
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    for severity in severities:
        if severity in report_content.upper():
            return severity
    
    return None


def extract_recommendations_from_report(report_content: str) -> List[str]:
    """
    Extract recommended containment actions from report.
    
    Args:
        report_content: Full text of incident report
        
    Returns:
        List of recommended actions as text snippets
    """
    recommendations = []
    
    # Look for lines containing action keywords
    action_keywords = [
        "isolate", "terminate", "revoke", "disable", "block",
        "quarantine", "restore", "patch", "escalate", "notify"
    ]
    
    for line in report_content.split("\n"):
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in action_keywords):
            if line.strip() and len(line) > 10:
                recommendations.append(line.strip())
    
    return recommendations


def aggregate_metrics(
    retrieval_metrics: Dict[str, float],
    generation_metrics: Dict[str, float],
    rag_metrics: Dict[str, float],
    security_metrics: Dict[str, float],
) -> Dict[str, Any]:
    """
    Aggregate all metric categories into a single report.
    
    Args:
        retrieval_metrics: Dict with Precision@5, Recall@5, MRR, nDCG@5
        generation_metrics: Dict with Faithfulness, Answer Relevance, Context Util.
        rag_metrics: Dict with Context Precision, Context Recall
        security_metrics: Dict with Classification Acc., Playbook Acc., Time Reduction
        
    Returns:
        Aggregated report dictionary
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "retrieval_metrics": retrieval_metrics,
        "generation_metrics": generation_metrics,
        "rag_metrics": rag_metrics,
        "security_metrics": security_metrics,
        "summary": {
            "avg_retrieval_score": (
                sum(retrieval_metrics.values()) / len(retrieval_metrics)
                if retrieval_metrics else 0.0
            ),
            "avg_generation_score": (
                sum(generation_metrics.values()) / len(generation_metrics)
                if generation_metrics else 0.0
            ),
            "avg_rag_score": (
                sum(rag_metrics.values()) / len(rag_metrics)
                if rag_metrics else 0.0
            ),
            "avg_security_score": (
                sum(security_metrics.values()) / len(security_metrics)
                if security_metrics else 0.0
            ),
        },
    }
    
    # Overall system score (weighted average)
    scores = [
        report["summary"]["avg_retrieval_score"] * 0.20,
        report["summary"]["avg_generation_score"] * 0.25,
        report["summary"]["avg_rag_score"] * 0.25,
        report["summary"]["avg_security_score"] * 0.30,
    ]
    report["summary"]["overall_system_score"] = sum(scores)
    
    return report


def save_evaluation_report(
    report: Dict[str, Any],
    output_path: Optional[str] = None,
) -> str:
    """
    Save evaluation report to JSON file.
    
    Args:
        report: Aggregated metrics report
        output_path: Output file path. Defaults to data/results/rag_evaluation_report.json
        
    Returns:
        Path to saved report
    """
    if output_path is None:
        output_path = PROJECT_ROOT / "data" / "results" / "rag_evaluation_report.json"
    
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    
    log.info(f"Evaluation report saved to {output_path}")
    return str(output_path)


def load_evaluation_report(
    report_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Load previously saved evaluation report.
    
    Args:
        report_path: Path to report JSON file
        
    Returns:
        Report dictionary or None if not found
    """
    if report_path is None:
        report_path = PROJECT_ROOT / "data" / "results" / "rag_evaluation_report.json"
    
    report_path = Path(report_path)
    if not report_path.exists():
        log.warning(f"Report not found: {report_path}")
        return None
    
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    
    log.info(f"Loaded evaluation report from {report_path}")
    return report
