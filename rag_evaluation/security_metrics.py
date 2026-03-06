"""
rag_evaluation/security_metrics.py
===================================
SOC-specific evaluation metrics for security operations.
"""

import logging
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

log = logging.getLogger("rag_evaluation.security_metrics")


def incident_classification_accuracy(
    predicted_attacks: List[str],
    ground_truth_attacks: List[str],
) -> float:
    """
    Compute Incident Classification Accuracy.
    
    Percentage of incidents correctly classified as their attack type.
    
    Args:
        predicted_attacks: Predicted attack types/IDs
        ground_truth_attacks: Ground truth attack types/IDs
        
    Returns:
        Accuracy [0, 1]
    """
    if not predicted_attacks or len(predicted_attacks) != len(ground_truth_attacks):
        return 0.0
    
    correct = sum(
        1 for pred, truth in zip(predicted_attacks, ground_truth_attacks)
        if pred.lower() == truth.lower()
    )
    
    accuracy = correct / len(predicted_attacks)
    return float(np.clip(accuracy, 0.0, 1.0))


def playbook_recommendation_accuracy(
    predicted_playbooks: List[List[str]],
    ground_truth_playbooks: List[List[str]],
) -> float:
    """
    Compute Playbook Recommendation Accuracy.
    
    Percentage of incidents with correct playbook recommendations.
    Uses set-based matching (any predicted playbook in ground truth = match).
    
    Args:
        predicted_playbooks: List of predicted playbook sets per incident
        ground_truth_playbooks: List of ground truth playbook sets per incident
        
    Returns:
        Accuracy [0, 1]
    """
    if (
        not predicted_playbooks
        or len(predicted_playbooks) != len(ground_truth_playbooks)
    ):
        return 0.0
    
    matches = 0
    for pred_set, truth_set in zip(predicted_playbooks, ground_truth_playbooks):
        pred_set = set(str(p).lower() for p in pred_set)
        truth_set = set(str(t).lower() for t in truth_set)
        
        # Match if at least one predicted playbook is correct
        if pred_set & truth_set:
            matches += 1
    
    accuracy = matches / len(predicted_playbooks)
    return float(np.clip(accuracy, 0.0, 1.0))


def analyst_time_reduction(
    manual_triage_time_minutes: float,
    automated_pipeline_time_minutes: float,
) -> float:
    """
    Compute Analyst Time Reduction.
    
    Percentage time saved by automated RAG pipeline vs manual triage.
    
    Args:
        manual_triage_time_minutes: Estimated manual triage time
        automated_pipeline_time_minutes: Actual automated pipeline time
        
    Returns:
        Time reduction percentage [0, 1]. 0.5 = 50% faster
    """
    if manual_triage_time_minutes <= 0:
        return 0.0
    
    time_saved = manual_triage_time_minutes - automated_pipeline_time_minutes
    reduction = time_saved / manual_triage_time_minutes
    
    return float(np.clip(reduction, 0.0, 1.0))


def detection_rate(
    true_positives: int,
    false_negatives: int,
) -> float:
    """
    Compute Detection Rate (Sensitivity/Recall).
    
    Percentage of actual attacks correctly detected.
    
    Args:
        true_positives: Count of correctly detected attacks
        false_negatives: Count of missed attacks
        
    Returns:
        Detection rate [0, 1]
    """
    total_actual = true_positives + false_negatives
    if total_actual == 0:
        return 0.0
    
    detection_rate_score = true_positives / total_actual
    return float(np.clip(detection_rate_score, 0.0, 1.0))


def false_positive_rate(
    false_positives: int,
    true_negatives: int,
) -> float:
    """
    Compute False Positive Rate.
    
    Percentage of normal events incorrectly flagged as threats.
    
    Args:
        false_positives: Count of normal events flagged as threats
        true_negatives: Count of correctly identified normal events
        
    Returns:
        False positive rate [0, 1]. Lower is better.
    """
    total_negative = false_positives + true_negatives
    if total_negative == 0:
        return 0.0
    
    fpr = false_positives / total_negative
    return float(np.clip(fpr, 0.0, 1.0))


def precision(true_positives: int, false_positives: int) -> float:
    """
    Compute Precision: fraction of alerts that are true attacks.
    
    Args:
        true_positives: Count of correctly detected attacks
        false_positives: Count of false alerts
        
    Returns:
        Precision [0, 1]
    """
    total_positives = true_positives + false_positives
    if total_positives == 0:
        return 0.0
    
    precision_score = true_positives / total_positives
    return float(np.clip(precision_score, 0.0, 1.0))


def f1_score(
    true_positives: int,
    false_positives: int,
    false_negatives: int,
) -> float:
    """
    Compute F1 Score: harmonic mean of precision and recall.
    
    Args:
        true_positives: Count of correctly detected attacks
        false_positives: Count of false alerts
        false_negatives: Count of missed attacks
        
    Returns:
        F1 score [0, 1]
    """
    recall = detection_rate(true_positives, false_negatives)
    prec = precision(true_positives, false_positives)
    
    if recall + prec == 0:
        return 0.0
    
    f1 = 2 * (prec * recall) / (prec + recall)
    return float(np.clip(f1, 0.0, 1.0))


def mean_time_to_detect(detection_times_minutes: List[float]) -> float:
    """
    Compute Mean Time to Detect (MTTD) in minutes.
    
    Args:
        detection_times_minutes: List of times from attack start to detection
        
    Returns:
        Mean detection time in minutes
    """
    if not detection_times_minutes:
        return float("inf")
    
    return float(np.mean(detection_times_minutes))


def mean_time_to_contain(containment_times_minutes: List[float]) -> float:
    """
    Compute Mean Time to Contain (MTTC) in minutes.
    
    Args:
        containment_times_minutes: List of times from detection to containment
        
    Returns:
        Mean containment time in minutes
    """
    if not containment_times_minutes:
        return float("inf")
    
    return float(np.mean(containment_times_minutes))


def incidents_per_analyst(
    total_incidents: int,
    num_analysts: int,
) -> float:
    """
    Compute incident load per analyst.
    
    Args:
        total_incidents: Total incidents in evaluation period
        num_analysts: Number of analysts in SOC
        
    Returns:
        Average incidents per analyst
    """
    if num_analysts <= 0:
        return 0.0
    
    return float(total_incidents / num_analysts)


def soc_efficiency_score(
    precision_score: float,
    recall_score: float,
    analyst_reduction: float,
    time_to_detect_minutes: float,
) -> float:
    """
    Compute overall SOC Efficiency Score.
    
    Weighted combination of detection quality and operational efficiency.
    
    Args:
        precision_score: Alert precision [0, 1]
        recall_score: Detection recall [0, 1]
        analyst_reduction: Time saved percentage [0, 1]
        time_to_detect_minutes: MTTD in minutes (normalized by 30-minute target)
        
    Returns:
        SOC Efficiency Score [0, 1]
    """
    # Normalize MTTD (target = 30 minutes for critical threats)
    mttd_score = 1.0 - min(time_to_detect_minutes / 30.0, 1.0)
    
    # Weighted average
    efficiency = (
        0.25 * precision_score +
        0.35 * recall_score +
        0.20 * analyst_reduction +
        0.20 * mttd_score
    )
    
    return float(np.clip(efficiency, 0.0, 1.0))


def compute_confusion_matrix_metrics(
    y_true: List[int],
    y_pred: List[int],
) -> Dict[str, float]:
    """
    Compute all confusion matrix-based metrics.
    
    Args:
        y_true: True labels (0=normal, 1=attack)
        y_pred: Predicted labels (0=normal, 1=attack)
        
    Returns:
        Dictionary with TP, TN, FP, FN, Precision, Recall, F1, Accuracy
    """
    if len(y_true) != len(y_pred):
        return {}
    
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    
    prec = precision(tp, fp)
    rec = detection_rate(tp, fn)
    f1 = f1_score(tp, fp, fn)
    acc = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    
    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "accuracy": float(acc),
        "fpr": float(false_positive_rate(fp, tn)),
        "specificity": float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0,
    }
