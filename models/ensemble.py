"""
models/ensemble.py
==================
Combines Isolation Forest, LOF, and Autoencoder into a final
ensemble anomaly detector using score-level fusion.

Fusion strategy: weighted average of normalized anomaly scores.
Each model's scores are normalized to [0, 1] then averaged with
weights tuned to each model's strengths:

  IF weight  = 0.35  (global outliers — privilege escalation, insider threat)
  LOF weight = 0.35  (local behavioral deviations — recon, backdoor)
  AE weight  = 0.30  (temporal pattern drift — data exfiltration)

The ensemble score is continuous. A window is flagged as an attack
if the ensemble score exceeds a tuned threshold.

This is your final production detector. Individual model scores
are preserved as features for the RAG retrieval layer — the alert
payload includes which models fired and by how much, giving the
RAG context for more targeted playbook retrieval.

Run AFTER training all three individual models:
    python models/isolation_forest.py
    python models/lof_model.py
    python models/autoencoder.py
    python models/ensemble.py

Output:
    data/results/ensemble_results.json
    data/models/ensemble_scores.csv   ← full score table for all windows
    data/results/ensemble_alerts.csv  ← flagged windows with context
"""

import json
import logging
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.model_utils import (
    load_feature_matrix,
    evaluate,
    save_results,
    compare_models,
    ATTACK_NAMES,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ensemble")

# Model weights (must sum to 1.0)
WEIGHTS = {
    "if": 0.35,
    "lof": 0.35,
    "ae": 0.30,
}


def _normalize_scores(scores: np.ndarray) -> np.ndarray:
    """Min-max normalize scores to [0, 1]."""
    s_min, s_max = scores.min(), scores.max()
    if s_max == s_min:
        return np.zeros_like(scores)
    return (scores - s_min) / (s_max - s_min)


def _load_score_file(path: str, score_col: str, pred_col: str) -> pd.DataFrame:
    """Load a per-window score CSV from individual model output."""
    p = Path(path)
    if not p.exists():
        # Map score file names to model file names
        model_map = {'ae_scores': 'autoencoder', 'if_scores': 'isolation_forest', 'lof_scores': 'lof_model'}
        model_name = model_map.get(p.stem, p.stem.replace('_scores',''))
        raise FileNotFoundError(
            f"Score file not found: {path}\n"
            f"Train the model first: python models/{model_name}.py"
        )
    df = pd.read_csv(path)
    df["window"] = pd.to_datetime(df["window"], utc=True)
    return df[["user_name", "window", score_col, pred_col]]


def run_ensemble(
    if_weight: float = WEIGHTS["if"],
    lof_weight: float = WEIGHTS["lof"],
    ae_weight: float = WEIGHTS["ae"],
    tune_threshold: bool = True,
) -> dict:
    """
    Load individual model scores, fuse them, evaluate, and save results.
    """
    log.info("Loading individual model scores...")

    # Load scores from each model
    if_df = _load_score_file("data/models/if_scores.csv", "if_score", "if_pred")
    lof_df = _load_score_file("data/models/lof_scores.csv", "lof_score", "lof_pred")
    ae_df = _load_score_file("data/models/ae_scores.csv", "ae_score", "ae_pred")

    # Merge all scores on (user_name, window)
    merged = if_df.merge(lof_df, on=["user_name", "window"], how="inner")
    merged = merged.merge(ae_df, on=["user_name", "window"], how="inner")
    log.info(f"Merged score table: {len(merged)} windows")

    # Normalize each model's scores to [0, 1]
    merged["if_norm"] = _normalize_scores(merged["if_score"].values)
    merged["lof_norm"] = _normalize_scores(merged["lof_score"].values)
    merged["ae_norm"] = _normalize_scores(merged["ae_score"].values)

    # Weighted ensemble score
    merged["ensemble_score"] = (
        if_weight * merged["if_norm"]
        + lof_weight * merged["lof_norm"]
        + ae_weight * merged["ae_norm"]
    )

    # Majority vote (secondary signal — not primary decision maker)
    merged["vote_count"] = merged["if_pred"] + merged["lof_pred"] + merged["ae_pred"]
    merged["majority_vote"] = (merged["vote_count"] >= 2).astype(int)

    # Load ground truth labels from feature matrix to evaluate
    df = load_feature_matrix()
    if "is_attack" in df.columns:
        label_df = df[["user_name", "window", "is_attack", "attack_id", "attack_name"]].copy()
        label_df["window"] = pd.to_datetime(label_df["window"], utc=True)
        merged = merged.merge(label_df, on=["user_name", "window"], how="left")
        merged["is_attack"] = merged["is_attack"].fillna(False)
        merged["attack_id"] = merged["attack_id"].fillna(0).astype(int)
        merged["attack_name"] = merged["attack_name"].fillna("normal")

        y_true = merged["is_attack"].astype(int).values
        y_multi = merged["attack_id"].values

        # Tune threshold on ensemble score
        if tune_threshold:
            from sklearn.metrics import f1_score
            best_f1, best_thresh = -1, 0.5
            for p in [80, 82, 85, 87, 89, 90, 91, 92, 93, 95, 97]:
                thresh = np.percentile(merged["ensemble_score"].values, p)
                y_pred = (merged["ensemble_score"].values >= thresh).astype(int)
                f1 = f1_score(y_true, y_pred, zero_division=0)
                if f1 > best_f1:
                    best_f1, best_thresh = f1, thresh
            log.info(f"Best ensemble threshold: {best_thresh:.4f} (F1={best_f1:.4f})")
        else:
            best_thresh = np.percentile(merged["ensemble_score"].values, 90)

        y_pred = (merged["ensemble_score"].values >= best_thresh).astype(int)
        merged["ensemble_pred"] = y_pred

        results = evaluate(y_true, y_pred, merged["ensemble_score"].values, y_multi, "Ensemble")
        results["weights"] = {"if": if_weight, "lof": lof_weight, "ae": ae_weight}
        results["threshold"] = float(best_thresh)

    else:
        log.warning("No labels found — running in unlabeled (production) mode")
        best_thresh = np.percentile(merged["ensemble_score"].values, 90)
        y_pred = (merged["ensemble_score"].values >= best_thresh).astype(int)
        merged["ensemble_pred"] = y_pred
        results = {"model": "Ensemble", "note": "Unlabeled — no evaluation metrics"}

    # ── Save full score table ──────────────────────────────────────────────────
    Path("data/models").mkdir(parents=True, exist_ok=True)
    score_cols = [
        "user_name", "window",
        "if_score", "lof_score", "ae_score",
        "if_norm", "lof_norm", "ae_norm",
        "ensemble_score", "if_pred", "lof_pred", "ae_pred",
        "vote_count", "majority_vote", "ensemble_pred",
    ]
    if "is_attack" in merged.columns:
        score_cols += ["is_attack", "attack_id", "attack_name"]

    merged[score_cols].to_csv("data/models/ensemble_scores.csv", index=False)
    log.info("Full score table saved to data/models/ensemble_scores.csv")

    # ── Save alert table (flagged windows only) ────────────────────────────────
    alerts = merged[merged["ensemble_pred"] == 1].copy()
    alerts = alerts.sort_values("ensemble_score", ascending=False)

    alert_cols = [
        "user_name", "window", "ensemble_score",
        "if_norm", "lof_norm", "ae_norm",
        "vote_count",
    ]
    if "attack_name" in alerts.columns:
        alert_cols += ["attack_name", "is_attack"]

    Path("data/results").mkdir(parents=True, exist_ok=True)
    alerts[alert_cols].to_csv("data/results/ensemble_alerts.csv", index=False)
    log.info(f"Alert table saved: {len(alerts)} flagged windows → data/results/ensemble_alerts.csv")

    save_results(results, "ensemble")

    # ── Print which models fired on each attack type ───────────────────────────
    if "attack_id" in merged.columns:
        _print_model_coverage(merged)

    return results


def _print_model_coverage(merged: pd.DataFrame) -> None:
    """Print per-attack breakdown of which models caught what."""
    print("\n" + "="*65)
    print("PER-ATTACK MODEL COVERAGE")
    print("="*65)
    print(f"{'Attack':<25} {'IF':>6} {'LOF':>6} {'AE':>6} {'Ensemble':>9}")
    print("-"*65)

    for attack_id, attack_name in ATTACK_NAMES.items():
        if attack_id == 0:
            continue
        mask = merged["attack_id"] == attack_id
        if mask.sum() == 0:
            continue
        subset = merged[mask]
        total = len(subset)

        def rate(col):
            return f"{subset[col].sum()}/{total}"

        print(
            f"  {attack_name:<23} "
            f"{rate('if_pred'):>6} "
            f"{rate('lof_pred'):>6} "
            f"{rate('ae_pred'):>6} "
            f"{rate('ensemble_pred'):>9}"
        )

    print("="*65 + "\n")


def generate_alert_payload(row: pd.Series) -> dict:
    """
    Generate a structured alert payload for a flagged window.
    This is what gets sent to the RAG retrieval layer.

    The RAG layer uses this to retrieve:
      - Similar past incidents from ChromaDB
      - Relevant MITRE ATT&CK techniques
      - Recommended response playbooks
    """
    # Determine which models fired
    models_fired = []
    if row.get("if_pred", 0):
        models_fired.append(f"IsolationForest(score={row.get('if_norm', 0):.3f})")
    if row.get("lof_pred", 0):
        models_fired.append(f"LOF(score={row.get('lof_norm', 0):.3f})")
    if row.get("ae_pred", 0):
        models_fired.append(f"Autoencoder(score={row.get('ae_norm', 0):.3f})")

    return {
        "alert_id": f"{row.get('user_name', 'u')}_{row.get('window', '')}",
        "timestamp": str(row.get("window", "")),
        "user": row.get("user_name", "unknown"),
        "ensemble_score": float(row.get("ensemble_score", 0)),
        "vote_count": int(row.get("vote_count", 0)),
        "models_fired": models_fired,
        "severity": (
            "critical" if row.get("ensemble_score", 0) > 0.85
            else "high" if row.get("ensemble_score", 0) > 0.70
            else "medium"
        ),
        # RAG retrieval query — embed this to find similar incidents + playbooks
        "rag_query": (
            f"User {row.get('user_name', 'unknown')} anomalous behavior: "
            f"ensemble score {row.get('ensemble_score', 0):.3f}, "
            f"models: {', '.join(models_fired) if models_fired else 'none'}. "
            f"IF={row.get('if_norm',0):.3f} LOF={row.get('lof_norm',0):.3f} "
            f"AE={row.get('ae_norm',0):.3f}."
        ),
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--if-weight", type=float, default=0.35)
    parser.add_argument("--lof-weight", type=float, default=0.35)
    parser.add_argument("--ae-weight", type=float, default=0.30)
    parser.add_argument("--no-tune", action="store_true")
    args = parser.parse_args()

    results = run_ensemble(
        if_weight=args.if_weight,
        lof_weight=args.lof_weight,
        ae_weight=args.ae_weight,
        tune_threshold=not args.no_tune,
    )

    print("\nRunning full model comparison...")
    compare_models()
