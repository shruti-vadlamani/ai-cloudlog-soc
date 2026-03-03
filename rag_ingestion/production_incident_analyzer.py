#!/usr/bin/env python3
"""
rag_ingestion/production_incident_analyzer.py
===============================================
Final step of the RAG pipeline. Reads flagged alerts from
ensemble_alerts.csv, enriches each via AlertEnricher (Neo4j + ChromaDB),
then calls Ollama phi3.5 to generate a human-readable incident report.

Run AFTER:
  1. python run_pipeline.py         (generates feature matrix)
  2. python run_models.py           (generates ensemble_alerts.csv)
  3. python rag_ingestion/ingest_vector_db.py
  4. python rag_ingestion/ingest_knowledge_graph.py

Usage:
  python rag_ingestion/production_incident_analyzer.py
  python rag_ingestion/production_incident_analyzer.py --num-events 10
  python rag_ingestion/production_incident_analyzer.py --csv data/results/ensemble_alerts.csv
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

PROJECT_ROOT = Path(__file__).parent.parent

from rag_ingestion.alert_enrichment import AlertEnricher, load_data

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("incident_analyzer")

OLLAMA_MODEL = "phi3.5:3.8b"
CHROMA_PATH = str(PROJECT_ROOT / "chroma_db")


# ── LLM Handler ───────────────────────────────────────────────────────────────

class LLMHandler:
    def __init__(self, model: str = OLLAMA_MODEL):
        self.model = model
        self.available = False
        self._init()

    def _init(self):
        try:
            import ollama
            self._ollama = ollama
            models = ollama.list()
            names = [m.model for m in models.models]
            if self.model not in names:
                log.warning(f"Model '{self.model}' not in Ollama. Available: {names}")
                log.warning("Run: ollama pull phi3.5:3.8b")
                return
            self.available = True
            log.info(f"✅ Ollama {self.model} ready")
        except ImportError:
            log.warning("ollama package not installed: pip install ollama")
        except Exception as e:
            log.warning(f"Ollama unavailable: {e}. Run: ollama serve")

    def generate(self, prompt: str) -> Optional[str]:
        if not self.available:
            return None
        try:
            response = self._ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.3,   # Lower temp for more consistent security analysis
                    "top_p": 0.9,
                    "num_ctx": 2048,      # phi3.5 context limit
                    "num_predict": 500,   # Keep response focused
                }
            )
            return response["message"]["content"]
        except Exception as e:
            log.error(f"Ollama call failed: {e}")
            return None


# ── Prompt Builder ────────────────────────────────────────────────────────────

def build_llm_prompt(payload: Dict) -> str:
    """
    Build a concise, structured prompt for phi3.5.
    Kept under ~1500 tokens to stay within phi3.5's num_ctx=2048.
    """
    alert = payload["alert"]
    detection = payload["detection"]
    rag = payload["rag_retrieval"]
    behavior = payload["behavioral_context"]

    # Techniques — compact
    techniques_str = "\n".join([
        f"  - {t['technique_id']}: {t['name']} [{', '.join(t.get('tactics', []))}]"
        for t in detection.get("techniques", [])[:3]
    ]) or "  - None matched"

    # Patterns — compact
    patterns_str = "\n".join([
        f"  - [{p['severity']}] {p['name']} (match={p['match_score']})"
        for p in detection.get("matched_patterns", [])[:3]
    ]) or "  - None matched"

    # Playbook triage questions — most useful for phi3.5 to reason from
    triage_str = ""
    for pb in detection.get("primary_playbooks", [])[:1]:
        qs = pb.get("triage_questions", [])[:3]
        if qs:
            triage_str = "\nTRIAGE QUESTIONS:\n" + "\n".join(f"  Q: {q}" for q in qs)

    # Containment — show top 2 actions
    containment_str = ""
    for pb in detection.get("primary_playbooks", [])[:1]:
        steps = pb.get("containment_steps", [])[:2]
        if steps:
            actions = []
            for step in steps:
                if isinstance(step, dict):
                    actions.append(f"  - {step.get('action', '')} → {step.get('cli', '')[:80]}")
                else:
                    actions.append(f"  - {str(step)[:100]}")
            containment_str = "\nCONTAINMENT ACTIONS:\n" + "\n".join(actions)

    # Chain playbooks — proactive
    chain_str = ""
    if detection.get("chain_playbooks"):
        chain_str = "\nATTACK CHAIN (likely next steps):\n" + "\n".join([
            f"  - {pb['chain_reason']}"
            for pb in detection["chain_playbooks"][:2]
        ])

    # Similar incidents
    similar_str = ""
    if rag.get("similar_past_incidents"):
        similar_str = "\nSIMILAR PAST INCIDENTS:\n" + "\n".join([
            f"  - {inc['attack_name']} (similarity={inc['similarity']}): {inc['summary'][:120]}"
            for inc in rag["similar_past_incidents"][:2]
        ])

    # Key behavioral signals
    features = behavior.get("feature_values", {})
    notable = []
    for col, val in features.items():
        if "zscore" in col and abs(val) > 2.0:
            notable.append(f"{col}={val:.1f}")
        elif col == "after_hours_ratio" and val > 0.3:
            notable.append(f"after_hours={val:.2f}")
        elif col == "s3_get_slope_3d" and abs(val) > 3:
            notable.append(f"s3_3day_slope={val:.1f}")
    signals_str = ", ".join(notable[:5]) or "No extreme signals"

    event_ctx = behavior.get("event_context", {})
    top_events = list(event_ctx.get("event_counts", {}).items())[:5]
    events_str = ", ".join([f"{e[0]}×{e[1]}" for e in top_events]) or "unavailable"

    prompt = f"""You are a senior AWS cloud security analyst. Analyze this anomaly detection alert concisely.

ALERT:
  User: {alert['user']}
  Time Window: {alert['window']}
  Severity: {alert['severity']}
  Ensemble Score: {alert['ensemble_score']} (1.0 = most anomalous)
  Models Fired: {', '.join(alert['models_fired']) or 'none'}
  Vote Count: {alert['vote_count']}/3

BEHAVIORAL SIGNALS:
  Key anomalies: {signals_str}
  Events observed: {events_str}
  Error rate: {event_ctx.get('error_rate', 0):.1%}

MITRE ATT&CK:
{techniques_str}

DETECTION PATTERNS MATCHED:
{patterns_str}
{triage_str}
{containment_str}
{chain_str}
{similar_str}

Provide a concise security analysis with:
1. Most likely attack classification and reasoning (2-3 sentences)
2. Top 3 immediate actions for the analyst
3. Key investigation questions to confirm or rule out false positive
4. Risk if unaddressed (1 sentence)

Be specific to AWS. Keep response under 400 words."""

    return prompt


# ── Report Generator ──────────────────────────────────────────────────────────

def generate_report(results: List[Dict], elapsed: float) -> str:
    lines = []
    lines.append("=" * 90)
    lines.append("SOC AUTOMATED INCIDENT ANALYSIS REPORT")
    lines.append("=" * 90)
    lines.append(f"Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Duration:   {elapsed:.1f}s")
    lines.append(f"Alerts:     {len(results)}")
    lines.append("=" * 90)

    for idx, r in enumerate(results, 1):
        alert = r["payload"]["alert"]
        detection = r["payload"]["detection"]

        lines.append(f"\n{'='*90}")
        lines.append(
            f"INCIDENT #{idx} | {alert['severity']} | "
            f"User: {alert['user']} | Score: {alert['ensemble_score']}"
        )
        lines.append(f"Window: {alert['window']}")
        lines.append(f"Models fired: {', '.join(alert['models_fired']) or 'none'}")
        lines.append("─" * 90)

        # Detection summary
        if detection.get("techniques"):
            lines.append("MITRE TECHNIQUES:")
            for t in detection["techniques"][:3]:
                lines.append(f"  {t['technique_id']}: {t['name']} [{', '.join(t.get('tactics', []))}]")

        if detection.get("matched_patterns"):
            lines.append("DETECTION PATTERNS:")
            for p in detection["matched_patterns"][:3]:
                lines.append(f"  [{p['severity']}] {p['name']} | match={p['match_score']} | {p['match_reason']}")

        if detection.get("primary_playbooks"):
            lines.append("PLAYBOOKS TRIGGERED:")
            for pb in detection["primary_playbooks"][:3]:
                lines.append(f"  {pb['playbook_id']}: {pb['name']}")

        if detection.get("chain_playbooks"):
            lines.append("ATTACK CHAIN (proactive):")
            for pb in detection["chain_playbooks"]:
                lines.append(f"  {pb['playbook_id']}: {pb['chain_reason']}")

        similar = r["payload"]["rag_retrieval"].get("similar_past_incidents", [])
        if similar:
            lines.append("SIMILAR PAST INCIDENTS:")
            for inc in similar[:2]:
                lines.append(f"  [{inc['attack_name']}] similarity={inc['similarity']}: {inc['summary'][:100]}")

        lines.append("─" * 90)
        lines.append("LLM ANALYSIS:")
        lines.append(r.get("llm_analysis") or "(LLM unavailable — enable Ollama: ollama serve && ollama pull phi3.5:3.8b)")
        lines.append("")

    return "\n".join(lines)


# ── Main Pipeline ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Incident Analyzer")
    parser.add_argument("--num-events", type=int, default=5, help="Number of top alerts to analyze")
    parser.add_argument("--csv", type=str, default="data/results/ensemble_alerts.csv")
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("SOC INCIDENT ANALYSIS PIPELINE")
    log.info("=" * 60)

    # ── Connect to databases ──────────────────────────────────────────────────
    import chromadb
    from neo4j import GraphDatabase
    from sentence_transformers import SentenceTransformer

    neo4j_uri = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASSWORD", "neo4j1234")

    log.info("Connecting to Neo4j...")
    try:
        driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        with driver.session() as s:
            count = s.run("MATCH (n) RETURN count(n) as c").single()["c"]
        log.info(f"✅ Neo4j: {count} nodes")
    except Exception as e:
        log.error(f"Neo4j connection failed: {e}")
        log.error("Start Neo4j: docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/neo4j1234 neo4j:latest")
        sys.exit(1)

    log.info("Connecting to ChromaDB...")
    try:
        chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
        cols = [c.name for c in chroma_client.list_collections()]
        log.info(f"✅ ChromaDB collections: {cols}")
    except Exception as e:
        log.error(f"ChromaDB connection failed: {e}")
        sys.exit(1)

    log.info("Loading sentence embedder...")
    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    log.info("✅ Embedder ready")

    llm = LLMHandler()
    enricher = AlertEnricher(driver, chroma_client, embedder)

    # ── Load data ─────────────────────────────────────────────────────────────
    log.info("Loading feature matrix and normalized events...")
    feature_df, normalized_df, alerts_df = load_data()

    # Override alerts CSV if specified
    if args.csv != "data/results/ensemble_alerts.csv" and Path(args.csv).exists():
        alerts_df = pd.read_csv(args.csv)
        alerts_df["window"] = pd.to_datetime(alerts_df["window"], utc=True)

    top_alerts = alerts_df.nlargest(args.num_events, "ensemble_score")
    log.info(f"Analyzing top {len(top_alerts)} alerts (of {len(alerts_df)} total flagged)")

    # ── Process alerts ────────────────────────────────────────────────────────
    results = []
    start = time.time()

    for idx, (_, row) in enumerate(top_alerts.iterrows(), 1):
        log.info(f"\nAlert {idx}/{len(top_alerts)}: {row.get('user_name')} | score={row.get('ensemble_score', 0):.3f}")

        # Enrich with RAG
        payload = enricher.enrich(row, feature_df, normalized_df)

        # Generate LLM analysis
        prompt = build_llm_prompt(payload)
        llm_analysis = llm.generate(prompt)

        if llm_analysis:
            log.info(f"  ✅ LLM analysis generated ({len(llm_analysis)} chars)")
        else:
            log.info("  ⚠️  LLM unavailable — database results only")

        results.append({
            "payload": payload,
            "llm_analysis": llm_analysis,
            "prompt": prompt,
        })

    elapsed = time.time() - start

    # ── Generate and save report ──────────────────────────────────────────────
    report = generate_report(results, elapsed)

    if not args.output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"data/results/incident_report_{ts}.txt"

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    log.info(f"\n✅ Report saved: {args.output}")
    log.info(f"⏱  Total time: {elapsed:.1f}s")

    driver.close()


if __name__ == "__main__":
    main()
