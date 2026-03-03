#!/usr/bin/env python3
"""
rag_ingestion/ingest_vector_db.py
===================================
Ingests two distinct document types into ChromaDB:

Collection 1 — "behavioral_incidents"
  Source: data/features/feature_matrix.csv.gz (attack windows only)
  Method: build_window_summary_text() → natural language per window
  Purpose: "Find me past incidents that looked like this"

Collection 2 — "threat_intelligence"
  Source: knowledge_base/*.json
  Method: embed_description / description fields per document
  Purpose: "Find MITRE techniques, patterns, playbooks for this alert"

Run AFTER run_pipeline.py has produced the feature matrix.
Run BEFORE production_incident_analyzer.py.
"""

import json
import logging
import sys
import os
from pathlib import Path

import pandas as pd
import chromadb
from sentence_transformers import SentenceTransformer

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from rag_ingestion.parquet_to_rag import build_window_summary_text, ingest_to_chromadb

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ingest_vector_db")

# Get project root directory (parent of rag_ingestion)
PROJECT_ROOT = Path(__file__).parent.parent
CHROMA_PATH = PROJECT_ROOT / "chroma_db"
KB_DIR = PROJECT_ROOT / "knowledge_base"
FEATURE_MATRIX_PATH = PROJECT_ROOT / "data/features/feature_matrix.csv.gz"
FEATURE_MATRIX_PARQUET = PROJECT_ROOT / "data/features/feature_matrix.parquet"


def load_feature_matrix() -> pd.DataFrame:
    """Load feature matrix — parquet preferred, csv.gz fallback."""
    if FEATURE_MATRIX_PARQUET.exists():
        df = pd.read_parquet(FEATURE_MATRIX_PARQUET)
    elif FEATURE_MATRIX_PATH.exists():
        df = pd.read_csv(FEATURE_MATRIX_PATH, compression="gzip")
        if "window" in df.columns:
            df["window"] = pd.to_datetime(df["window"], utc=True)
    else:
        raise FileNotFoundError(
            "Feature matrix not found. Run: python run_pipeline.py --stage features"
        )
    log.info(f"Loaded feature matrix: {df.shape}")
    return df


def ingest_behavioral_incidents(client: chromadb.ClientAPI, embedder: SentenceTransformer):
    """
    Ingest labeled attack windows from the feature matrix as
    'past incident' documents. These are what get retrieved when
    the analyzer asks 'find me similar past incidents.'

    Uses build_window_summary_text() from parquet_to_rag.py to
    convert each feature row to natural language before embedding.
    """
    log.info("Loading feature matrix for behavioral incident ingestion...")
    df = load_feature_matrix()

    # Only ingest attack windows as known incidents
    if "is_attack" in df.columns:
        attack_df = df[df["is_attack"] == True].copy()
        log.info(f"Attack windows found: {len(attack_df)} (out of {len(df)} total)")
    else:
        log.warning("No 'is_attack' column found — ingesting all windows")
        attack_df = df.copy()

    if attack_df.empty:
        log.warning("No attack windows to ingest. Skipping behavioral incidents.")
        return

    # Recreate collection fresh
    try:
        client.delete_collection("behavioral_incidents")
    except Exception:
        pass
    collection = client.create_collection(
        "behavioral_incidents",
        metadata={"hnsw:space": "cosine"}
    )

    documents, ids, embeddings, metadatas = [], [], [], []

    for idx, row in attack_df.iterrows():
        text = build_window_summary_text(row)

        user = str(row.get("user_name", "unknown"))
        window = str(row.get("window", idx))
        attack_name = str(row.get("attack_name", "unknown"))
        attack_id = int(row.get("attack_id", 0))

        doc_id = f"inc_{user}_{window}".replace(" ", "_").replace(":", "-")[:128]

        documents.append(text)
        ids.append(doc_id)
        embeddings.append(embedder.encode(text).tolist())
        metadatas.append({
            "user_name": user,
            "window": window,
            "attack_name": attack_name,
            "attack_id": attack_id,
            "is_attack": True,
            "total_events": float(row.get("total_events", 0)),
            "s3_get_events": float(row.get("s3_get_events", 0)),
            "iam_write_events": float(row.get("iam_write_events", 0)),
            "iam_list_events": float(row.get("iam_list_events", 0)),
            "s3_delete_events": float(row.get("s3_delete_events", 0)),
            "total_events_zscore": float(row.get("total_events_zscore", 0)),
            "s3_get_slope_3d": float(row.get("s3_get_slope_3d", 0)),
            "after_hours_ratio": float(row.get("after_hours_ratio", 0)),
        })

    # Batch upsert
    batch_size = 50
    for i in range(0, len(documents), batch_size):
        collection.add(
            documents=documents[i:i+batch_size],
            ids=ids[i:i+batch_size],
            embeddings=embeddings[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size],
        )

    log.info(f"✅ Behavioral incidents ingested: {len(documents)} attack windows → 'behavioral_incidents'")


def ingest_knowledge_base(client: chromadb.ClientAPI, embedder: SentenceTransformer):
    """
    Ingest knowledge base JSON files into 'threat_intelligence' collection.
    Uses embedding_description if available (richer), falls back to description.
    """
    try:
        client.delete_collection("threat_intelligence")
    except Exception:
        pass
    collection = client.create_collection(
        "threat_intelligence",
        metadata={"hnsw:space": "cosine"}
    )

    documents, ids, embeddings, metadatas = [], [], [], []
    doc_counter = 0

    # ── MITRE Techniques ──────────────────────────────────────────────────────
    mitre_path = KB_DIR / "mitre_techniques.json"
    if mitre_path.exists():
        with open(mitre_path, encoding='utf-8') as f:
            techniques = json.load(f)

        for tech in techniques:
            tech_id = tech.get("technique_id", "")
            if not tech_id:
                continue

            name = tech.get("name", "")
            description = tech.get("description", "")
            tactics = ", ".join(tech.get("tactics", []))
            platforms = ", ".join(tech.get("platforms", []))
            aws_indicators = tech.get("aws_indicators", {})
            # aws_indicators can be either a dict or an empty list
            if isinstance(aws_indicators, dict):
                ct_events = ", ".join(aws_indicators.get("cloudtrail_events", [])[:5])
            else:
                ct_events = ""
            enables = ", ".join(tech.get("enables", []))

            text = (
                f"MITRE {tech_id}: {name}. "
                f"Tactics: {tactics}. Platforms: {platforms}. "
                f"{description} "
                f"CloudTrail events: {ct_events}. "
                f"Enables: {enables}."
            )

            doc_id = f"mitre_{tech_id}_{doc_counter}"
            documents.append(text)
            ids.append(doc_id)
            embeddings.append(embedder.encode(text).tolist())
            metadatas.append({
                "source": "mitre_techniques.json",
                "type": "technique",
                "technique_id": tech_id,
                "name": name,
            })
            doc_counter += 1

        log.info(f"  MITRE techniques: {len(techniques)} loaded")

    # ── Detection Patterns ────────────────────────────────────────────────────
    dp_path = KB_DIR / "detection_patterns.json"
    if dp_path.exists():
        with open(dp_path, encoding='utf-8') as f:
            patterns = json.load(f)

        for det in patterns:
            pattern_id = det.get("pattern_id", "")
            if not pattern_id:
                continue

            name = det.get("name", "")
            # Prefer embedding_description (richer) over description
            text_body = det.get("embedding_description") or det.get("description", "")
            severity = det.get("severity", "")
            techniques = ", ".join(det.get("techniques_detected", []))
            triggers = ", ".join(det.get("triggers_playbook", []))

            # Include behavioral indicators for feature-level retrieval
            bi = det.get("behavioral_indicators", {})
            bi_text = " ".join([
                f"{col}>{v['threshold']}" if v.get("direction") == "above"
                else f"{col}<{v['threshold']}"
                for col, v in bi.items()
            ]) if bi else ""

            user_ctx = det.get("user_context", {})
            persona_note = user_ctx.get("persona_note", "")

            text = (
                f"Detection Pattern {pattern_id}: {name}. "
                f"Severity: {severity}. "
                f"{text_body} "
                f"Techniques: {techniques}. "
                f"Triggers: {triggers}. "
                f"Feature signals: {bi_text}. "
                f"{persona_note}"
            ).strip()

            event_names = det.get("cloudtrail_event_patterns", {}).get("eventName", [])

            doc_id = f"dp_{pattern_id}_{doc_counter}"
            documents.append(text)
            ids.append(doc_id)
            embeddings.append(embedder.encode(text).tolist())
            metadatas.append({
                "source": "detection_patterns.json",
                "type": "detection_pattern",
                "pattern_id": pattern_id,
                "name": name,
                "severity": severity,
                "cloudtrail_events": json.dumps(event_names),
            })
            doc_counter += 1

        log.info(f"  Detection patterns: {len(patterns)} loaded")

    # ── Playbooks ─────────────────────────────────────────────────────────────
    pb_path = KB_DIR / "playbooks.json"
    if pb_path.exists():
        with open(pb_path, encoding='utf-8') as f:
            playbooks = json.load(f)

        for pb in playbooks:
            pb_id = pb.get("playbook_id", "")
            if not pb_id:
                continue

            name = pb.get("name", "")
            incident_types = ", ".join(pb.get("incident_types", []))
            techniques = ", ".join(pb.get("techniques_addressed", []))
            triage_qs = " ".join(pb.get("triage_questions", [])[:3])

            response = pb.get("response_phases", {})
            contain_count = len(response.get("containment", []))
            investigate_steps = " ".join([
                s.get("step", "") if isinstance(s, dict) else str(s)
                for s in response.get("investigate", [])[:2]
            ])

            text = (
                f"Playbook {pb_id}: {name}. "
                f"Incident types: {incident_types}. "
                f"Techniques: {techniques}. "
                f"Triage: {triage_qs} "
                f"Investigation: {investigate_steps}. "
                f"{contain_count} containment actions available."
            )

            doc_id = f"pb_{pb_id}_{doc_counter}"
            documents.append(text)
            ids.append(doc_id)
            embeddings.append(embedder.encode(text).tolist())
            metadatas.append({
                "source": "playbooks.json",
                "type": "playbook",
                "playbook_id": pb_id,
                "name": name,
            })
            doc_counter += 1

        log.info(f"  Playbooks: {len(playbooks)} loaded")

    # ── AWS Services ──────────────────────────────────────────────────────────
    svc_path = KB_DIR / "aws_services.json"
    if svc_path.exists():
        with open(svc_path, encoding='utf-8') as f:
            services = json.load(f)

        for svc in services:
            svc_name = svc.get("service_name", "")
            if not svc_name:
                continue

            description = svc.get("description", "")
            sensitivity = svc.get("security_sensitivity", "")
            techniques = ", ".join(svc.get("related_techniques", []))
            sensitive_ops = ", ".join(svc.get("sensitive_operations", [])[:6])
            detection_focus = " ".join(svc.get("detection_focus", [])[:3])

            text = (
                f"AWS Service {svc_name} (sensitivity: {sensitivity}): {description} "
                f"Sensitive operations: {sensitive_ops}. "
                f"Detection focus: {detection_focus}. "
                f"Related techniques: {techniques}."
            )

            doc_id = f"svc_{svc_name}_{doc_counter}"
            documents.append(text)
            ids.append(doc_id)
            embeddings.append(embedder.encode(text).tolist())
            metadatas.append({
                "source": "aws_services.json",
                "type": "aws_service",
                "service_name": svc_name,
                "service_id": svc.get("service_id", svc_name),
                "security_sensitivity": sensitivity,
            })
            doc_counter += 1

        log.info(f"  AWS services: {len(services)} loaded")

    # Batch add all KB documents
    batch_size = 50
    for i in range(0, len(documents), batch_size):
        collection.add(
            documents=documents[i:i+batch_size],
            ids=ids[i:i+batch_size],
            embeddings=embeddings[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size],
        )

    log.info(f"✅ Threat intelligence ingested: {len(documents)} documents → 'threat_intelligence'")


def main():
    log.info("Initializing ChromaDB and embedder...")
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    log.info("✅ Ready")

    log.info("\n── Stage 1: Behavioral Incidents ────────────────────────────")
    ingest_behavioral_incidents(client, embedder)

    log.info("\n── Stage 2: Threat Intelligence Knowledge Base ──────────────")
    ingest_knowledge_base(client, embedder)

    log.info("\n=== Vector DB Ingestion Complete ===")
    for col_name in ["behavioral_incidents", "threat_intelligence"]:
        try:
            col = client.get_collection(col_name)
            log.info(f"  {col_name}: {col.count()} documents")
        except Exception:
            pass


if __name__ == "__main__":
    main()
