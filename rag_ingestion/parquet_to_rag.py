"""
rag_ingestion/parquet_to_rag.py
=================================
Reads normalized events from Parquet and feeds them into
your friend's RAG layer (ChromaDB + Neo4j).

Ingestion philosophy:
  - ChromaDB: Store per-window behavioral summaries as text embeddings.
    Retrieval query = anomaly description → get similar past incidents,
    MITRE mappings, and playbooks.
  - Neo4j: Store the event graph (users → actions → resources → timestamps).
    Graph queries = "what other resources did this user access before this event?"

This file is a skeleton — adapt the ChromaDB and Neo4j
connection details to match your friend's setup.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any

import pandas as pd

log = logging.getLogger(__name__)


# ── ChromaDB Ingestion ────────────────────────────────────────────────────────

def build_window_summary_text(row: pd.Series) -> str:
    """
    Convert a feature window row into a natural language summary
    for ChromaDB embedding. This text is what gets embedded and
    retrieved when an anomaly is detected.

    Example output:
    "User eve-analyst at 2026-02-23 14:00 UTC performed 87 S3 GetObject
     operations (2.3x above baseline, z-score=4.1). No IAM events.
     Business hours. No errors. Gradual volume increase over 3 days
     (slope=12.4). Window: 5 minutes."
    """
    user = row.get("user_name", "unknown")
    window = row.get("window", "")
    total = int(row.get("total_events", 0))
    s3_gets = int(row.get("s3_get_events", 0))
    iam_writes = int(row.get("iam_write_events", 0))
    iam_lists = int(row.get("iam_list_events", 0))
    deletes = int(row.get("s3_delete_events", 0))
    errors = int(row.get("error_events", 0))
    bytes_out = float(row.get("bytes_out_total", 0))
    zscore_total = float(row.get("total_events_zscore", 0))
    zscore_s3get = float(row.get("s3_get_events_zscore", 0))
    slope = float(row.get("s3_get_slope_3d", 0))
    is_biz_hrs = bool(row.get("window_is_business_hours", True))
    is_weekend = bool(row.get("window_is_weekend", False))
    attack_name = row.get("attack_name", "normal")

    parts = [
        f"User {user} at {window}",
        f"performed {total} total events in 5 minutes.",
        f"S3 GetObject: {s3_gets} (z-score={zscore_s3get:.1f}).",
        f"IAM writes: {iam_writes}. IAM list ops: {iam_lists}.",
        f"S3 deletes: {deletes}. Errors: {errors}.",
        f"Bytes transferred out: {bytes_out:.0f}.",
        f"Overall volume z-score: {zscore_total:.1f}.",
        f"3-day S3 GET slope: {slope:.2f}.",
        f"Time context: {'business hours' if is_biz_hrs else 'off hours'}, {'weekend' if is_weekend else 'weekday'}.",
        f"Label: {attack_name}.",
    ]

    return " ".join(parts)


def ingest_to_chromadb(
    feature_df: pd.DataFrame,
    chroma_client,      # chromadb.Client
    collection_name: str = "cloudtrail_windows",
    attack_windows_only: bool = False,
) -> None:
    """
    Ingest feature windows into ChromaDB as embedded text documents.

    Each document = one 5-minute behavioral window summary.
    Metadata = all feature values + label.

    Args:
        feature_df: Output of feature_builder.build_feature_matrix (with labels)
        chroma_client: Initialized chromadb client from your friend's setup
        collection_name: ChromaDB collection name
        attack_windows_only: If True, only ingest labeled attack windows
                             (for knowledge base of known attacks)
    """
    collection = chroma_client.get_or_create_collection(collection_name)

    if attack_windows_only and "is_attack" in feature_df.columns:
        df = feature_df[feature_df["is_attack"]].copy()
        log.info(f"Ingesting {len(df)} attack windows to ChromaDB")
    else:
        df = feature_df.copy()
        log.info(f"Ingesting {len(df)} windows to ChromaDB")

    documents = []
    metadatas = []
    ids = []

    for idx, row in df.iterrows():
        doc_text = build_window_summary_text(row)
        documents.append(doc_text)

        # Metadata: everything ChromaDB can store (flat, primitive values only)
        meta = {
            "user_name": str(row.get("user_name", "")),
            "window": str(row.get("window", "")),
            "attack_id": int(row.get("attack_id", 0)),
            "attack_name": str(row.get("attack_name", "normal")),
            "is_attack": bool(row.get("is_attack", False)),
            "total_events": float(row.get("total_events", 0)),
            "s3_get_events": float(row.get("s3_get_events", 0)),
            "iam_write_events": float(row.get("iam_write_events", 0)),
            "total_events_zscore": float(row.get("total_events_zscore", 0)),
            "s3_get_slope_3d": float(row.get("s3_get_slope_3d", 0)),
        }
        metadatas.append(meta)
        ids.append(f"{row.get('user_name', 'u')}_{row.get('window', idx)}")

    # Batch upsert (ChromaDB handles embedding internally if you set up embedding fn)
    batch_size = 100
    for i in range(0, len(documents), batch_size):
        collection.upsert(
            documents=documents[i:i+batch_size],
            metadatas=metadatas[i:i+batch_size],
            ids=ids[i:i+batch_size],
        )

    log.info(f"ChromaDB ingestion complete: {len(documents)} windows in '{collection_name}'")


# ── Neo4j Ingestion ───────────────────────────────────────────────────────────

def ingest_to_neo4j(
    normalized_df: pd.DataFrame,
    neo4j_driver,       # neo4j.GraphDatabase.driver(...)
    batch_size: int = 500,
) -> None:
    """
    Ingest normalized events into Neo4j as a property graph.

    Graph schema:
      (User)-[:PERFORMED]->(Event)-[:ON]->(Resource)
      (Event)-[:AT]->(TimeWindow)

    This enables graph queries like:
      "What resources did eve-analyst access before the anomaly?"
      "Which users share access to the same buckets as the attacker?"

    Args:
        normalized_df: Output of normalizer.normalize_events
        neo4j_driver: Initialized Neo4j driver from your friend's setup
        batch_size: Rows per transaction
    """
    with neo4j_driver.session() as session:
        # Create constraints (idempotent)
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Event) REQUIRE e.eventID IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (r:Resource) REQUIRE r.name IS UNIQUE")

    # Process in batches
    records = normalized_df.to_dict(orient="records")
    total = len(records)
    log.info(f"Ingesting {total} events to Neo4j...")

    for i in range(0, total, batch_size):
        batch = records[i : i + batch_size]

        with neo4j_driver.session() as session:
            session.execute_write(_write_batch, batch)

        if i % 5000 == 0:
            log.info(f"  Neo4j: {i}/{total} events ingested")

    log.info(f"Neo4j ingestion complete: {total} events")


def _write_batch(tx, batch: list) -> None:
    """Neo4j transaction: upsert users, events, and resources."""
    cypher = """
    UNWIND $events AS ev
    MERGE (u:User {name: ev.user_name})
    SET u.user_type = ev.user_type,
        u.arn = ev.user_arn
    CREATE (e:Event {
        eventID: ev.eventID,
        eventName: ev.eventName,
        eventSource: ev.eventSource,
        eventTime: ev.eventTime_str,
        isReadOnly: ev.is_read_only,
        isError: ev.is_error,
        errorCode: ev.error_code,
        sourceIP: ev.sourceIPAddress,
        isAttack: ev.is_attack,
        attackId: ev.attack_id,
        attackName: ev.attack_name
    })
    MERGE (u)-[:PERFORMED]->(e)
    FOREACH (bucket IN CASE WHEN ev.request_bucket_name IS NOT NULL
                            THEN [ev.request_bucket_name] ELSE [] END |
        MERGE (r:Resource {name: bucket, type: 's3_bucket'})
        MERGE (e)-[:ON]->(r)
    )
    """
    events = [
        {
            "user_name": r.get("user_name") or "unknown",
            "user_type": r.get("user_type") or "",
            "user_arn": r.get("user_arn") or "",
            "eventID": r.get("eventID") or "",
            "eventName": r.get("eventName") or "",
            "eventSource": r.get("eventSource") or "",
            "eventTime_str": str(r.get("eventTime_str") or ""),
            "is_read_only": bool(r.get("is_read_only", True)),
            "is_error": bool(r.get("is_error", False)),
            "error_code": r.get("error_code") or "",
            "sourceIPAddress": r.get("sourceIPAddress") or "",
            "request_bucket_name": r.get("request_bucket_name"),
            "is_attack": bool(r.get("is_attack", False)),
            "attack_id": int(r.get("attack_id", 0)),
            "attack_name": str(r.get("attack_name", "normal")),
        }
        for r in batch
    ]
    tx.run(cypher, events=events)
