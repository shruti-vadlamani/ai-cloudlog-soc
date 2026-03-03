#!/usr/bin/env python3
"""
rag_ingestion/ingest_knowledge_graph.py
=========================================
Loads knowledge base + CloudTrail event graph into Neo4j.

Two separate graphs in one DB:

Graph 1 — Knowledge Base (static)
  Nodes: MITRETechnique, DetectionPattern, Playbook, AWSService
  Relations: DETECTED_BY, TRIGGERS, AFFECTS, ENABLES, REQUIRES, SUPPLEMENTS

Graph 2 — Event Graph (from your normalized data)
  Nodes: User, Event, Resource
  Relations: PERFORMED, ON
  Source: parquet_to_rag.ingest_to_neo4j()

Run AFTER run_pipeline.py, BEFORE production_incident_analyzer.py.
"""

import json
import logging
import os
import sys
from pathlib import Path

from neo4j import GraphDatabase

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ingest_knowledge_graph")

PROJECT_ROOT = Path(__file__).parent.parent
KB_DIR = PROJECT_ROOT / "knowledge_base"


class KnowledgeGraphIngester:
    def __init__(self, uri="neo4j://127.0.0.1:7687", user="neo4j", password="neo4j1234"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def clear_knowledge_graph(self):
        """Clear only knowledge base nodes (not the event graph)."""
        log.info("Clearing knowledge base nodes...")
        with self.driver.session() as s:
            s.run("MATCH (n:MITRETechnique) DETACH DELETE n")
            s.run("MATCH (n:DetectionPattern) DETACH DELETE n")
            s.run("MATCH (n:Playbook) DETACH DELETE n")
            s.run("MATCH (n:AWSService) DETACH DELETE n")
        log.info("Knowledge base nodes cleared")

    def create_indexes(self):
        """Create indexes for query performance."""
        log.info("Creating indexes...")
        with self.driver.session() as s:
            s.run("CREATE INDEX IF NOT EXISTS FOR (t:MITRETechnique) ON (t.technique_id)")
            s.run("CREATE INDEX IF NOT EXISTS FOR (d:DetectionPattern) ON (d.id)")
            s.run("CREATE INDEX IF NOT EXISTS FOR (p:Playbook) ON (p.id)")
            s.run("CREATE INDEX IF NOT EXISTS FOR (s:AWSService) ON (s.service_id)")
            s.run("CREATE INDEX IF NOT EXISTS FOR (s:AWSService) ON (s.name)")
        log.info("Indexes created")

    def ingest_mitre_techniques(self):
        path = KB_DIR / "mitre_techniques.json"
        if not path.exists():
            log.warning(f"Not found: {path}")
            return

        with open(path, encoding='utf-8') as f:
            techniques = json.load(f)

        count = 0
        with self.driver.session() as s:
            for tech in techniques:
                tech_id = tech.get("technique_id", "")
                if not tech_id:
                    continue
                s.run("""
                    MERGE (t:MITRETechnique {technique_id: $id})
                    SET t.name = $name,
                        t.tactics = $tactics,
                        t.platforms = $platforms,
                        t.description = $description,
                        t.enables = $enables
                """, id=tech_id,
                     name=tech.get("name", ""),
                     tactics=tech.get("tactics", []),
                     platforms=tech.get("platforms", []),
                     description=tech.get("description", ""),
                     enables=tech.get("enables", []))
                count += 1

        log.info(f"✅ MITRE techniques: {count}")

    def ingest_aws_services(self):
        path = KB_DIR / "aws_services.json"
        if not path.exists():
            log.warning(f"Not found: {path}")
            return

        with open(path, encoding='utf-8') as f:
            services = json.load(f)

        count = 0
        with self.driver.session() as s:
            for svc in services:
                svc_name = svc.get("service_name", "")
                if not svc_name:
                    continue
                # service_id added by copilot enhancement; fallback to name
                service_id = svc.get("service_id", svc_name.upper().replace(" ", "_"))
                s.run("""
                    MERGE (svc:AWSService {service_id: $service_id})
                    SET svc.name = $name,
                        svc.description = $description,
                        svc.security_sensitivity = $sensitivity,
                        svc.sensitive_operations = $sensitive_ops,
                        svc.high_risk_operations = $high_risk,
                        svc.event_source = $event_source,
                        svc.related_techniques = $techniques
                """, service_id=service_id,
                     name=svc_name,
                     description=svc.get("description", ""),
                     sensitivity=svc.get("security_sensitivity", "Medium"),
                     sensitive_ops=svc.get("sensitive_operations", []),
                     high_risk=svc.get("high_risk_operations", []),
                     event_source=svc.get("event_source", ""),
                     techniques=svc.get("related_techniques", []))
                count += 1

        log.info(f"✅ AWS services: {count}")

    def ingest_detection_patterns(self):
        path = KB_DIR / "detection_patterns.json"
        if not path.exists():
            log.warning(f"Not found: {path}")
            return

        with open(path, encoding='utf-8') as f:
            patterns = json.load(f)

        count = 0
        with self.driver.session() as s:
            for det in patterns:
                pattern_id = det.get("pattern_id", "")
                if not pattern_id:
                    continue

                # Extract cloudtrail event names for graph-level matching
                ct_events = det.get("cloudtrail_event_patterns", {}).get("eventName", [])

                # behavioral_indicators stored as JSON string (Neo4j can't store dicts)
                bi = json.dumps(det.get("behavioral_indicators", {}))
                user_ctx = json.dumps(det.get("user_context", {}))

                s.run("""
                    MERGE (d:DetectionPattern {id: $id})
                    SET d.name = $name,
                        d.severity = $severity,
                        d.description = $description,
                        d.embedding_description = $emb_desc,
                        d.cloudtrail_events = $ct_events,
                        d.techniques_detected = $techniques,
                        d.triggers_playbook = $triggers,
                        d.behavioral_indicators = $bi,
                        d.user_context = $user_ctx,
                        d.false_positive_sources = $fp,
                        d.threshold = $threshold,
                        d.time_window_minutes = $time_window,
                        d.anomaly_score_threshold = $score_thresh
                """, id=pattern_id,
                     name=det.get("name", ""),
                     severity=det.get("severity", ""),
                     description=det.get("description", ""),
                     emb_desc=det.get("embedding_description", ""),
                     ct_events=ct_events,
                     techniques=det.get("techniques_detected", []),
                     triggers=det.get("triggers_playbook", []),
                     bi=bi,
                     user_ctx=user_ctx,
                     fp=det.get("false_positive_sources", []),
                     threshold=det.get("threshold", 0),
                     time_window=det.get("time_window_minutes", 0),
                     score_thresh=det.get("anomaly_score_threshold", 0.5))
                count += 1

        log.info(f"✅ Detection patterns: {count}")

    def ingest_playbooks(self):
        path = KB_DIR / "playbooks.json"
        if not path.exists():
            log.warning(f"Not found: {path}")
            return

        with open(path, encoding='utf-8') as f:
            playbooks = json.load(f)

        count = 0
        with self.driver.session() as s:
            for pb in playbooks:
                pb_id = pb.get("playbook_id", "")
                if not pb_id:
                    continue

                # Store triage questions and related playbooks as arrays
                triage_qs = pb.get("triage_questions", [])
                related = pb.get("related_playbooks", [])

                # Flatten response phases for quick retrieval
                phases = pb.get("response_phases", {})
                containment_steps = json.dumps(phases.get("containment", []))
                investigate_steps = json.dumps(phases.get("investigate", []))

                s.run("""
                    MERGE (p:Playbook {id: $id})
                    SET p.name = $name,
                        p.incident_types = $incident_types,
                        p.techniques_addressed = $techniques,
                        p.triage_questions = $triage,
                        p.related_playbooks = $related,
                        p.containment_steps = $containment,
                        p.investigate_steps = $investigate,
                        p.escalation_criteria = $escalation
                """, id=pb_id,
                     name=pb.get("name", ""),
                     incident_types=pb.get("incident_types", []),
                     techniques=pb.get("techniques_addressed", []),
                     triage=triage_qs,
                     related=related,
                     containment=containment_steps,
                     investigate=investigate_steps,
                     escalation=pb.get("escalation_criteria", []))
                count += 1

        log.info(f"✅ Playbooks: {count}")

    def ingest_graph_relations(self):
        path = KB_DIR / "graph_relations.json"
        if not path.exists():
            log.warning(f"Not found: {path}")
            return

        with open(path, encoding='utf-8') as f:
            raw = json.load(f)

        # Handle both list format and {relationship_types, relationships} format
        if isinstance(raw, list):
            relations = raw
        else:
            relations = raw.get("relationships", [])

        # Label → (node_label, id_property)
        LABEL_MAP = {
            "MITRETechnique": ("MITRETechnique", "technique_id"),
            "DetectionPattern": ("DetectionPattern", "id"),
            "Playbook": ("Playbook", "id"),
            "AWSService": ("AWSService", "service_id"),
        }

        # Relationship type counters
        rel_counts = {}
        skipped = 0

        with self.driver.session() as s:
            for rel in relations:
                src_entity = rel.get("source_entity", "")
                src_type = rel.get("source_type", "")
                tgt_entity = rel.get("target_entity", "")
                tgt_type = rel.get("target_type", "")
                relationship = rel.get("relationship", "")
                confidence = float(rel.get("confidence", 0.5))

                if not all([src_entity, tgt_entity, relationship]):
                    skipped += 1
                    continue

                if src_type not in LABEL_MAP or tgt_type not in LABEL_MAP:
                    skipped += 1
                    continue

                src_label, src_prop = LABEL_MAP[src_type]
                tgt_label, tgt_prop = LABEL_MAP[tgt_type]
                rel_name = relationship.upper().replace("-", "_").replace(" ", "_")

                # AWSService can be looked up by name OR service_id
                # Try service_id first, fall back to name match
                if tgt_type == "AWSService":
                    query = f"""
                    MATCH (s:{src_label} {{{src_prop}: $src}})
                    MATCH (t:{tgt_label})
                    WHERE t.service_id = $tgt OR t.name = $tgt
                    MERGE (s)-[r:{rel_name}]->(t)
                    SET r.confidence = $conf
                    """
                elif src_type == "AWSService":
                    query = f"""
                    MATCH (s:{src_label})
                    WHERE s.service_id = $src OR s.name = $src
                    MATCH (t:{tgt_label} {{{tgt_prop}: $tgt}})
                    MERGE (s)-[r:{rel_name}]->(t)
                    SET r.confidence = $conf
                    """
                else:
                    query = f"""
                    MATCH (s:{src_label} {{{src_prop}: $src}})
                    MATCH (t:{tgt_label} {{{tgt_prop}: $tgt}})
                    MERGE (s)-[r:{rel_name}]->(t)
                    SET r.confidence = $conf
                    """

                try:
                    s.run(query, src=src_entity, tgt=tgt_entity, conf=confidence)
                    rel_counts[rel_name] = rel_counts.get(rel_name, 0) + 1
                except Exception as e:
                    log.debug(f"Relation {src_entity}->{tgt_entity}: {e}")
                    skipped += 1

        total = sum(rel_counts.values())
        log.info(f"✅ Graph relations: {total} created, {skipped} skipped")
        for rtype, cnt in sorted(rel_counts.items()):
            log.info(f"   {rtype}: {cnt}")

    def ingest_event_graph(self):
        """
        Ingest CloudTrail events as User→Event→Resource graph.
        Uses parquet_to_rag.ingest_to_neo4j().
        """
        events_path = PROJECT_ROOT / "data" / "normalized" / "events_labeled.csv.gz"
        events_parquet = PROJECT_ROOT / "data" / "normalized" / "events.parquet"

        import pandas as pd
        if events_parquet.exists():
            df = pd.read_parquet(events_parquet)
        elif events_path.exists():
            df = pd.read_csv(events_path, compression="gzip")
        else:
            log.warning("Normalized events not found — skipping event graph ingestion")
            log.warning("Run: python run_pipeline.py --stage ingest")
            return

        # Add eventTime string for Neo4j (can't store datetime objects)
        if "eventTime" in df.columns:
            df["eventTime_str"] = df["eventTime"].astype(str)
        else:
            df["eventTime_str"] = ""

        # is_attack and attack columns
        for col, default in [("is_attack", False), ("attack_id", 0), ("attack_name", "normal"), ("is_error", False)]:
            if col not in df.columns:
                df[col] = default

        log.info(f"Ingesting {len(df)} events to Neo4j event graph...")

        from rag_ingestion.parquet_to_rag import ingest_to_neo4j
        ingest_to_neo4j(df, self.driver)
        log.info("✅ Event graph ingested")

    def close(self):
        self.driver.close()


def main():
    uri = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "neo4j1234")

    ingester = KnowledgeGraphIngester(uri, user, password)

    # Verify connection
    with ingester.driver.session() as s:
        count = s.run("MATCH (n) RETURN count(n) as c").single()["c"]
        log.info(f"✅ Neo4j connected: {count} existing nodes")

    ingester.create_indexes()

    log.info("\n── Knowledge Base Nodes ─────────────────────────────────────")
    ingester.ingest_mitre_techniques()
    ingester.ingest_aws_services()
    ingester.ingest_detection_patterns()
    ingester.ingest_playbooks()

    log.info("\n── Knowledge Base Relationships ─────────────────────────────")
    ingester.ingest_graph_relations()

    log.info("\n── CloudTrail Event Graph ───────────────────────────────────")
    ingester.ingest_event_graph()

    # Verify
    with ingester.driver.session() as s:
        result = s.run("""
            MATCH (n)
            RETURN labels(n)[0] as label, count(n) as count
            ORDER BY count DESC
        """)
        log.info("\nNode counts:")
        for rec in result:
            log.info(f"  {rec['label']}: {rec['count']}")

    ingester.close()
    log.info("\n=== Knowledge Graph Ingestion Complete ===")


if __name__ == "__main__":
    main()
