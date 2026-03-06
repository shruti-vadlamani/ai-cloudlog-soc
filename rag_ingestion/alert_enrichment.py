"""
rag_ingestion/alert_enrichment.py
===================================
The bridge between your ML model output and the RAG layer.

Takes one flagged row from ensemble_alerts.csv, joins it to the
feature matrix and normalized events, then builds a structured
enrichment payload by querying both Neo4j and ChromaDB.

This is the file that makes the RAG layer actually useful —
it translates ML scores into retrieval queries that return
detection patterns, playbooks, and similar past incidents.

Usage (standalone):
    python rag_ingestion/alert_enrichment.py

Usage (imported):
    from rag_ingestion.alert_enrichment import AlertEnricher
    enricher = AlertEnricher(neo4j_driver, chroma_client, embedder)
    payload = enricher.enrich(alert_row, feature_df, normalized_df)
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

PROJECT_ROOT = Path(__file__).parent.parent
log = logging.getLogger(__name__)

# ── Feature columns that map to detection pattern behavioral_indicators ────────
# These are the z-score and count features most useful for pattern matching
KEY_FEATURE_COLS = [
    "iam_write_events", "iam_list_events", "s3_get_events",
    "s3_delete_events", "after_hours_ratio", "iam_ratio", "write_ratio",
    "delete_ratio", "iam_write_ratio", "total_events_zscore",
    "iam_events_zscore", "s3_get_events_zscore", "iam_list_events_zscore",
    "iam_write_events_zscore", "s3_delete_events_zscore", "s3_get_slope_3d",
]


class AlertEnricher:
    """
    Enriches a flagged ensemble alert with RAG context.

    Flow for each alert:
    1. Load feature values for the flagged window
    2. Load raw events from the flagged user around the alert time
    3. Match feature values against detection pattern behavioral_indicators
       in Neo4j → get candidate patterns
    4. For each matched pattern, traverse graph to get techniques + playbooks
    5. Follow ENABLES chains to get next-likely-technique playbooks
    6. Query ChromaDB behavioral_incidents for similar past windows
    7. Query ChromaDB threat_intelligence for relevant technique context
    8. Assemble final enriched payload
    """

    def __init__(self, neo4j_driver, chroma_client, embedder, use_graph_bridges: bool = True):
        self.driver = neo4j_driver
        self.chroma = chroma_client
        self.embedder = embedder
        self.use_graph_bridges = use_graph_bridges  # Use pre-built graph bridges for matching
        self._init_chroma_collections()

    def _init_chroma_collections(self):
        """Get ChromaDB collections."""
        try:
            self.incidents_col = self.chroma.get_collection("behavioral_incidents")
        except Exception:
            self.incidents_col = None
            log.warning("behavioral_incidents collection not found — run ingest_vector_db.py")

        try:
            self.ti_col = self.chroma.get_collection("threat_intelligence")
        except Exception:
            self.ti_col = None
            log.warning("threat_intelligence collection not found — run ingest_vector_db.py")

    # ── Main entry point ──────────────────────────────────────────────────────

    def enrich(
        self,
        alert_row: pd.Series,
        feature_df: pd.DataFrame,
        normalized_df: pd.DataFrame,
    ) -> Dict:
        """
        Enrich one alert row with full RAG context.

        Args:
            alert_row: One row from ensemble_alerts.csv
            feature_df: Full feature matrix (to get feature values for this window)
            normalized_df: Normalized events (to get raw event context)

        Returns:
            Enriched alert payload dict ready to pass to LLM
        """
        user = alert_row.get("user_name", "unknown")
        window = alert_row.get("window", "")
        ensemble_score = float(alert_row.get("ensemble_score", 0))
        if_score = float(alert_row.get("if_norm", 0))
        lof_score = float(alert_row.get("lof_norm", 0))
        ae_score = float(alert_row.get("ae_norm", 0))
        vote_count = int(alert_row.get("vote_count", 0))

        log.info(f"Enriching alert: user={user}, window={window}, score={ensemble_score:.3f}")

        # Step 1: Get feature values for this specific window
        feature_values = self._get_feature_values(feature_df, user, window)

        # Step 2: Get raw events around alert window
        event_context = self._get_event_context(normalized_df, user, window)

        # Step 3: Determine which models fired
        models_fired = self._models_that_fired(if_score, lof_score, ae_score)

        # Step 4: Match detection patterns via Neo4j
        # Use graph bridges if available (faster, pre-computed)
        if self.use_graph_bridges:
            matched_patterns = self._match_detection_patterns_via_graph(user, window)
        else:
            matched_patterns = self._match_detection_patterns(
                feature_values, event_context.get("event_names", [])
            )

        # Step 5: Get techniques + playbooks from graph
        graph_intel = self._get_graph_intel(matched_patterns)

        # Step 6: Follow ENABLES chains for proactive playbooks
        chain_playbooks = self._get_chain_playbooks(graph_intel.get("technique_ids", []))

        # Step 7: ChromaDB — similar past incidents
        similar_incidents = self._search_similar_incidents(
            user, feature_values, alert_row.get("attack_name", "")
        )

        # Step 8: ChromaDB — relevant threat intel
        ti_docs = self._search_threat_intel(
            matched_patterns, graph_intel.get("technique_ids", [])
        )

        # Step 9: Build severity
        severity = self._compute_severity(ensemble_score, vote_count, matched_patterns)

        payload = {
            "alert": {
                "user": user,
                "window": str(window),
                "ensemble_score": round(ensemble_score, 4),
                "severity": severity,
                "models_fired": models_fired,
                "vote_count": vote_count,
                "model_scores": {
                    "isolation_forest": round(if_score, 4),
                    "lof": round(lof_score, 4),
                    "autoencoder": round(ae_score, 4),
                },
            },
            "behavioral_context": {
                "feature_values": feature_values,
                "event_context": event_context,
            },
            "detection": {
                "matched_patterns": matched_patterns,
                "techniques": graph_intel.get("techniques", []),
                "primary_playbooks": graph_intel.get("playbooks", []),
                "chain_playbooks": chain_playbooks,
            },
            "rag_retrieval": {
                "similar_past_incidents": similar_incidents,
                "threat_intel_docs": ti_docs,
            },
            "rag_query": self._build_rag_query(
                user, feature_values, matched_patterns,
                graph_intel.get("techniques", []), models_fired
            ),
        }

        return payload

    # ── Feature extraction ────────────────────────────────────────────────────

    def _get_feature_values(
        self, feature_df: pd.DataFrame, user: str, window
    ) -> Dict:
        """Get feature values for the specific (user, window) pair."""
        if feature_df is None or feature_df.empty:
            return {}

        try:
            window_ts = pd.to_datetime(window, utc=True)
            mask = (feature_df["user_name"] == user) & (
                pd.to_datetime(feature_df["window"], utc=True) == window_ts
            )
            matches = feature_df[mask]

            if matches.empty:
                return {}

            row = matches.iloc[0]
            return {
                col: float(row[col])
                for col in KEY_FEATURE_COLS
                if col in row.index
            }
        except Exception as e:
            log.debug(f"Feature lookup failed: {e}")
            return {}

    def _get_event_context(
        self, normalized_df: pd.DataFrame, user: str, window, minutes_before: int = 30
    ) -> Dict:
        """Get raw CloudTrail events for this user around the alert window."""
        if normalized_df is None or normalized_df.empty:
            return {"event_names": [], "event_count": 0, "error_rate": 0.0}

        try:
            window_ts = pd.to_datetime(window, utc=True)
            start = window_ts - pd.Timedelta(minutes=minutes_before)
            end = window_ts + pd.Timedelta(minutes=5)

            event_time_col = "eventTime" if "eventTime" in normalized_df.columns else None
            if not event_time_col:
                return {"event_names": [], "event_count": 0}

            et = pd.to_datetime(normalized_df[event_time_col], utc=True)
            mask = (
                (normalized_df["user_name"] == user)
                & (et >= start)
                & (et <= end)
            )
            window_events = normalized_df[mask]

            if window_events.empty:
                return {"event_names": [], "event_count": 0}

            event_names = window_events["eventName"].value_counts().to_dict()
            error_events = window_events.get("is_error", pd.Series([False] * len(window_events)))
            error_rate = float(error_events.sum() / len(window_events)) if len(window_events) > 0 else 0.0

            return {
                "event_names": list(event_names.keys()),
                "event_counts": {str(k): int(v) for k, v in event_names.items()},
                "event_count": int(len(window_events)),
                "error_rate": round(error_rate, 3),
                "unique_resources": int(
                    window_events.get("request_bucket_name", pd.Series()).nunique()
                ) if "request_bucket_name" in window_events.columns else 0,
            }
        except Exception as e:
            log.debug(f"Event context lookup failed: {e}")
            return {"event_names": [], "event_count": 0}

    # ── Graph retrieval ───────────────────────────────────────────────────────

    def _match_detection_patterns(
        self, feature_values: Dict, event_names: List[str]
    ) -> List[Dict]:
        """
        Find detection patterns that match this alert's features and event names.

        Two retrieval paths:
        Path A — CloudTrail event name match: pattern.cloudtrail_events ∩ event_names
        Path B — Behavioral indicator match: pattern.behavioral_indicators thresholds
                 compared against actual feature values

        Returns patterns sorted by match strength.
        """
        if not self.driver:
            return []

        matched = {}

        with self.driver.session() as s:
            # Path A: event name matching
            if event_names:
                result = s.run("""
                    MATCH (d:DetectionPattern)
                    WHERE any(ev IN d.cloudtrail_events WHERE ev IN $events)
                    RETURN d.id as id, d.name as name, d.severity as severity,
                           d.description as description,
                           d.techniques_detected as techniques,
                           d.triggers_playbook as triggers,
                           d.behavioral_indicators as bi,
                           d.user_context as user_ctx,
                           d.false_positive_sources as fp
                """, events=event_names)

                for rec in result:
                    pid = rec["id"]
                    if pid and pid not in matched:
                        matched[pid] = {
                            "pattern_id": pid,
                            "name": rec["name"] or "",
                            "severity": rec["severity"] or "",
                            "description": rec["description"] or "",
                            "techniques": rec["techniques"] or [],
                            "triggers_playbook": rec["triggers"] or [],
                            "false_positive_sources": rec["fp"] or [],
                            "match_reason": "cloudtrail_event_match",
                            "match_score": 0.7,
                        }

        # Path B: behavioral indicator matching
        if feature_values:
            with self.driver.session() as s:
                result = s.run("""
                    MATCH (d:DetectionPattern)
                    WHERE d.behavioral_indicators IS NOT NULL
                    RETURN d.id as id, d.name as name, d.severity as severity,
                           d.description as description,
                           d.techniques_detected as techniques,
                           d.triggers_playbook as triggers,
                           d.behavioral_indicators as bi,
                           d.false_positive_sources as fp
                """)

                for rec in result:
                    pid = rec["id"]
                    if not pid or not rec["bi"]:
                        continue

                    try:
                        bi = json.loads(rec["bi"])
                    except Exception:
                        continue

                    match_score = self._score_behavioral_match(feature_values, bi)
                    if match_score > 0.5:
                        if pid not in matched or match_score > matched[pid].get("match_score", 0):
                            matched[pid] = {
                                "pattern_id": pid,
                                "name": rec["name"] or "",
                                "severity": rec["severity"] or "",
                                "description": rec["description"] or "",
                                "techniques": rec["techniques"] or [],
                                "triggers_playbook": rec["triggers"] or [],
                                "false_positive_sources": rec["fp"] or [],
                                "match_reason": "behavioral_indicator_match",
                                "match_score": round(match_score, 3),
                            }

        sorted_patterns = sorted(
            matched.values(), key=lambda x: x["match_score"], reverse=True
        )
        log.info(f"Matched {len(sorted_patterns)} detection patterns")
        return sorted_patterns[:5]  # Top 5

    def _match_detection_patterns_via_graph(self, user: str, window: str) -> List[Dict]:
        """
        Match detection patterns using pre-built graph bridges.
        
        This method leverages the TRIGGERS_INDICATOR edges created by bridge_graphs.py.
        Instead of computing matches in Python, it traverses the pre-built graph.
        
        Flow:
        1. Find the Window node for this (user, window)
        2. Traverse TRIGGERS_INDICATOR edges to matched DetectionPattern nodes
        3. For each pattern, get techniques and playbooks
        
        This is much faster than _match_detection_patterns() because:
        - No feature threshold evaluation in Python
        - No loading all patterns and computing scores
        - Direct graph traversal with pre-computed match_score
        
        Args:
            user: User name
            window: Window timestamp string
            
        Returns:
            List of matched pattern dicts with techniques and playbooks
        """
        if not self.driver:
            return []
        
        window_id = f"{user}_{window}"
        
        with self.driver.session() as s:
            result = s.run("""
                MATCH (u:User {name: $user})-[:HAD_WINDOW]->(w:Window {window_id: $window_id})
                MATCH (w)-[ti:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                OPTIONAL MATCH (t:MITRETechnique)-[:DETECTED_BY]->(d)
                OPTIONAL MATCH (d)-[:TRIGGERS]->(p:Playbook)
                RETURN 
                    d.id as pattern_id,
                    d.name as pattern_name,
                    d.severity as severity,
                    d.description as description,
                    d.false_positive_sources as fp,
                    ti.match_score as match_score,
                    ti.matched_features as matched_features,
                    d.techniques_detected as techniques,
                    collect(DISTINCT t.technique_id) as technique_ids_from_graph,
                    collect(DISTINCT {
                        id: p.id, 
                        name: p.name, 
                        triage: p.triage_questions, 
                        containment: p.containment_steps,
                        incident_types: p.incident_types
                    }) as playbooks
                ORDER BY ti.match_score DESC
            """, user=user, window_id=window_id)
            
            patterns = []
            for rec in result:
                # Parse containment steps (stored as JSON string)
                playbooks = []
                for pb in rec["playbooks"]:
                    if pb.get("id"):
                        try:
                            containment = json.loads(pb.get("containment") or "[]")
                        except (json.JSONDecodeError, TypeError):
                            containment = []
                        playbooks.append({
                            "playbook_id": pb["id"],
                            "name": pb["name"] or "",
                            "incident_types": pb.get("incident_types") or [],
                            "triage_questions": pb.get("triage") or [],
                            "containment_steps": containment[:3],  # Top 3 for LLM context
                        })
                
                patterns.append({
                    "pattern_id": rec["pattern_id"],
                    "name": rec["pattern_name"] or "",
                    "severity": rec["severity"] or "",
                    "description": rec["description"] or "",
                    "techniques": rec["techniques"] or [],
                    "triggers_playbook": rec["techniques"] or [],  # For backward compatibility
                    "false_positive_sources": rec["fp"] or [],
                    "match_reason": "graph_bridge_triggers_indicator",
                    "match_score": round(rec["match_score"], 3),
                    "matched_features": rec["matched_features"] or [],
                    "playbooks": playbooks,  # Include playbooks directly in pattern
                })
            
            log.info(f"Matched {len(patterns)} detection patterns via graph bridges")
            return patterns[:5]  # Top 5

    def _score_behavioral_match(self, feature_values: Dict, bi: Dict) -> float:
        """
        Score how well a window's feature values match a pattern's
        behavioral_indicators thresholds. Returns 0.0–1.0.
        """
        if not bi or not feature_values:
            return 0.0

        hits = 0
        total = len(bi)
        for col, threshold_def in bi.items():
            actual = feature_values.get(col)
            if actual is None:
                continue
            threshold = threshold_def.get("threshold", 0)
            direction = threshold_def.get("direction", "above")
            if direction == "above" and actual > threshold:
                hits += 1
            elif direction == "below" and actual < threshold:
                hits += 1

        return hits / total if total > 0 else 0.0

    def _get_graph_intel(self, matched_patterns: List[Dict]) -> Dict:
        """
        Traverse Neo4j from matched detection patterns to get:
        - Techniques (via DETECTED_BY reverse)
        - Playbooks (via TRIGGERS)
        - Affected AWS services
        """
        if not matched_patterns or not self.driver:
            return {"techniques": [], "playbooks": [], "services": [], "technique_ids": []}

        pattern_ids = [p["pattern_id"] for p in matched_patterns]
        techniques, playbooks, services = {}, {}, {}

        with self.driver.session() as s:
            result = s.run("""
                MATCH (d:DetectionPattern)
                WHERE d.id IN $pattern_ids
                OPTIONAL MATCH (t:MITRETechnique)-[:DETECTED_BY]->(d)
                OPTIONAL MATCH (d)-[:TRIGGERS]->(p:Playbook)
                OPTIONAL MATCH (t)-[:AFFECTS]->(svc:AWSService)
                RETURN
                    t.technique_id as tech_id,
                    t.name as tech_name,
                    t.tactics as tactics,
                    t.description as tech_desc,
                    p.id as pb_id,
                    p.name as pb_name,
                    p.triage_questions as triage,
                    p.containment_steps as containment,
                    p.incident_types as incident_types,
                    svc.name as svc_name,
                    svc.security_sensitivity as sensitivity
            """, pattern_ids=pattern_ids)

            for rec in result:
                if rec["tech_id"]:
                    techniques[rec["tech_id"]] = {
                        "technique_id": rec["tech_id"],
                        "name": rec["tech_name"] or "",
                        "tactics": rec["tactics"] or [],
                        "description": (rec["tech_desc"] or "")[:200],
                    }
                if rec["pb_id"]:
                    try:
                        containment = json.loads(rec["containment"] or "[]")
                    except Exception:
                        containment = []
                    playbooks[rec["pb_id"]] = {
                        "playbook_id": rec["pb_id"],
                        "name": rec["pb_name"] or "",
                        "incident_types": rec["incident_types"] or [],
                        "triage_questions": rec["triage"] or [],
                        "containment_steps": containment[:3],  # Top 3 for LLM context
                    }
                if rec["svc_name"]:
                    services[rec["svc_name"]] = {
                        "name": rec["svc_name"],
                        "sensitivity": rec["sensitivity"] or "Medium",
                    }

        return {
            "techniques": list(techniques.values()),
            "technique_ids": list(techniques.keys()),
            "playbooks": list(playbooks.values()),
            "services": list(services.values()),
        }

    def _get_chain_playbooks(self, technique_ids: List[str]) -> List[Dict]:
        """
        Follow ENABLES relationships to find what this attack commonly leads to.
        Pre-fetch those playbooks proactively.

        E.g. reconnaissance detected → ENABLES → privilege_escalation
        → return privilege escalation playbook too
        """
        if not technique_ids or not self.driver:
            return []

        chain_playbooks = {}
        with self.driver.session() as s:
            result = s.run("""
                MATCH (t1:MITRETechnique)-[:ENABLES]->(t2:MITRETechnique)
                WHERE t1.technique_id IN $tech_ids
                OPTIONAL MATCH (t2)-[:DETECTED_BY]->(d:DetectionPattern)-[:TRIGGERS]->(p:Playbook)
                RETURN t1.technique_id as from_tech,
                       t2.technique_id as to_tech,
                       t2.name as to_name,
                       p.id as pb_id,
                       p.name as pb_name,
                       p.incident_types as incident_types
            """, tech_ids=technique_ids)

            for rec in result:
                if rec["pb_id"] and rec["pb_id"] not in chain_playbooks:
                    chain_playbooks[rec["pb_id"]] = {
                        "playbook_id": rec["pb_id"],
                        "name": rec["pb_name"] or "",
                        "incident_types": rec["incident_types"] or [],
                        "chain_reason": (
                            f"{rec['from_tech']} commonly enables {rec['to_tech']} "
                            f"({rec['to_name']})"
                        ),
                    }

        return list(chain_playbooks.values())[:3]

    # ── ChromaDB retrieval ────────────────────────────────────────────────────

    def _search_similar_incidents(
        self, user: str, feature_values: Dict, attack_hint: str = ""
    ) -> List[Dict]:
        """
        Search behavioral_incidents using multi-query retrieval strategy.
        
        Generates three different semantic views of the alert to improve recall:
        - Query A: Behavioral summary (feature values)
        - Query B: Anomaly description (event patterns)
        - Query C: Attack style (attack characteristics)
        
        Combines results from all queries, keeping highest similarity for each incident.
        """
        if not self.incidents_col or not self.embedder:
            return []

        # Extract feature values
        iam_writes = int(feature_values.get("iam_write_events", 0))
        iam_lists = int(feature_values.get("iam_list_events", 0))
        s3_gets = int(feature_values.get("s3_get_events", 0))
        s3_dels = int(feature_values.get("s3_delete_events", 0))
        after_hrs = float(feature_values.get("after_hours_ratio", 0))
        total_z = float(feature_values.get("total_events_zscore", 0))
        slope = float(feature_values.get("s3_get_slope_3d", 0))

        # ── Generate three semantic views of the alert ────────────────────────
        
        # Query A: Behavioral summary (feature counts and ratios)
        query_a = (
            f"User {user} anomaly: iam writes {iam_writes}, iam list {iam_lists}, "
            f"s3 reads {s3_gets}, s3 deletes {s3_dels}, after hours activity {after_hrs:.2f}"
        )
        
        # Query B: Anomaly description (detection-focused)
        query_b = (
            f"AWS CloudTrail anomaly detection: abnormal IAM activity and S3 access. "
            f"event volume zscore {total_z:.1f}, suspicious user behavior, {attack_hint}"
        )
        
        # Query C: Attack style query (attack characteristics)
        query_c = (
            f"possible cloud security attack involving IAM privilege escalation, "
            f"s3 data access anomaly, unusual API activity by user {user}, "
            f"s3 exfiltration pattern slope {slope:.2f}"
        )
        
        queries = [query_a, query_b, query_c]
        log.debug(f"Multi-query retrieval: {queries}")

        try:
            # ── Embed all three queries ────────────────────────────────────────
            embeddings = self.embedder.encode(queries)
            
            # ── Run ChromaDB search for each query ──────────────────────────────
            combined_results = {}  # {doc_id: {doc, meta, best_similarity}}
            
            for idx, embedding in enumerate(embeddings):
                log.debug(f"Query {idx + 1}/3 searching ChromaDB...")
                
                results = self.incidents_col.query(
                    query_embeddings=[embedding.tolist()],
                    n_results=4,  # Get more per query to improve recall
                    include=["documents", "metadatas", "distances"]
                )
                
                # ── Combine results, keeping highest similarity ──────────────────
                if results and results["documents"]:
                    for doc, meta, dist in zip(
                        results["documents"][0],
                        results["metadatas"][0],
                        results["distances"][0]
                    ):
                        similarity = round(1 - dist, 3)  # Convert distance to similarity
                        doc_id = f"{meta.get('user_name', 'unknown')}_{doc[:50]}"
                        
                        # Keep highest similarity score for this document
                        if (
                            doc_id not in combined_results 
                            or similarity > combined_results[doc_id]["similarity"]
                        ):
                            combined_results[doc_id] = {
                                "doc": doc,
                                "meta": meta,
                                "similarity": similarity,
                            }
            
            # ── Sort by similarity and return top 3 ─────────────────────────────
            sorted_results = sorted(
                combined_results.values(),
                key=lambda x: x["similarity"],
                reverse=True
            )[:3]
            
            similar = [
                {
                    "summary": result["doc"],
                    "attack_name": result["meta"].get("attack_name", "unknown"),
                    "user": result["meta"].get("user_name", "unknown"),
                    "similarity": result["similarity"],
                }
                for result in sorted_results
            ]
            
            log.debug(f"Found {len(similar)} similar incidents (multi-query)")
            return similar
            
        except Exception as e:
            log.debug(f"Multi-query incident search failed: {e}")
            return []


    def _search_threat_intel(
        self, matched_patterns: List[Dict], technique_ids: List[str]
    ) -> List[Dict]:
        """Search threat_intelligence collection for relevant context."""
        if not self.ti_col or not self.embedder:
            return []

        # Build query from pattern names and technique IDs
        pattern_names = " ".join([p.get("name", "") for p in matched_patterns[:3]])
        tech_str = " ".join(technique_ids[:3])
        query = f"{pattern_names} {tech_str} AWS CloudTrail anomaly detection response"

        try:
            embedding = self.embedder.encode(query).tolist()
            results = self.ti_col.query(
                query_embeddings=[embedding],
                n_results=4,
                include=["documents", "metadatas", "distances"]
            )

            docs = []
            if results and results["documents"]:
                for doc, meta, dist in zip(
                    results["documents"][0],
                    results["metadatas"][0],
                    results["distances"][0]
                ):
                    docs.append({
                        "content": doc[:300],  # Truncate for LLM context
                        "type": meta.get("type", "unknown"),
                        "source_id": meta.get("technique_id") or meta.get("pattern_id") or meta.get("playbook_id", ""),
                        "similarity": round(1 - dist, 3),
                    })
            return docs
        except Exception as e:
            log.debug(f"Threat intel search failed: {e}")
            return []

    # ── Utility methods ───────────────────────────────────────────────────────

    def _models_that_fired(self, if_score: float, lof_score: float, ae_score: float) -> List[str]:
        fired = []
        if if_score > 0.5:
            fired.append(f"IsolationForest({if_score:.3f})")
        if lof_score > 0.5:
            fired.append(f"LOF({lof_score:.3f})")
        if ae_score > 0.5:
            fired.append(f"Autoencoder({ae_score:.3f})")
        return fired

    def _compute_severity(
        self, ensemble_score: float, vote_count: int, patterns: List[Dict]
    ) -> str:
        critical_patterns = any(p.get("severity") == "Critical" for p in patterns)
        if ensemble_score > 0.85 or (vote_count == 3 and critical_patterns):
            return "CRITICAL"
        elif ensemble_score > 0.70 or vote_count >= 2:
            return "HIGH"
        elif ensemble_score > 0.50:
            return "MEDIUM"
        return "LOW"

    def _build_rag_query(
        self, user: str, features: Dict, patterns: List[Dict],
        techniques: List[Dict], models_fired: List[str]
    ) -> str:
        """Build the natural language query string passed to the LLM."""
        pattern_names = ", ".join([p.get("name", "") for p in patterns[:2]])
        tech_names = ", ".join([t.get("name", "") for t in techniques[:2]])
        model_str = ", ".join(models_fired)

        notable_features = []
        for col, val in features.items():
            if "zscore" in col and abs(val) > 2.0:
                notable_features.append(f"{col}={val:.1f}")
            elif col == "after_hours_ratio" and val > 0.5:
                notable_features.append(f"after_hours={val:.2f}")
            elif col == "s3_get_slope_3d" and abs(val) > 5:
                notable_features.append(f"s3_slope={val:.1f}")

        features_str = ", ".join(notable_features[:4])

        return (
            f"User {user} flagged by {model_str}. "
            f"Patterns matched: {pattern_names}. "
            f"Techniques: {tech_names}. "
            f"Key signals: {features_str}. "
            f"Determine attack type, severity, and immediate response."
        )


# ── Standalone runner ─────────────────────────────────────────────────────────

def load_data():
    """Load all data needed for enrichment."""
    import pandas as pd

    # Feature matrix
    fm_path = PROJECT_ROOT / "data" / "features" / "feature_matrix.csv.gz"
    fm_parquet = PROJECT_ROOT / "data" / "features" / "feature_matrix.parquet"
    if fm_parquet.exists():
        feature_df = pd.read_parquet(fm_parquet)
    elif fm_path.exists():
        feature_df = pd.read_csv(fm_path, compression="gzip")
        if "window" in feature_df.columns:
            feature_df["window"] = pd.to_datetime(feature_df["window"], utc=True)
    else:
        raise FileNotFoundError("Feature matrix not found. Run run_pipeline.py first.")

    # Normalized events
    norm_path = PROJECT_ROOT / "data" / "normalized" / "events_labeled.csv.gz"
    norm_parquet = PROJECT_ROOT / "data" / "normalized" / "events.parquet"
    if norm_parquet.exists():
        normalized_df = pd.read_parquet(norm_parquet)
    elif norm_path.exists():
        normalized_df = pd.read_csv(norm_path, compression="gzip")
    else:
        normalized_df = pd.DataFrame()
        log.warning("Normalized events not found — event context will be empty")

    # Ensemble alerts
    alerts_path = PROJECT_ROOT / "data" / "results" / "ensemble_alerts.csv"
    if not alerts_path.exists():
        raise FileNotFoundError("ensemble_alerts.csv not found. Run run_models.py first.")
    alerts_df = pd.read_csv(alerts_path)
    alerts_df["window"] = pd.to_datetime(alerts_df["window"], utc=True)

    return feature_df, normalized_df, alerts_df


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    import os
    import chromadb
    from neo4j import GraphDatabase
    from sentence_transformers import SentenceTransformer

    neo4j_uri = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASSWORD", "neo4j1234")

    log.info("Connecting to Neo4j and ChromaDB...")
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    client = chromadb.PersistentClient(path=str(PROJECT_ROOT / "chroma_db"))
    embedder = SentenceTransformer("all-MiniLM-L6-v2")

    enricher = AlertEnricher(driver, client, embedder)

    log.info("Loading data...")
    feature_df, normalized_df, alerts_df = load_data()

    log.info(f"Processing top 5 alerts from {len(alerts_df)} flagged windows...")
    top_alerts = alerts_df.nlargest(5, "ensemble_score")

    results = []
    for _, row in top_alerts.iterrows():
        payload = enricher.enrich(row, feature_df, normalized_df)
        results.append(payload)

        print(f"\n{'='*60}")
        print(f"ALERT: {payload['alert']['user']} | "
              f"{payload['alert']['severity']} | "
              f"score={payload['alert']['ensemble_score']}")
        print(f"  Models fired: {', '.join(payload['alert']['models_fired'])}")
        print(f"  Patterns matched: {len(payload['detection']['matched_patterns'])}")
        for p in payload['detection']['matched_patterns']:
            print(f"    [{p['severity']}] {p['name']} (match={p['match_score']})")
        print(f"  Techniques: {[t['technique_id'] for t in payload['detection']['techniques']]}")
        print(f"  Playbooks: {[pb['playbook_id'] for pb in payload['detection']['primary_playbooks']]}")
        print(f"  Chain playbooks: {[pb['playbook_id'] for pb in payload['detection']['chain_playbooks']]}")
        print(f"  Similar incidents: {len(payload['rag_retrieval']['similar_past_incidents'])}")
        print(f"  RAG query: {payload['rag_query']}")

    driver.close()
    log.info("Done.")


if __name__ == "__main__":
    main()
