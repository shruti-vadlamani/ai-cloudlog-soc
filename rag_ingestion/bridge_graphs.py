#!/usr/bin/env python3
"""
rag_ingestion/bridge_graphs.py
================================
Unified graph bridging — connects CloudTrail event/window data to knowledge base graph.

Creates bridges between two previously disconnected graphs:
  Graph 1 — Knowledge Base: MITRETechnique, DetectionPattern, Playbook, AWSService
  Graph 2 — Event Provenance: User, Event, Resource

Bridge components:
  1. Window nodes from feature matrix (aggregated behavioral data)
  2. MATCHES_PATTERN edges (Event → DetectionPattern based on eventName)
  3. TRIGGERS_INDICATOR edges (Window → DetectionPattern based on feature thresholds)
  4. HAD_WINDOW edges (User → Window for temporal context)
  5. ANOMALOUS_FOR edges (Window → User for flagged windows)

Run AFTER:
  - run_pipeline.py (generates features)
  - run_models.py (generates ensemble scores)
  - ingest_knowledge_graph.py (loads KB into Neo4j)
  - parquet_to_rag.ingest_to_neo4j (loads event graph)

Usage:
    python rag_ingestion/bridge_graphs.py
"""

import gzip
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from neo4j import GraphDatabase

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("bridge_graphs")

PROJECT_ROOT = Path(__file__).parent.parent
FEATURE_MATRIX_PARQUET = PROJECT_ROOT / "data" / "features" / "feature_matrix.parquet"
FEATURE_MATRIX_CSVGZ = PROJECT_ROOT / "data" / "features" / "feature_matrix.csv.gz"
ENSEMBLE_SCORES_CSV = PROJECT_ROOT / "data" / "models" / "ensemble_scores.csv"

BATCH_SIZE = 200


class GraphBridge:
    """
    Connects event provenance graph to knowledge base graph via Window nodes
    and semantic edges.
    """

    def __init__(
        self,
        uri: str = None,
        user: str = None,
        password: str = None
    ):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "neo4j1234")
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        log.info(f"Connected to Neo4j at {self.uri}")

    def close(self):
        self.driver.close()

    # ── Step 1: Add Window nodes ──────────────────────────────────────────────

    def ingest_window_nodes(self) -> int:
        """
        Create Window nodes from feature matrix and ensemble scores.
        Links each Window to its User via HAD_WINDOW relationship.

        Returns:
            Number of Window nodes created/updated
        """
        log.info("Step 1: Ingesting Window nodes from feature matrix...")

        # Load feature matrix
        feature_df = self._load_feature_matrix()
        if feature_df.empty:
            log.warning("Feature matrix is empty, skipping Window node ingestion")
            return 0

        # Load ensemble scores
        ensemble_df = self._load_ensemble_scores()

        # Join ensemble scores to feature matrix
        if not ensemble_df.empty:
            # Ensure both DataFrames have matching data types for 'window' column
            if "window" in feature_df.columns and "window" in ensemble_df.columns:
                # Convert both to datetime for consistent merging
                feature_df["window"] = pd.to_datetime(feature_df["window"], utc=True)
                ensemble_df["window"] = pd.to_datetime(ensemble_df["window"], utc=True)
            
            feature_df = feature_df.merge(
                ensemble_df[["user_name", "window", "ensemble_score", "ensemble_pred"]],
                on=["user_name", "window"],
                how="left"
            )
            feature_df["ensemble_score"] = feature_df["ensemble_score"].fillna(0.0)
            feature_df["ensemble_pred"] = feature_df["ensemble_pred"].fillna(0).astype(int)
        else:
            feature_df["ensemble_score"] = 0.0
            feature_df["ensemble_pred"] = 0

        log.info(f"Loaded {len(feature_df)} windows from feature matrix")

        # Create constraint for Window nodes
        with self.driver.session() as s:
            s.run("CREATE CONSTRAINT IF NOT EXISTS FOR (w:Window) REQUIRE w.window_id IS UNIQUE")

        # Batch ingest Window nodes
        records = feature_df.to_dict(orient="records")
        total = len(records)
        created_count = 0

        for i in range(0, total, BATCH_SIZE):
            batch = records[i : i + BATCH_SIZE]
            with self.driver.session() as s:
                result = s.execute_write(self._write_window_batch, batch)
                created_count += result

            if (i + BATCH_SIZE) % 1000 == 0 or i + BATCH_SIZE >= total:
                log.info(f"  Windows: {min(i + BATCH_SIZE, total)}/{total} processed")

        log.info(f"✅ Window nodes: {created_count} created/updated")
        return created_count

    def _load_feature_matrix(self) -> pd.DataFrame:
        """Load feature matrix from parquet or csv.gz."""
        if FEATURE_MATRIX_PARQUET.exists():
            log.info(f"Loading feature matrix from {FEATURE_MATRIX_PARQUET}")
            return pd.read_parquet(FEATURE_MATRIX_PARQUET)
        elif FEATURE_MATRIX_CSVGZ.exists():
            log.info(f"Loading feature matrix from {FEATURE_MATRIX_CSVGZ}")
            with gzip.open(FEATURE_MATRIX_CSVGZ, 'rt') as f:
                return pd.read_csv(f)
        else:
            log.error("Feature matrix not found at expected paths")
            return pd.DataFrame()

    def _load_ensemble_scores(self) -> pd.DataFrame:
        """Load ensemble scores from CSV."""
        if ENSEMBLE_SCORES_CSV.exists():
            log.info(f"Loading ensemble scores from {ENSEMBLE_SCORES_CSV}")
            df = pd.read_csv(ENSEMBLE_SCORES_CSV)
            # Ensure ensemble_pred is int
            if "ensemble_pred" in df.columns:
                df["ensemble_pred"] = df["ensemble_pred"].astype(int)
            return df
        else:
            log.warning("Ensemble scores not found")
            return pd.DataFrame()

    @staticmethod
    def _write_window_batch(tx, batch: List[Dict]) -> int:
        """Write batch of Window nodes and HAD_WINDOW relationships."""
        windows = []
        for row in batch:
            window_id = f"{row.get('user_name', 'unknown')}_{row.get('window', '')}"
            windows.append({
                "window_id": window_id,
                "user_name": str(row.get("user_name", "unknown")),
                "window": str(row.get("window", "")),
                "total_events": float(row.get("total_events", 0)),
                "iam_write_events": float(row.get("iam_write_events", 0)),
                "iam_list_events": float(row.get("iam_list_events", 0)),
                "s3_get_events": float(row.get("s3_get_events", 0)),
                "s3_delete_events": float(row.get("s3_delete_events", 0)),
                "after_hours_ratio": float(row.get("after_hours_ratio", 0)),
                "iam_ratio": float(row.get("iam_ratio", 0)),
                "write_ratio": float(row.get("write_ratio", 0)),
                "delete_ratio": float(row.get("delete_ratio", 0)),
                "total_events_zscore": float(row.get("total_events_zscore", 0)),
                "iam_events_zscore": float(row.get("iam_events_zscore", 0)),
                "s3_get_events_zscore": float(row.get("s3_get_events_zscore", 0)),
                "iam_list_events_zscore": float(row.get("iam_list_events_zscore", 0)),
                "iam_write_events_zscore": float(row.get("iam_write_events_zscore", 0)),
                "s3_delete_events_zscore": float(row.get("s3_delete_events_zscore", 0)),
                "s3_get_slope_3d": float(row.get("s3_get_slope_3d", 0)),
                "window_is_business_hours": bool(row.get("window_is_business_hours", True)),
                "window_is_weekend": bool(row.get("window_is_weekend", False)),
                "ensemble_score": float(row.get("ensemble_score", 0.0)),
                "ensemble_pred": int(row.get("ensemble_pred", 0)),
                "is_attack": bool(row.get("is_attack", False)),
                "attack_name": str(row.get("attack_name", "normal")),
            })

        cypher = """
        UNWIND $windows AS w
        MERGE (win:Window {window_id: w.window_id})
        SET win.user_name = w.user_name,
            win.window = w.window,
            win.total_events = w.total_events,
            win.iam_write_events = w.iam_write_events,
            win.iam_list_events = w.iam_list_events,
            win.s3_get_events = w.s3_get_events,
            win.s3_delete_events = w.s3_delete_events,
            win.after_hours_ratio = w.after_hours_ratio,
            win.iam_ratio = w.iam_ratio,
            win.write_ratio = w.write_ratio,
            win.delete_ratio = w.delete_ratio,
            win.total_events_zscore = w.total_events_zscore,
            win.iam_events_zscore = w.iam_events_zscore,
            win.s3_get_events_zscore = w.s3_get_events_zscore,
            win.iam_list_events_zscore = w.iam_list_events_zscore,
            win.iam_write_events_zscore = w.iam_write_events_zscore,
            win.s3_delete_events_zscore = w.s3_delete_events_zscore,
            win.s3_get_slope_3d = w.s3_get_slope_3d,
            win.window_is_business_hours = w.window_is_business_hours,
            win.window_is_weekend = w.window_is_weekend,
            win.ensemble_score = w.ensemble_score,
            win.ensemble_pred = w.ensemble_pred,
            win.is_attack = w.is_attack,
            win.attack_name = w.attack_name
        MERGE (u:User {name: w.user_name})
        MERGE (u)-[:HAD_WINDOW]->(win)
        """
        result = tx.run(cypher, windows=windows)
        summary = result.consume()
        return summary.counters.nodes_created + summary.counters.properties_set

    # ── Step 2: MATCHES_PATTERN edges (Event → DetectionPattern) ──────────────

    def create_matches_pattern_edges(self) -> int:
        """
        Create MATCHES_PATTERN edges from Event nodes to DetectionPattern nodes
        based on eventName matching cloudtrail_events array.

        Uses efficient Cypher query (no Python loop).

        Returns:
            Number of MATCHES_PATTERN edges created
        """
        log.info("Step 2: Creating MATCHES_PATTERN edges (Event → DetectionPattern)...")

        with self.driver.session() as s:
            result = s.run("""
                MATCH (e:Event), (d:DetectionPattern)
                WHERE e.eventName IN d.cloudtrail_events
                MERGE (e)-[:MATCHES_PATTERN {confidence: 0.9}]->(d)
            """)
            summary = result.consume()
            edges_created = summary.counters.relationships_created

        log.info(f"✅ MATCHES_PATTERN edges: {edges_created} created")
        return edges_created

    # ── Step 3: TRIGGERS_INDICATOR edges (Window → DetectionPattern) ──────────

    def create_triggers_indicator_edges(self) -> int:
        """
        Create TRIGGERS_INDICATOR edges from Window nodes to DetectionPattern nodes
        based on behavioral_indicators threshold matching.

        This compares Window feature values against DetectionPattern thresholds.
        Only creates edge if match_score >= 0.5 (at least half indicators match).

        Returns:
            Number of TRIGGERS_INDICATOR edges created
        """
        log.info("Step 3: Creating TRIGGERS_INDICATOR edges (Window → DetectionPattern)...")

        # Load all DetectionPattern nodes with behavioral_indicators
        patterns = self._load_detection_patterns()
        if not patterns:
            log.warning("No detection patterns found with behavioral_indicators")
            return 0

        log.info(f"Loaded {len(patterns)} detection patterns")

        # Load all Window nodes with feature values
        windows = self._load_window_features()
        if not windows:
            log.warning("No windows found")
            return 0

        log.info(f"Loaded {len(windows)} windows")

        # Compute matches
        edges = []
        for window_id, window_features in windows.items():
            for pattern_id, pattern_indicators in patterns.items():
                match_score, matched_features = self._compute_match_score(
                    window_features, pattern_indicators
                )
                if match_score >= 0.5:
                    edges.append({
                        "window_id": window_id,
                        "pattern_id": pattern_id,
                        "match_score": round(match_score, 3),
                        "matched_features": matched_features,
                    })

        log.info(f"Computed {len(edges)} Window-Pattern matches (score >= 0.5)")

        # Batch write edges
        total = len(edges)
        created_count = 0

        for i in range(0, total, BATCH_SIZE):
            batch = edges[i : i + BATCH_SIZE]
            with self.driver.session() as s:
                result = s.execute_write(self._write_triggers_indicator_batch, batch)
                created_count += result

            if (i + BATCH_SIZE) % 1000 == 0 or i + BATCH_SIZE >= total:
                log.info(f"  TRIGGERS_INDICATOR: {min(i + BATCH_SIZE, total)}/{total} processed")

        log.info(f"✅ TRIGGERS_INDICATOR edges: {created_count} created")
        return created_count

    def _load_detection_patterns(self) -> Dict[str, Dict]:
        """Load all DetectionPattern nodes with behavioral_indicators."""
        patterns = {}
        with self.driver.session() as s:
            result = s.run("""
                MATCH (d:DetectionPattern)
                WHERE d.behavioral_indicators IS NOT NULL
                RETURN d.id as pattern_id, d.behavioral_indicators as bi
            """)
            for rec in result:
                try:
                    bi = json.loads(rec["bi"])
                    if bi:
                        patterns[rec["pattern_id"]] = bi
                except (json.JSONDecodeError, TypeError):
                    continue
        return patterns

    def _load_window_features(self) -> Dict[str, Dict]:
        """Load all Window nodes with feature values."""
        windows = {}
        with self.driver.session() as s:
            result = s.run("""
                MATCH (w:Window)
                RETURN w.window_id as window_id,
                       w.iam_write_events as iam_write_events,
                       w.iam_list_events as iam_list_events,
                       w.s3_get_events as s3_get_events,
                       w.s3_delete_events as s3_delete_events,
                       w.after_hours_ratio as after_hours_ratio,
                       w.iam_ratio as iam_ratio,
                       w.write_ratio as write_ratio,
                       w.delete_ratio as delete_ratio,
                       w.total_events_zscore as total_events_zscore,
                       w.iam_events_zscore as iam_events_zscore,
                       w.s3_get_events_zscore as s3_get_events_zscore,
                       w.iam_list_events_zscore as iam_list_events_zscore,
                       w.iam_write_events_zscore as iam_write_events_zscore,
                       w.s3_delete_events_zscore as s3_delete_events_zscore,
                       w.s3_get_slope_3d as s3_get_slope_3d
            """)
            for rec in result:
                window_id = rec["window_id"]
                windows[window_id] = {
                    "iam_write_events": rec.get("iam_write_events", 0),
                    "iam_list_events": rec.get("iam_list_events", 0),
                    "s3_get_events": rec.get("s3_get_events", 0),
                    "s3_delete_events": rec.get("s3_delete_events", 0),
                    "after_hours_ratio": rec.get("after_hours_ratio", 0),
                    "iam_ratio": rec.get("iam_ratio", 0),
                    "write_ratio": rec.get("write_ratio", 0),
                    "delete_ratio": rec.get("delete_ratio", 0),
                    "total_events_zscore": rec.get("total_events_zscore", 0),
                    "iam_events_zscore": rec.get("iam_events_zscore", 0),
                    "s3_get_events_zscore": rec.get("s3_get_events_zscore", 0),
                    "iam_list_events_zscore": rec.get("iam_list_events_zscore", 0),
                    "iam_write_events_zscore": rec.get("iam_write_events_zscore", 0),
                    "s3_delete_events_zscore": rec.get("s3_delete_events_zscore", 0),
                    "s3_get_slope_3d": rec.get("s3_get_slope_3d", 0),
                }
        return windows

    def _compute_match_score(
        self, window_features: Dict, pattern_indicators: Dict
    ) -> Tuple[float, List[str]]:
        """
        Compute how well a window matches a pattern's behavioral indicators.

        Args:
            window_features: Feature values for a window
            pattern_indicators: Behavioral thresholds from DetectionPattern

        Returns:
            (match_score, matched_features) where match_score is 0.0-1.0
        """
        if not pattern_indicators:
            return 0.0, []

        hits = 0
        matched_features = []
        total = len(pattern_indicators)

        for feature_name, threshold_def in pattern_indicators.items():
            actual_value = window_features.get(feature_name)
            if actual_value is None:
                continue

            threshold = threshold_def.get("threshold", 0)
            direction = threshold_def.get("direction", "above")

            if direction == "above" and actual_value > threshold:
                hits += 1
                matched_features.append(feature_name)
            elif direction == "below" and actual_value < threshold:
                hits += 1
                matched_features.append(feature_name)

        match_score = hits / total if total > 0 else 0.0
        return match_score, matched_features

    @staticmethod
    def _write_triggers_indicator_batch(tx, batch: List[Dict]) -> int:
        """Write batch of TRIGGERS_INDICATOR edges."""
        cypher = """
        UNWIND $edges AS e
        MATCH (w:Window {window_id: e.window_id})
        MATCH (d:DetectionPattern {id: e.pattern_id})
        MERGE (w)-[:TRIGGERS_INDICATOR {
            match_score: e.match_score,
            matched_features: e.matched_features
        }]->(d)
        """
        result = tx.run(cypher, edges=batch)
        summary = result.consume()
        return summary.counters.relationships_created

    # ── Step 4: ANOMALOUS_FOR edges ────────────────────────────────────────────

    def create_anomalous_for_edges(self) -> int:
        """
        Create ANOMALOUS_FOR edges from anomalous Window nodes to their User nodes.
        Only for windows where ensemble_pred == 1 (flagged as anomaly).

        Returns:
            Number of ANOMALOUS_FOR edges created
        """
        log.info("Step 4: Creating ANOMALOUS_FOR edges (Window → User for anomalies)...")

        with self.driver.session() as s:
            result = s.run("""
                MATCH (u:User)-[:HAD_WINDOW]->(w:Window)
                WHERE w.ensemble_pred = 1
                MERGE (w)-[:ANOMALOUS_FOR]->(u)
            """)
            summary = result.consume()
            edges_created = summary.counters.relationships_created

        log.info(f"✅ ANOMALOUS_FOR edges: {edges_created} created")
        return edges_created

    # ── Verification ───────────────────────────────────────────────────────────

    def verify_bridges(self) -> None:
        """
        Verify the bridge graph by printing statistics and example traversals.
        """
        log.info("=" * 70)
        log.info("BRIDGE GRAPH VERIFICATION")
        log.info("=" * 70)

        with self.driver.session() as s:
            # Count nodes and edges
            window_count = s.run("MATCH (w:Window) RETURN count(w) as cnt").single()["cnt"]
            matches_pattern_count = s.run(
                "MATCH ()-[r:MATCHES_PATTERN]->() RETURN count(r) as cnt"
            ).single()["cnt"]
            triggers_indicator_count = s.run(
                "MATCH ()-[r:TRIGGERS_INDICATOR]->() RETURN count(r) as cnt"
            ).single()["cnt"]
            had_window_count = s.run(
                "MATCH ()-[r:HAD_WINDOW]->() RETURN count(r) as cnt"
            ).single()["cnt"]
            anomalous_for_count = s.run(
                "MATCH ()-[r:ANOMALOUS_FOR]->() RETURN count(r) as cnt"
            ).single()["cnt"]

            print("\nBridge Graph Summary:")
            print(f"  Window nodes: {window_count}")
            print(f"  MATCHES_PATTERN edges: {matches_pattern_count}  (Event→DetectionPattern)")
            print(f"  TRIGGERS_INDICATOR edges: {triggers_indicator_count}  (Window→DetectionPattern)")
            print(f"  HAD_WINDOW edges: {had_window_count}  (User→Window)")
            print(f"  ANOMALOUS_FOR edges: {anomalous_for_count}  (Window→User)")

            # Coverage statistics
            windows_with_patterns = s.run("""
                MATCH (w:Window)-[:TRIGGERS_INDICATOR]->()
                RETURN count(DISTINCT w) as cnt
            """).single()["cnt"]

            attack_windows_total = s.run("""
                MATCH (w:Window)
                WHERE w.is_attack = true
                RETURN count(w) as cnt
            """).single()["cnt"]

            attack_windows_matched = s.run("""
                MATCH (w:Window)-[:TRIGGERS_INDICATOR]->()
                WHERE w.is_attack = true
                RETURN count(DISTINCT w) as cnt
            """).single()["cnt"]

            print("\nCoverage:")
            coverage_pct = (windows_with_patterns / window_count * 100) if window_count > 0 else 0
            print(f"  Windows with at least 1 matched pattern: {windows_with_patterns} / {window_count} ({coverage_pct:.1f}%)")
            
            if attack_windows_total > 0:
                attack_coverage_pct = (attack_windows_matched / attack_windows_total * 100)
                print(f"  Attack windows with at least 1 matched pattern: {attack_windows_matched} / {attack_windows_total} ({attack_coverage_pct:.1f}%)")

            # Example traversal
            print("\nExample traversal (first anomalous window):")
            result = s.run("""
                MATCH (u:User)-[:HAD_WINDOW]->(w:Window)-[ti:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                WHERE w.ensemble_pred = 1
                OPTIONAL MATCH (t:MITRETechnique)-[:DETECTED_BY]->(d)
                OPTIONAL MATCH (d)-[:TRIGGERS]->(p:Playbook)
                RETURN u.name as user,
                       w.window as window,
                       w.ensemble_score as score,
                       d.name as pattern,
                       ti.match_score as match_score,
                       collect(DISTINCT t.technique_id) as techniques,
                       collect(DISTINCT p.name) as playbooks
                LIMIT 1
            """).single()

            if result:
                print(f"  User: {result['user']}")
                print(f"  Window: {result['window']}")
                print(f"  Ensemble Score: {result['score']:.3f}")
                print(f"  Matched Pattern: {result['pattern']}")
                print(f"  Match Score: {result['match_score']:.3f}")
                print(f"  Techniques: {result['techniques']}")
                print(f"  Playbooks: {result['playbooks']}")
            else:
                print("  No anomalous windows found with pattern matches")

            # Show pattern with most triggers
            print("\nTop 3 Detection Patterns by trigger count:")
            result = s.run("""
                MATCH (w:Window)-[:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                RETURN d.id as pattern_id,
                       d.name as pattern_name,
                       d.severity as severity,
                       count(w) as trigger_count
                ORDER BY trigger_count DESC
                LIMIT 3
            """)
            for idx, rec in enumerate(result, 1):
                print(f"  {idx}. {rec['pattern_name']} ({rec['severity']}) - {rec['trigger_count']} triggers")

        log.info("=" * 70)
        log.info("✅ Bridge graph verification complete")
        log.info("=" * 70)


def main():
    """Main entry point for graph bridging."""
    log.info("=" * 70)
    log.info("UNIFIED GRAPH BRIDGING")
    log.info("=" * 70)

    bridge = GraphBridge()

    try:
        # Step 1: Ingest Window nodes
        window_count = bridge.ingest_window_nodes()

        # Step 2: Create MATCHES_PATTERN edges
        matches_pattern_count = bridge.create_matches_pattern_edges()

        # Step 3: Create TRIGGERS_INDICATOR edges
        triggers_indicator_count = bridge.create_triggers_indicator_edges()

        # Step 4: Create ANOMALOUS_FOR edges
        anomalous_for_count = bridge.create_anomalous_for_edges()

        # Verification
        bridge.verify_bridges()

        log.info("")
        log.info("=" * 70)
        log.info("BRIDGE CREATION COMPLETE")
        log.info("=" * 70)
        log.info(f"  Window nodes: {window_count}")
        log.info(f"  MATCHES_PATTERN edges: {matches_pattern_count}")
        log.info(f"  TRIGGERS_INDICATOR edges: {triggers_indicator_count}")
        log.info(f"  ANOMALOUS_FOR edges: {anomalous_for_count}")
        log.info("=" * 70)

    except Exception as e:
        log.error(f"Bridge creation failed: {e}", exc_info=True)
        raise
    finally:
        bridge.close()


if __name__ == "__main__":
    main()
