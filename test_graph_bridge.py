#!/usr/bin/env python3
"""
Test script for unified graph bridging.

This script demonstrates how to:
1. Run the graph bridge creation
2. Verify the bridges
3. Use graph-accelerated alert enrichment

Usage:
    python test_graph_bridge.py
"""

import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("test_graph_bridge")


def test_bridge_creation():
    """Test creating graph bridges."""
    log.info("=" * 70)
    log.info("TEST 1: Graph Bridge Creation")
    log.info("=" * 70)
    
    from rag_ingestion.bridge_graphs import GraphBridge
    
    bridge = GraphBridge()
    try:
        # Create bridges
        window_count = bridge.ingest_window_nodes()
        log.info(f"✅ Created {window_count} Window nodes")
        
        matches_count = bridge.create_matches_pattern_edges()
        log.info(f"✅ Created {matches_count} MATCHES_PATTERN edges")
        
        triggers_count = bridge.create_triggers_indicator_edges()
        log.info(f"✅ Created {triggers_count} TRIGGERS_INDICATOR edges")
        
        anomalous_count = bridge.create_anomalous_for_edges()
        log.info(f"✅ Created {anomalous_count} ANOMALOUS_FOR edges")
        
        # Verify
        bridge.verify_bridges()
        
        return True
    except Exception as e:
        log.error(f"Bridge creation failed: {e}", exc_info=True)
        return False
    finally:
        bridge.close()


def test_graph_queries():
    """Test basic graph queries after bridging."""
    log.info("")
    log.info("=" * 70)
    log.info("TEST 2: Graph Queries")
    log.info("=" * 70)
    
    from neo4j import GraphDatabase
    
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "neo4j1234")
    
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    try:
        with driver.session() as s:
            # Query 1: Find anomalous windows with patterns
            log.info("\nQuery 1: Anomalous windows with matched patterns")
            result = s.run("""
                MATCH (w:Window)-[ti:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                WHERE w.ensemble_pred = 1
                RETURN w.user_name as user_name, w.window as window_time, 
                       w.ensemble_score as ensemble_score, 
                       d.name as pattern_name, ti.match_score as match_score
                ORDER BY w.ensemble_score DESC
                LIMIT 3
            """)
            for idx, rec in enumerate(result, 1):
                log.info(f"  {idx}. User: {rec['user_name']}, "
                        f"Score: {rec['ensemble_score']:.3f}, "
                        f"Pattern: {rec['pattern_name']} (match: {rec['match_score']:.2f})")
            
            # Query 2: Pattern trigger frequency
            log.info("\nQuery 2: Most frequently triggered patterns")
            result = s.run("""
                MATCH (w:Window)-[:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                RETURN d.name as pattern_name, d.severity as severity, 
                       count(w) as trigger_count
                ORDER BY trigger_count DESC
                LIMIT 3
            """)
            for idx, rec in enumerate(result, 1):
                log.info(f"  {idx}. {rec['pattern_name']} ({rec['severity']}) - "
                        f"{rec['trigger_count']} triggers")
            
            # Query 3: Full chain traversal
            log.info("\nQuery 3: Full attack chain (Window → Pattern → Technique → Playbook)")
            result = s.run("""
                MATCH (w:Window)-[:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                MATCH (t:MITRETechnique)-[:DETECTED_BY]->(d)
                MATCH (d)-[:TRIGGERS]->(p:Playbook)
                WHERE w.is_attack = true
                RETURN w.user_name as user_name, w.attack_name as attack_name, 
                       d.name as pattern, t.technique_id as technique_id, 
                       p.name as playbook
                LIMIT 3
            """)
            for idx, rec in enumerate(result, 1):
                log.info(f"  {idx}. {rec['user_name']} ({rec['attack_name']}) → "
                        f"{rec['pattern']} → {rec['technique_id']} → {rec['playbook']}")
            
        return True
    except Exception as e:
        log.error(f"Graph queries failed: {e}", exc_info=True)
        return False
    finally:
        driver.close()


def test_alert_enrichment():
    """Test graph-accelerated alert enrichment."""
    log.info("")
    log.info("=" * 70)
    log.info("TEST 3: Graph-Accelerated Alert Enrichment")
    log.info("=" * 70)
    
    import pandas as pd
    import chromadb
    from neo4j import GraphDatabase
    from sentence_transformers import SentenceTransformer
    from rag_ingestion.alert_enrichment import AlertEnricher
    
    PROJECT_ROOT = Path(__file__).parent
    
    # Load data
    try:
        alerts_path = PROJECT_ROOT / "data" / "results" / "ensemble_alerts.csv"
        if not alerts_path.exists():
            log.warning("No alerts found, skipping enrichment test")
            return True
        
        alerts_df = pd.read_csv(alerts_path)
        alerts_df["window"] = pd.to_datetime(alerts_df["window"], utc=True)
        
        feature_path = PROJECT_ROOT / "data" / "features" / "feature_matrix.parquet"
        if feature_path.exists():
            feature_df = pd.read_parquet(feature_path)
        else:
            log.warning("Feature matrix not found, skipping enrichment test")
            return True
        
        # Get normalized events (optional)
        normalized_df = pd.DataFrame()
        
    except Exception as e:
        log.warning(f"Could not load data for enrichment test: {e}")
        return True
    
    # Setup connections
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "neo4j1234")
    
    driver = GraphDatabase.driver(uri, auth=(user, password))
    client = chromadb.PersistentClient(path=str(PROJECT_ROOT / "chroma_db"))
    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    
    try:
        # Test with graph bridges (new method)
        enricher_graph = AlertEnricher(driver, client, embedder, use_graph_bridges=True)
        
        # Test with legacy method
        enricher_legacy = AlertEnricher(driver, client, embedder, use_graph_bridges=False)
        
        # Pick first alert
        alert = alerts_df.iloc[0]
        
        log.info(f"\nEnriching alert: user={alert['user_name']}, score={alert['ensemble_score']:.3f}")
        
        # Compare methods
        import time
        
        log.info("\n1. Graph bridge method (NEW):")
        start = time.time()
        payload_graph = enricher_graph.enrich(alert, feature_df, normalized_df)
        graph_time = time.time() - start
        log.info(f"   Time: {graph_time*1000:.1f}ms")
        log.info(f"   Matched patterns: {len(payload_graph['detection']['matched_patterns'])}")
        for p in payload_graph['detection']['matched_patterns'][:3]:
            log.info(f"     - {p['name']} (score: {p['match_score']:.2f})")
        
        log.info("\n2. Legacy Python method (OLD):")
        start = time.time()
        payload_legacy = enricher_legacy.enrich(alert, feature_df, normalized_df)
        legacy_time = time.time() - start
        log.info(f"   Time: {legacy_time*1000:.1f}ms")
        log.info(f"   Matched patterns: {len(payload_legacy['detection']['matched_patterns'])}")
        for p in payload_legacy['detection']['matched_patterns'][:3]:
            log.info(f"     - {p['name']} (score: {p['match_score']:.2f})")
        
        speedup = legacy_time / graph_time if graph_time > 0 else 0
        log.info(f"\n✅ Speedup: {speedup:.1f}x faster with graph bridges")
        
        return True
    except Exception as e:
        log.error(f"Alert enrichment test failed: {e}", exc_info=True)
        return False
    finally:
        driver.close()


def main():
    """Run all tests."""
    log.info("UNIFIED GRAPH BRIDGE TEST SUITE")
    log.info("")
    
    tests = [
        ("Bridge Creation", test_bridge_creation),
        ("Graph Queries", test_graph_queries),
        ("Alert Enrichment", test_alert_enrichment),
    ]
    
    results = {}
    for name, test_func in tests:
        try:
            success = test_func()
            results[name] = success
        except Exception as e:
            log.error(f"Test '{name}' crashed: {e}", exc_info=True)
            results[name] = False
    
    # Summary
    log.info("")
    log.info("=" * 70)
    log.info("TEST SUMMARY")
    log.info("=" * 70)
    for name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        log.info(f"{status} - {name}")
    
    total = len(results)
    passed = sum(results.values())
    log.info("")
    log.info(f"Total: {passed}/{total} tests passed")
    log.info("=" * 70)
    
    return all(results.values())


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
