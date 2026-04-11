#!/usr/bin/env python3
"""
Quick verification script for graph bridge status.

Usage:
    python verify_graph_status.py
"""

from neo4j import GraphDatabase
from rag_ingestion.neo4j_env import get_neo4j_config


def main():
    cfg = get_neo4j_config(require_credentials=True)
    uri = cfg["uri"]
    user = cfg["username"]
    password = cfg["password"]
    database = cfg.get("database")
    
    print("=" * 70)
    print("GRAPH BRIDGE STATUS CHECK")
    print("=" * 70)
    print(f"Connecting to Neo4j at {uri}...")
    
    driver = GraphDatabase.driver(uri, auth=(user, password))
    session_kwargs = {"database": database} if database else {}
    
    try:
        with driver.session(**session_kwargs) as s:
            # Check if bridges exist
            print("\n📊 Node Counts:")
            window_count = s.run("MATCH (w:Window) RETURN count(w) as cnt").single()["cnt"]
            user_count = s.run("MATCH (u:User) RETURN count(u) as cnt").single()["cnt"]
            event_count = s.run("MATCH (e:Event) RETURN count(e) as cnt").single()["cnt"]
            pattern_count = s.run("MATCH (d:DetectionPattern) RETURN count(d) as cnt").single()["cnt"]
            
            print(f"  Windows: {window_count}")
            print(f"  Users: {user_count}")
            print(f"  Events: {event_count}")
            print(f"  Detection Patterns: {pattern_count}")
            
            print("\n🔗 Bridge Edge Counts:")
            had_window = s.run("MATCH ()-[r:HAD_WINDOW]->() RETURN count(r) as cnt").single()["cnt"]
            matches_pattern = s.run("MATCH ()-[r:MATCHES_PATTERN]->() RETURN count(r) as cnt").single()["cnt"]
            triggers_indicator = s.run("MATCH ()-[r:TRIGGERS_INDICATOR]->() RETURN count(r) as cnt").single()["cnt"]
            anomalous_for = s.run("MATCH ()-[r:ANOMALOUS_FOR]->() RETURN count(r) as cnt").single()["cnt"]
            
            print(f"  HAD_WINDOW: {had_window}")
            print(f"  MATCHES_PATTERN: {matches_pattern}")
            print(f"  TRIGGERS_INDICATOR: {triggers_indicator}")
            print(f"  ANOMALOUS_FOR: {anomalous_for}")
            
            # Check bridge status
            print("\n✅ Bridge Status:")
            if window_count == 0:
                print("  ⚠️  No Window nodes found")
                print("     → Run: python rag_ingestion/bridge_graphs.py")
            elif had_window == 0:
                print("  ⚠️  Window nodes exist but not linked to Users")
                print("     → Run: python rag_ingestion/bridge_graphs.py")
            elif triggers_indicator == 0:
                print("  ⚠️  No TRIGGERS_INDICATOR edges found")
                print("     → Check detection patterns have behavioral_indicators")
                print("     → Run: python rag_ingestion/bridge_graphs.py")
            else:
                print("  ✅ Bridges active and functional")
                if window_count > 0:
                    windows_with_patterns = s.run("""
                        MATCH (w:Window)-[:TRIGGERS_INDICATOR]->()
                        RETURN count(DISTINCT w) as cnt
                    """).single()["cnt"]
                    coverage = (windows_with_patterns / window_count) * 100 if window_count > 0 else 0
                    print(f"  📈 Pattern coverage: {coverage:.1f}% of windows matched")
            
            # Check alert enrichment readiness
            print("\n🚨 Alert Enrichment Readiness:")
            anomaly_count = s.run("MATCH (w:Window) WHERE w.ensemble_pred = 1 RETURN count(w) as cnt").single()["cnt"]
            anomalies_matched = s.run("""
                MATCH (w:Window)-[:TRIGGERS_INDICATOR]->()
                WHERE w.ensemble_pred = 1
                RETURN count(DISTINCT w) as cnt
            """).single()["cnt"]
            
            print(f"  Total anomalies: {anomaly_count}")
            print(f"  Anomalies with patterns: {anomalies_matched}")
            
            if anomaly_count > 0:
                enrichment_rate = (anomalies_matched / anomaly_count) * 100
                print(f"  Enrichment rate: {enrichment_rate:.1f}%")
                
                if enrichment_rate > 80:
                    print("  ✅ Ready for production alert enrichment")
                elif enrichment_rate > 50:
                    print("  ⚠️  Moderate enrichment coverage")
                    print("     → Consider adjusting pattern thresholds")
                else:
                    print("  ❌ Low enrichment coverage")
                    print("     → Review knowledge_base/detection_patterns.json")
            
            # Show sample traversal
            if triggers_indicator > 0:
                print("\n🔍 Sample Attack Chain:")
                try:
                    result = s.run("""
                        MATCH (u:User)-[:HAD_WINDOW]->(w:Window)
                              -[ti:TRIGGERS_INDICATOR]->(d:DetectionPattern)
                        OPTIONAL MATCH (t:MITRETechnique)-[:DETECTED_BY]->(d)
                        OPTIONAL MATCH (d)-[:TRIGGERS]->(p:Playbook)
                        WHERE w.ensemble_pred = 1
                        RETURN u.name as user_name, w.window as window_time, w.ensemble_score,
                               d.name as pattern_name, ti.match_score,
                               collect(DISTINCT t.technique_id)[0] as technique,
                               collect(DISTINCT p.name)[0] as playbook
                        LIMIT 1
                    """).single()
                    
                    if result:
                        print(f"  User: {result['user_name']}")
                        if result['window_time']:
                            print(f"  Window: {result['window_time']}")
                        if result.get('ensemble_score') is not None:
                            print(f"  Score: {result['ensemble_score']:.3f}")
                        if result.get('pattern_name'):
                            match_score = result.get('match_score', 0)
                            print(f"  Pattern: {result['pattern_name']} (match: {match_score:.2f})")
                        if result.get('technique'):
                            print(f"  Technique: {result['technique']}")
                        if result.get('playbook'):
                            print(f"  Playbook: {result['playbook']}")
                    else:
                        print("  No anomalous windows found with pattern matches")
                except Exception as sample_error:
                    print(f"  ⚠️  Could not retrieve sample: {sample_error}")
        
        print("\n" + "=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error connecting to Neo4j: {e}")
        print("\nTroubleshooting:")
        print("  1. Check Neo4j is running: docker ps OR neo4j status")
        print("  2. Verify connection details in environment variables")
        print("  3. Verify .env has neo4j_uri, neo4j_username, neo4j_password")
        return 1
    finally:
        driver.close()
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
