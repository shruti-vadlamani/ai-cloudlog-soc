from neo4j import GraphDatabase
from rag_ingestion.neo4j_env import get_neo4j_config

cfg = get_neo4j_config(require_credentials=True)
driver = GraphDatabase.driver(cfg["uri"], auth=(cfg["username"], cfg["password"]))

with driver.session(database=cfg.get("database")) as session:
    # Count all nodes by type
    result = session.run("""
        MATCH (n)
        WITH labels(n)[0] as label, count(n) as count
        RETURN label, count
        ORDER BY count DESC
    """)
    
    print("=== Node Counts ===")
    for row in result:
        print(f"{row['label']}: {row['count']}")
    
    # Sample some nodes
    print("\n=== Sample Nodes ===")
    result = session.run("""
        MATCH (n)
        RETURN labels(n)[0] as label, n.name as name, n.id as id, n.user_name as user_name
        LIMIT 5
    """)
    
    for row in result:
        print(f"Label: {row['label']}, Name: {row['name']}, ID: {row['id']}, User: {row['user_name']}")

driver.close()
