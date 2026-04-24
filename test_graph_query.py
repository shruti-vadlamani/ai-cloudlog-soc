import requests
import json
import time

time.sleep(2)

r = requests.post('http://localhost:8000/api/rag/graph/query', 
    json={'query': 'give the travel patterns of the graph', 'limit': 25})

d = r.json()
print(f"Summary: {d.get('summary')}")
print(f"Matches: {len(d.get('matches', []))}")
print(f"Nodes: {len(d.get('nodes', []))}")
print(f"Edges: {len(d.get('edges', []))}")
print(f"\nInsights: {d.get('insights', [])}")
