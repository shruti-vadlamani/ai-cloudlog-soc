import requests
import json

# Test simple graph query
r = requests.post('http://localhost:8000/api/rag/graph/query', 
    json={'query': 'T1078', 'limit': 10}, 
    timeout=15)

print(f'Status: {r.status_code}')
d = r.json()
print(f'Nodes: {len(d.get("nodes", []))}')
print(f'Edges: {len(d.get("edges", []))}')
print(f'Summary: {d.get("summary", "")[:100]}...')




