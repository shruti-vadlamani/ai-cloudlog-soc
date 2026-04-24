import requests
import json

# Test basic graph query
try:
    r = requests.post('http://localhost:8000/api/rag/graph/query', 
        json={'query': 'users', 'limit': 10}, 
        timeout=10)
    print(f'✓ Graph Query Status: {r.status_code}')
    d = r.json()
    print(f'  Nodes: {len(d.get("nodes", []))}')
    print(f'  Edges: {len(d.get("edges", []))}')
except Exception as e:
    print(f'✗ Graph Query Failed: {e}')

# Test subgraph endpoint
try:
    r = requests.get('http://localhost:8000/api/rag/graph/subgraph?limit=20', timeout=5)
    print(f'✓ Subgraph Status: {r.status_code}')
    d = r.json()
    print(f'  Nodes: {len(d.get("nodes", []))}')
    print(f'  Edges: {len(d.get("edges", []))}')
except Exception as e:
    print(f'✗ Subgraph Failed: {e}')

# Test techniques dropdown
try:
    r = requests.get('http://localhost:8000/api/rag/techniques?limit=5', timeout=5)
    print(f'✓ Techniques Status: {r.status_code}')
    d = r.json()
    print(f'  Found: {len(d)} techniques')
except Exception as e:
    print(f'✗ Techniques Failed: {e}')
