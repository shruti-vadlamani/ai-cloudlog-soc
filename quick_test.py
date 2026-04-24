import requests
r = requests.post('http://localhost:8000/api/rag/graph/query', json={'query': 'users', 'limit': 5}, timeout=10)
print(f'Status: {r.status_code}, Nodes: {len(r.json().get("nodes", []))}')
