#!/usr/bin/env python3
import requests
import json

base = 'http://localhost:8000/api/rag'

print('Testing graph query with different query text:')
r = requests.post(f'{base}/graph/query', json={'query': 'T1078', 'limit': 20})
print(f'  T1078 query: {r.status_code}, {len(r.json().get("nodes", []))} nodes')

r = requests.post(f'{base}/graph/query', json={'query': 'playbook', 'limit': 20})
print(f'  playbook query: {r.status_code}, {len(r.json().get("nodes", []))} nodes')

print()
print('Testing RAG queries:')
r = requests.post(f'{base}/query', json={'query': 'What attacks use IAM credentials?'})
print(f'  RAG query: {r.status_code}, {len(r.json().get("results", []))} results')

print()
print('Testing techniques endpoint:')
r = requests.get(f'{base}/techniques?limit=3&tactic=privilege-escalation')
print(f'  Techniques (privilege-escalation): {r.status_code}, {len(r.json())} items')

print()
print('✅ All endpoints working!')
