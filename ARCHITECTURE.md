# AI CloudLog SOC - Deployment Architecture

## System Overview

```
Internet Users
    ↓
┌──────────────────────────────────────────────────────┐
│  VERCEL (Frontend)                                    │
│  ├─ React Application                               │
│  ├─ Charts, Dashboards, Visualizations             │
│  ├─ URL: https://ai-cloudlog-soc-XXXX.vercel.app  │
│  └─ Auto-scales, CDN distributed globally          │
└──────────────────────────────────────────────────────┘
         ↓ HTTP Requests (via REACT_APP_API_URL)
         ↓ CORS-enabled API calls
         ↓
┌──────────────────────────────────────────────────────┐
│  RENDER (Backend)                                     │
│  ├─ FastAPI Server                                  │
│  ├─ Endpoints: /api/alerts, /api/rag, /api/stats   │
│  ├─ URL: https://ai-cloudlog-soc-XXXX.onrender.com│
│  ├─ Python 3.11 + Gunicorn + Uvicorn              │
│  ├─ Free tier: auto-sleeps after 15 min idle       │
│  ├─ Persistent Disk: /var/tmp/chroma_db (1GB)      │
│  ├─ ML Models: Isolation Forest, LOF, Autoencoder  │
│  └─ RAG Engine: ChromaDB + Sentence Transformers   │
└──────────────────────────────────────────────────────┘
    ↓                         ↓
    ↓                         ↓
    ↓ (Vector queries)        ↓ (Graph queries)
    ↓                         ↓
┌──────────────────────────┐ ┌──────────────────────────┐
│ CHROMADB (Vector DB)     │ │ NEO4J AURA (Graph DB)   │
│ ├─ Location: Render FS   │ │ ├─ Cloud hosted         │
│ ├─ Embeddings: ST models │ │ ├─ Free: 5GB            │
│ ├─ Persistence: SQLite   │ │ ├─ Query: CYPHER        │
│ ├─ Use: Alert enrichment │ │ └─ Security graph       │
│ └─ Free                  │ │   + MITRE ATT&CK        │
└──────────────────────────┘ └──────────────────────────┘
         ↓ (Optional)
         ↓ (for real logs)
    ┌──────────────────┐
    │ AWS S3 CloudTrail│
    │ ├─ Your bucket   │
    │ ├─ Real AWS logs │
    │ └─ Via boto3     │
    └──────────────────┘
```

---

## Data Flow

### 1. User Views Dashboard
```
User Browser
    ↓ (GET https://ai-cloudlog-soc-XXXX.vercel.app)
Vercel (React Static)
    ↓ (serves index.html, JS bundles)
Browser
    ↓ (fetch('/api/alerts'))
    ↓ (with REACT_APP_API_URL)
Render Backend
    ↓ (FastAPI routes to /api/alerts)
Render Code
    ↓ (query ChromaDB + Neo4j)
ChromaDB + Neo4j
    ↓ (return results)
Render Backend
    ↓ (JSON response)
Browser
    ↓ (render on page)
User sees Dashboard
```

### 2. ML Alert Generation
```
Render Backend (scheduled or on-demand)
    ↓ (load CloudTrail logs)
data_ingestion/
    ↓ (normalize events)
feature_engineering/
    ↓ (create features)
models/ (IF, LOF, Autoencoder)
    ↓ (detect anomalies)
alerts.csv
    ↓ (ingest)
rag_ingestion/
    ↓ (embed + index)
ChromaDB + Neo4j
    ↓ (store)
Next API call
    ↓ (retrieves alerts)
Frontend Dashboard
```

---

## Component Details

### Frontend (Vercel)
- **Framework**: React 19
- **UI**: Tailwind CSS
- **Charts**: Recharts
- **Visualization**: vis-network (for knowledge graph)
- **HTTP Client**: Axios
- **Deployment**: Vercel (serverless)
- **Serving**: Edge network (CDN)
- **Cost**: Free

### Backend (Render)
- **Framework**: FastAPI
- **Server**: Uvicorn (ASGI) + Gunicorn (WSGI)
- **Language**: Python 3.11
- **Async**: Full async/await support
- **Hots**: 0.5 CPU, 512MB RAM (free)
- **Persistence**: 1GB disk
- **Cost**: Free (with limitations)

### Vector Database (ChromaDB)
- **Type**: Vector similarity search
- **Embeddings**: Sentence-Transformers (all-MiniLM-L6-v2)
- **Storage**: SQLite (on Render disk)
- **Purpose**: Fast semantic search of alerts
- **Collections**: soc_alerts (configurable)
- **Format**: Vector embeddings + metadata
- **Cost**: Free (included)

### Knowledge Graph (Neo4j Aura)
- **Type**: Property graph database
- **Query Language**: Cypher
- **Features**: 
  - Security techniques (MITRE)
  - AWS services
  - Detection patterns
  - Incident relationships
- **Storage**: Neo4j cloud (5GB free)
- **Cost**: Free tier (5GB)

---

## Request/Response Cycle

### Example: Get Alerts

```
Browser Request:
  GET /api/alerts?severity=HIGH&offset=0&limit=10

                    ↓

Vercel (static assets - not involved)

                    ↓

Network → Render Backend

                    ↓

FastAPI Router:
  @router.get("/")
  async def list_alerts(...)

                    ↓

Alert Service:
  query_alerts(severity, limit, offset)

                    ↓

ChromaDB Query:
  (if using vector search)
  "Get HIGH severity alerts"
  [embedding of query]
  → nearest neighbors from ChromaDB

                    ↓

Neo4j Query:
  (if enriching with context)
  MATCH (a:Alert)-[:RELATED_TO]-(t:Technique)
  WHERE a.severity = "HIGH"

                    ↓

Combine Results + Format

                    ↓

FastAPI Response:
  {
    "total": 42,
    "alerts": [
      {
        "id": "alert-123",
        "severity": "HIGH",
        "description": "...",
        "enrichment": {...}
      },
      ...
    ]
  }

                    ↓

Network → Browser

                    ↓

React State Update

                    ↓

UI Render (Charts, Tables)

                    ↓

User sees new data
```

---

## Environment Separation

### Development (Local)
```
Frontend:
  URL: http://localhost:3000
  setupProxy: routes /api to http://localhost:8000
  REACT_APP_API_URL: http://localhost:8000

Backend:
  URL: http://localhost:8000
  ENVIRONMENT: development
  CORS: Allow all origins
  Neo4j: Your Aura instance
  ChromaDB: local ./chroma_db/

Database:
  Neo4j: Cloud (same as prod)
  ChromaDB: Local filesystem
```

### Production (Deployed)
```
Frontend:
  URL: https://ai-cloudlog-soc-XXXX.vercel.app
  REACT_APP_API_URL: https://ai-cloudlog-soc-XXXX.onrender.com
  No setupProxy needed (direct HTTPS)

Backend:
  URL: https://ai-cloudlog-soc-XXXX.onrender.com
  ENVIRONMENT: production
  CORS: Only allow FRONTEND_URL
  Neo4j: Your Aura instance
  ChromaDB: Render persistent disk (/var/tmp/chroma_db/)

Database:
  Neo4j: Cloud (same as dev)
  ChromaDB: Render persistent volume
```

---

## Cold Start & Performance

### Free Render Performance Profile

```
Request Timeline:
┌─────────────────────────────────────────────────────┐
│ Idle > 15 minutes (Free tier auto-sleep)           │
└─────────────────────────────────────────────────────┘
      ↓
    [New Request]
      ↓
┌─────────────────────────────────────────────────────┐
│ Render wakes up (cost: 20-30 seconds)              │
│ ├─ Load Python runtime                            │
│ ├─ Load dependencies                              │
│ ├─ Initialize FastAPI app                         │
│ └─ Connect to Neo4j + ChromaDB                    │
└─────────────────────────────────────────────────────┘
      ↓
    [First request takes ~30s]
      ↓
    [Subsequent requests ~200-500ms]
      ↓
┌─────────────────────────────────────────────────────┐
│ Keeps running for next 15 minutes                  │
│ Fast responses (~200ms per request)                │
└─────────────────────────────────────────────────────┘
```

### Mitigating Cold Starts

**Option 1: Keep-Alive Ping (Free)**
```javascript
// From frontend, ping backend every 5 min
setInterval(() => {
  fetch(`${API_URL}/health`).catch(console.error);
}, 5 * 60 * 1000);
```

**Option 2: Upgrade Render Plan ($5/mo)**
- Railway Starter: $5/month (always-on)
- Render Starter: $7/month (always-on)

**Option 3: Switch to Fly.io ($5/mo)**
- Always-on, reasonable performance

---

## Scaling Path

### Phase 1: MVP (Current Setup - FREE)
```
Vercel ← → Render (free) + Neo4j Aura (free) + ChromaDB
│
└─ Best for: Testing, demos, small deployments
```

### Phase 2: Reliable Prod ($5-10/mo)
```
Vercel ← → Railway/Fly.io ($5) + Neo4j Aura (free) 
                                + Supabase pgvector ($10)
│
└─ Best for: Production with 99.9% uptime
```

### Phase 3: Enterprise ($100+/mo)
```
CloudFront (CDN)
    ↓
Lambda@Edge (serverless API gateway)
    ↓
Auto-scaling backend (EC2/ECS)
    ↓
RDS PostgreSQL + Aurora
    ↓
ElastiCache (Redis)
    ↓
S3 (logs storage)
```

---

## Monitoring & Logs

### View Logs

**Vercel:**
- Dashboard → Deployments → Click deployment → Runtime Logs
- Or: `vercel logs <project-name>`

**Render:**
- Dashboard → Services → Select service → Logs tab
- Real-time streaming

**Local Development:**
- Terminal shows both Frontend (port 3000) and Backend (port 8000) logs
- Set `ENVIRONMENT=development` for verbose logging

---

## Deployment Summary Table

| Component | Platform | Plan | Cost | Region |
|-----------|----------|------|------|--------|
| Frontend | Vercel | Free | $0 | Global CDN |
| Backend | Render | Free | $0 | US/EU/etc |
| Vector DB | ChromaDB | N/A | $0 | Render disk |
| Graph DB | Neo4j Aura | Free | $0 | Cloud (5GB) |
| **TOTAL** | | | **$0** | |

---

## Architecture Decisions

### Why Render vs Alternatives?

| Feature | Render | Railway | Fly.io | Heroku | AWS |
|---------|--------|----------|---------|--------|-----|
| **Free Tier** | Yes ($0) | $5/mo min | $5/mo min | No | Complex |
| **Cold Start** | Yes (30s) | No | No | N/A | Complex |
| **Postgres** | Yes | Yes | Yes | Yes | Yes |
| **Persistent Disk** | Yes (1GB) | Yes | Yes | Yes | Yes |
| **Ease** | Easy | Medium | Medium | Easy | Hard |

**Choice:** Render - free + good free tier features

### Why Firebase is NOT better

- Firebase = serverless frontend only
- No traditional backend server
- Would need Cloud Functions (paid)
- Harder to deploy ML models
- Less control over dependencies

### Why NOT use EC2

- Too expensive for free tier testing
- Too complex to manage
- Don't need 24/7 uptime yet
- Can migrate later

---

## Failover & Backup Strategy

### Current Setup (Free)
- **No automatic failover**
- **No backup**: ChromaDB is in-memory-ish (SQLite)
- Neo4j Aura IS backed up (their responsibility)

### Recommendations

1. **Backup ChromaDB monthly**
   ```bash
   # Download from Render disk
   render exec -service <service-id> tar -czf chroma_backup.tar.gz chroma_db/
   ```

2. **Re-seed on failover**
   ```bash
   # Scripts provided: rag_ingestion/ingest_vector_db.py
   ```

3. **For production**: Use Supabase with nightly backups

---

**Deployment is now ready. Start with QUICK_START_DEPLOY.md!** 🚀
