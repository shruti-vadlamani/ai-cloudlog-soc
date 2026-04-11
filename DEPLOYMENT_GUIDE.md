# Deployment Guide: Frontend (Vercel) + Backend (Render)

## Project Structure After Reorganization

```
ai-cloudlog-soc/
│
├── frontend/                          # Vercel deployment
│   ├── package.json
│   ├── vercel.json
│   ├── public/
│   ├── src/
│   └── .env (template for REACT_APP_API_URL)
│
├── backend/                           # Render deployment
│   ├── __init__.py
│   ├── main.py
│   ├── config.yaml
│   ├── requirements.txt
│   ├── runtime.txt                    # Python version for Render
│   ├── build.sh                       # Build script for Render
│   ├── .env (for Neo4j, ChromaDB config)
│   │
│   ├── api/
│   ├── models/
│   ├── services/
│   │
│   ├── data_generation/               # ML pipeline utilities
│   ├── data_ingestion/
│   ├── feature_engineering/
│   ├── models/
│   ├── rag_ingestion/
│   ├── rag_evaluation/
│   ├── aws_connector/
│   ├── scripts/
│   │
│   ├── knowledge_base/                # Static knowledge data
│   ├── ground_truth/
│   │
│   └── chroma_db/                     # Persistent ChromaDB storage
│       └── (Render will mount this)
│
├── .env (shared config template)
├── .gitignore
├── README.md
└── DEPLOYMENT_GUIDE.md
```

---

## Deployment Options Comparison

### Option A: **Recommended** - FastAPI (Render) + React (Vercel)

| Service | Platform | Price | Features |
|---------|----------|-------|----------|
| **Backend** | Render | **Free** | 0.5 CPU, 512MB RAM, auto-sleep after 15 min idle |
| **Frontend** | Vercel | **Free** | Unlimited deployments, serverless functions |
| **Vector DB** | ChromaDB (in-memory or SQLite) | **Free** | Included in backend |
| **Knowledge Graph** | Neo4j Aura | **Free** (5GB) | Already configured ✓ |

**Total Cost:** $0/month

**Limitations:**
- Render auto-sleeps after 15 min inactivity (cold start ~30s)
- ChromaDB stored on Render filesystem (lost on re-deploy)
- 512MB RAM may be tight with ML models

**Solution:** Use ChromaDB persistent storage + sync approach

---

### Option B: **Higher Perf, Still Free** - Supabase + Vercel

| Service | Platform | Price | Features |
|---------|----------|-------|----------|
| **Backend** | Supabase (PostgREST) | **Free** | PostgreSQL + vector ext (pgvector) |
| **Frontend** | Vercel | **Free** | Same as above |
| **Vector DB** | pgvector (PostgreSQL) | **Free** | Built into Supabase |
| **Knowledge Graph** | Neo4j Aura | **Free** (5GB) | Already configured ✓ |

**Total Cost:** $0/month

**Pros:**
- PostgreSQL is more reliable than in-memory ChromaDB
- pgvector extension for vector storage
- No auto-sleep

**Cons:**
- Requires refactoring ChromaDB → pgvector queries

---

### Option C: **Production Ready** - Railway + Vercel

| Service | Platform | Price | Features |
|---------|----------|-------|----------|
| **Backend** | Railway | **$5/month** | 1GB RAM, always-on |
| **Frontend** | Vercel | **Free** | Same as above |
| **Storage** | Railway Volumes | **$10/month** | 200GB persistent storage |
| **Databases** | Neo4j Aura | **Free** | Already configured ✓ |

**Total Cost:** $15/month

**Pros:**
- Always-on backend (no cold starts)
- Reliable persistent storage for ChromaDB
- Good performance for ML models

---

## 🎯 RECOMMENDED: Option A (Render + Vercel)

Why?
- **Free tier sufficient** for development/testing
- **Quick deployment** (< 5 minutes)
- **Minimal refactoring** (keep ChromaDB as-is)
- **Upgrade path** to paid Render when needed

If cold-start is an issue → upgrade to Railway ($5/mo) instead

---

## Step-by-Step Deployment

### Prerequisites
- Vercel account (vercel.com) - login with GitHub
- Render account (render.com) - free tier
- Both repos should be on GitHub

### Part 1: Reorganize Project Folders ✅

**Move folders to backend/**
```bash
# From root, group utilities into backend/utils
mv data_generation/ backend/
mv data_ingestion/ backend/
mv feature_engineering/ backend/
mv models/ backend/                    # Rename if conflict with models/ in backend/
mv rag_ingestion/ backend/
mv rag_evaluation/ backend/
mv aws_connector/ backend/
mv scripts/ backend/
mv knowledge_base/ backend/
mv ground_truth/ backend/
mv chroma_db/ backend/                 # ChromaDB persistence
mv data/ backend/                      # All data files
```

### Part 2: Create Deployment Files

**backend/runtime.txt**
```
python-3.11
```

**backend/build.sh**
```bash
#!/bin/bash
set -e

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Creating necessary directories..."
mkdir -p chroma_db
mkdir -p data

echo "Build complete!"
```

**backend/.env.example** (template for Render)
```env
# Neo4j
NEO4J_URI=neo4j+s://[YOUR_INSTANCE_ID].databases.neo4j.io
NEO4J_USERNAME=[YOUR_USERNAME]
NEO4J_PASSWORD=[YOUR_PASSWORD]
NEO4J_DATABASE=[YOUR_DB_NAME]

# Frontend URL (update after Vercel deployment)
FRONTEND_URL=https://your-frontend.vercel.app

# Optional: AWS credentials (for real S3 integration)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=ap-south-1

# ChromaDB (local SQLite)
CHROMA_DATA_DIR=./chroma_db
```

**backend/Procfile** (for Render)
```
web: gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.main:app
```

**frontend/.env.production** (for Vercel)
```
REACT_APP_API_URL=https://your-backend.onrender.com
```

**backend/main.py** (update CORS)
```python
# Near line 45, replace:
cors_origins = [
    "http://localhost:3000",           # Development
    "http://localhost:8000",
    os.getenv("FRONTEND_URL", "*"),    # Production
]

# Use:
if os.getenv("ENVIRONMENT") == "production":
    cors_origins = [os.getenv("FRONTEND_URL")]
else:
    cors_origins = ["*"]
```

### Part 3: Deploy Frontend to Vercel

1. Push code to GitHub
   ```bash
   git add .
   git commit -m "Prepare for deployment"
   git push origin main
   ```

2. Go to **vercel.com** → Import Project
   - Select `ai-cloudlog-soc` repo
   - Set root directory: `frontend`
   - Add environment variable:
     - `REACT_APP_API_URL` = (will update after backend deploy)
   - Click Deploy ✓

3. Note your Vercel URL: `https://ai-cloudlog-soc-[xxx].vercel.app`

### Part 4: Deploy Backend to Render

1. Go to **render.com** → Create New Service
   - Select "Web Service"
   - Connect GitHub repo
   - Build Command: `pip install -r backend/requirements.txt`
   - Start Command: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.main:app`
   - Select Region (closest to users)
   - Select Free tier

2. Add Environment Variables:
   ```
   NEO4J_URI=neo4j+s://...
   NEO4J_USERNAME=...
   NEO4J_PASSWORD=...
   NEO4J_DATABASE=...
   FRONTEND_URL=https://ai-cloudlog-soc-[xxx].vercel.app
   ENVIRONMENT=production
   ```

3. Add Persistent Disk for ChromaDB:
   - Mount Path: `/var/tmp/chroma_db`
   - Size: 1GB (free tier)
   - Update code: `CHROMA_DATA_DIR=/var/tmp/chroma_db`

4. Click Deploy ✓

5. Note your Render URL: `https://ai-cloudlog-soc-backend-[xxx].onrender.com`

### Part 5: Update Frontend Env Variables

1. Go back to Vercel Dashboard
2. Settings → Environment Variables
3. Add/Update: `REACT_APP_API_URL=https://ai-cloudlog-soc-backend-[xxx].onrender.com`
4. RedDeploy frontend

---

## Post-Deployment Checklist

- [ ] Frontend loads on Vercel
- [ ] Backend API responds on Render
- [ ] Frontend can call backend endpoints (test with `/api/alerts`)
- [ ] Neo4j connection works
- [ ] ChromaDB persists across redeployments
- [ ] Logs visible in Render dashboard

## Troubleshooting

### Cold Start Issues
If Render backend takes >30s to respond:
- Add keep-alive ping from frontend every 5 min
- Upgrade to Railway ($5/mo) for always-on

### ChromaDB Lost After Redeploy
- Solution: Use Render Persistent Disk (configured above)
- Or: Sync to PostgreSQL (pgvector)

### CORS Errors
- Check `FRONTEND_URL` is set correctly
- Update `backend/main.py` CORS config
- Redeploy backend

---

## Future: Scaling to Production

When ready for real traffic:

| Component | Upgrade |
|-----------|---------|
| Backend | Railway Pro ($15/mo) or Fly.io ($5/mo) |
| Vector DB | Supabase (pgvector) or Pinecone |
| Knowledge Graph | Neo4j Aura Pro ($200/mo) |
| File Storage | AWS S3 ($0.023/GB) |

