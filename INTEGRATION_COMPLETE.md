# 🎉 Cloud SOC Backend - Complete Integration Guide

## What Was Built

I've transformed your Cloud SOC project from **manual script execution** to a **fully automated production system** with an integrated FastAPI backend.

## 🔄 Before vs After

### ❌ Before (Manual Process)
```bash
# Step 1: Generate synthetic data
python run_pipeline.py

# Step 2: Run ML models
python run_models.py

# Step 3: Run RAG ingestion
python rag_ingestion/ingest_vector_db.py

# Step 4: Analyze results manually
```

### ✅ After (Automated Pipeline)
```bash
# Start backend
python start_backend.py

# Trigger pipeline via API (ingests REAL CloudTrail logs from S3)
curl -X POST "http://localhost:8000/api/pipeline/run" \
  -H "Content-Type: application/json" \
  -d '{"s3_bucket": "my-cloudtrail-logs", "run_async": true}'

# Everything else happens automatically!
```

---

## 📁 New Files Created

```
soc-project/
├── backend/
│   ├── __init__.py
│   ├── main.py                      # ⭐ FastAPI app with startup pipeline
│   ├── config.yaml                  # ⭐ Production configuration
│   ├── requirements.txt
│   ├── README.md
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── alerts.py               # Alert REST endpoints
│   │   ├── stats.py                # Statistics endpoints
│   │   ├── rag.py                  # RAG query endpoints
│   │   └── pipeline.py             # ⭐ Pipeline orchestration endpoints
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── alert_service.py        # Alert data loading
│   │   ├── rag_service.py          # RAG queries & enrichment
│   │   └── pipeline_service.py     # ⭐ Production pipeline orchestrator
│   │
│   └── models/
│       ├── __init__.py
│       └── schemas.py              # Pydantic models
│
├── start_backend.py                 # Convenience startup script
├── BACKEND_GUIDE.md                 # ⭐ Complete usage guide
└── requirements.txt                 # ⭐ Updated with FastAPI deps

⭐ = Core pipeline integration files
```

---

## 🚀 Key Features

### 1. **Production Pipeline Orchestration**
- ✅ Reads **real CloudTrail logs** from S3 (via `aws_connector`)
- ✅ Skips synthetic data generation (only for research/testing)
- ✅ Runs normalization → features → ML models automatically
- ✅ Updates alerts database in real-time
- ✅ Optional RAG vector store updates

### 2. **REST API for Everything**
- ✅ Query alerts with filtering (user, score, date, attack type)
- ✅ Get enriched alert context (MITRE techniques, playbooks)
- ✅ Search RAG knowledge base (threat intel, patterns)
- ✅ View dashboard statistics (timeline, severity, users)
- ✅ **Trigger pipeline runs** via API
- ✅ **Monitor pipeline status** in real-time

### 3. **Flexible Deployment**
- ✅ **Manual trigger**: Call API endpoint when needed
- ✅ **Scheduled runs**: Auto-run every N hours (cron)
- ✅ **On-demand**: SOC analyst triggers via button click
- ✅ **Startup automatic**: Optional pipeline run when backend starts

---

## 🎯 Production Workflow

### Setup (One-time)

1. **Configure AWS S3 bucket** in `backend/config.yaml`:
```yaml
aws:
  s3_bucket: "your-cloudtrail-logs-bucket"
  s3_prefix: "AWSLogs/911234567890/CloudTrail/ap-south-1/"
  profile: "default"
```

2. **Configure AWS credentials**:
```bash
aws configure
# Or set environment variables:
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
```

3. **Install dependencies** (if not already):
```bash
pip install -r requirements.txt
```

### Daily Operation

**Option A: Automated (Scheduled)**
```yaml
# backend/config.yaml
pipeline:
  schedule:
    enabled: true
    cron: "0 */6 * * *"  # Every 6 hours
```
Backend automatically ingests new logs and updates alerts!

**Option B: Manual Trigger (via API)**
```bash
# Start backend
python start_backend.py

# Trigger pipeline (in another terminal or via frontend button)
curl -X POST "http://localhost:8000/api/pipeline/run" \
  -H "Content-Type: application/json" \
  -d '{
    "s3_bucket": "my-cloudtrail-logs",
    "start_date": "2026-03-01",
    "end_date": "2026-03-04",
    "run_async": true
  }'
```

**Option C: Auto-run on Startup**
```yaml
# backend/config.yaml
pipeline:
  run_on_startup: true
```
Pipeline runs once when backend starts.

---

## 📊 API Endpoints Overview

### Pipeline Control
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/pipeline/run` | Trigger pipeline (S3 → Models → Alerts) |
| GET | `/api/pipeline/status` | Check if pipeline is running |
| GET | `/api/pipeline/history` | View past pipeline runs |
| GET | `/api/pipeline/data-status` | Check data file status |
| GET | `/api/pipeline/config` | View pipeline configuration |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts (paginated, filterable) |
| GET | `/api/alerts/{user}/{window}` | Get enriched alert details |
| GET | `/api/alerts/filters` | Get available filter options |
| GET | `/api/alerts/summary/timeline` | Alert timeline data |

### RAG & Knowledge Base
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/rag/query` | Search knowledge base |
| GET | `/api/rag/playbooks` | List incident response playbooks |
| GET | `/api/rag/techniques` | List MITRE ATT&CK techniques |
| GET | `/api/rag/collections` | Get ChromaDB collections |

### Statistics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats/overview` | Dashboard metrics |
| GET | `/api/stats/models` | ML model performance |
| GET | `/api/stats/severity-distribution` | Alert severity breakdown |

---

## 🔧 Configuration Reference

`backend/config.yaml`:

```yaml
# AWS S3 Configuration (for real CloudTrail ingestion)
aws:
  s3_bucket: "your-cloudtrail-logs-bucket"
  s3_prefix: "AWSLogs/123456789/CloudTrail/ap-south-1/"
  profile: "default"
  region: "ap-south-1"

# Pipeline Configuration
pipeline:
  # Auto-run pipeline on backend startup
  run_on_startup: false
  
  # Default stages to run
  default_stages:
    - "ingest"      # Read from S3, normalize
    - "features"    # Build feature matrix
    - "models"      # Run ML models
    # - "rag"       # Update vector store (optional)
  
  # Default date range (days back from current date)
  default_lookback_days: 7
  
  # Scheduled pipeline runs (requires APScheduler)
  schedule:
    enabled: false
    cron: "0 */6 * * *"  # Every 6 hours

# API Configuration
api:
  # CORS origins (for production, specify frontend URL)
  cors_origins:
    - "*"  # Allow all origins (development only)
  
  max_page_size: 200

# Logging
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
```

---

## 🧪 Testing the Backend

### 1. Check Health
```bash
curl http://localhost:8000/health
# {"status": "healthy"}
```

### 2. Check Data Status
```bash
curl http://localhost:8000/api/pipeline/data-status
```

Returns which data files exist and when they were last updated.

### 3. View Current Alerts
```bash
curl "http://localhost:8000/api/alerts?page=1&page_size=10"
```

### 4. Trigger Pipeline (using existing synthetic data)
```bash
# If you have synthetic data from run_pipeline.py, just check alerts:
curl "http://localhost:8000/api/alerts?min_score=0.7"
```

### 5. Trigger Pipeline (with real S3 data)
```bash
curl -X POST "http://localhost:8000/api/pipeline/run" \
  -H "Content-Type: application/json" \
  -d '{
    "s3_bucket": "my-cloudtrail-bucket",
    "start_date": "2026-03-01",
    "end_date": "2026-03-04",
    "stages": ["ingest", "features", "models"],
    "run_async": true
  }'
```

### 6. Check Pipeline Status
```bash
curl http://localhost:8000/api/pipeline/status
```

### 7. Query RAG Knowledge Base
```bash
curl -X POST "http://localhost:8000/api/rag/query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "privilege escalation AWS IAM",
    "max_results": 5,
    "collection": "threat_intelligence"
  }'
```

---

## 📝 What Happens in a Pipeline Run

When you call `POST /api/pipeline/run`:

```
1. INGEST (5-60 seconds)
   ├─ Connect to S3 bucket
   ├─ Download CloudTrail .json.gz files for date range
   ├─ Parse and normalize events
   └─ Save to data/normalized/events_labeled.parquet
   
2. FEATURES (30-120 seconds)
   ├─ Load normalized events
   ├─ Compute 5-min and 1-hour time windows
   ├─ Calculate 43 behavioral features
   ├─ Add z-scores and anomaly indicators
   └─ Save to data/features/feature_matrix.parquet
   
3. MODELS (2-5 minutes)
   ├─ Run Isolation Forest → data/models/if_scores.csv
   ├─ Run LOF → data/models/lof_scores.csv
   ├─ Run Autoencoder → data/models/ae_scores.csv
   ├─ Run Ensemble fusion → data/models/ensemble_scores.csv
   └─ Generate alerts → data/results/ensemble_alerts.csv
   
4. RAG (optional, 30 seconds)
   ├─ Ingest new incidents to ChromaDB
   └─ Update vector embeddings

✅ Pipeline complete!
   Alert API endpoints now serve the latest data
```

---

## 🎨 Next Steps: Frontend Dashboard

The backend is ready! Now you can build a frontend that:

1. **Displays alerts table** (connects to `/api/alerts`)
2. **Shows alert details** (connects to `/api/alerts/{user}/{window}`)
3. **RAG query interface** (connects to `/api/rag/query`)
4. **Dashboard charts** (connects to `/api/stats/overview`)
5. **Pipeline trigger button** (connects to `/api/pipeline/run`)

I can help you build:
- React dashboard with Material-UI or Tailwind
- Vue.js SPA
- Simple HTML/JavaScript interface

Let me know when you're ready for the frontend! 🚀

---

## 📚 Documentation

- **Full API docs**: http://localhost:8000/docs (Swagger UI)
- **Alternative docs**: http://localhost:8000/redoc
- **Backend guide**: `BACKEND_GUIDE.md`
- **Backend README**: `backend/README.md`
- **Project README**: `README.md`

---

## 🔍 Monitoring & Debugging

### View Pipeline Logs
```bash
curl http://localhost:8000/api/pipeline/history | jq '.runs[0].logs'
```

### Check What Stages Completed
```bash
curl http://localhost:8000/api/pipeline/history | jq '.runs[0].stages_completed'
```

### View Error Messages
```bash
curl http://localhost:8000/api/pipeline/history | jq '.runs[0].error_message'
```

### See How Many Events Were Ingested
```bash
curl http://localhost:8000/api/pipeline/history | jq '.runs[0].events_ingested'
```

### See How Many Alerts Were Generated
```bash
curl http://localhost:8000/api/pipeline/history | jq '.runs[0].alerts_generated'
```

---

## 🎯 Summary

✅ **Backend is production-ready!**
- Automatically ingests CloudTrail logs from S3
- Runs ML models to detect anomalies
- Generates alerts with MITRE context
- Provides REST API for SOC analysts
- Can be triggered manually, scheduled, or run on startup

✅ **No more manual script running!**
- Everything is automated through the API
- Pipeline status is trackable
- Logs are preserved for debugging

✅ **Ready for frontend integration!**
- All data is available via REST endpoints
- CORS is configured for frontend access
- Interactive API docs available at `/docs`
