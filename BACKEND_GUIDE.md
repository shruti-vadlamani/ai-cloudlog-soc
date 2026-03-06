# Cloud SOC Backend - Quick Start Guide

## Overview

This backend provides a **fully automated** Security Operations Center (SOC) for AWS CloudTrail analysis:

- **Automated Pipeline**: Reads CloudTrail logs from S3, runs ML models, generates alerts
- **REST API**: Query alerts, get enriched context, search knowledge base
- **RAG-Powered Analysis**: MITRE ATT&CK techniques, incident response playbooks
- **Real-time Updates**: Trigger pipeline manually or schedule automatic runs

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure AWS (for production CloudTrail ingestion)

Edit `backend/config.yaml`:

```yaml
aws:
  s3_bucket: "your-cloudtrail-logs-bucket"
  s3_prefix: "AWSLogs/911234567890/CloudTrail/ap-south-1/"
  profile: "default"
```

Configure AWS credentials:
```bash
aws configure
```

### 3. Start the Backend

```bash
python start_backend.py
```

Access:
- API: http://localhost:8000
- Interactive docs: http://localhost:8000/docs

## Usage Workflows

### Development Mode (using synthetic data)

For testing and development, generate synthetic CloudTrail data:

```bash
# 1. Generate synthetic logs
python run_pipeline.py

# 2. Run ML models
python run_models.py

# 3. Start backend (reads existing CSV files)
python start_backend.py
```

### Production Mode (using real CloudTrail logs)

The backend handles everything automatically:

```bash
# 1. Start backend
python start_backend.py

# 2. Trigger pipeline via API
curl -X POST "http://localhost:8000/api/pipeline/run" \
  -H "Content-Type: application/json" \
  -d '{
    "s3_bucket": "my-cloudtrail-logs",
    "start_date": "2026-03-01",
    "end_date": "2026-03-04",
    "run_async": true
  }'

# 3. Check pipeline status
curl "http://localhost:8000/api/pipeline/status"

# 4. View alerts
curl "http://localhost:8000/api/alerts?min_score=0.7"
```

### Automated Mode (scheduled pipeline runs)

Configure in `backend/config.yaml`:

```yaml
pipeline:
  schedule:
    enabled: true
    cron: "0 */6 * * *"  # Run every 6 hours
```

The backend will automatically:
1. Ingest new CloudTrail logs from S3
2. Run ML models
3. Generate alerts
4. Update the dashboard

## Key API Endpoints

### Pipeline Control
- `POST /api/pipeline/run` - Trigger CloudTrail ingestion + ML analysis
- `GET /api/pipeline/status` - Check if pipeline is running
- `GET /api/pipeline/history` - View past pipeline runs

### Alerts
- `GET /api/alerts` - List all alerts (with filtering)
- `GET /api/alerts/{user}/{window}` - Get enriched alert with MITRE context
- `GET /api/alerts/summary/timeline` - Alert timeline graph

### RAG Queries
- `POST /api/rag/query` - Search knowledge base (threat intel, patterns)
- `GET /api/rag/playbooks` - List incident response playbooks
- `GET /api/rag/techniques` - MITRE ATT&CK techniques

### Statistics
- `GET /api/stats/overview` - Dashboard metrics
- `GET /api/stats/models` - ML model performance

## Pipeline Stages

What happens when you trigger `/api/pipeline/run`:

1. **Ingest** (5-60 seconds)
   - Reads CloudTrail logs from S3
   - Normalizes JSON to Parquet format
   - ~10,000 events/second

2. **Features** (30-120 seconds)
   - Builds 5-minute and 1-hour time windows
   - Computes 43 behavioral features
   - Adds z-score anomaly indicators

3. **Models** (2-5 minutes)
   - Isolation Forest (global outliers)
   - Local Outlier Factor (local deviations)
   - Autoencoder (temporal patterns)
   - Ensemble (weighted fusion)

4. **RAG** (optional, 30 seconds)
   - Updates vector store with new incidents
   - Indexes behavioral patterns

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Alert API    │  │ RAG API      │  │ Pipeline API     │  │
│  │ (Query)      │  │ (Enrich)     │  │ (Orchestrate)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│         │                  │                    │           │
│         ├──────────────────┴────────────────────┤           │
│         │                                       │           │
│  ┌──────▼──────────┐                   ┌───────▼────────┐  │
│  │  Alert Service  │                   │ Pipeline Orch. │  │
│  │  (Load CSV)     │                   │ (S3 → Models)  │  │
│  └─────────────────┘                   └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                    │                           │
        ┌───────────▼──────────┐    ┌──────────▼──────────┐
        │  Data Files          │    │  AWS S3             │
        │  - ensemble_alerts   │    │  - CloudTrail logs  │
        │  - feature_matrix    │    │                     │
        │  - model scores      │    │                     │
        └──────────────────────┘    └─────────────────────┘
```

## Monitoring

### Check if data exists
```bash
curl "http://localhost:8000/api/pipeline/data-status"
```

Returns:
```json
{
  "files": {
    "normalized_events": {"exists": true, "size_mb": 2.5, "row_count": 18234},
    "feature_matrix": {"exists": true, "size_mb": 0.8, "row_count": 3647},
    "ensemble_alerts": {"exists": true, "size_mb": 0.05, "row_count": 235}
  },
  "ready": true
}
```

### View pipeline logs
```bash
curl "http://localhost:8000/api/pipeline/history" | jq '.runs[0].logs'
```

## Configuration Reference

`backend/config.yaml`:

```yaml
aws:
  s3_bucket: "your-bucket"        # Required for production
  s3_prefix: null                 # Auto-detected if null
  profile: "default"              # AWS CLI profile
  region: "ap-south-1"

pipeline:
  run_on_startup: false           # Auto-run when backend starts
  default_stages:                 # Pipeline stages to run
    - "ingest"
    - "features"
    - "models"
  default_lookback_days: 7        # How many days of logs to process
  enable_rag: false               # Update RAG after models
  schedule:
    enabled: false                # Enable scheduled runs
    cron: "0 */6 * * *"          # Cron expression

api:
  cors_origins:                   # CORS configuration
    - "*"                         # Allow all (dev only)
  max_page_size: 200
  rate_limit: null                # Requests per minute

logging:
  level: "INFO"
  format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
```

## Troubleshooting

### Pipeline fails with "No events found"
- Check S3 bucket name and prefix
- Verify AWS credentials: `aws s3 ls s3://your-bucket/`
- Check date range includes CloudTrail data

### "ChromaDB not available"
RAG features require ChromaDB ingestion:
```bash
python rag_ingestion/ingest_vector_db.py
```

### "Model files not found"
Pipeline needs to run at least once:
```bash
curl -X POST "http://localhost:8000/api/pipeline/run" -H "Content-Type: application/json" -d '{"run_async": true}'
```

## Next Steps

1. **Deploy Frontend**: Build React dashboard (see `frontend/` directory)
2. **Setup Neo4j**: Enable graph-based pattern matching
3. **Enable Ollama**: Add LLM-powered incident analysis
4. **Production Deploy**: Host on cloud (AWS ECS, Lambda, etc.)

## Documentation

- Full API docs: http://localhost:8000/docs
- Backend README: `backend/README.md`
- Project README: `../README.md`
