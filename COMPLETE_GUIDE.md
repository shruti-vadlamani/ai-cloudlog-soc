# Cloud SOC - Complete System Guide

## 🎯 Quick Start

### 1. Start the Backend
```bash
cd backend
python start_backend.py
```
Backend runs at http://localhost:8000

### 2. Start the Frontend
```bash
cd frontend
npm start
```
Frontend opens at http://localhost:3000

### 3. Access the Dashboard
Open your browser to http://localhost:3000

## 📋 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloud SOC System                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Frontend (React)          Backend (FastAPI)                │
│  ┌──────────────┐         ┌─────────────────┐              │
│  │ Dashboard    │◄────────┤ Stats API       │              │
│  │ Alerts Table │◄────────┤ Alerts API      │              │
│  │ RAG Query    │◄────────┤ RAG API         │              │
│  │ Pipeline     │◄────────┤ Pipeline API    │              │
│  └──────────────┘         └────────┬────────┘              │
│                                    │                        │
│                          ┌─────────▼──────────┐             │
│                          │ Pipeline Orchestrator│            │
│                          └─────────┬──────────┘             │
│                                    │                        │
│              ┌─────────────────────┼─────────────┐          │
│              │                     │             │          │
│         ┌────▼────┐          ┌────▼───┐    ┌───▼────┐     │
│         │ AWS S3  │          │ ML     │    │ RAG    │     │
│         │ Ingest  │          │ Models │    │ Enrich │     │
│         └────┬────┘          └────┬───┘    └───┬────┘     │
│              │                    │            │          │
│              ▼                    ▼            ▼          │
│         Data Files         Alerts CSV    ChromaDB        │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## 🔧 Backend Features

### Pipeline Orchestration
The backend has replaced manual script execution with automated pipeline:

**Before:**
```bash
python run_pipeline.py
python run_models.py
python rag_ingestion/production_incident_analyzer.py
```

**After:**
```python
# Automatic on startup (if configured)
# OR manual via API
POST /api/pipeline/run
```

### Pipeline Stages
1. **Ingest**: Load CloudTrail logs from AWS S3
2. **Features**: Compute 43 behavioral features per time window
3. **Models**: Run Isolation Forest, LOF, Autoencoder, Ensemble
4. **RAG**: Update vector database with new alerts

### API Endpoints

**Health & Status**
- `GET /health` - Backend health check
- `GET /api/pipeline/status` - Current pipeline status
- `GET /api/pipeline/data-status` - Data files status

**Alerts**
- `GET /api/alerts` - List alerts (paginated, filterable)
- `GET /api/alerts/{user}/{window}` - Get enriched alert details
- `GET /api/alerts/filters` - Available filter values
- `GET /api/alerts/timeline` - Alert timeline data
- `GET /api/alerts/top-users` - Most affected users

**Statistics**
- `GET /api/stats/overview` - Dashboard overview
- `GET /api/stats/models` - ML model performance
- `GET /api/stats/severity-distribution` - Severity breakdown
- `GET /api/stats/attack-distribution` - Attack type distribution

**RAG Knowledge Base**
- `POST /api/rag/query` - Query knowledge base
- `GET /api/rag/playbooks` - List response playbooks
- `GET /api/rag/techniques` - MITRE ATT&CK techniques
- `GET /api/rag/collections` - Available collections

**Pipeline Control**
- `POST /api/pipeline/run` - Trigger pipeline execution
- `GET /api/pipeline/history` - Execution history
- `GET /api/pipeline/config` - Pipeline configuration

## 🎨 Frontend Features

### Dashboard View (📊)
- Total alerts counter
- Severity distribution (High/Medium/Low)
- Top attack types with counts
- Top affected users
- Alert timeline visualization
- Real-time metrics

### Alerts View (🚨)
**Table Features:**
- Paginated alert list (20 per page)
- Filter by user name
- Filter by minimum score
- Filter by attack status
- Sort by score or date
- Color-coded severity badges
- Visual score bars

**Alert Details Modal:**
- Complete alert information
- MITRE ATT&CK technique mappings
- Detected behavioral patterns
- Response playbooks with steps
- Individual model scores breakdown
- Behavioral context from RAG
- Similar past incidents

### RAG Query View (🔍)
- Natural language search interface
- Collection selector (all, threat intel, behavioral)
- Similarity scores for results
- Expandable metadata
- Query tips and examples
- Real-time search results

### Pipeline View (⚙️)
- Current pipeline status indicator
- Manual pipeline trigger button
- Stage configuration checkboxes
- Data status dashboard (files, sizes, row counts)
- Execution history table
- Real-time progress updates
- Success/failure tracking

## 📊 Data Flow

### Normal Operation Flow
```
1. S3 CloudTrail Logs
   ↓
2. aws_connector.s3_cloudtrail_reader.load_all_events_from_s3()
   ↓
3. data/normalized/events_labeled.parquet (18,294 events)
   ↓
4. feature_engineering.window_aggregator.compute_all_windows()
   ↓
5. data/features/feature_matrix.parquet (7,759 windows, 43 features)
   ↓
6. ML Models (IF, LOF, Autoencoder)
   ↓
7. data/models/*.csv (individual scores)
   ↓
8. Ensemble Model (weighted fusion: 0.35, 0.35, 0.30)
   ↓
9. data/results/ensemble_alerts.csv (233 alerts)
   ↓
10. RAG Ingestion (ChromaDB + Neo4j)
   ↓
11. Frontend Dashboard Display
```

## 🔐 Configuration

### Backend Configuration (backend/config.yaml)
```yaml
aws:
  s3_bucket: "your-cloudtrail-bucket"
  s3_prefix: "AWSLogs/"

pipeline:
  run_on_startup: false
  schedule:
    enabled: false
    cron: "0 */6 * * *"  # Every 6 hours

api:
  host: "0.0.0.0"
  port: 8000
  cors_origins:
    - "http://localhost:3000"
```

### Frontend Configuration (frontend/package.json)
```json
{
  "proxy": "http://localhost:8000"
}
```

## 🚀 Deployment Modes

### Development Mode
**Backend:**
```bash
cd backend
python start_backend.py
# Or with uvicorn directly
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm start
```

### Production Mode
**Backend:**
```bash
cd backend
# Install production dependencies
pip install gunicorn

# Run with gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

**Frontend:**
```bash
cd frontend
npm run build

# Serve with nginx or serve
npm install -g serve
serve -s build -l 3000
```

### Automated Mode (Scheduled Pipeline)
Edit `backend/config.yaml`:
```yaml
pipeline:
  run_on_startup: true  # Run on backend startup
  schedule:
    enabled: true
    cron: "0 */6 * * *"  # Run every 6 hours
```

## 🛠️ Typical Workflows

### Workflow 1: Daily Security Review
1. Open dashboard to see high-level metrics
2. Check for high-severity alerts (red badges)
3. Click alert to view details and MITRE techniques
4. Review suggested playbooks
5. Use RAG to research similar incidents
6. Document findings

### Workflow 2: Incident Investigation
1. Go to Alerts tab
2. Filter by specific user or time window
3. Sort by highest scores
4. Open alert details
5. Review behavioral patterns
6. Query RAG for related threat intelligence
7. Follow response playbook steps

### Workflow 3: Threat Hunting
1. Go to RAG Query tab
2. Enter threat-related keywords
3. Review similar past incidents
4. Check MITRE techniques
5. Go to Alerts to find matching patterns
6. Investigate flagged users

### Workflow 4: Manual Pipeline Run
1. Go to Pipeline tab
2. Configure stages to run
3. Click "Run Pipeline"
4. Monitor status in real-time
5. Check data status after completion
6. Review execution history

## 🔍 Troubleshooting

### Backend Issues

**Port 8000 already in use:**
```powershell
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

**Import errors:**
```bash
pip install -r requirements.txt --upgrade
```

**Pipeline failures:**
- Check logs in backend console
- Verify S3 bucket access
- Check data/ directory permissions
- Ensure all data files exist

### Frontend Issues

**Backend connection failed:**
- Verify backend is running on port 8000
- Check CORS configuration in backend/config.yaml
- Open browser console for errors

**Blank dashboard:**
- Ensure data files exist (run pipeline first)
- Check browser console for API errors
- Verify proxy setting in package.json

**Slow loading:**
- Large alert datasets may take time to load
- Use pagination and filters
- Consider reducing page_size parameter

## 📈 Performance Tips

### Backend Optimization
- Increase page_size for faster bulk queries
- Use filters to reduce data transferred
- Enable pipeline scheduling for off-peak hours
- Consider caching frequently accessed data

### Frontend Optimization
- Use pagination (default 20 items)
- Apply filters before loading large datasets
- Clear browser cache if performance degrades
- Close detail modals when not in use

## 🔒 Security Considerations

### Production Deployment
1. **Enable authentication**: Add JWT or OAuth2
2. **HTTPS only**: Use SSL certificates
3. **Rate limiting**: Prevent API abuse
4. **Input validation**: Already implemented with Pydantic
5. **CORS restrictions**: Limit to specific domains
6. **Environment variables**: Store AWS credentials securely
7. **Logging**: Monitor all API access

### AWS Configuration
- Use IAM roles with minimal S3 permissions
- Enable CloudTrail encryption at rest
- Implement bucket policies
- Rotate access keys regularly

## 📝 Data Schema

### Alert Schema
```python
{
  "user_name": str,
  "window_id": int,
  "ensemble_score": float,  # 0.0 - 1.0
  "isolation_forest_score": float,
  "lof_score": float,
  "autoencoder_score": float,
  "is_attack": bool,
  "attack_type": str
}
```

### Enriched Alert Schema
```python
{
  ...base_alert,
  "mitre_techniques": [
    {"technique_id": str, "technique_name": str}
  ],
  "detection_patterns": [str],
  "playbooks": [
    {
      "name": str,
      "triage_questions": [str],
      "containment_steps": [str]
    }
  ],
  "behavioral_context": str,
  "similar_incidents": [...]
}
```

## 🎓 Learning Resources

### Understanding the ML Pipeline
- **Isolation Forest**: Global outlier detection
- **LOF**: Local density-based anomaly detection
- **Autoencoder**: Reconstruction error for temporal patterns
- **Ensemble**: Weighted voting (0.35, 0.35, 0.30)

### Feature Engineering
43 behavioral features computed per 5-minute window:
- Event type diversity (entropy, unique counts)
- Temporal patterns (rate, burstiness)
- AWS service usage patterns
- Error rates and status codes
- Geographic and IP diversity
- Resource access patterns

## 🚧 Future Enhancements

### Planned Features
- [ ] Real-time WebSocket updates for live alerts
- [ ] Alert acknowledgment and case management
- [ ] User authentication and RBAC
- [ ] Custom dashboard widgets
- [ ] Alert export (PDF, CSV)
- [ ] Email notifications for high-severity alerts
- [ ] Integration with SIEM systems
- [ ] Advanced threat hunting queries
- [ ] Machine learning model retraining interface
- [ ] Collaborative investigation notes

## 📞 Support

### Getting Help
- Check `BACKEND_GUIDE.md` for backend details
- Check `frontend/README.md` for frontend details
- Review `INTEGRATION_COMPLETE.md` for architecture
- Check API docs at http://localhost:8000/docs

### Common Questions

**Q: How often should I run the pipeline?**
A: For production, every 6 hours is recommended. For testing, run manually as needed.

**Q: What's the difference between collections in RAG?**
A: `threat_intelligence` contains MITRE, playbooks, patterns. `behavioral_incidents` contains past alert data.

**Q: Can I use this without AWS S3?**
A: Yes, you can use synthetic data generation or load local CloudTrail logs.

**Q: How do I add custom detection patterns?**
A: Edit `knowledge_base/detection_patterns.json` and re-run RAG ingestion.

**Q: What severity threshold should I investigate first?**
A: High severity (score >= 0.7) should be investigated immediately.

## ✅ System Status Checklist

Before deploying:
- [x] Backend FastAPI server running on port 8000
- [x] Frontend React server running on port 3000
- [x] Pipeline orchestration functional
- [x] ML models trained and loaded
- [x] RAG vector database populated
- [x] Data files present (normalized, features, alerts)
- [x] API documentation accessible at /docs
- [x] CORS configured for frontend
- [ ] Authentication system (optional for production)
- [ ] HTTPS/SSL certificates (for production)
- [ ] Monitoring and logging (for production)

---

**Version:** 1.0.0  
**Last Updated:** 2026-03-02  
**Compatibility:** Python 3.9+, Node.js 14+, React 19+
