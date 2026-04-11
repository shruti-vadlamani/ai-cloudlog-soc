# Cloud SOC Frontend

A React-based dashboard for security analysts to monitor and investigate AWS CloudTrail security alerts detected by ML models.

## Features

### 📊 Dashboard View
- Real-time security metrics overview
- Severity distribution (High/Medium/Low)
- Top attack types and affected users
- Alert timeline visualization

### 🚨 Alerts View
- Comprehensive alert table with filtering and sorting
- Filter by user, score threshold, and attack status
- Pagination support for large datasets
- Click any alert to view enriched details
- Alert detail modal with:
  - MITRE ATT&CK technique mappings
  - Detection patterns that triggered the alert
  - Response playbooks with triage questions
  - Individual model scores (IF, LOF, Autoencoder)
  - Behavioral context from RAG

### 🔍 RAG Query View
- Search the knowledge base with natural language queries
- Query threat intelligence and behavioral incidents
- View similarity scores and metadata
- Example queries for common security scenarios

### ⚙️ Pipeline View
- Monitor pipeline execution status
- Trigger new pipeline runs manually
- Configure stages (ingest, models, RAG)
- View data status (files, row counts, sizes)
- Execution history with timing and success/failure tracking

## Tech Stack

- **React 19.2.4**: Modern React with hooks
- **Pure CSS**: Custom dark theme optimized for SOC environments
- **Proxy Setup**: Connects to FastAPI backend on port 8000

## Getting Started

### Prerequisites
- Node.js 14+
- Backend running on http://localhost:8000

### Installation

Dependencies are already installed. If you need to reinstall:

```bash
npm install
```

### Running the Frontend

Start the development server:

```bash
npm start
```

The app will open at http://localhost:3000 and automatically proxy API requests to the backend.

### Building for Production

```bash
npm run build
```

This creates an optimized production build in the `build/` folder.

### Deployment Configuration

For local development, keep `REACT_APP_API_BASE_URL` empty and use proxy.

For deployed frontend/backend (different domains), set:

```bash
REACT_APP_API_BASE_URL=https://your-backend-domain.com
```

The frontend will call `https://your-backend-domain.com/api/...` directly.

## API Integration

The frontend communicates with the FastAPI backend through these endpoints:

- `GET /health` - Backend health check
- `GET /api/stats/overview` - Dashboard statistics
- `GET /api/alerts` - Paginated alert list with filters
- `GET /api/alerts/{user}/{window}` - Enriched alert details
- `POST /api/rag/query` - RAG knowledge base search
- `GET /api/pipeline/status` - Current pipeline status
- `POST /api/pipeline/run` - Trigger pipeline execution
- `GET /api/pipeline/history` - Pipeline execution history
- `GET /api/pipeline/data-status` - Data files status

## Project Structure

```
frontend/
├── public/           # Static files
├── src/
│   ├── components/   # React components
│   │   ├── DashboardView.js
│   │   ├── AlertsView.js
│   │   ├── AlertDetailModal.js
│   │   ├── RAGQueryView.js
│   │   └── PipelineView.js
│   ├── App.js       # Main app with navigation
│   └── index.css    # Global styles
└── package.json     # Dependencies
```

## Design Principles

- **Dark theme**: Reduces eye strain for SOC analysts working long hours
- **Information density**: Displays critical security data efficiently
- **Fast loading**: Minimal dependencies for quick startup
- **Responsive**: Works on various screen sizes
- **Intuitive navigation**: Tab-based interface with clear sections

## Usage Tips

### Investigating Alerts
1. Go to **Alerts** tab
2. Filter by high-severity alerts (`min_score: 0.7`)
3. Click an alert to see enriched details
4. Review MITRE techniques and response playbooks
5. Use RAG Query to research similar incidents

### Running the Pipeline
1. Go to **Pipeline** tab
2. Configure which stages to run
3. Click **Run Pipeline** to start
4. Monitor status and view logs
5. Check **Data Status** to verify new data

### Querying Knowledge Base
1. Go to **RAG Query** tab
2. Enter a security-related question
3. Select collection (all, threat intel, or behavioral)
4. Review results with similarity scores
5. Expand metadata for additional context

## Troubleshooting

**Backend connection failed**
- Ensure backend is running: `cd backend && python start_backend.py`
- Check backend is on port 8000
- Verify CORS is enabled in backend config

**Alerts not loading**
- Verify data files exist (check Pipeline → Data Status)
- Run the pipeline if needed
- Check browser console for errors

**Blank page**
- Check console for JavaScript errors
- Verify all component files are present
- Try clearing browser cache

## Next Steps

- Add real-time WebSocket updates for live alert streaming
- Implement alert acknowledgment and case management
- Add user authentication and role-based access control
- Export reports and alert timelines
- Create custom dashboards with saved queries
