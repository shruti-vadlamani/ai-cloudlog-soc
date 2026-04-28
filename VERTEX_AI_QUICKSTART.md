# Quick Start: Vertex AI Integration

## What Was Done

✅ **Replaced Ollama with Google Cloud Vertex AI (Gemini)**

- Removed all Ollama integration code
- Added `backend/services/vertex_ai_client.py` — Vertex AI client service
- Updated `RAGService` to use Vertex AI
- Updated API endpoints to use Vertex AI for LLM synthesis
- Added Google Cloud SDK to requirements

## 3-Step Setup

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

Installs:
- `google-cloud-aiplatform` — Vertex AI SDK
- `google-auth` — Google authentication

### Step 2: Verify GCP Setup

Your `.env` should have:
```dotenv
GCP_CREDENTIALS='{"type":"service_account","project_id":"your-project-id",...}'
```

**Verify** that your GCP service account has the `roles/aiplatform.user` role.

If not, ask your GCP admin to grant it:
```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:YOUR_SA@PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/aiplatform.user
```

### Step 3: Restart Backend

```bash
# Stop current backend (Ctrl+C in Terminal 2)
# Wait 2 seconds
# Then restart:
python start_backend.py
```

**Expected log output:**
```
INFO: Vertex AI initialized: project=ac4ec2d4, location=us-central1, model=gemini-1.5-pro
```

## Test It

### Without LLM (Search Only)
```bash
curl "http://localhost:8000/api/rag/query?q=privilege+escalation&use_llm=false"
```

Returns: ChromaDB search results only

### With LLM (Search + Synthesis)
```bash
curl "http://localhost:8000/api/rag/query?q=privilege+escalation&use_llm=true"
```

Returns: Search results + Gemini explanation

## Files Changed

| File | Status | What Changed |
|------|--------|--------------|
| `backend/services/vertex_ai_client.py` | ✅ NEW | Vertex AI client service |
| `backend/services/rag_service.py` | ✅ UPDATED | Use Vertex AI instead of Ollama |
| `backend/api/rag.py` | ✅ UPDATED | Use Vertex AI for graph explanations |
| `requirements.txt` | ✅ UPDATED | Added google-cloud packages |
| `backend/README.md` | ✅ UPDATED | Documented Vertex AI |
| `VERTEX_AI_SETUP.md` | ✅ NEW | Full setup guide |
| `OLLAMA_MIGRATION.md` | ✅ NEW | Migration summary |

## Troubleshooting

### Backend won't start
```
ERROR: Could not determine project ID
```
**Solution:** Set `GCP_PROJECT_ID` in `.env`:
```dotenv
GCP_PROJECT_ID=ac4ec2d4
```

### LLM not working but search works
```
WARNING: Vertex AI initialization failed
```
**Check:**
1. Is `GCP_CREDENTIALS` valid JSON?
2. Does service account have `roles/aiplatform.user`?
3. Is Vertex AI API enabled in GCP project?

**Enable Vertex AI API:**
```bash
gcloud services enable aiplatform.googleapis.com --project=ac4ec2d4
```

### Slow responses
- Use `gemini-1.5-flash` for faster responses (cheaper too)
- Reduce `max_tokens` from 1024 to 512

## Next Steps

1. **Read full setup guide:** See `VERTEX_AI_SETUP.md`
2. **Monitor costs:** Check GCP Console → Vertex AI usage
3. **Optimize if needed:** See cost optimization in `VERTEX_AI_SETUP.md`

## Quick Reference

### Test Endpoints

RAG query with LLM:
```
GET /api/rag/query?q=security+question&use_llm=true
```

Get playbooks:
```
GET /api/rag/playbooks
```

Get MITRE techniques:
```
GET /api/rag/techniques
```

Graph query with explanation:
```
POST /api/rag/graph-query
{
  "query": "What are all paths to privilege escalation?",
  "explain": true
}
```

### No LLM Needed For:
- Searching ChromaDB
- Retrieving playbooks
- Getting MITRE techniques
- Alert enrichment (basic)
- Graph traversal

LLM only used for:
- Synthesizing search explanations (`use_llm=true`)
- Explaining graph analysis
- Optional alert enrichment details

## Done! 🎉

Your backend now uses **Google Vertex AI (Gemini)** instead of Ollama.

**Benefits:**
- ✅ No local LLM needed
- ✅ Better model quality (Gemini 1.5)
- ✅ Managed service (no maintenance)
- ✅ Higher reliability
- ✅ Graceful fallback if unavailable

**Cost:** ~$0.00015 per query (~$0.015/day for 100 queries)

Have questions? See `VERTEX_AI_SETUP.md` for detailed documentation.
