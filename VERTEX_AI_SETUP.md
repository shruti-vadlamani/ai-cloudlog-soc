# Vertex AI (Gemini) Integration Setup

This guide explains how to set up Google Cloud Vertex AI with Gemini models for LLM synthesis in the Cloud SOC backend.

## Prerequisites

1. **Google Cloud Project** — You should have a GCP project already set up
2. **Vertex AI API Enabled** — Enable the Vertex AI API in your GCP project:
   ```
   gcloud services enable aiplatform.googleapis.com
   ```
3. **Service Account with Vertex AI Permissions** — Your `GCP_CREDENTIALS` should contain a service account JSON payload with these roles:
   - `roles/aiplatform.user` (Vertex AI User)
   - Or `roles/editor` for broad access

## Environment Setup

### 1. Install Dependencies

The required packages are already listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

This installs:
- `google-cloud-aiplatform>=1.42.0` — Google Cloud Vertex AI SDK
- `google-auth>=2.25.0` — Google authentication library

### 2. Set Up Google Cloud Credentials

The backend reads credentials from `GCP_CREDENTIALS` in `.env` and parses it as JSON.

```dotenv
GCP_CREDENTIALS='{"type":"service_account","project_id":"your-project-id",...}'
```

**Make sure this JSON payload is a valid service account key with Vertex AI permissions.**

### 3. Extract Project ID (Optional but Recommended)

The Vertex AI client will automatically detect your project ID from `GCP_CREDENTIALS`. You can also explicitly set it:

```dotenv
GCP_PROJECT_ID=your-project-id
```

## How It Works

### Initialization Flow

1. **RAGService starts** — During `_init_rag()`, it calls `get_vertex_ai_client()`
2. **VertexAIClient initializes** — Loads credentials from `GCP_CREDENTIALS`
3. **Gemini Model loaded** — The `gemini-1.5-pro` model is instantiated
4. **LLM enabled** — RAG queries with `use_llm=true` now use Gemini instead of Ollama

### API Usage

#### Query with LLM Synthesis

```bash
curl "http://localhost:8000/api/rag/query?q=What+are+privilege+escalation+indicators&use_llm=true"
```

The backend will:
1. Search ChromaDB for relevant documents
2. Send the top results + question to Gemini
3. Return an LLM-synthesized explanation

#### Without LLM (Search Only)

```bash
curl "http://localhost:8000/api/rag/query?q=What+are+privilege+escalation+indicators&use_llm=false"
```

Returns only ChromaDB search results, no LLM synthesis.

## Files Changed

### New Files
- `backend/services/vertex_ai_client.py` — Vertex AI client service with Gemini integration

### Modified Files
- `backend/services/rag_service.py` — Initialize Vertex AI client, use in `_generate_explanation()`
- `backend/api/rag.py` — Update graph explanation endpoint to use Vertex AI
- `requirements.txt` — Added Google Cloud dependencies

### Removed/Replaced
- **Ollama references** — All Ollama integration code removed/commented
- **Ollama API calls** — Replaced with Vertex AI SDK calls

## Troubleshooting

### "Could not determine project ID" Error

**Solution:** Set `GCP_PROJECT_ID` in `.env`:
```dotenv
GCP_PROJECT_ID=your-gcp-project-id
```

Or ensure your `GCP_CREDENTIALS` payload has proper project metadata.

### "Vertex AI initialization failed" Warning

**Check:**
1. Is `GCP_CREDENTIALS` set and valid JSON?
2. Does the service account have `roles/aiplatform.user` permission?
3. Is the Vertex AI API enabled in your GCP project?

**Enable Vertex AI API:**
```bash
gcloud services enable aiplatform.googleapis.com --project=your-project-id
```

### "No text extracted from Gemini response" Error

**Possible causes:**
- Model is rate-limited (try again after a few seconds)
- Response was filtered for safety reasons
- API quota exceeded

**Check quotas:**
```bash
gcloud compute project-info describe --project=your-project-id
```

### Slow Response Times

**Optimization:**
1. Increase `max_tokens` in `vertex_ai_client.py` if responses are being cut off
2. Use `temperature=0.3` (already set) for faster, more deterministic responses
3. Consider using `gemini-1.5-flash` for faster responses at lower cost:
   ```python
   VertexAIClient(model_name="gemini-2.0-flash-001")
   ```

## API Reference

### VertexAIClient Methods

#### `generate_text_sync(prompt, temperature=0.3, max_tokens=1024, top_p=0.9)`

Generate text from a prompt (synchronous, for FastAPI).

**Args:**
- `prompt` (str): Input text
- `temperature` (float): Creativity (0.0-1.0, lower = deterministic)
- `max_tokens` (int): Maximum response length
- `top_p` (float): Nucleus sampling parameter

**Returns:** Generated text (str)

**Example:**
```python
client = get_vertex_ai_client()
response = client.generate_text_sync(
    "What is privilege escalation?",
    temperature=0.3,
    max_tokens=512
)
```

#### `chat(messages, temperature=0.3, max_tokens=1024, top_p=0.9)`

Chat-style interface (returns Ollama-compatible format for backward compatibility).

**Args:**
- `messages` (list): List of `{"role": "user"/"assistant", "content": "..."}`
- Other parameters same as `generate_text_sync`

**Returns:**
```python
{
    "message": {
        "content": "Generated response..."
    }
}
```

## Configuration

### Model Selection

Change the Gemini model in `backend/services/rag_service.py`:

```python
self.llm_handler = get_vertex_ai_client(
    model_name="gemini-2.0-flash-001"  # Latest model with better performance
)
```

Available models:
- `gemini-1.5-pro` — Most capable, better reasoning (default)
- `gemini-1.5-flash` — Faster, cheaper, good for simple tasks
- `gemini-1.0-pro` — Older model, widely available

### Temperature Tuning

Lower temperature for more consistent analysis (already set to 0.3):
- `0.0` — Deterministic (same answer every time)
- `0.3` — Focused, consistent (good for security analysis)
- `0.7` — Balanced creativity and consistency
- `1.0` — Maximum creativity

### Response Length

Adjust `max_tokens` based on your needs:
- `512` — Short responses (faster, cheaper)
- `1024` — Medium responses (default)
- `2048` — Long detailed responses (slower, more expensive)

## Cost Optimization

Vertex AI Gemini pricing is based on input/output tokens. To reduce costs:

1. **Use Gemini Flash** for simpler tasks:
   ```python
   model_name="gemini-1.5-flash"
   ```

2. **Reduce max_tokens** — Shorter responses = lower cost:
   ```python
   max_tokens=512  # Instead of 1024
   ```

3. **Cache results** — Don't re-query for identical prompts

4. **Batch requests** — Process multiple queries in one API call

## Monitoring

Check Vertex AI usage in GCP Console:
1. Go to [Vertex AI → Model Evaluation](https://console.cloud.google.com/vertex-ai/model-evaluation)
2. Monitor token usage and costs
3. Set up billing alerts to avoid surprises

## Support

For issues:
1. Check logs in `backend/` output
2. Verify GCP credentials and permissions
3. Check [Vertex AI documentation](https://cloud.google.com/vertex-ai/docs)
4. Review error messages in `backend/services/vertex_ai_client.py`
