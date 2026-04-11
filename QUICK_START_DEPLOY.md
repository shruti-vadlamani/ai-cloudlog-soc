# Quick Start: Deploy to Vercel + Render

## 📋 Prerequisites

- [ ] GitHub account with the repo pushed
- [ ] Vercel account (free tier at vercel.com)
- [ ] Render account (free tier at render.com)
- [ ] Neo4j Aura instance (already configured in `.env`)

---

## 🚀 Part 1: Deploy Frontend to Vercel (5 min)

### Step 1: Go to Vercel Dashboard
1. Visit [vercel.com](https://vercel.com)
2. Sign up or log in with GitHub
3. Click **Add New** → **Project**

### Step 2: Import Repository
1. Select your GitHub repo `ai-cloudlog-soc`
2. Click **Import**

### Step 3: Configure Build
- **Framework Preset:** React
- **Root Directory:** `frontend`
- **Build Command:** `npm run build`
- **Output Directory:** `build`
- **Install Command:** `npm ci`

### Step 4: Environment Variables
Add only this (will update after backend deploy):
```
REACT_APP_API_URL=https://api.example.com
REACT_APP_ENVIRONMENT=production
```

### Step 5: Deploy
- Click **Deploy**
- Wait ~2 min
- Note your Vercel URL: `https://your-project-XXXX.vercel.app`

✅ **Frontend is live!**

---

## 🚀 Part 2: Deploy Backend to Render (10 min)

### Step 1: Push Backend Folder to GitHub
Ensure your repo has proper structure:
```
ai-cloudlog-soc/
├── backend/               ← All backend code here
├── frontend/              ← All frontend code here
├── .env                   ← Environment variables
└── README.md
```

### Step 2: Go to Render Dashboard
1. Visit [render.com](https://render.com)
2. Sign up or log in with GitHub
3. Click **New +** → **Web Service**

### Step 3: Connect Repository
1. Select your `ai-cloudlog-soc` repo
2. Click **Connect**

### Step 4: Configure Service

**Basic Settings:**
- **Name:** `ai-cloudlog-soc-backend`
- **Region:** Choose closest to your users
- **Branch:** `main`
- **Runtime:** `Python 3.11`
- **Build Command:**
  ```bash
  pip install -r backend/requirements.txt
  ```
- **Start Command:**
  ```bash
  gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.main:app --bind 0.0.0.0:$PORT
  ```

**Plan:** Select **Free** tier

### Step 5: Add Environment Variables
Click **Advanced** and add:
```
ENVIRONMENT=production
FRONTEND_URL=https://your-project-XXXX.vercel.app
NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
NEO4J_USERNAME=your-username
NEO4J_PASSWORD=your-password
NEO4J_DATABASE=your-db-name
CHROMA_DATA_DIR=/var/tmp/chroma_db
```

### Step 6: Add Persistent Storage
1. In **Advanced** → Click **Create Disk**
2. **Mount Path:** `/var/tmp/chroma_db`
3. **Size:** `1 GB` (free tier max)

### Step 7: Deploy
- Click **Create Web Service**
- Wait ~3-5 min for build
- Note your Render URL: `https://ai-cloudlog-soc-backend-XXXX.onrender.com`

✅ **Backend is live!**

---

## 🔗 Part 3: Update Frontend to Point to Backend (2 min)

### Go Back to Vercel Dashboard
1. Select your `ai-cloudlog-soc` project
2. Go to **Settings** → **Environment Variables**
3. Update `REACT_APP_API_URL`:
   - Old: `https://api.example.com`
   - New: `https://ai-cloudlog-soc-backend-XXXX.onrender.com`
4. Click **Save**

### Redeploy Frontend
1. Go to **Deployments**
2. Click the latest deployment
3. Click **Redeploy** (top right)
4. Confirm

✅ **Frontend now connects to backend!**

---

## ✅ Verification Checklist

### Test Frontend
1. Open `https://your-project-XXXX.vercel.app`
2. Should load without errors
3. Check DevTools Console for API errors

### Test Backend
1. Open `https://ai-cloudlog-soc-backend-XXXX.onrender.com/health`
2. Should return: `{"status": "healthy"}`
3. Open `/api/alerts` to test API
4. Check response in **Render Logs** dashboard

### Test Connection
In frontend DevTools Console:
```javascript
fetch('https://ai-cloudlog-soc-backend-XXXX.onrender.com/api/alerts')
  .then(r => r.json())
  .then(d => console.log('Success:', d))
  .catch(e => console.error('Error:', e))
```

Should return alerts data (no CORS errors).

---

## 🆘 Common Issues & Fixes

### Issue: "Backend offline" on frontend
**Causes:**
- Render URL not updated in Vercel env vars
- Render service still building (wait 5 min)
- CORS not configured

**Fix:**
```bash
# 1. Check env var
vercel env list

# 2. Re-deploy Vercel
vercel redeploy --prod

# 3. Check Render logs
# Go to Render dashboard → View logs
```

### Issue: "Cold start" - first request takes 30 sec
**This is normal on Render free tier.**

**Solution 1 (Free):** 
- Add keep-alive ping every 5 min from frontend

**Solution 2 ($5/mo):**
- Upgrade Render to **Starter** ($5/mo) for always-on

**Solution 3 ($5/mo):**
- Switch to **Railway** instead of Render

### Issue: ChromaDB lost after redeploy
**Cause:** Persistent disk not mounted

**Fix:**
1. Go to Render dashboard
2. Select your service
3. **Disks** → Add disk with `/var/tmp/chroma_db`
4. Redeploy

### Issue: Neo4j connection error
**Fix:**
1. Verify credentials in `.env`
2. Check Neo4j Aura whitelist (allow all IPs)
3. Test locally:
   ```bash
   python -c "from neo4j import GraphDatabase; db = GraphDatabase.driver('neo4j+s://...', auth=('user', 'pass')); print(db.driver); db.close()"
   ```

---

## 📊 Monitoring & Logs

### Vercel Logs
1. Go to [vercel.com](https://vercel.com)
2. Select project → **Deployments**
3. Click deployment → **Runtime Logs**

### Render Logs
1. Go to [render.com](https://render.com)
2. Select service
3. Click **Logs** tab (real-time)

### Check Environment Variables (Render)
1. Select service → **Settings**
2. Scroll to **Environment**
3. Verify all vars are set

---

## 🆙 Next Steps: Scaling

When ready for production:

**Option 1: Always-On Backend ($5/mo)**
- Render **Starter** plan → $5/month
- No cold starts, better performance

**Option 2: Better DB ($15/mo)**
- Switch ChromaDB to **Supabase** (PostgreSQL + pgvector)
- More reliable than in-memory storage

**Option 3: Enterprise ($100+/mo)**
- AWS EC2 or Railway
- Neo4j Aura Pro
- S3 for CloudTrail logs

---

## 🎯 What's Deployed

**Frontend (Vercel)**
- React UI with charts & graphs
- Calls backend API via `REACT_APP_API_URL`

**Backend (Render)**
- FastAPI server
- ML model endpoints
- RAG/ChromaDB queries
- Neo4j knowledge graph queries
- Auto-sleeps after 15 min (free tier)

**Databases**
- Neo4j Aura (cloud, free 5GB)
- ChromaDB (in Render filesystem)

---

## 💡 Tips

- **Keep `.env` in `.gitignore`** (never commit secrets)
- **Use `.env.example`** for template
- **Test locally first** before deploying:
  ```bash
  # Terminal 1
  cd backend && uvicorn backend.main:app --reload
  
  # Terminal 2
  cd frontend && npm start
  ```
- **Monitor cold starts** - can add ping job if needed
- **Backup ChromaDB** before major updates

---

**Done! Your AI CloudLog SOC is live on the internet.** 🎉

Need help? Check the [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) for advanced options.
