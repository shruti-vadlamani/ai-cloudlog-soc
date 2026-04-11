# Pre-Deployment Checklist

## ✅ Local Setup & Testing (Do This First!)

### 1. Environment Setup
- [ ] Copy `.env.example` to `.env` (locally only)
- [ ] Fill in Neo4j Aura credentials from your account
- [ ] Never commit `.env` (it's in `.gitignore`)

### 2. Run Backend Locally
```bash
# From project root
cd backend
pip install -r requirements.txt
export ENVIRONMENT=development
export FRONTEND_URL=http://localhost:3000
uvicorn main:app --reload --port 8000
```
- [ ] Server starts without errors
- [ ] Logs show "Uvicorn running on http://127.0.0.1:8000"
- [ ] Visit http://localhost:8000/health → should return `{"status": "healthy"}`
- [ ] Visit http://localhost:8000/api/alerts → should return alerts or empty list

### 3. Run Frontend Locally
```bash
# From project root
cd frontend
npm install  # if not already done
npm start
```
- [ ] Frontend opens at http://localhost:3000
- [ ] No red errors in browser console
- [ ] "Backend proxy target: http://localhost:8000" in console

### 4. Test Connection
In browser console (F12):
```javascript
fetch('http://localhost:8000/api/alerts')
  .then(r => r.json())
  .then(d => console.log('Success:', d))
  .catch(e => console.error('Error:', e))
```
- [ ] Returns data (no CORS errors)

### 5. Test Neo4j Connection
```bash
# From backend directory
python -c "
from neo4j import GraphDatabase
uri = 'neo4j+s://YOUR_INSTANCE.databases.neo4j.io'
driver = GraphDatabase.driver(uri, auth=('YOUR_USER', 'YOUR_PASS'))
print('✓ Neo4j connection successful')
driver.close()
"
```
- [ ] Prints "✓ Neo4j connection successful"

---

## ✅ Code Quality & Git Setup

### 6. Code Review
- [ ] No hardcoded credentials in code
- [ ] No `print()` statements (use logging)
- [ ] No development URLs in production config
- [ ] Requirements match installed versions: `pip list`

### 7. Git Setup
```bash
# From project root
git status
```
- [ ] Only modified files are listed (no .env visible!)
- [ ] Check `.gitignore` includes `.env`, `node_modules/`, `__pycache__/`

### 8. Commit Your Changes
```bash
# If not already done
git add .
git commit -m "Setup deployment configuration

- Add Vercel config for frontend
- Add Render config for backend
- Add deployment guides and docs
- Update CORS for production/development
- Add environment variable templates
"
git push origin main
```
- [ ] Changes pushed to GitHub

### 9. Verify Git Doesn't Have Secrets
```bash
# Search for any leftover credentials
git log --all --grep="password\|secret\|key" --oneline
git grep -i "password\|secret\|api_key" -- . ':!DEPLOYMENT*' ':!ARCHITECTURE*'
```
- [ ] No credentials found in git history
- [ ] Only templates shown (DEPLOYMENT_GUIDE.md, etc.)

---

## ✅ Files Verification

### 10. Required Files Exist
```bash
# From project root, verify these files:
ls -la backend/runtime.txt          # ✓
ls -la backend/Procfile             # ✓
ls -la backend/.env.example         # ✓
ls -la backend/build.sh             # ✓
ls -la frontend/.env.development    # ✓
ls -la frontend/.env.production     # ✓
ls -la DEPLOYMENT_GUIDE.md          # ✓
ls -la QUICK_START_DEPLOY.md        # ✓
```
- [ ] All 8 files exist

### 11. Backend Structure
- [ ] `backend/` has subdirectories: `api/`, `services/`, `models/`, `data_generation/`, `rag_ingestion/`
- [ ] `backend/main.py` starts server on `/`
- [ ] `backend/config.yaml` has Neo4j config

### 12. Frontend Structure
- [ ] `frontend/src/` has `App.js`, `components/`, etc.
- [ ] `frontend/package.json` has build script
- [ ] `frontend/public/index.html` exists

---

## ✅ Deployment Configuration Review

### 13. Backend Files
Check `backend/Procfile`:
```bash
cat backend/Procfile
# Should contain: web: gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.main:app...
```
- [ ] Procfile is correct

Check `backend/runtime.txt`:
```bash
cat backend/runtime.txt
# Should be: python-3.11.8
```
- [ ] Python version is 3.11.x

Check `backend/requirements.txt` includes:
```bash
grep -E "gunicorn|fastapi|uvicorn|chromadb|neo4j" backend/requirements.txt
```
- [ ] gunicorn ≥ 21.2.0
- [ ] fastapi ≥ 0.104.0
- [ ] uvicorn ≥ 0.24.0
- [ ] chromadb ≥ 0.4.0
- [ ] neo4j ≥ 5.14.0

### 14. Frontend Files
Check `frontend/vercel.json`:
```bash
cat frontend/vercel.json
# Should have buildCommand, outputDirectory, etc.
```
- [ ] Vercel config exists

Check `frontend/.env.production`:
```bash
cat frontend/.env.production
# Should have REACT_APP_API_URL placeholder
```
- [ ] Environment template exists

### 15. Main app.py CORS Config
```bash
grep -A 10 "environment = os.getenv" backend/main.py
# Should check ENVIRONMENT and set CORS accordingly
```
- [ ] CORS logic updated for prod/dev

---

## ✅ Security Checklist

### 16. No Secrets in Code
```bash
# Search for common secret patterns
grep -r "password\|secret\|key\|token" backend/ \
  | grep -v "requirements\|config.yaml\|.env.example\|DEPLOYMENT\|ARCHITECTURE" \
  | head -20
```
- [ ] Only configuration references (no actual values)

### 17. No Credentials in Git
```bash
# Check recent git history
git log --oneline -10
git show HEAD:backend/main.py | grep -i "password\|token\|secret" || echo "✓ No secrets in HEAD"
```
- [ ] No credentials committed

### 18. .env File Handling
```bash
# Verify .env is NOT in git
git ls-files | grep "\.env$"
# Should return nothing
```
- [ ] `.env` is not tracked in git
- [ ] Only `.env.example` and `.env.*` templates are tracked

---

## ✅ Pre-Deployment Final Checks

### 19. Test Build Process
```bash
# Simulate Render build
cd backend
pip install -r requirements.txt --dry-run
pip install gunicorn
echo "Build simulation OK"
```
- [ ] All dependencies installable

### 20. Database Connectivity
```bash
# Test all databases locally
python -c "
import chromadb
import neo4j
print('✓ Imports successful')

# Test Neo4j (with real credentials from .env)
from dotenv import load_dotenv
import os
load_dotenv()

driver = neo4j.GraphDatabase.driver(
    os.getenv('NEO4J_URI'),
    auth=(os.getenv('NEO4J_USERNAME'), os.getenv('NEO4J_PASSWORD'))
)
print('✓ Neo4j connected')
driver.close()

# Test ChromaDB
db = chromadb.Client()
print('✓ ChromaDB connected')
"
```
- [ ] Both databases connect successfully

### 21. API Endpoints Test
```bash
# Start backend
cd backend
uvicorn main:app --port 8000 &
sleep 3

# Test endpoints
curl http://localhost:8000/health
curl http://localhost:8000/api/alerts

# Kill process
pkill -f "uvicorn main:app"
```
- [ ] `/health` returns `{"status": "healthy"}`
- [ ] `/api/alerts` returns JSON (data or empty)

### 22. Frontend Build Test
```bash
# From frontend directory
npm install
npm run build
# Should create build/ directory with no errors
```
- [ ] Build succeeds
- [ ] No TypeScript/ESLint errors
- [ ] `./frontend/build/` folder created

---

## ✅ Ready for Deployment!

### Final Checklist
- [ ] All local tests pass
- [ ] Code committed to GitHub `main` branch
- [ ] No `.env` file in git (only `.env.example`)
- [ ] All required deployment files created
- [ ] Backend can start with gunicorn
- [ ] Frontend builds successfully
- [ ] Neo4j Aura credentials working
- [ ] ChromaDB can initialize

### Next Step: DEPLOY!

Go to **[QUICK_START_DEPLOY.md](./QUICK_START_DEPLOY.md)** for step-by-step deployment.

---

## 🆘 If Something Fails

### Backend won't start locally?
```bash
# Check Python version
python --version  # Should be ≥ 3.8, ideally 3.11

# Install dependencies fresh
pip install --upgrade pip
pip install -r backend/requirements.txt

# Try with uvicorn directly
cd backend
uvicorn main:app --reload
```

### Frontend won't start?
```bash
# Clear cache
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Neo4j connection fails?
```bash
# Verify credentials
echo "URI: $NEO4J_URI"
echo "USER: $NEO4J_USERNAME"
# (don't echo password)

# Test with cypher-shell (if installed)
cypher-shell -a $NEO4J_URI -u $NEO4J_USERNAME -p $NEO4J_PASSWORD "RETURN 1;"
```

### Get help in Render logs (after deploying)
```bash
# When deployed, check Render logs
# Go to Render dashboard → Logs tab
# Search for "ERROR" or service name
```

---

**You're ready to deploy!** 🚀

Next: [QUICK_START_DEPLOY.md](./QUICK_START_DEPLOY.md)
