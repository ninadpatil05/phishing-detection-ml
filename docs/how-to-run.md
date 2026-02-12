# How to Run - Phishing Detection System

## Quick Start Guide

### Prerequisites
- Python 3.10+ installed
- Node.js 18+ installed
- Virtual environment activated

---

## Starting the System

### Terminal 1: Backend (FastAPI)

```bash
# 1. Navigate to project root
cd d:\Projects\phishing-detection-ml

# 2. Activate virtual environment
venv\Scripts\activate

# 3. Start backend server
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

**Expected Output:**
```
======================================================================
LOADING ML MODELS
======================================================================
Loading models...
[OK] All models loaded successfully
======================================================================

INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Application startup complete.
```

**✓ Success Indicators:**
- `[OK] All models loaded successfully` - Models are ready
- `Application startup complete` - API is running
- No error messages

**Backend URLs:**
- API: http://localhost:8000
- Swagger Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

---

### Terminal 2: Frontend (React)

```bash
# 1. Navigate to frontend directory
cd d:\Projects\phishing-detection-ml\frontend\dashboard

# 2. Install dependencies (first time only)
npm install

# 3. Start development server
npm start
```

**Expected Output:**
```
Compiled successfully!

You can now view phishing-detection-dashboard in the browser.

  Local:            http://localhost:3000
  On Your Network:  http://192.168.x.x:3000

Note that the development build is not optimized.
To create a production build, use npm run build.
```

**✓ Success Indicators:**
- `Compiled successfully!` - No build errors
- Browser opens automatically to http://localhost:3000
- No error messages in console

**Frontend URL:**
- Dashboard: http://localhost:3000

---

### Terminal 3: Test Connection

```bash
# Navigate to project root
cd d:\Projects\phishing-detection-ml

# Run connection test
python scripts\test_connection.py
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════════╗
║     PHISHING DETECTION - CONNECTION DIAGNOSTIC TOOL              ║
╚═══════════════════════════════════════════════════════════════════╝

======================================================================
TEST 1: Backend Health Check
======================================================================

✓ SUCCESS: Backend is running!
ℹ INFO:   Status: healthy
ℹ INFO:   Version: 1.0.0
ℹ INFO:   Models loaded: True

======================================================================
TEST 2: Prediction Endpoint
======================================================================

✓ SUCCESS: Prediction endpoint working!
ℹ INFO:   Verdict: PHISHING
ℹ INFO:   Risk Score: 0.XXX
ℹ INFO:   Confidence: HIGH

...

Overall: 4/4 tests passed

✓ ALL TESTS PASSED! System is working correctly.
```

---

## Testing the Dashboard

### 1. Open Dashboard
Navigate to: http://localhost:3000

### 2. Test Phishing Email
Paste this into the email input:
```
URGENT! Your bank account has been suspended!
Click http://192.168.1.1/verify immediately to restore access!
Account: 1234567890
```

Click **"Analyze Email"**

**Expected Result:**
- Verdict: **PHISHING**
- Risk Score: **0.85-0.95** (high)
- Confidence: **HIGH**
- Shows risk factors (urgency words, IP URL, etc.)

### 3. Test Safe Email
Paste this into the email input:
```
Hi,

Just wanted to check in about our meeting tomorrow at 2pm.
Let me know if you're still available.

Best regards,
John
```

Click **"Analyze Email"**

**Expected Result:**
- Verdict: **SAFE**
- Risk Score: **0.05-0.15** (low)
- Confidence: **HIGH**

---

## Troubleshooting

### Backend Won't Start

**Problem:** `ModuleNotFoundError` or import errors

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

---

**Problem:** `Models not loaded` error

**Solution:**
```bash
# Generate test models
python scripts\quick_test_setup.py
```

---

**Problem:** Port 8000 already in use

**Solution:**
```bash
# Kill process on port 8000
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Or use different port
uvicorn src.api.main:app --reload --port 8001
```

---

### Frontend Won't Start

**Problem:** `npm ERR!` or dependency errors

**Solution:**
```bash
cd frontend\dashboard

# Clear cache
rmdir /s /q node_modules
del package-lock.json

# Reinstall
npm install
npm start
```

---

**Problem:** "Cannot GET /" error

**Solution:**
Make sure you're in the `frontend/dashboard` directory, not project root.

---

### Connection Issues

**Problem:** Dashboard shows "API offline" or "Analysis failed"

**Solution:**
```bash
# 1. Check if backend is running
curl http://localhost:8000/health

# 2. Run connection test
python scripts\test_connection.py

# 3. Check browser console for errors (F12)
# Look for CORS errors or network failures
```

---

**Problem:** CORS errors in browser console

**Solution:**
Backend CORS is configured for `http://localhost:3000`.
If using different port, update `src/api/main.py` line 112:
```python
allow_origins=[
    "http://localhost:3000",  # Add your port here
],
```

---

## Quick Commands Reference

```bash
# Backend
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend\dashboard && npm start

# Test connection
python scripts\test_connection.py

# Run tests
pytest --cov=src

# Generate models
python scripts\quick_test_setup.py
```

---

## Port Configuration

| Service | Port | URL |
|---------|------|-----|
| Backend API | 8000 | http://localhost:8000 |
| API Docs | 8000 | http://localhost:8000/docs |
| Frontend | 3000 | http://localhost:3000 |

**Note:** If ports conflict, you can change them:
- Backend: Add `--port 8001` to uvicorn command
- Frontend: Set `PORT=3001` environment variable

---

## Environment Variables

### Backend
None required for local development.

### Frontend
Create `frontend/dashboard/.env`:
```env
REACT_APP_API_BASE_URL=http://localhost:8000/api/v1
```

Default value is used if not set.

---

## Success Checklist

Before using the system, verify:

- [ ] Backend terminal shows "Application startup complete"
- [ ] Backend terminal shows "[OK] All models loaded successfully"
- [ ] Frontend terminal shows "Compiled successfully!"
- [ ] http://localhost:8000/health returns `{"status": "healthy"}`
- [ ] http://localhost:8000/docs shows Swagger UI
- [ ] http://localhost:3000 loads the dashboard
- [ ] Test email analysis works in dashboard
- [ ] `python scripts\test_connection.py` shows all tests passed

---

## Next Steps

Once everything is running:

1. **Try the Dashboard** - http://localhost:3000
2. **Explore API Docs** - http://localhost:8000/docs
3. **Run Tests** - `pytest`
4. **Try Browser Extension** - Load from `frontend/browser-extension/`

---

## Need Help?

1. Run connection test: `python scripts\test_connection.py`
2. Check backend logs in Terminal 1
3. Check frontend console (F12 in browser)
4. Verify both services are running

**Common issue:** If dashboard can't connect, backend is probably not running or models aren't loaded.
