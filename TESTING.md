# Testing Guide - Phishing Detection System

Quick guide to run and test the entire system from scratch.

---

## 🚀 Quick Start (Full System Test)

### Option 1: Docker (Easiest)

```bash
# Build and run everything
docker-compose up -d

# Check logs
docker-compose logs -f

# Access:
# - Frontend: http://localhost:3000
# - Backend API: http://localhost:8000/docs
```

### Option 2: Manual Setup (Step-by-Step)

---

## 📋 Step-by-Step Testing

### Step 1: Install Dependencies

```bash
cd d:\Projects\phishing-detection-ml

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Prepare Data

```bash
# Download dataset (if not already done)
# Place CSV in data/raw/phishing_dataset.csv

# Load and split data
python src/preprocessing/data_loader.py
```

**Expected output:**
```
✓ Loaded 11,430 records
✓ Train: 7,430, Val: 2,000, Test: 2,000
✓ Saved to data/processed/
```

### Step 3: Train Models

```bash
# Train text classifier
python src/training/text_classifier.py

# Train URL classifier
python src/training/url_classifier.py

# Train ensemble
python src/training/ensemble_model.py
```

**Expected output:**
```
✓ Text Classifier: 88.5% accuracy
✓ URL Classifier: 84.2% accuracy
✓ Ensemble: 91.3% accuracy
✓ Models saved to models/
```

### Step 4: Run Backend API

```bash
# Start API server
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

**Expected output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

**Test API:**
```bash
# Health check
curl http://localhost:8000/health

# Make prediction
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d "{\"email_text\": \"URGENT! Verify your account at http://phishing.com\"}"
```

### Step 5: Run Frontend Dashboard

```bash
cd frontend/dashboard

# Install dependencies
npm install

# Start development server
npm start
```

**Access:** http://localhost:3000

### Step 6: Run Browser Extension

```bash
# Open Chrome and go to:
chrome://extensions/

# Enable "Developer mode" (top right)

# Click "Load unpacked"

# Select folder:
d:\Projects\phishing-detection-ml\frontend\browser-extension\

# Extension should appear in toolbar
```

### Step 7: Run Tests

```bash
cd d:\Projects\phishing-detection-ml

# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# View coverage report
# Open: htmlcov/index.html
```

---

## 🧪 Manual Testing Scenarios

### Test 1: Phishing Email Detection

**Input (via Dashboard or API):**
```
URGENT! Your bank account has been suspended.
Click here immediately to verify: http://192.168.1.1/verify
Account: 1234567890
Login now or lose access!
```

**Expected Output:**
- Verdict: **PHISHING**
- Risk Score: **0.85-0.95**
- Confidence: **HIGH**
- Top Risk Factors:
  - Urgency words detected
  - IP-based URL
  - Financial keywords

### Test 2: Legitimate Email

**Input:**
```
Hi there,

Just wanted to check in about our meeting tomorrow at 2pm.
Let me know if you're still available.

Best regards,
John
```

**Expected Output:**
- Verdict: **LEGITIMATE**
- Risk Score: **0.05-0.15**
- Confidence: **HIGH**

### Test 3: Suspicious Email (Medium Risk)

**Input:**
```
Hello,

Your package is waiting for pickup.
Click here: http://track-package-delivery.com/id=12345

Thanks
```

**Expected Output:**
- Verdict: **PHISHING** or **LEGITIMATE** (borderline)
- Risk Score: **0.40-0.60**
- Confidence: **MEDIUM**

---

## 🔍 Testing Each Component

### Test Text Features

```bash
python -c "
from src.feature_engineering.text_features import TextFeatureExtractor

extractor = TextFeatureExtractor()
emails = ['URGENT! Verify account!', 'Meeting at 3pm']
features = extractor.fit_transform(emails)
print(f'Features extracted: {features.shape}')
"
```

### Test URL Features

```bash
python -c "
from src.feature_engineering.url_features import URLFeatureExtractor

extractor = URLFeatureExtractor()
emails = ['Click http://192.168.1.1/verify', 'Visit https://google.com']
features = extractor.fit_transform(emails)
print(f'URL features: {features.shape}')
"
```

### Test Ensemble Model

```bash
python -c "
from src.training.ensemble import EnsembleModel

# Load saved ensemble
ensemble = EnsembleModel.load('models/ensemble/v1.0/')

# Predict
email = 'URGENT! Bank suspended! Click http://phish.com'
prediction = ensemble.predict([email])
print(f'Prediction: {prediction[0]}')
"
```

---

## 🌐 API Endpoint Tests

### 1. Predict Endpoint

```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Test email"
  }'
```

### 2. Explain Endpoint

```bash
curl -X POST http://localhost:8000/api/v1/explain \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "URGENT! Click here: http://evil.com"
  }'
```

### 3. Feedback Endpoint

```bash
# First make a prediction to get prediction_id
PRED_ID=$(curl -s -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"email_text": "test"}' | jq -r '.prediction_id')

# Submit feedback
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Content-Type: application/json" \
  -d "{
    \"prediction_id\": \"$PRED_ID\",
    \"true_label\": 0,
    \"comment\": \"This was actually safe\"
  }"
```

### 4. Feedback Stats

```bash
curl http://localhost:8000/api/v1/feedback/stats
```

---

## 🐛 Troubleshooting

### Models Not Found

```bash
# Check if models exist
dir models\

# If missing, train models:
python src/training/text_classifier.py
python src/training/url_classifier.py
python src/training/ensemble_model.py
```

### API Won't Start

```bash
# Check if port 8000 is in use
netstat -ano | findstr :8000

# Kill process if needed
taskkill /PID <PID> /F

# Or use different port
uvicorn src.api.main:app --port 8001
```

### Import Errors

```bash
# Add src to PYTHONPATH
set PYTHONPATH=d:\Projects\phishing-detection-ml\src

# Or install as package
pip install -e .
```

### Database Errors

```bash
# Initialize database
python -c "from src.api.database import init_db; init_db()"

# Or delete and recreate
del data\phishing.db
python src/api/database.py
```

### Frontend Won't Start

```bash
cd frontend/dashboard

# Clear cache
rmdir /s /q node_modules
del package-lock.json

# Reinstall
npm install
npm start
```

---

## 📊 Generating Reports

### Model Performance Report

```bash
python scripts/generate_model_report.py
```

Output: `outputs/reports/model_report.html`

### Sample Predictions

```bash
python scripts/generate_samples.py
```

Output: `outputs/samples/predictions.json`

---

## ✅ Verification Checklist

- [ ] Virtual environment activated
- [ ] Dependencies installed (`pip list`)
- [ ] Data loaded (`data/processed/` exists)
- [ ] Models trained (`models/` exists)
- [ ] API running (`http://localhost:8000/health`)
- [ ] Frontend running (`http://localhost:3000`)
- [ ] Tests passing (`pytest`)
- [ ] Browser extension loaded

---

## 🎯 Quick Test Commands

```bash
# Full test sequence
cd d:\Projects\phishing-detection-ml
venv\Scripts\activate
python src/preprocessing/data_loader.py
python src/training/text_classifier.py
python src/training/url_classifier.py
python src/training/ensemble_model.py
uvicorn src.api.main:app --reload

# In another terminal
cd frontend/dashboard
npm start

# In another terminal  
pytest --cov=src
```

---

## 🚀 Next Steps

1. **Test with real phishing emails** from PhishTank or OpenPhish
2. **Measure performance** with model report
3. **Try adversarial examples** to test robustness
4. **Deploy with Docker** for demo
5. **Share with classmates** for feedback

**Happy testing! 🎉**
