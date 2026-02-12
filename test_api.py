"""
Simple API Test Script

Run this to test if your phishing detection API is working.
"""

import requests
import json

print("=" * 70)
print("TESTING PHISHING DETECTION API")
print("=" * 70)

# Test 1: Health Check
print("\n1. Testing Health Endpoint...")
try:
    response = requests.get("http://localhost:8000/health")
    if response.status_code == 200:
        print("   [OK] API is running!")
        print(f"   Response: {response.json()}")
    else:
        print(f"   [FAIL] Health check failed: {response.status_code}")
except Exception as e:
    print(f"   [FAIL] Cannot connect to API: {e}")
    print("\n   Make sure the API is running:")
    print("   uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000")
    exit(1)

# Test 2: Phishing Email Detection
print("\n2. Testing Phishing Email Detection...")
phishing_email = {
    "email_text": "URGENT! Your bank account has been suspended! Click http://192.168.1.1/verify NOW!"
}

try:
    response = requests.post(
        "http://localhost:8000/api/v1/predict",
        json=phishing_email,
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code == 200:
        result = response.json()
        print("   [OK] Prediction successful!")
        print(f"   Verdict: {result['verdict']}")
        print(f"   Risk Score: {result['risk_score']:.2f}")
        print(f"   Confidence: {result['confidence']}")
    else:
        print(f"   [FAIL] Prediction failed: {response.status_code}")
        print(f"   Error: {response.text}")
except Exception as e:
    print(f"   [FAIL] Prediction error: {e}")

# Test 3: Safe Email Detection
print("\n3. Testing Safe Email Detection...")
safe_email = {
    "email_text": "Hi, just checking in about our meeting tomorrow at 2pm. Let me know if you're available."
}

try:
    response = requests.post(
        "http://localhost:8000/api/v1/predict",
        json=safe_email,
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code == 200:
        result = response.json()
        print("   [OK] Prediction successful!")
        print(f"   Verdict: {result['verdict']}")
        print(f"   Risk Score: {result['risk_score']:.2f}")
        print(f"   Confidence: {result['confidence']}")
    else:
        print(f"   [FAIL] Prediction failed: {response.status_code}")
        print(f"   Error: {response.text}")
except Exception as e:
    print(f"   [FAIL] Prediction error: {e}")

print("\n" + "=" * 70)
print("TESTING COMPLETE!")
print("=" * 70)
print("\nNext steps:")
print("  1. Open browser: http://localhost:8000/docs")
print("  2. Try the interactive API documentation")
print("  3. Run frontend: cd frontend\\dashboard && npm start")

