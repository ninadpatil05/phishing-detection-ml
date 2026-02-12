"""
Connection Test Script

Tests the connection between frontend and backend.
Shows exactly what's working and what's broken.
"""

import requests
import json
import sys

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_success(message):
    print(f"{GREEN}✓ SUCCESS:{RESET} {message}")

def print_fail(message):
    print(f"{RED}✗ FAIL:{RESET} {message}")

def print_info(message):
    print(f"{YELLOW}ℹ INFO:{RESET} {message}")

def print_header(message):
    print(f"\n{BOLD}{'='*70}")
    print(f"{message}")
    print(f"{'='*70}{RESET}\n")

def test_backend_health():
    """Test if backend is running and responding"""
    print_header("TEST 1: Backend Health Check")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print_success("Backend is running!")
            print_info(f"  Status: {data.get('status')}")
            print_info(f"  Version: {data.get('version')}")
            print_info(f"  Models loaded: {data.get('models_loaded')}")
            return True
        else:
            print_fail(f"Backend returned status code: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print_fail("Cannot connect to backend at http://localhost:8000")
        print_info("  Make sure backend is running:")
        print_info("  uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000")
        return False
    except Exception as e:
        print_fail(f"Unexpected error: {e}")
        return False

def test_predict_endpoint():
    """Test /api/v1/predict endpoint"""
    print_header("TEST 2: Prediction Endpoint")
    
    test_email = "URGENT! Your bank account suspended! Click http://192.168.1.1/verify"
    
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/predict",
            json={"email_text": test_email},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print_success("Prediction endpoint working!")
            print_info(f"  Prediction ID: {data.get('prediction_id')}")
            print_info(f"  Verdict: {data.get('verdict')}")
            print_info(f"  Risk Score: {data.get('risk_score'):.3f}")
            print_info(f"  Confidence: {data.get('confidence')}")
            print_info(f"  Processing Time: {data.get('processing_time_ms'):.2f}ms")
            return True
        else:
            print_fail(f"Prediction failed with status: {response.status_code}")
            print_info(f"  Error: {response.text}")
            return False
            
    except Exception as e:
        print_fail(f"Prediction request failed: {e}")
        return False

def test_cors():
    """Test CORS configuration"""
    print_header("TEST 3: CORS Configuration")
    
    try:
        # Simulate a CORS preflight request
        response = requests.options(
            "http://localhost:8000/api/v1/predict",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            },
            timeout=5
        )
        
        cors_header = response.headers.get('Access-Control-Allow-Origin')
        
        if cors_header:
            print_success("CORS is configured!")
            print_info(f"  Allowed Origin: {cors_header}")
            print_info(f"  Allowed Methods: {response.headers.get('Access-Control-Allow-Methods')}")
            return True
        else:
            print_fail("CORS headers not found!")
            print_info("  Frontend may not be able to connect")
            return False
            
    except Exception as e:
        print_fail(f"CORS test failed: {e}")
        return False

def test_frontend_connectivity():
    """Test if frontend can reach backend"""
    print_header("TEST 4: Frontend Connectivity")
    
    print_info("Testing from frontend perspective...")
    print_info("  Frontend URL: http://localhost:3000")
    print_info("  Backend URL: http://localhost:8000/api/v1")
    
    # This mimics what the frontend does
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/predict",
            json={"email_text": "test"},
            headers={
                "Content-Type": "application/json",
                "Origin": "http://localhost:3000"
            },
            timeout=5
        )
        
        if response.status_code in [200, 422]:  # 422 = validation error (expected for "test")
            print_success("Frontend can connect to backend!")
            return True
        else:
            print_fail(f"Connection issue: {response.status_code}")
            return False
            
    except Exception as e:
        print_fail(f"Frontend cannot connect: {e}")
        return False

def main():
    print(f"{BOLD}")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║     PHISHING DETECTION - CONNECTION DIAGNOSTIC TOOL              ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(RESET)
    
    results = []
    
    # Run all tests
    results.append(("Backend Health", test_backend_health()))
    
    if results[0][1]:  # Only continue if backend is running
        results.append(("Prediction Endpoint", test_predict_endpoint()))
        results.append(("CORS Configuration", test_cors()))
        results.append(("Frontend Connectivity", test_frontend_connectivity()))
    else:
        print_info("\nSkipping remaining tests (backend not running)")
    
    # Summary
    print_header("SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"  {test_name:.<50} {status}")
    
    print(f"\n{BOLD}Overall: {passed}/{total} tests passed{RESET}\n")
    
    if passed == total:
        print(f"{GREEN}{BOLD}✓ ALL TESTS PASSED! System is working correctly.{RESET}\n")
        print("You can now use the dashboard at: http://localhost:3000")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}✗ SOME TESTS FAILED. See errors above.{RESET}\n")
        print("Common fixes:")
        print("  1. Make sure backend is running: uvicorn src.api.main:app --reload")
        print("  2. Make sure you're in the project root directory")
        print("  3. Check if models are loaded (models_loaded should be True)")
        sys.exit(1)

if __name__ == "__main__":
    main()
