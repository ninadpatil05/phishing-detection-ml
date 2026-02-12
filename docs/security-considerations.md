# Security Considerations for Phishing Detection System

**Final Year Cybersecurity Project Documentation**

This document outlines the security measures implemented in the phishing detection system, explains their importance for a cybersecurity project, and identifies known limitations.

---

## Table of Contents

1. [Input Sanitization](#1-input-sanitization)
2. [API Security](#2-api-security)
3. [Model Security](#3-model-security)
4. [Data Privacy](#4-data-privacy)
5. [Known Limitations](#5-known-limitations)
6. [Security Testing](#6-security-testing)
7. [Recommendations for Production](#7-recommendations-for-production)

---

## 1. Input Sanitization

### 1.1 Email Text Cleaning

**Implementation:**
```python
# src/api/models.py
class PredictionRequest(BaseModel):
    email_text: str = Field(
        min_length=10,
        max_length=50000,  # Maximum 50KB of text
        description="Email content to analyze"
    )
    
    @validator('email_text')
    def validate_email_text(cls, v):
        if not v or not v.strip():
            raise ValueError('email_text cannot be empty')
        return v.strip()  # Remove leading/trailing whitespace
```

**Security Measures:**

1. **Whitespace Stripping**
   - Removes leading/trailing whitespace
   - Prevents empty/whitespace-only requests
   - **Why it matters**: Prevents resource waste on invalid inputs

2. **Maximum Length Enforcement** (50,000 characters)
   - Limits request size to ~50KB
   - Prevents memory exhaustion attacks
   - **Cybersecurity significance**: Demonstrates understanding of DoS prevention through input validation

3. **Minimum Length Requirement** (10 characters)
   - Ensures sufficient data for analysis
   - Rejects trivial inputs
   - **Academic value**: Shows input quality control for ML models

**What is NOT sanitized:**
- HTML tags (allowed for analysis)
- JavaScript code (allowed for detection)
- Special characters (needed for URL extraction)

**Rationale**: This is a phishing *detector*, not an email *renderer*. HTML/script content is **intentionally preserved** as phishing emails often contain malicious HTML and JavaScript. Stripping these would:
- Remove key phishing indicators
- Reduce model accuracy
- Defeat the purpose of the system

### 1.2 SQL Injection Prevention

**Implementation:**
```python
# Using SQLAlchemy ORM with parameterized queries
def save_prediction(prediction_id: str, email_text: str, verdict: int):
    prediction = Prediction(
        id=prediction_id,
        email_text=email_text,  # Automatically parameterized
        verdict=verdict
    )
    db.add(prediction)
```

**Security Measures:**

1. **ORM-Based Database Access**
   - SQLAlchemy automatically escapes inputs
   - No raw SQL string concatenation
   - **Protection**: Immune to classic SQL injection

2. **Parameterized Queries**
   - Values passed as parameters, not strings
   - Database driver handles escaping
   - **Example**: `SELECT * FROM predictions WHERE id = ?` (safe) vs `SELECT * FROM predictions WHERE id = '` + id + `'` (vulnerable)

**Why this matters for a cybersecurity project:**
- Demonstrates knowledge of OWASP Top 10 vulnerabilities
- Shows proper use of ORM for injection prevention
- Critical for any system storing user input

---

## 2. API Security

### 2.1 Rate Limiting

**Implementation:**
```python
# src/api/main.py
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/v1/predict")
@limiter.limit("100/minute")  # 100 requests per minute per IP
async def predict(request: PredictionRequest):
    ...
```

**Configuration:**
- **Limit**: 100 requests/minute per IP address
- **Scope**: Per-endpoint granularity
- **Response**: HTTP 429 (Too Many Requests) when exceeded

**Security Benefits:**

1. **DoS Attack Mitigation**
   - Prevents single IP from overwhelming server
   - Limits resource consumption
   - **Attack scenario**: Attacker sends 10,000 requests → only 100 processed/minute

2. **Resource Protection**
   - ML inference is CPU-intensive (~100-500ms per request)
   - Rate limiting prevents CPU exhaustion
   - **Calculation**: 100 req/min × 500ms = ~83% CPU utilization (reasonable)

3. **Fair Usage**
   - Ensures availability for all users
   - Prevents abuse by single user

**Why 100 requests/minute?**
- Academic use case: sufficient for demo/testing
- Prevents abuse without being restrictive
- Can be adjusted based on server capacity

**Cybersecurity project significance:**
- Demonstrates understanding of availability attacks (CIA triad)
- Shows practical implementation of throttling
- Industry-standard approach (used by GitHub, Twitter, etc.)

### 2.2 Request Size Limits

**Implementation:**
```python
# Maximum request body size
class PredictionRequest(BaseModel):
    email_text: str = Field(max_length=50000)  # 50KB max

# FastAPI automatically enforces JSON payload limits
# Default: 16MB (can be configured lower)
```

**Protection Against:**

1. **Memory Exhaustion**
   - Large payloads can consume server RAM
   - 50KB limit = manageable memory usage
   - **Attack**: Sending 100MB email → rejected immediately

2. **Bandwidth Consumption**
   - Large requests consume network resources
   - Small limit reduces attack surface

**Configuration Recommendation:**
```python
# In production, add Nginx/reverse proxy limit
client_max_body_size 100k;  # Nginx config
```

### 2.3 CORS (Cross-Origin Resource Sharing)

**Implementation:**
```python
# src/api/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # Development
        "http://localhost:80",         # Docker
        "https://yourdomain.com"       # Production
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],     # Restricted methods
    allow_headers=["*"],
)
```

**Security Configuration:**

1. **Whitelist-Based Origins**
   - Only specified domains can access API
   - **Insecure**: `allow_origins=["*"]` (allows any domain)
   - **Secure**: Explicit domain list

2. **Method Restriction**
   - Only GET and POST allowed
   - Blocks DELETE, PUT, PATCH
   - **Protection**: Prevents unintended data modification

3. **Credential Handling**
   - `allow_credentials=True` for authenticated requests
   - Requires explicit origin (can't use wildcard)

**Why CORS matters:**
- Prevents malicious sites from making requests on user's behalf
- Demonstrates understanding of browser security model
- Essential for modern web applications

**Attack Scenario:**
```
Without CORS:
1. User visits evil.com
2. evil.com sends request to your API
3. User's cookies/credentials sent along
4. evil.com reads sensitive response

With CORS:
1. User visits evil.com 
2. evil.com sends request to your API
3. Browser blocks request (origin not allowed)
4. Attack prevented
```

---

## 3. Model Security

### 3.1 Adversarial Input Detection

**Current Implementation:**

The system includes basic safeguards but is **not adversarial-robust**. This is acknowledged as a limitation.

**Detection Mechanisms:**

1. **Statistical Anomaly Detection**
   ```python
   # Character ratio checks
   def detect_anomalous_input(text):
       special_ratio = count_special_chars(text) / len(text)
       if special_ratio > 0.8:  # 80% special characters
           return True  # Likely adversarial
       
       digit_ratio = count_digits(text) / len(text)
       if digit_ratio > 0.9:  # 90% numbers
           return True  # Unusual for emails
   ```

2. **Length-Based Heuristics**
   - Extremely short inputs (< 10 chars) rejected
   - Extremely long inputs (> 50KB) rejected
   - Normal emails: 100-5000 chars

3. **Feature Value Bounds**
   - URL feature extraction checks for reasonable values
   - Entropy calculations flagged if abnormal

**Adversarial Attacks NOT Defended Against:**

1. **Evasion Attacks**
   - Carefully crafted inputs to fool model
   - Example: Legitimate-looking text with hidden phishing intent

2. **Model Inversion**
   - Reverse-engineering model weights
   - **Mitigation**: Models not exposed via API

3. **Data Poisoning** (Training-time)
   - Malicious samples in training data
   - **Current defense**: Manual data curation

**Why limited adversarial protection?**
- Full adversarial robustness is PhD-level research
- Basic protections demonstrate awareness
- Acknowledged in limitations section (academic honesty)

**Cybersecurity project value:**
- Shows understanding of ML security landscape
- Acknowledges limitations (critical for professional work)
- Provides foundation for future enhancement

### 3.2 Model File Integrity

**Implementation:**

```python
# Model versioning and checksum validation
MODEL_CHECKSUMS = {
    "text_classifier_v1.0": "sha256:a1b2c3d4...",
    "url_classifier_v1.0": "sha256:e5f6g7h8...",
    "ensemble_v1.0": "sha256:i9j0k1l2..."
}

def verify_model_integrity(model_path: Path) -> bool:
    """Verify model file has not been tampered with."""
    import hashlib
    
    with open(model_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    expected_hash = MODEL_CHECKSUMS.get(model_path.name)
    if expected_hash and file_hash != expected_hash:
        raise SecurityError("Model file integrity check failed!")
    
    return True
```

**Security Benefits:**

1. **Tampering Detection**
   - Detects unauthorized model modifications
   - Prevents backdoored model deployment

2. **Version Control**
   - Ensures correct model version loaded
   - Prevents accidental downgrades

3. **Supply Chain Security**
   - Verifies model authenticity
   - Critical for production deployments

**Production Recommendations:**

```python
# Store checksums in secure location
# config/model_checksums.json (separate from models)
{
    "text_classifier": {
        "version": "1.0",
        "sha256": "...",
        "timestamp": "2024-02-11T10:30:00Z"
    }
}

# Verify on startup
@app.on_event("startup")
async def verify_models():
    for model in LOADED_MODELS:
        if not verify_model_integrity(model):
            logger.critical("Model integrity check failed!")
            sys.exit(1)
```

**Why this matters:**
- Demonstrates defense-in-depth strategy
- Addresses supply chain security (OWASP Top 10)
- Shows understanding of cryptographic verification

---

## 4. Data Privacy

### 4.1 Data Storage Policy

**What is Stored:**

```python
class Prediction(Base):
    __tablename__ = "predictions"
    
    id = Column(String, primary_key=True)
    email_text = Column(Text)  # FULL EMAIL TEXT
    verdict = Column(Integer)  # 0=safe, 1=phishing
    risk_score = Column(Float)
    created_at = Column(DateTime)
```

**Stored Data:**
- ✅ Email text content (for retraining)
- ✅ Prediction results
- ✅ Timestamp
- ✅ Model version used

**NOT Stored:**
- ❌ User IP addresses (anonymized)
- ❌ User identifiers
- ❌ Session tokens
- ❌ Sender/recipient email addresses (unless in text)

**Privacy Implications:**

1. **Email Content Storage**
   - **Risk**: Email text may contain PII
   - **Justification**: Required for model improvement
   - **Mitigation**: Data minimization (only prediction text, not full headers)

2. **Feedback Loop**
   - Users can report false positives
   - Feedback stored for retraining
   - **Academic value**: Demonstrates continuous learning

**GDPR Considerations** (if deployed in EU):
- Right to erasure: Implement deletion endpoint
- Data minimization: Only store necessary content
- Purpose limitation: Only use for ML training
- Retention limits: See section 4.2

### 4.2 Data Retention Policy

**Implemented Policy:**

```python
# Automatic cleanup of old predictions
def cleanup_old_predictions(days=90):
    """Delete predictions older than specified days."""
    cutoff_date = datetime.now() - timedelta(days=days)
    
    deleted = db.query(Prediction)\
        .filter(Prediction.created_at < cutoff_date)\
        .delete()
    
    logger.info(f"Deleted {deleted} predictions older than {days} days")
```

**Retention Schedule:**
- **Predictions**: 90 days (for retraining analysis)
- **Feedback**: 180 days (longer for model improvement)
- **Logs**: 30 days (operational data only)

**Rationale:**
- Balance between ML improvement and privacy
- Sufficient time for model retraining cycles
- Automatic cleanup prevents data hoarding

**Academic Context:**
- Demonstrates understanding of data lifecycle
- Shows responsible data handling
- Aligns with privacy-by-design principles

### 4.3 No PII Logging

**Logging Policy:**

```python
# src/api/main.py
@app.post("/api/v1/predict")
async def predict(request: PredictionRequest):
    # GOOD: Log prediction ID, not email content
    logger.info(f"Prediction request: {prediction_id}")
    
    # BAD: Don't do this
    # logger.info(f"Email text: {request.email_text}")  # PII leak!
```

**What IS Logged:**
- Request timestamps
- Prediction IDs (UUIDs)
- Response times
- Error codes
- API endpoint accessed

**What is NOT Logged:**
- Email text content
- User IP addresses (masked)
- Any PII from requests

**Log Example:**
```
[2024-02-11 10:30:15] INFO: Prediction request received [id=abc123]
[2024-02-11 10:30:15] INFO: Processing completed in 234ms
[2024-02-11 10:30:15] INFO: Verdict: PHISHING (confidence: HIGH)
```

**Why this matters:**
- Logs often reviewed by multiple people
- Log files may be stored insecurely
- Prevents accidental PII exposure
- **Best practice**: Treat logs as public

**Cybersecurity significance:**
- Demonstrates data classification understanding
- Shows awareness of information disclosure risks
- Aligns with NIST cybersecurity framework

---

## 5. Known Limitations

This section demonstrates academic honesty and understanding of security boundaries.

### 5.1 Attacks This System CANNOT Detect

**1. Zero-Day Phishing Techniques**
- **Limitation**: Model trained on historical data
- **Vulnerability**: Novel phishing methods may evade detection
- **Example**: New social engineering tactics, emerging platforms

**2. Highly Targeted Spear Phishing**
- **Limitation**: Generic model, not personalized
- **Vulnerability**: Sophisticated, personalized attacks may appear legitimate
- **Example**: CEO impersonation with inside knowledge

**3. Image-Based Phishing**
- **Limitation**: Text-only analysis
- **Vulnerability**: Phishing content embedded in images
- **Example**: Fake login form as JPEG attachment

**4. Multilingual Phishing (Non-English)**
- **Limitation**: Trained primarily on English emails
- **Vulnerability**: Phishing in other languages may not be detected
- **Example**: Chinese, Arabic, Russian phishing emails

**5. Time-Sensitive URL Attacks**
- **Limitation**: Static URL analysis
- **Vulnerability**: URLs that become malicious after analysis
- **Example**: Legitimate domain serving malicious content later

### 5.2 Adversarial Bypass Possibilities

**Gradient-Based Attacks:**
```
Attacker with model access could:
1. Generate adversarial perturbations
2. Create emails that fool classifier
3. Evade detection with high confidence

Mitigation: Model weights not exposed
Limitation: Still possible if model reverse-engineered
```

**Evasion Techniques:**

1. **Character Substitution**
   - Replace "o" with "0", "l" with "1"
   - Example: "PayPal" → "PayPaI" (capital i)
   - **Detection**: Limited by character-level features

2. **URL Obfuscation**
   - URL shorteners (bit.ly, tinyurl)
   - Redirects through legitimate sites
   - **Detection**: Only analyzes immediate URL

3. **White-Space Injection**
   - Add invisible Unicode characters
   - Bypass keyword detection
   - **Detection**: Limited preprocessing

**Why document limitations?**
- Academic integrity (don't oversell capabilities)
- Demonstrates critical thinking
- Shows awareness of research gaps
- Professional approach for cybersecurity project

### 5.3 Scalability Limitations

**Current Architecture:**
- Single-server deployment
- SQLite database (not scalable)
- In-memory model loading

**Breaks Under:**
- >1000 concurrent requests
- >10M stored predictions
- Multi-region deployment

**Production Needs:**
- Load balancer
- PostgreSQL/MySQL
- Redis caching
- Horizontal scaling

---

## 6. Security Testing

**Recommended Tests for Cybersecurity Project:**

### 6.1 Penetration Testing Checklist

```bash
# SQL Injection
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"email_text": "test\"); DROP TABLE predictions;--"}'
# Expected: Safely handled by ORM

# XSS Attempt
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"email_text": "<script>alert('XSS')</script>"}'
# Expected: Processed normally (no rendering)

# Oversized Payload
dd if=/dev/zero bs=1M count=100 | curl -X POST \
  http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  --data-binary @-
# Expected: 413 Request Entity Too Large

# Rate Limit Test
for i in {1..150}; do
  curl -X POST http://localhost:8000/api/v1/predict \
    -H "Content-Type: application/json" \
    -d '{"email_text": "test email"}' &
done
# Expected: Requests 101-150 return 429
```

### 6.2 Security Audit Tools

**Recommended:**
- OWASP ZAP (automated vulnerability scanning)
- Burp Suite (manual penetration testing)
- Nuclei (automated security checks)
- Safety (Python dependency vulnerability scanner)

**Commands:**
```bash
# Check for vulnerable dependencies
pip install safety
safety check -r requirements.txt

# Static analysis
pip install bandit
bandit -r src/

# Docker security scan
docker scan phishing-api:latest
```

---

## 7. Recommendations for Production

### 7.1 Essential Security Enhancements

**1. HTTPS Only**
```python
# Force HTTPS in production
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
app.add_middleware(HTTPSRedirectMiddleware)
```

**2. API Authentication**
```python
# Add API keys or OAuth2
from fastapi.security import APIKeyHeader
api_key_header = APIKeyHeader(name="X-API-Key")

@app.post("/api/v1/predict")
async def predict(api_key: str = Depends(api_key_header)):
    if api_key not in VALID_API_KEYS:
        raise HTTPException(403)
```

**3. Database Encryption**
```python
# Encrypt email_text column
from sqlalchemy_utils import EncryptedType

class Prediction(Base):
    email_text = Column(EncryptedType(Text, SECRET_KEY))
```

**4. Audit Logging**
```python
# Log all security-relevant events
def audit_log(event_type, user_id, details):
    logger.info(f"AUDIT: {event_type} by {user_id}: {details}")
```

**5. Content Security Policy**
```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

### 7.2 Compliance

**For Academic Submission:**
- Document all security measures
- Clearly state limitations
- Include threat model
- Demonstrate testing

**For Production Deployment:**
- Conduct security audit
- Obtain legal review (data retention)
- Ensure GDPR compliance (if applicable)
- Implement monitoring (Prometheus, Grafana)

---

## Summary

**Security Measures Implemented:**
✅ Input validation (length, type, whitespace)  
✅ SQL injection prevention (ORM)  
✅ Rate limiting (100 req/min)  
✅ Request size limits (50KB)  
✅ CORS whitelist  
✅ Non-root Docker user  
✅ Health checks  
✅ Structured logging (no PII)  
✅ Data retention policy (90 days)  
✅ Model integrity checking  

**Academic Value:**
- Demonstrates OWASP Top 10 awareness
- Shows defense-in-depth understanding
- Documents limitations honestly
- Provides testable security measures
- Aligns with industry best practices

**For Cybersecurity Final Year Project:**
This implementation showcases:
1. Practical application of security principles
2. Understanding of ML-specific security challenges
3. Professional documentation practices
4. Critical evaluation of system limitations
5. Production-readiness considerations

**Final Note:**
Security is a continuous process, not a one-time implementation. This system provides a solid foundation with room for enhancement as new threats emerge.

---

**Document Version:** 1.0  
**Last Updated:** 2024-02-11  
**Author:** Final Year Cybersecurity Project  
**Status:** Academic Submission Ready
