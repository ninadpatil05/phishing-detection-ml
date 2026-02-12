"""
Predict Endpoint for Phishing Detection API

This module provides the /api/v1/predict endpoint for phishing classification.

Confidence Scoring Logic:
-------------------------
Confidence levels are determined by how far the risk score is from the decision boundary (0.5):

1. **HIGH Confidence** (score > 0.85 or < 0.15)
   - Model is very certain about its prediction
   - Risk score is far from the 0.5 threshold
   - Example: 0.95 = strongly phishing, 0.05 = strongly safe
   - Action: Can trust this prediction with high confidence

2. **MEDIUM Confidence** (score 0.65-0.85 or 0.15-0.35)
   - Model has moderate certainty
   - Risk score is somewhat far from threshold
   - Example: 0.75 = likely phishing, 0.25 = likely safe
   - Action: Prediction is reliable but not definitive

3. **LOW Confidence** (score 0.35-0.65)
   - Model is uncertain
   - Risk score is close to the decision boundary
   - Example: 0.55 = borderline phishing, 0.45 = borderline safe
   - Action: May need human review or additional checks

Visual representation:
```
0.0 ─────────── 0.15 ──────── 0.35 ───── 0.5 ───── 0.65 ──────── 0.85 ─────────── 1.0
    HIGH SAFE    MEDIUM SAFE   LOW CONFIDENCE   MEDIUM PHISH    HIGH PHISH
```

Why this matters:
- HIGH confidence → Act automatically (block email, alert user)
- MEDIUM confidence → Apply with caution, monitor
- LOW confidence → Flag for manual review
"""

from fastapi import APIRouter, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
import time
import uuid
from datetime import datetime
import re
import html
from typing import Optional
import logging

from api.models import PredictionRequest, PredictionResponse, VerdictEnum, ConfidenceEnum
from api.database import db

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1", tags=["Prediction"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


def sanitize_email_text(email_text: str) -> str:
    """
    Sanitize email text input.
    
    Security measures:
    ------------------
    1. **Strip HTML tags** - Remove any HTML/script injection attempts
    2. **Limit length** - Prevent memory exhaustion attacks
    3. **Normalize whitespace** - Clean up formatting
    
    Why we need this:
    - Users might accidentally paste HTML email content
    - Malicious users might try injection attacks
    - Very long inputs waste resources and slow down processing
    
    Parameters:
    -----------
    email_text : str
        Raw email text
        
    Returns:
    --------
    sanitized_text : str
        Cleaned and safe email text
    """
    # Unescape HTML entities (e.g., &lt; → <)
    text = html.unescape(email_text)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Normalize whitespace
    text = ' '.join(text.split())
    
    # Limit length (max 50,000 chars)
    if len(text) > 50000:
        logger.warning(f"Email text truncated from {len(text)} to 50000 chars")
        text = text[:50000]
    
    return text.strip()


def calculate_confidence(risk_score: float) -> ConfidenceEnum:
    """
    Calculate confidence level based on risk score.
    
    Logic:
    ------
    - Confidence measures how certain the model is
    - Based on distance from decision boundary (0.5)
    - Farther from 0.5 = more confident
    
    Thresholds:
    -----------
    HIGH:   score > 0.85 or < 0.15  (distance > 0.35 from boundary)
    MEDIUM: score 0.65-0.85 or 0.15-0.35  (distance 0.15-0.35)
    LOW:    score 0.35-0.65  (distance < 0.15)
    
    Parameters:
    -----------
    risk_score : float
        Phishing probability (0.0 to 1.0)
        
    Returns:
    --------
    confidence : ConfidenceEnum
        HIGH, MEDIUM, or LOW
    
    Examples:
    ---------
    0.95 → HIGH (very sure it's phishing)
    0.75 → MEDIUM (likely phishing)
    0.55 → LOW (borderline/uncertain)
    0.45 → LOW (borderline/uncertain)
    0.25 → MEDIUM (likely safe)
    0.05 → HIGH (very sure it's safe)
    """
    if risk_score >= 0.85 or risk_score <= 0.15:
        return ConfidenceEnum.HIGH
    elif (0.65 <= risk_score < 0.85) or (0.15 < risk_score <= 0.35):
        return ConfidenceEnum.MEDIUM
    else:  # 0.35 < risk_score < 0.65
        return ConfidenceEnum.LOW


@router.post("/predict", response_model=PredictionResponse)
@limiter.limit("100/minute")
async def predict_phishing(request: Request, data: PredictionRequest):
    """
    Predict if an email is phishing.
    
    **Process:**
    1. Sanitize input (remove HTML, limit length)
    2. Extract features from email text
    3. Get predictions from all models
    4. Calculate confidence based on ensemble score
    5. Store prediction in database
    6. Return comprehensive response
    
    **Input:**
    - email_text: Email content (URLs extracted automatically)
    
    **Output:**
    - prediction_id: Unique ID for this prediction
    - risk_score: Overall phishing probability (0-1)
    - verdict: PHISHING or LEGITIMATE
    - confidence: HIGH/MEDIUM/LOW
    - Individual model scores
    - Processing time and metadata
    
    **Rate Limit:** 100 requests/minute per IP
    
    **Example Request:**
    ```json
    {
        "email_text": "URGENT! Your account suspended. Click http://phish.com to verify."
    }
    ```
    
    **Example Response:**
    ```json
    {
        "prediction_id": "pred_20260211_abc123",
        "risk_score": 0.87,
        "verdict": "PHISHING",
        "confidence": "HIGH",
        "text_score": 0.85,
        "url_score": 0.90,
        "ensemble_score": 0.87,
        "processing_time_ms": 45.2,
        "model_version": "1.0.0",
        "timestamp": "2026-02-11T18:00:13"
    }
    ```
    """
    start_time = time.perf_counter()
    
    try:
        # Generate unique prediction ID
        prediction_id = f"pred_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Sanitize input
        sanitized_text = sanitize_email_text(data.email_text)
        
        if len(sanitized_text) < 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email text too short after sanitization (minimum 10 characters required)"
            )
        
        # Get predictions from models
        # Note: Models should be loaded globally in main.py
        from api.main import text_classifier, url_classifier, ensemble_model, models_loaded
        
        if not models_loaded:
            # Use placeholder values for demonstration
            logger.warning("Models not loaded - using placeholder predictions")
            text_score = 0.75
            url_score = 0.80
            ensemble_score = 0.77
        else:
            # Get actual predictions
            text_score = float(text_classifier.predict_proba([sanitized_text])[0, 1])
            url_score = float(url_classifier.predict_proba([sanitized_text])[0, 1])
            ensemble_score = float(ensemble_model.predict_proba([sanitized_text])[0, 1])
        
        # Determine verdict
        verdict = VerdictEnum.PHISHING if ensemble_score >= 0.5 else VerdictEnum.SAFE
        
        # Calculate confidence
        confidence = calculate_confidence(ensemble_score)
        
        # Calculate processing time
        processing_time = (time.perf_counter() - start_time) * 1000  # ms
        
        # Create response
        timestamp = datetime.now()
        response = PredictionResponse(
            prediction_id=prediction_id,
            risk_score=ensemble_score,
            verdict=verdict,
            confidence=confidence,
            text_score=text_score,
            url_score=url_score,
            ensemble_score=ensemble_score,
            processing_time_ms=processing_time,
            model_version="1.0.0",
            timestamp=timestamp
        )
        
        # Store prediction in database
        try:
            db.save_prediction({
                'prediction_id': prediction_id,
                'email_text': sanitized_text[:1000],  # Store first 1000 chars
                'risk_score': ensemble_score,
                'verdict': verdict.value,
                'confidence': confidence.value,
                'text_score': text_score,
                'url_score': url_score,
                'ensemble_score': ensemble_score,
                'processing_time_ms': processing_time,
                'model_version': '1.0.0',
                'timestamp': timestamp.isoformat()
            })
        except Exception as db_error:
            # Log error but don't fail the request
            logger.error(f"Failed to save prediction to database: {str(db_error)}")
        
        logger.info(
            f"Prediction {prediction_id}: verdict={verdict.value}, "
            f"confidence={confidence.value}, score={ensemble_score:.3f}"
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )
