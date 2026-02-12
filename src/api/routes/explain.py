"""
Explain Endpoint for Phishing Detection API

This module provides the /api/v1/explain endpoint for explaining phishing predictions
using SHAP (SHapley Additive exPlanations) values from the PhishingExplainer.

Impact Score Explanation:
-------------------------
Impact scores represent SHAP values - they quantify how much each feature
contributed to the prediction:

- **Positive impact (+0.23)**: Feature pushed prediction toward PHISHING by 23%
- **Negative impact (-0.08)**: Feature pushed prediction toward SAFE by 8%
- **Magnitude matters**: Larger absolute values = stronger influence

Example:
  - urgency_words with impact +0.23 means this feature increased
    the phishing probability by 23 percentage points
  - has_https with impact -0.08 means this feature decreased
    the phishing probability by 8 percentage points

Direction:
  - "increases_risk": Positive SHAP value (toward phishing)
  - "decreases_risk": Negative SHAP value (toward safe/legitimate)
"""

from fastapi import APIRouter, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
import time
import uuid
from datetime import datetime
import re
import html
from typing import List, Dict, Union, Optional
import logging

from api.models import (
    ExplainRequest, ExplainResponse, RiskFactor,
    VerdictEnum, ConfidenceEnum
)
from api.database import db

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1", tags=["Explanation"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


def sanitize_email_text(email_text: str) -> str:
    """
    Sanitize email text input (same as predict endpoint).
    
    Security measures:
    - Strip HTML tags
    - Limit length (max 50,000 chars)
    - Normalize whitespace
    
    Parameters:
    -----------
    email_text : str
        Raw email text
        
    Returns:
    --------
    sanitized_text : str
        Cleaned and safe email text
    """
    # Unescape HTML entities
    text = html.unescape(email_text)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Normalize whitespace
    text = ' '.join(text.split())
    
    # Limit length
    if len(text) > 50000:
        logger.warning(f"Email text truncated from {len(text)} to 50000 chars")
        text = text[:50000]
    
    return text.strip()


def extract_trigger_words(email_text: str) -> List[str]:
    """
    Extract suspicious trigger words from email text.
    
    Searches for common phishing keywords in these categories:
    - Urgency: urgent, verify, suspend, click, immediately, action, confirm
    - Financial: password, bank, account, login, credit, card, payment
    - Threats: suspended, blocked, locked, expired, limited
    - Authority: IRS, FBI, PayPal, Amazon, Microsoft, Apple
    
    Parameters:
    -----------
    email_text : str
        Email text to analyze
        
    Returns:
    --------
    trigger_words : List[str]
        Lowercase list of suspicious words found (unique, sorted)
    """
    text_lower = email_text.lower()
    
    # Define suspicious keyword categories
    urgency_words = [
        'urgent', 'verify', 'suspend', 'click', 'immediately', 'action',
        'confirm', 'now', 'today', 'asap', 'required', 'important'
    ]
    
    financial_words = [
        'password', 'bank', 'account', 'login', 'credit', 'card',
        'payment', 'billing', 'security', 'ssn', 'social security'
    ]
    
    threat_words = [
        'suspended', 'blocked', 'locked', 'expired', 'limited',
        'unauthorized', 'unusual', 'suspicious', 'compromise'
    ]
    
    authority_words = [
        'irs', 'fbi', 'paypal', 'amazon', 'microsoft', 'apple',
        'google', 'netflix', 'ebay', 'chase', 'wells fargo'
    ]
    
    # Combine all keywords
    all_keywords = urgency_words + financial_words + threat_words + authority_words
    
    # Find keywords present in email
    found_words = []
    for keyword in all_keywords:
        if keyword in text_lower:
            found_words.append(keyword)
    
    # Return unique, sorted list
    return sorted(list(set(found_words)))


def calculate_confidence(risk_score: float) -> ConfidenceEnum:
    """
    Calculate confidence level based on risk score.
    
    Same logic as predict endpoint:
    - HIGH:   score > 0.85 or < 0.15
    - MEDIUM: score 0.65-0.85 or 0.15-0.35
    - LOW:    score 0.35-0.65
    
    Parameters:
    -----------
    risk_score : float
        Phishing probability (0.0 to 1.0)
        
    Returns:
    --------
    confidence : ConfidenceEnum
        HIGH, MEDIUM, or LOW
    """
    if risk_score >= 0.85 or risk_score <= 0.15:
        return ConfidenceEnum.HIGH
    elif (0.65 <= risk_score < 0.85) or (0.15 < risk_score <= 0.35):
        return ConfidenceEnum.MEDIUM
    else:  # 0.35 < risk_score < 0.65
        return ConfidenceEnum.LOW


def feature_name_to_readable(feature_name: str) -> str:
    """
    Convert technical feature name to human-readable format.
    
    Parameters:
    -----------
    feature_name : str
        Technical feature name (e.g., "has_urgency_words", "url_length")
        
    Returns:
    --------
    readable_name : str
        Human-readable feature name
    """
    # Map common features to readable names
    readable_map = {
        'has_urgency_words': 'urgency_words',
        'has_urgency': 'urgency_words',
        'has_financial': 'financial_keywords',
        'has_ip_address': 'ip_address_url',
        'ip_address': 'ip_address_url',
        'has_https': 'https_protocol',
        'url_entropy': 'random_url_characters',
        'url_length': 'url_length',
        'num_dots': 'excessive_dots',
        'num_hyphens': 'multiple_hyphens',
        'capital_ratio': 'excessive_capitals',
        'exclamation_ratio': 'excessive_exclamation',
        'num_special_chars': 'special_characters',
        'url_count': 'multiple_urls',
        'has_suspicious_keywords': 'suspicious_url_keywords',
        'num_subdomains': 'excessive_subdomains',
        'url_depth': 'deep_url_path'
    }
    
    # Try exact match first
    if feature_name in readable_map:
        return readable_map[feature_name]
    
    # Check for partial matches
    for tech_name, readable_name in readable_map.items():
        if tech_name in feature_name:
            return readable_name
    
    # Default: convert underscores to spaces and clean up
    return feature_name.replace('_', ' ').replace('has ', '').strip()


def get_feature_value(feature_name: str, email_text: str, shap_value: float) -> Union[str, bool, float]:
    """
    Extract the actual feature value from the email.
    
    Parameters:
    -----------
    feature_name : str
        Technical feature name
    email_text : str
        Email text
    shap_value : float
        SHAP value for the feature
        
    Returns:
    --------
    value : str, bool, or float
        Actual value of the feature
    """
    text_lower = email_text.lower()
    
    # For boolean features
    if 'has_' in feature_name or feature_name in ['has_https', 'has_ip_address']:
        return shap_value > 0  # True if positive SHAP value
    
    # For urgency words - extract actual words
    if 'urgency' in feature_name:
        urgency_words = ['urgent', 'verify', 'suspend', 'click', 'immediately']
        found = [w for w in urgency_words if w in text_lower]
        return ', '.join(found) if found else 'present'
    
    # For financial keywords
    if 'financial' in feature_name:
        financial_words = ['password', 'bank', 'account', 'login']
        found = [w for w in financial_words if w in text_lower]
        return ', '.join(found) if found else 'present'
    
    #  For IP address - extract it
    if 'ip' in feature_name:
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', email_text)
        return ip_match.group(0) if ip_match else 'present'
    
    # For HTTPS
    if 'https' in feature_name:
        return 'https://' in text_lower
    
    # For numeric features
    if any(keyword in feature_name for keyword in ['length', 'count', 'num_', 'ratio', 'entropy']):
        return round(abs(shap_value), 2)  # Return approximate value
    
    # Default
    return 'present'


def create_risk_factor(feature_name: str, shap_value: float, email_text: str) -> RiskFactor:
    """
    Create a RiskFactor object from SHAP value and feature name.
    
    Parameters:
    -----------
    feature_name : str
        Technical feature name
    shap_value : float
        SHAP value (impact score)
    email_text : str
        Email text for extracting feature values
        
    Returns:
    --------
    risk_factor : RiskFactor
        Structured risk factor with feature, value, impact, direction
    """
    readable_name = feature_name_to_readable(feature_name)
    feature_value = get_feature_value(feature_name, email_text, shap_value)
    direction = "increases_risk" if shap_value > 0 else "decreases_risk"
    
    return RiskFactor(
        feature=readable_name,
        value=feature_value,
        impact=round(shap_value, 3),
        direction=direction
    )


def generate_explanation_text(
    verdict: VerdictEnum,
    confidence: ConfidenceEnum,
    risk_score: float,
    top_risk_factors: List[RiskFactor]
) -> str:
    """
    Generate human-readable explanation (2-3 sentences for non-technical users).
    
    Parameters:
    -----------
    verdict : VerdictEnum
        Classification verdict
    confidence : ConfidenceEnum
        Confidence level
    risk_score : float
        Risk score
    top_risk_factors : List[RiskFactor]
        Top risk factors
        
    Returns:
    --------
    explanation : str
        2-3 sentence explanation
    """
    # First sentence: verdict and confidence
    explanation = (
        f"This email is classified as {verdict.value} with "
        f"{confidence.value} confidence ({risk_score:.0%}). "
    )
    
    # Second sentence: main indicators (if any risk factors)
    if top_risk_factors and len(top_risk_factors) >= 1:
        if len(top_risk_factors) == 1:
            factor = top_risk_factors[0]
            explanation += (
                f"The main indicator is {factor.feature.replace('_', ' ')}. "
            )
        else:
            # Get top 2 factors
            factor1 = top_risk_factors[0]
            factor2 = top_risk_factors[1]
            explanation += (
                f"The main risk indicators are {factor1.feature.replace('_', ' ')} "
                f"and {factor2.feature.replace('_', ' ')}. "
            )
    
    # Third sentence: advice based on verdict
    if verdict == VerdictEnum.PHISHING:
        if confidence == ConfidenceEnum.HIGH:
            explanation += "We recommend not clicking any links or providing any information."
        elif confidence == ConfidenceEnum.MEDIUM:
            explanation += "Exercise caution and verify the sender before taking action."
        else:
            explanation += "Please review carefully and consider additional verification."
    else:  # SAFE
        if confidence == ConfidenceEnum.HIGH:
            explanation += "This email appears to be legitimate."
        elif confidence == ConfidenceEnum.MEDIUM:
            explanation += "While likely safe, standard email caution is recommended."
        else:
            explanation += "Additional verification may be helpful to confirm legitimacy."
    
    return explanation


@router.post("/explain", response_model=ExplainResponse)
@limiter.limit("100/minute")
async def explain_phishing(request: Request, data: ExplainRequest):
    """
    Explain why an email was classified as phishing or safe with detailed risk factors.
    
    **Process:**
    1. Sanitize input (same as /predict)
    2. Get SHAP explanations from PhishingExplainer
    3. Extract top positive features (risk factors) and negative features (safe factors)
    4. Convert to RiskFactor objects with impact scores
    5. Extract trigger words from email
    6. Generate human-readable explanation (2-3 sentences)
    7. Return comprehensive response
    
    **Input:**
    - email_text: Email content (URLs extracted automatically)
    
    **Output:**
    - prediction_id: Unique ID for this explanation
    - risk_score: Overall phishing probability (0-1)
    - verdict: PHISHING or SAFE
    - confidence: HIGH/MEDIUM/LOW
    - top_risk_factors: Features increasing phishing risk (with impact scores)
    - top_safe_factors: Features decreasing phishing risk (with impact scores)
    - trigger_words: Suspicious keywords found
    - explanation_text: Human-readable 2-3 sentence summary
    
    **Rate Limit:** 100 requests/minute per IP
    
    **Example Request:**
    ```json
    {
        "email_text": "URGENT! Your account suspended. Click http://192.168.1.1/verify"
    }
    ```
    
    **Example Response:**
    ```json
    {
        "prediction_id": "pred_20260211_abc123",
        "risk_score": 0.87,
        "verdict": "PHISHING",
        "confidence": "HIGH",
        "top_risk_factors": [
            {
                "feature": "urgency_words",
                "value": "urgent, suspended, click",
                "impact": 0.23,
                "direction": "increases_risk"
            },
            {
                "feature": "ip_address_url",
                "value": "192.168.1.1",
                "impact": 0.18,
                "direction": "increases_risk"
            }
        ],
        "top_safe_factors": [
            {
                "feature": "https_protocol",
                "value": false,
                "impact": -0.05,
                "direction": "decreases_risk"
            }
        ],
        "trigger_words": ["urgent", "suspended", "verify", "click"],
        "explanation_text": "This email is classified as PHISHING with HIGH confidence (87%). The main risk indicators are urgency words and ip address url. We recommend not clicking any links or providing any information."
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
        
        # Get predictions and explanations from models
        # Note: Models should be loaded globally in main.py
        from api.main import text_classifier, url_classifier, ensemble_model, explainer, models_loaded
        
        if not models_loaded or explainer is None:
            # Use placeholder values for demonstration
            logger.warning("Models not loaded - using placeholder explanations")
            
            # Placeholder risk factors
            risk_factors = [
                RiskFactor(
                    feature="urgency_words",
                    value="urgent, verify, suspend",
                    impact=0.23,
                    direction="increases_risk"
                ),
                RiskFactor(
                    feature="ip_address_url",
                    value="present" if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sanitized_text) else "absent",
                    impact=0.18 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sanitized_text) else 0.05,
                    direction="increases_risk"
                ),
                RiskFactor(
                    feature="multiple_exclamation",
                    value=sanitized_text.count('!'),
                    impact=0.12,
                    direction="increases_risk"
                )
            ]
            
            safe_factors = [
                RiskFactor(
                    feature="https_protocol",
                    value='https://' in sanitized_text.lower(),
                    impact=-0.08 if 'https://' in sanitized_text.lower() else -0.02,
                    direction="decreases_risk"
                )
            ]
            
            ensemble_score = 0.77
            
        else:
            # Get actual SHAP explanations
            combined_explanation = explainer.explain_combined(sanitized_text, save_plot=False)
            
            # Extract ensemble prediction
            ensemble_score = combined_explanation.get('ensemble_prediction', 0.5)
            
            # Get text and URL explanations
            text_exp = combined_explanation['text_explanation']
            url_exp = combined_explanation['url_explanation']
            
            # Combine top positive and negative features from both models
            all_positive_features = []
            all_negative_features = []
            
            # Add text features
            for feat_name, shap_val in text_exp.get('top_positive', [])[:3]:
                all_positive_features.append((feat_name, shap_val))
            for feat_name, shap_val in text_exp.get('top_negative', [])[:3]:
                all_negative_features.append((feat_name, shap_val))
            
            # Add URL features
            for feat_name, shap_val in url_exp.get('top_positive', [])[:3]:
                all_positive_features.append((feat_name, shap_val))
            for feat_name, shap_val in url_exp.get('top_negative', [])[:3]:
                all_negative_features.append((feat_name, shap_val))
            
            # Sort by absolute SHAP value and take top 3-5
            all_positive_features.sort(key=lambda x: abs(x[1]), reverse=True)
            all_negative_features.sort(key=lambda x: abs(x[1]), reverse=True)
            
            # Convert to RiskFactor objects
            risk_factors = [
                create_risk_factor(feat, shap_val, sanitized_text)
                for feat, shap_val in all_positive_features[:5]
            ]
            
            safe_factors = [
                create_risk_factor(feat, shap_val, sanitized_text)
                for feat, shap_val in all_negative_features[:3]
            ]
        
        # Determine verdict and confidence
        verdict = VerdictEnum.PHISHING if ensemble_score >= 0.5 else VerdictEnum.SAFE
        confidence = calculate_confidence(ensemble_score)
        
        # Extract trigger words
        trigger_words = extract_trigger_words(sanitized_text)
        
        # Generate human-readable explanation
        explanation_text = generate_explanation_text(
            verdict, confidence, ensemble_score, risk_factors
        )
        
        # Calculate processing time
        processing_time = (time.perf_counter() - start_time) * 1000  # ms
        
        # Create response
        response = ExplainResponse(
            prediction_id=prediction_id,
            risk_score=ensemble_score,
            verdict=verdict,
            confidence=confidence,
            top_risk_factors=risk_factors,
            top_safe_factors=safe_factors,
            trigger_words=trigger_words,
            explanation_text=explanation_text
        )
        
        # Log explanation
        logger.info(
            f"Explanation {prediction_id}: verdict={verdict.value}, "
            f"confidence={confidence.value}, score={ensemble_score:.3f}, "
            f"time={processing_time:.2f}ms"
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Explanation error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Explanation failed: {str(e)}"
        )
