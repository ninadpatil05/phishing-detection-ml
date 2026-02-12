"""
Pydantic Models for Phishing Detection API

This module defines request and response schemas for API endpoints.

What is Pydantic?
-----------------
Pydantic is a data validation library that uses Python type hints to:
1. **Validate input data** - Ensures requests match expected format
2. **Serialize/deserialize** - Converts between JSON and Python objects
3. **Automatic documentation** - FastAPI uses these models for OpenAPI/Swagger docs
4. **Type safety** - Catches errors at runtime before they cause bugs

Example:
--------
If someone sends {"email_text": 123} instead of {"email_text": "some string"},
Pydantic will automatically reject it with a clear error message.

Benefits:
- Prevents invalid data from reaching your code
- Auto-generates API documentation
- Provides clear error messages to API users
- Ensures type safety throughout your application
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Union, Dict
from datetime import datetime
from enum import Enum


class VerdictEnum(str, Enum):
    """Prediction verdict options."""
    SAFE = "SAFE"
    PHISHING = "PHISHING"


class ConfidenceEnum(str, Enum):
    """Confidence level options."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ============================================================================
# PREDICTION ENDPOINTS
# ============================================================================

class PredictionRequest(BaseModel):
    """
    Request schema for phishing prediction.
    
    Attributes:
    -----------
    email_text : str
        The email content to analyze (URLs extracted automatically)
    
    Example:
    --------
    {
        "email_text": "URGENT! Click here to verify your account: http://phishing.com"
    }
    """
    email_text: str = Field(
        ...,
        description="Email content to analyze for phishing indicators",
        min_length=10,
        max_length=50000,
        example="URGENT! Your account has been suspended. Click http://192.168.1.1/verify to restore access."
    )
    
    @validator('email_text')
    def validate_email_text(cls, v):
        """Ensure email text is not just whitespace."""
        if not v or not v.strip():
            raise ValueError('email_text cannot be empty or whitespace')
        return v.strip()


class PredictionResponse(BaseModel):
    """
    Response schema for phishing prediction.
    
    Attributes:
    -----------
    prediction_id : str
        Unique identifier for this prediction
    risk_score : float
        Overall phishing probability (0.0 to 1.0)
    verdict : VerdictEnum
        Final classification (SAFE or PHISHING)
    confidence : ConfidenceEnum
        Prediction confidence level (LOW, MEDIUM, HIGH)
    text_score : float
        Text classifier probability
    url_score : float
        URL classifier probability
    ensemble_score : float
        Ensemble model probability (same as risk_score)
    processing_time_ms : float
        Request processing time in milliseconds
    model_version : str
        Version of the model used
    timestamp : datetime
        When the prediction was made
    
    Example:
    --------
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
        "timestamp": "2026-02-11T17:53:22"
    }
    """
    prediction_id: str = Field(
        ...,
        description="Unique identifier for this prediction",
        example="pred_20260211_abc123"
    )
    risk_score: float = Field(
        ...,
        description="Overall phishing probability (0.0 = safe, 1.0 = phishing)",
        ge=0.0,
        le=1.0
    )
    verdict: VerdictEnum = Field(
        ...,
        description="Final classification verdict"
    )
    confidence: ConfidenceEnum = Field(
        ...,
        description="Confidence level of the prediction"
    )
    text_score: float = Field(
        ...,
        description="Text classifier probability",
        ge=0.0,
        le=1.0
    )
    url_score: float = Field(
        ...,
        description="URL classifier probability",
        ge=0.0,
        le=1.0
    )
    ensemble_score: float = Field(
        ...,
        description="Ensemble model probability (weighted average)",
        ge=0.0,
        le=1.0
    )
    processing_time_ms: float = Field(
        ...,
        description="Request processing time in milliseconds",
        ge=0.0
    )
    model_version: str = Field(
        ...,
        description="Version of the ML model used",
        example="1.0.0"
    )
    timestamp: datetime = Field(
        ...,
        description="When the prediction was made"
    )


# ============================================================================
# EXPLANATION ENDPOINTS
# ============================================================================

class RiskFactor(BaseModel):
    """
    Individual risk or safety factor with impact score.
    
    Attributes:
    -----------
    feature : str
        Human-readable feature name (e.g., "urgency_words", "ip_address_url")
    value : str, bool, or float
        Actual feature value from the email
    impact : float
        SHAP value showing contribution to prediction
        - Positive: Increases phishing risk
        - Negative: Decreases phishing risk (toward safe)
    direction : str
        "increases_risk" or "decreases_risk"
    
    Example:
    --------
    {
        "feature": "urgency_words",
        "value": "verify, suspend",
        "impact": 0.23,
        "direction": "increases_risk"
    }
    """
    feature: str = Field(
        ...,
        description="Human-readable feature name",
        example="urgency_words"
    )
    value: Union[str, bool, float] = Field(
        ...,
        description="Feature value extracted from email",
        example="verify, suspend"
    )
    impact: float = Field(
        ...,
        description="SHAP value (impact score) - how much this feature contributed to the prediction",
        example=0.23
    )
    direction: str = Field(
        ...,
        description="Impact direction: 'increases_risk' or 'decreases_risk'",
        example="increases_risk"
    )

class ExplainRequest(BaseModel):
    """
    Request schema for prediction explanation.
    
    Attributes:
    -----------
    email_text : str
        The email content to explain
    
    Example:
    --------
    {
        "email_text": "Click here to claim your prize!"
    }
    """
    email_text: str = Field(
        ...,
        description="Email content to explain",
        min_length=10,
        max_length=50000,
        example="URGENT! Verify your account now: http://phish.example.com/login"
    )
    
    @validator('email_text')
    def validate_email_text(cls, v):
        """Ensure email text is not just whitespace."""
        if not v or not v.strip():
            raise ValueError('email_text cannot be empty or whitespace')
        return v.strip()


class ExplainResponse(BaseModel):
    """
    Enhanced response schema for prediction explanation with SHAP-based risk factors.
    
    Attributes:
    -----------
    prediction_id : str
        Unique identifier for this explanation
    risk_score : float
        Overall phishing probability (0.0 to 1.0)
    verdict : VerdictEnum
        Final classification (PHISHING or SAFE)
    confidence : ConfidenceEnum
        Prediction confidence (HIGH, MEDIUM, LOW)
    top_risk_factors : List[RiskFactor]
        Features that increase phishing risk (positive SHAP values)
    top_safe_factors : List[RiskFactor]
        Features that decrease phishing risk (negative SHAP values)
    trigger_words : List[str]
        Suspicious keywords found in the email
    explanation_text : str
        Human-readable explanation (2-3 sentences for non-technical users)
    
    Example:
    --------
    {
        "prediction_id": "pred_20260211_abc123",
        "risk_score": 0.87,
        "verdict": "PHISHING",
        "confidence": "HIGH",
        "top_risk_factors": [
            {
                "feature": "urgency_words",
                "value": "verify, suspend",
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
                "feature": "has_https",
                "value": true,
                "impact": -0.08,
                "direction": "decreases_risk"
            }
        ],
        "trigger_words": ["verify", "account", "suspend"],
        "explanation_text": "This email is classified as PHISHING with HIGH confidence (87%). The main risk indicators are urgency words like 'verify' and 'suspend', and the URL uses an IP address instead of a proper domain name."
    }
    """
    prediction_id: str = Field(
        ...,
        description="Unique identifier for this explanation",
        example="pred_20260211_abc123"
    )
    risk_score: float = Field(
        ...,
        description="Overall phishing probability (0.0 = safe, 1.0 = phishing)",
        ge=0.0,
        le=1.0
    )
    verdict: VerdictEnum = Field(
        ...,
        description="Final classification verdict"
    )
    confidence: ConfidenceEnum = Field(
        ...,
        description="Prediction confidence level"
    )
    top_risk_factors: List[RiskFactor] = Field(
        ...,
        description="Features that increase phishing risk (sorted by impact)",
        example=[
            {
                "feature": "urgency_words",
                "value": "verify, suspend",
                "impact": 0.23,
                "direction": "increases_risk"
            }
        ]
    )
    top_safe_factors: List[RiskFactor] = Field(
        ...,
        description="Features that decrease phishing risk (sorted by impact magnitude)",
        example=[
            {
                "feature": "has_https",
                "value": True,
                "impact": -0.08,
                "direction": "decreases_risk"
            }
        ]
    )
    trigger_words: List[str] = Field(
        ...,
        description="Suspicious keywords found in email",
        example=["verify", "account", "suspend"]
    )
    explanation_text: str = Field(
        ...,
        description="Human-readable explanation (2-3 sentences for non-technical users)",
        example="This email is classified as PHISHING with HIGH confidence (87%). The main risk indicators are urgency words like 'verify' and 'suspend', and the URL uses an IP address instead of a proper domain name."
    )


# ============================================================================
# FEEDBACK ENDPOINTS
# ============================================================================

class FeedbackRequest(BaseModel):
    """
    Request schema for user feedback on predictions.
    
    Attributes:
    -----------
    prediction_id : str
        Unique ID of the prediction being reviewed
    true_label : int
        The actual label (user correction): 0 = SAFE, 1 = PHISHING
    comment : Optional[str]
        Additional comments from user
    
    Example:
    --------
    {
        "prediction_id": "pred_123abc",
        "true_label": 0,
        "comment": "This was actually a legitimate marketing email"
    }
    """
    prediction_id: str = Field(
        ...,
        description="Unique identifier of the prediction",
        min_length=1,
        max_length=100,
        example="pred_20260211_abc123"
    )
    true_label: int = Field(
        ...,
        description="The actual correct label: 0 = SAFE/LEGITIMATE, 1 = PHISHING",
        ge=0,
        le=1,
        example=0
    )
    comment: Optional[str] = Field(
        None,
        description="Optional comments or context",
        max_length=1000,
        example="This was a legitimate promotional email from our partner"
    )


class FeedbackResponse(BaseModel):
    """
    Response schema for feedback submission.
    
    Attributes:
    -----------
    message : str
        Confirmation message
    feedback_id : str
        Unique ID for the submitted feedback
    will_improve_model : bool
        Whether this feedback will be used to improve the model
    
    Example:
    --------
    {
        "message": "Thank you for feedback",
        "feedback_id": "fb_20260211_xyz789",
        "will_improve_model": true
    }
    """
    message: str = Field(
        ...,
        description="Confirmation message",
        example="Thank you for feedback. Your input helps improve our model!"
    )
    feedback_id: str = Field(
        ...,
        description="Unique identifier for this feedback",
        example="fb_20260211_xyz789"
    )
    will_improve_model: bool = Field(
        ...,
        description="Whether this feedback will be used to improve the model",
        example=True
    )


class FeedbackStatsResponse(BaseModel):
    """
    Response schema for feedback statistics endpoint.
    
    Attributes:
    -----------
    total_predictions : int
        Total number of predictions made
    total_feedback : int
        Total feedback submissions received
    false_positives : int
        Number of emails predicted as phishing but were actually safe
    false_negatives : int
        Number of emails predicted as safe but were actually phishing
    accuracy_from_feedback : Optional[float]
        Model accuracy based on user feedback (None if no feedback yet)
    
    Example:
    --------
    {
        "total_predictions": 1523,
        "total_feedback": 127,
        "false_positives": 8,
        "false_negatives": 3,
        "accuracy_from_feedback": 0.913
    }
    """
    total_predictions: int = Field(
        ...,
        description="Total number of predictions made",
        example=1523
    )
    total_feedback: int = Field(
        ...,
        description="Total feedback submissions received",
        example=127
    )
    false_positives: int = Field(
        ...,
        description="Emails predicted as phishing but were actually safe",
        example=8
    )
    false_negatives: int = Field(
        ...,
        description="Emails predicted as safe but were actually phishing",
        example=3
    )
    accuracy_from_feedback: Optional[float] = Field(
        None,
        description="Model accuracy based on user feedback (None if no feedback yet)",
        ge=0.0,
        le=1.0,
        example=0.913
    )


# ============================================================================
# HEALTH CHECK
# ============================================================================

class HealthResponse(BaseModel):
    """
    Response schema for health check endpoint.
    
    Attributes:
    -----------
    status : str
        Health status
    version : str
        API version
    models_loaded : bool
        Whether ML models are loaded
    
    Example:
    --------
    {
        "status": "healthy",
        "version": "1.0.0",
        "models_loaded": true
    }
    """
    status: str = Field(
        ...,
        description="Health status of the API",
        example="healthy"
    )
    version: str = Field(
        ...,
        description="API version",
        example="1.0.0"
    )
    models_loaded: bool = Field(
        ...,
        description="Whether ML models are loaded and ready",
        example=True
    )


# ============================================================================
# ERROR RESPONSES
# ============================================================================

class ErrorResponse(BaseModel):
    """
    Standard error response schema.
    
    Attributes:
    -----------
    error : str
        Error type
    message : str
        Error message
    detail : Optional[str]
        Additional error details
    
    Example:
    --------
    {
        "error": "ValidationError",
        "message": "email_text cannot be empty",
        "detail": "Field 'email_text' must contain at least 10 characters"
    }
    """
    error: str = Field(
        ...,
        description="Error type",
        example="ValidationError"
    )
    message: str = Field(
        ...,
        description="Error message",
        example="Invalid input data"
    )
    detail: Optional[str] = Field(
        None,
        description="Additional error details",
        example="Field 'email_text' is required"
    )
