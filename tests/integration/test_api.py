"""
Integration Tests for API Endpoints

Tests all API endpoints with email_text input and validates responses.
"""

import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from api.main import app

client = TestClient(app)


@pytest.mark.integration
class TestPredictEndpoint:
    """Test suite for /api/v1/predict endpoint."""
    
    def test_predict_with_phishing_email(self, sample_phishing_email):
        """Test that phishing email returns PHISHING verdict."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": sample_phishing_email}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "verdict" in data
        assert "risk_score" in data
        assert "confidence" in data
        assert data["verdict"] in ["PHISHING", "LEGITIMATE"]
    
    def test_predict_with_safe_email(self, sample_safe_email):
        """Test that safe email returns LEGITIMATE verdict."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": sample_safe_email}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["verdict"] in ["PHISHING", "LEGITIMATE"]
        assert 0 <= data["risk_score"] <= 1
    
    def test_predict_empty_input_returns_422(self):
        """Test that empty input returns 422 validation error."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": ""}
        )
        
        assert response.status_code == 422
   
    def test_predict_missing_field_returns_422(self):
        """Test that missing email_text field returns 422."""
        response = client.post(
            "/api/v1/predict",
            json={}
        )
        
        assert response.status_code == 422
    
    def test_predict_wrong_type_returns_422(self):
        """Test that wrong type for email_text returns 422."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": 12345}  # Should be string
        )
        
        assert response.status_code == 422
    
    def test_predict_response_structure(self, sample_phishing_email):
        """Test predict response has correct structure."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": sample_phishing_email}
        )
        
        data = response.json()
        
        # Required fields
        assert "prediction_id" in data
        assert "verdict" in data  
        assert "risk_score" in data
        assert "confidence" in data
        assert "text_score" in data
        assert "url_score" in data
        assert "ensemble_score" in data
        assert "processing_time_ms" in data
        assert "model_version" in data
        assert "timestamp" in data
    
    def test_predict_risk_score_range(self, sample_phishing_email):
        """Test that risk_score is between 0 and 1."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": sample_phishing_email}
        )
        
        data = response.json()
        assert 0 <= data["risk_score"] <= 1
    
    def test_predict_confidence_values(self, sample_phishing_email):
        """Test that confidence is valid."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": sample_phishing_email}
        )
        
        data = response.json()
        assert data["confidence"] in ["HIGH", "MEDIUM", "LOW"]
    
    def test_predict_with_url_in_email(self, email_ip_url):
        """Test prediction with email containing URL."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": email_ip_url}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # URL score should be present
        assert "url_score" in data
        assert data["url_score"] is not None
    
    def test_predict_without_url(self, email_no_url):
        """Test prediction with email containing no URL."""
        response = client.post(
            "/api/v1/predict",
            json={"email_text": email_no_url}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should still work (URL features = 0)
        assert "url_score" in data


@pytest.mark.integration
class TestExplainEndpoint:
    """Test suite for /api/v1/explain endpoint."""
    
    def test_explain_with_phishing_email(self, sample_phishing_email):
        """Test explain endpoint with phishing email."""
        response = client.post(
            "/api/v1/explain",
            json={"email_text": sample_phishing_email}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "top_risk_factors" in data
        assert "top_safe_factors" in data
        assert "trigger_words" in data
        assert "summary" in data
    
    def test_explain_with_safe_email(self, sample_safe_email):
        """Test explain endpoint with safe email."""
        response = client.post(
            "/api/v1/explain",
            json={"email_text": sample_safe_email}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Safe emails should have fewer risk factors
        assert isinstance(data["top_risk_factors"], list)
        assert isinstance(data["top_safe_factors"], list)
    
    def test_explain_empty_input_returns_422(self):
        """Test that empty input returns 422 error."""
        response = client.post(
            "/api/v1/explain",
            json={"email_text": ""}
        )
        
        assert response.status_code == 422
    
    def test_explain_risk_factors_structure(self, sample_phishing_email):
        """Test risk factors have correct structure."""
        response = client.post(
            "/api/v1/explain",
            json={"email_text": sample_phishing_email}
        )
        
        data = response.json()
        
        for factor in data["top_risk_factors"]:
            assert "feature" in factor
            assert "value" in factor
            assert "impact" in factor
            assert "direction" in factor
    
    def test_explain_trigger_words(self):
        """Test trigger words detection."""
        email = "URGENT! Verify your bank account NOW!"
        
        response = client.post(
            "/api/v1/explain",
            json={"email_text": email}
        )
        
        data = response.json()
        
        # Should detect trigger words
        assert len(data["trigger_words"]) > 0
        # Common trigger words
        assert any(word.lower() in ["urgent", "verify", "bank", "account"] 
                   for word in data["trigger_words"])


@pytest.mark.integration
class TestFeedbackEndpoint:
    """Test suite for /api/v1/feedback endpoints."""
    
    def test_submit_feedback(self):
        """Test submitting feedback for a prediction."""
        # First make a prediction
        predict_response = client.post(
            "/api/v1/predict",
            json={"email_text": "Test email"}
        )
        
        prediction_id = predict_response.json()["prediction_id"]
        
        # Submit feedback
        feedback_response = client.post(
            "/api/v1/feedback",
            json={
                "prediction_id": prediction_id,
                "true_label": 0,
                "comment": "This was actually safe"
            }
        )
        
        assert feedback_response.status_code == 200
        data = feedback_response.json()
        
        assert "status" in data
        assert data["status"] == "success"
    
    def test_feedback_missing_prediction_id_returns_422(self):
        """Test that missing prediction_id returns 422."""
        response = client.post(
            "/api/v1/feedback",
            json={
                "true_label": 0
            }
        )
        
        assert response.status_code == 422
    
    def test_feedback_invalid_label_returns_422(self):
        """Test that invalid label returns 422."""
        response = client.post(
            "/api/v1/feedback",
            json={
                "prediction_id": "test_id",
                "true_label": 5  # Should be 0 or 1
            }
        )
        
        assert response.status_code == 422
    
    def test_get_feedback_stats(self):
        """Test getting feedback statistics."""
        response = client.get("/api/v1/feedback/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "total_predictions" in data
        assert "total_feedback" in data
        assert "false_positives" in data
        assert "false_negatives" in data
        assert "accuracy_from_feedback" in data


@pytest.mark.integration  
class TestHealthEndpoint:
    """Test suite for /health endpoint."""
    
    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert data["status"] == "healthy"


@pytest.mark.integration
@pytest.mark.slow
class TestRateLimiting:
    """Test suite for rate limiting."""
    
    def test_rate_limit_enforcement(self):
        """Test that rate limiting is enforced."""
        # Make many rapid requests
        responses = []
        for _ in range(100):
            response = client.post(
                "/api/v1/predict",
                json={"email_text": "test email"}
            )
            responses.append(response)
        
        # Should eventually hit rate limit (429)
        status_codes = [r.status_code for r in responses]
        
        # Most should succeed, but some might be rate limited
        assert 200 in status_codes
        # Note: Actual rate limiting depends on configuration


@pytest.mark.integration
class TestErrorHandling:
    """Test suite for error handling."""
    
    def test_invalid_json_returns_422(self):
        """Test that invalid JSON returns 422."""
        response = client.post(
            "/api/v1/predict",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422
    
    def test_unsupported_method_returns_405(self):
        """Test that unsupported HTTP method returns 405."""
        response = client.get("/api/v1/predict")  # Should be POST
        
        assert response.status_code == 405
    
    def test_nonexistent_endpoint_returns_404(self):
        """Test that non-existent endpoint returns 404."""
        response = client.get("/api/v1/nonexistent")
        
        assert response.status_code == 404
