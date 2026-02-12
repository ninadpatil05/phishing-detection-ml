"""
Unit Tests for Ensemble Model

Tests the EnsembleModel class with weighted averaging and threshold classification.
"""

import pytest
import numpy as np
import pandas as pd
from unittest.mock import Mock, MagicMock
from training.ensemble import EnsembleModel


@pytest.mark.unit
class TestEnsembleModel:
    """Test suite for EnsembleModel."""
    
    def test_initialization_with_default_weights(self):
        """Test initialization with default weights (0.6/0.4)."""
        text_clf = Mock()
        url_clf = Mock()
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf
        )
        
        assert ensemble.text_weight == 0.6
        assert ensemble.url_weight == 0.4
        assert ensemble.threshold == 0.5
    
    def test_initialization_with_custom_weights(self):
        """Test initialization with custom weights."""
        text_clf = Mock()
        url_clf = Mock()
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.7,
            url_weight=0.3
        )
        
        assert ensemble.text_weight == 0.7
        assert ensemble.url_weight == 0.3
    
    def test_weights_must_sum_to_one(self):
        """Test that weights must sum to 1.0."""
        text_clf = Mock()
        url_clf = Mock()
        
        with pytest.raises(ValueError, match="must sum to 1.0"):
            EnsembleModel(
                text_classifier=text_clf,
                url_classifier=url_clf,
                text_weight=0.5,
                url_weight=0.6  # Sum = 1.1
            )
    
    def test_predict_proba_weighted_average(self):
        """Test that predict_proba correctly computes weighted average."""
        # Mock classifiers
        text_clf = Mock()
        url_clf = Mock()
        
        # Mock predictions: [P(safe), P(phishing)]
        text_clf.predict_proba.return_value = np.array([[0.3, 0.7]])  # 70% phishing
        url_clf.predict_proba.return_value = np.array([[0.6, 0.4]])   # 40% phishing
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.6,
            url_weight=0.4
        )
        
        email = ["test email"]
        probs = ensemble.predict_proba(email)
        
        # Expected: (0.7 * 0.6) + (0.4 * 0.4) = 0.42 + 0.16 = 0.58
        expected_phishing_prob = (0.7 * 0.6) + (0.4 * 0.4)
        expected_safe_prob = (0.3 * 0.6) + (0.6 * 0.4)
        
        np.testing.assert_almost_equal(probs[0, 1], expected_phishing_prob)
        np.testing.assert_almost_equal(probs[0, 0], expected_safe_prob)
    
    def test_predict_with_threshold(self):
        """Test that predict applies threshold correctly."""
        text_clf = Mock()
        url_clf = Mock()
        
        # Risk score = 0.58 (above 0.5 threshold) → PHISHING
        text_clf.predict_proba.return_value = np.array([[0.3, 0.7]])
        url_clf.predict_proba.return_value = np.array([[0.6, 0.4]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.6,
            url_weight=0.4,
            threshold=0.5
        )
        
        prediction = ensemble.predict(["test"])
        
        assert prediction[0] == 1  # Phishing
    
    def test_predict_below_threshold(self):
        """Test prediction below threshold."""
        text_clf = Mock()
        url_clf = Mock()
        
        # Risk score = 0.30 (below 0.5 threshold) → SAFE
        text_clf.predict_proba.return_value = np.array([[0.8, 0.2]])
        url_clf.predict_proba.return_value = np.array([[0.6, 0.4]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.6,
            url_weight=0.4,
            threshold=0.5
        )
        
        prediction = ensemble.predict(["test"])
        
        assert prediction[0] == 0  # Safe
    
    def test_custom_threshold(self):
        """Test with custom classification threshold."""
        text_clf = Mock()
        url_clf = Mock()
        
        # Risk score = 0.58
        text_clf.predict_proba.return_value = np.array([[0.3, 0.7]])
        url_clf.predict_proba.return_value = np.array([[0.6, 0.4]])
        
        # With higher threshold, should classify as safe
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.6,
            url_weight=0.4,
            threshold=0.6  # Higher threshold
        )
        
        prediction = ensemble.predict(["test"])
        
        assert prediction[0] == 0  # Safe (0.58 < 0.6)
    
    def test_predict_without_classifiers_raises_error(self):
        """Test that predict raises error if classifiers not loaded."""
        ensemble = EnsembleModel()
        
        with pytest.raises(ValueError, match="must be loaded"):
            ensemble.predict(["test"])
    
    def test_predict_proba_without_classifiers_raises_error(self):
        """Test that predict_proba raises error if classifiers not loaded."""
        ensemble = EnsembleModel()
        
        with pytest.raises(ValueError, match="must be loaded"):
            ensemble.predict_proba(["test"])
    
    def test_get_individual_scores(self):
        """Test getting individual scores from each classifier."""
        text_clf = Mock()
        url_clf = Mock()
        
        text_clf.predict_proba.return_value = np.array([[0.3, 0.7]])
        text_clf.predict.return_value = np.array([1])
        
        url_clf.predict_proba.return_value = np.array([[0.6, 0.4]])
        url_clf.predict.return_value = np.array([0])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf
        )
        
        scores = ensemble.get_individual_scores(["test"])
        
        assert 'text_probs' in scores
        assert 'url_probs' in scores
        assert 'ensemble_probs' in scores
        assert 'text_preds' in scores
        assert 'url_preds' in scores
        assert 'ensemble_preds' in scores
    
    def test_predict_with_email_text_input(self, sample_phishing_email):
        """Test prediction with email_text as input."""
        text_clf = Mock()
        url_clf = Mock()
        
        text_clf.predict_proba.return_value = np.array([[0 2, 0.8]])
        url_clf.predict_proba.return_value = np.array([[0.3, 0.7]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf
        )
        
        prediction = ensemble.predict([sample_phishing_email])
        
        # Should call both classifiers with email text
        text_clf.predict_proba.assert_called_once()
        url_clf.predict_proba.assert_called_once()
        
        assert prediction.shape == (1,)
    
    def test_multiple_emails_prediction(self, sample_emails_list):
        """Test prediction with multiple emails."""
        text_clf = Mock()
        url_clf = Mock()
        
        n = len(sample_emails_list)
        text_clf.predict_proba.return_value = np.random.rand(n, 2)
        url_clf.predict_proba.return_value = np.random.rand(n, 2)
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf
        )
        
        predictions = ensemble.predict(sample_emails_list)
        
        assert predictions.shape == (5,)
        assert all(p in [0, 1] for p in predictions)
    
    def test_weight_combination_0_6_0_4(self):
        """Test specific weight combination (0.6/0.4)."""
        text_clf = Mock()
        url_clf = Mock()
        
        # Text: 100% phishing, URL: 0% phishing
        text_clf.predict_proba.return_value = np.array([[0.0, 1.0]])
        url_clf.predict_proba.return_value = np.array([[1.0, 0.0]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.6,
            url_weight=0.4
        )
        
        probs = ensemble.predict_proba(["test"])
        
        # Expected: (1.0 * 0.6) + (0.0 * 0.4) = 0.6
        np.testing.assert_almost_equal(probs[0, 1], 0.6)
    
    def test_equal_weights(self):
        """Test with equal weights (0.5/0.5)."""
        text_clf = Mock()
        url_clf = Mock()
        
        text_clf.predict_proba.return_value = np.array([[0.2, 0.8]])
        url_clf.predict_proba.return_value = np.array([[0.6, 0.4]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf,
            text_weight=0.5,
            url_weight=0.5
        )
        
        probs = ensemble.predict_proba(["test"])
        
        # Expected: (0.8 + 0.4) / 2 = 0.6
        np.testing.assert_almost_equal(probs[0, 1], 0.6)
    
    def test_pandas_series_input(self):
        """Test with pandas Series input."""
        text_clf = Mock()
        url_clf = Mock()
        
        text_clf.predict_proba.return_value = np.array([[0.3, 0.7], [0.6, 0.4]])
        url_clf.predict_proba.return_value = np.array([[0.4, 0.6], [0.7, 0.3]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf
        )
        
        series = pd.Series(["email1", "email2"])
        predictions = ensemble.predict(series)
        
        assert predictions.shape == (2,)
    
    def test_numpy_array_input(self):
        """Test with numpy array input."""
        text_clf = Mock()
        url_clf = Mock()
        
        text_clf.predict_proba.return_value = np.array([[0.3, 0.7]])
        url_clf.predict_proba.return_value = np.array([[0.4, 0.6]])
        
        ensemble = EnsembleModel(
            text_classifier=text_clf,
            url_classifier=url_clf
        )
        
        array = np.array(["email1"])
        predictions = ensemble.predict(array)
        
        assert predictions.shape == (1,)
