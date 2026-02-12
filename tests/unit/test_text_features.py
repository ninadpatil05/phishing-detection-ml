"""
Unit Tests for Text Feature Extraction

Tests the TextFeatureExtractor class with various edge cases and input types.
"""

import pytest
import numpy as np
import pandas as pd
from feature_engineering.text_features import TextFeatureExtractor


@pytest.mark.unit
class TestTextFeatureExtractor:
    """Test suite for TextFeatureExtractor."""
    
    def test_initialization(self):
        """Test extractor initialization."""
        extractor = TextFeatureExtractor(max_tfidf_features=100)
        assert extractor.max_tfidf_features == 100
        assert extractor.tfidf_vectorizer is None
        assert len(extractor.urgency_words) > 0
        assert len(extractor.financial_words) > 0
    
    def test_fit_with_list(self, sample_emails_list):
        """Test fit method with list of strings."""
        extractor = TextFeatureExtractor(max_tfidf_features=50)
        extractor.fit(sample_emails_list)
        
        assert extractor.tfidf_vectorizer is not None
        assert extractor.feature_names_ is not None
        assert len(extractor.feature_names_) > 0
    
    def test_fit_with_pandas_series(self, sample_emails_list):
        """Test fit method with pandas Series."""
        extractor = TextFeatureExtractor(max_tfidf_features=50)
        series = pd.Series(sample_emails_list)
        extractor.fit(series)
        
        assert extractor.tfidf_vectorizer is not None
    
    def test_fit_with_numpy_array(self, sample_emails_list):
        """Test fit method with numpy array."""
        extractor = TextFeatureExtractor(max_tfidf_features=50)
        array = np.array(sample_emails_list)
        extractor.fit(array)
        
        assert extractor.tfidf_vectorizer is not None
    
    def test_transform_before_fit_raises_error(self, sample_phishing_email):
        """Test that transform raises error if called before fit."""
        extractor = TextFeatureExtractor()
        
        with pytest.raises(ValueError, match="must be fitted"):
            extractor.transform([sample_phishing_email])
    
    def test_fit_transform(self, sample_emails_list):
        """Test fit_transform method."""
        extractor = TextFeatureExtractor(max_tfidf_features=50)
        features = extractor.fit_transform(sample_emails_list)
        
        assert isinstance(features, np.ndarray)
        assert features.shape[0] == len(sample_emails_list)
        assert features.shape[1] > 9  # TF-IDF + 9 custom features
    
    def test_transform_shape(self, sample_emails_list):
        """Test output feature matrix shape."""
        extractor = TextFeatureExtractor(max_tfidf_features=100)
        features = extractor.fit_transform(sample_emails_list)
        
        # Should have max 100 TF-IDF features + 9 custom = max 109
        assert features.shape[1] <= 109
        # Should have same number of rows as input
        assert features.shape[0] == len(sample_emails_list)
    
    def test_empty_string_handling(self, empty_email):
        """Test handling of empty strings."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["some text", "more text"])
        
        features = extractor.transform([empty_email])
        
        # Should return zeros for custom features
        custom_features = features[0, -9:]
        assert np.all(custom_features == 0)
    
    def test_very_long_text(self, long_email):
        """Test with very long text."""
        extractor = TextFeatureExtractor(max_tfidf_features=50)
        extractor.fit([long_email])
        
        features = extractor.transform([long_email])
        
        # Should handle without error
        assert features.shape == (1, extractor.max_tfidf_features + 9)
        # Email length should be very high
        assert features[0, -9] > 10000  # email_length custom feature
    
    def test_special_characters_only(self, special_chars_email):
        """Test with only special characters."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["normal text"])
        
        features = extractor.transform([special_chars_email])
        
        # Special character ratio should be very high
        special_ratio = features[0, -3]  # special_char_ratio
        assert special_ratio > 0.5
    
    def test_non_english_text(self, non_english_email):
        """Test with non-English text."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit([non_english_email, "english text"])
        
        features = extractor.transform([non_english_email])
        
        # Should handle without errors
        assert features.shape[0] == 1
    
    def test_urgency_word_detection(self):
        """Test urgency word feature extraction."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["normal email"])
        
        # Email with urgency word
        urgent = "URGENT please verify your account"
        features_urgent = extractor.transform([urgent])
        has_urgency = features_urgent[0, -6]  # has_urgency_words
        
        # Email without urgency word
        normal = "Hello how are you"
        features_normal = extractor.transform([normal])
        no_urgency = features_normal[0, -6]
        
        assert has_urgency == 1
        assert no_urgency == 0
    
    def test_financial_word_detection(self):
        """Test financial word feature extraction."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["normal email"])
        
        # Email with financial word
        financial = "Please login to your bank account"
        features_financial = extractor.transform([financial])
        has_financial = features_financial[0, -5]  # has_financial_words
        
        # Email without financial word
        normal = "Meeting at 3pm tomorrow"
        features_normal = extractor.transform([normal])
        no_financial = features_normal[0, -5]
        
        assert has_financial == 1
        assert no_financial == 0
    
    def test_exclamation_count(self):
        """Test exclamation mark counting."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["test"])
        
        email_many = "URGENT!!! VERIFY NOW!!!"
        features = extractor.transform([email_many])
        exclamation_count = features[0, -7]  # exclamation_count
        
        assert exclamation_count == 6
    
    def test_capital_ratio(self):
        """Test capital letter ratio calculation."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["test"])
        
        # All caps
        all_caps = "URGENT MESSAGE"
        features_caps = extractor.transform([all_caps])
        capital_ratio = features_caps[0, -4]  # capital_ratio
        
        # Should be close to 1.0 (ignoring space)
        assert capital_ratio > 0.8
    
    def test_url_count_in_text(self):
        """Test URL counting in email text."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["test"])
        
        email_urls = "Visit http://example.com and https://test.org"
        features = extractor.transform([email_urls])
        url_count = features[0, -1]  # url_count
        
        assert url_count == 2
    
    def test_word_count(self):
        """Test word count feature."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["test"])
        
        email = "This is a test email with seven words"
        features = extractor.transform([email])
        word_count = features[0, -8]  # word_count
        
        assert word_count == 8
    
    def test_avg_word_length(self):
        """Test average word length calculation."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit(["test"])
        
        # Short words
        short = "I am ok"
        features_short = extractor.transform([short])
        avg_short = features_short[0, -2]  # avg_word_length
        
        # Long words
        long = "extraordinarily sophisticated communication"
        features_long = extractor.transform([long])
        avg_long = features_long[0, -2]
        
        assert avg_long > avg_short
    
    def test_get_feature_names(self, sample_emails_list):
        """Test getting feature names."""
        extractor = TextFeatureExtractor(max_tfidf_features=50)
        extractor.fit(sample_emails_list)
        
        feature_names = extractor.get_feature_names()
        
        assert len(feature_names) > 0
        assert 'email_length' in feature_names
        assert 'word_count' in feature_names
        assert 'has_urgency_words' in feature_names
    
    def test_get_feature_names_before_fit_raises_error(self):
        """Test that get_feature_names raises error before fit."""
        extractor = TextFeatureExtractor()
        
        with pytest.raises(ValueError, match="must be fitted"):
            extractor.get_feature_names()
    
    def test_feature_consistency(self, sample_phishing_email):
        """Test that transform produces consistent features."""
        extractor = TextFeatureExtractor(max_tfidf_features=10)
        extractor.fit([sample_phishing_email, "normal email"])
        
        features1 = extractor.transform([sample_phishing_email])
        features2 = extractor.transform([sample_phishing_email])
        
        np.testing.assert_array_equal(features1, features2)
    
    def test_pipeline_compatibility(self, sample_emails_list):
        """Test sklearn pipeline compatibility."""
        extractor = TextFeatureExtractor(max_tfidf_features=20)
        
        # Test fit returns self
        result = extractor.fit(sample_emails_list)
        assert result is extractor
        
        # Test fit_transform works
        features = extractor.fit_transform(sample_emails_list)
        assert features is not None
