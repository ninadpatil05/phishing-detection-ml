"""
Unit Tests for URL Feature Extraction

Tests the URLFeatureExtractor class with various edge cases and URL patterns.
"""

import pytest
import numpy as np
import pandas as pd
from feature_engineering.url_features import URLFeatureExtractor


@pytest.mark.unit
class TestURLFeatureExtractor:
    """Test suite for URLFeatureExtractor."""
    
    def test_initialization(self):
        """Test extractor initialization."""
        extractor = URLFeatureExtractor()
        assert extractor is not None
    
    def test_fit_with_emails(self, sample_emails_list):
        """Test fit method with email list."""
        extractor = URLFeatureExtractor()
        extractor.fit(sample_emails_list)
        
        # Should fit without errors
        assert extractor is not None
    
    def test_transform_with_url(self, email_ip_url):
        """Test transform with email containing URL."""
        extractor = URLFeatureExtractor()
        extractor.fit([email_ip_url])
        
        features = extractor.transform([email_ip_url])
        
        assert isinstance(features, np.ndarray)
        assert features.shape[0] == 1
        # Should have 14 URL features
        assert features.shape[1] == 14
    
    def test_no_url_returns_zeros(self, email_no_url):
        """Test that email without URL returns zero features."""
        extractor = URLFeatureExtractor()
        extractor.fit([email_no_url, "http://example.com"])
        
        features = extractor.transform([email_no_url])
        
        # All features should be zero when no URL present
        assert np.all(features == 0)
    
    def test_multiple_urls_uses_first(self, email_multiple_urls):
        """Test that only first URL is used when multiple URLs present."""
        extractor = URLFeatureExtractor()
        extractor.fit([email_multiple_urls])
        
        features = extractor.transform([email_multiple_urls])
        
        # Should extract features from first URL (http://example.com)
        # Has HTTPS should be 0 (first is http)
        has_https = features[0, 8]
        assert has_https == 0
    
    def test_malformed_url_handling(self, email_malformed_url):
        """Test handling of malformed URLs."""
        extractor = URLFeatureExtractor()
        extractor.fit([email_malformed_url])
        
        features = extractor.transform([email_malformed_url])
        
        # Should handle gracefully (extract what it can or return zeros)
        assert features.shape == (1, 14)
    
    def test_ip_based_url_detection(self, email_ip_url):
        """Test IP-based URL detection."""
        extractor = URLFeatureExtractor()
        extractor.fit([email_ip_url])
        
        features = extractor.transform([email_ip_url])
        
        # has_ip_address feature (index 7) should be 1
        has_ip = features[0, 7]
        assert has_ip == 1
    
    def test_https_detection(self):
        """Test HTTPS detection."""
        extractor = URLFeatureExtractor()
        
        https_email = "Visit https://secure-site.com"
        http_email = "Visit http://unsecure-site.com"
        
        extractor.fit([https_email, http_email])
        
        features_https = extractor.transform([https_email])
        features_http = extractor.transform([http_email])
        
        # has_https feature (index 8)
        assert features_https[0, 8] == 1  # HTTPS present
        assert features_http[0, 8] == 0   # HTTPS absent
    
    def test_url_length_extraction(self):
        """Test URL length feature."""
        extractor = URLFeatureExtractor()
        
        short_url = "http://ex.co"
        long_url = "http://very-long-domain-name-here.com/path/to/page"
        
        extractor.fit([short_url, long_url])
        
        features_short = extractor.transform([short_url])
        features_long = extractor.transform([long_url])
        
        # url_length (index 0)
        assert features_long[0, 0] > features_short[0, 0]
    
    def test_hyphen_count(self):
        """Test hyphen counting in URLs."""
        extractor = URLFeatureExtractor()
        
        email = "http://secure-login-verify-account.com"
        extractor.fit([email])
        
        features = extractor.transform([email])
        
        # num_hyphens (index 3)
        assert features[0, 3] >= 3
    
    def test_dot_count(self):
        """Test dot counting in URLs."""
        extractor = URLFeatureExtractor()
        
        email = "http://sub.domain.example.com"
        extractor.fit([email])
        
        features = extractor.transform([email])
        
        # num_dots (index 2)
        # Should have multiple dots
        assert features[0, 2] >= 2
    
    def test_digit_count(self):
        """Test digit counting in URLs."""
        extractor = URLFeatureExtractor()
        
        email = "http://site123.com/page456"
        extractor.fit([email])
        
        features = extractor.transform([email])
        
        # num_digits (index 5)
        assert features[0, 5] >= 5  # 1,2,3,4,5,6
    
    def test_special_char_count(self):
        """Test special character counting."""
        extractor = URLFeatureExtractor()
        
        email = "http://site.com?param=value&other=123"
        extractor.fit([email])
        
        features = extractor.transform([email])
        
        # num_special_chars (index 6)
        # Should detect ?, =, &
        assert features[0, 6] >= 3
    
    def test_suspicious_keywords(self):
        """Test suspicious keyword detection in URL."""
        extractor = URLFeatureExtractor()
        
        suspicious = "http://secure-login-verify.com"
        normal = "http://example.com"
        
        extractor.fit([suspicious, normal])
        
        features_sus = extractor.transform([suspicious])
        features_norm = extractor.transform([normal])
        
        # has_suspicious_keywords (index 11)
        assert features_sus[0, 11] == 1
        assert features_norm[0, 11] == 0
    
    def test_url_entropy(self):
        """Test URL entropy calculation."""
        extractor = URLFeatureExtractor()
        
        random = "http://asjdf2398asdf.com"
        readable = "http://example.com"
        
        extractor.fit([random, readable])
        
        features_random = extractor.transform([random])
        features_readable = extractor.transform([readable])
        
        # url_entropy (index 9)
        # Random should have higher entropy
        assert features_random[0, 9] > features_readable[0, 9]
    
    def test_subdomain_count(self):
        """Test subdomain counting."""
        extractor = URLFeatureExtractor()
        
        many_subs = "http://login.secure.paypal.fake-site.com"
        few_subs = "http://example.com"
        
        extractor.fit([many_subs, few_subs])
        
        features_many = extractor.transform([many_subs])
        features_few = extractor.transform([few_subs])
        
        # num_subdomains (index 10)
        assert features many[0, 10] > features_few[0, 10]
    
    def test_url_depth(self):
        """Test URL depth (slash count)."""
        extractor = URLFeatureExtractor()
        
        deep = "http://site.com/path/to/page/deep/content"
        shallow = "http://site.com/page"
        
        extractor.fit([deep, shallow])
        
        features_deep = extractor.transform([deep])
        features_shallow = extractor.transform([shallow])
        
        # url_depth (index 12)
        assert features_deep[0, 12] > features_shallow[0, 12]
    
    def test_port_number_detection(self):
        """Test port number detection."""
        extractor = URLFeatureExtractor()
        
        with_port = "http://site.com:8080/page"
        without_port = "http://site.com/page"
        
        extractor.fit([with_port, without_port])
        
        features_with = extractor.transform([with_port])
        features_without = extractor.transform([without_port])
        
        # has_port (index 13)
        assert features_with[0, 13] == 1
        assert features_without[0, 13] == 0
    
    def test_empty_string_handling(self, empty_email):
        """Test handling of empty strings."""
        extractor = URLFeatureExtractor()
        extractor.fit(["http://example.com"])
        
        features = extractor.transform([empty_email])
        
        # Should return zeros
        assert np.all(features == 0)
    
    def test_pandas_series_input(self):
        """Test with pandas Series input."""
        extractor = URLFeatureExtractor()
        
        series = pd.Series([
            "http://example.com",
            "http://test.org"
        ])
        
        extractor.fit(series)
        features = extractor.transform(series)
        
        assert features.shape == (2, 14)
    
    def test_numpy_array_input(self):
        """Test with numpy array input."""
        extractor = URLFeatureExtractor()
        
        array = np.array([
            "http://example.com",
            "http://test.org"
        ])
        
        extractor.fit(array)
        features = extractor.transform(array)
        
        assert features.shape == (2, 14)
    
    def test_fit_transform(self):
        """Test fit_transform method."""
        extractor = URLFeatureExtractor()
        
        emails = [
            "http://example.com",
            "http://192.168.1.1",
            "No URL here"
        ]
        
        features = extractor.fit_transform(emails)
        
        assert features.shape == (3, 14)
    
    def test_feature_consistency(self):
        """Test that transform produces consistent features."""
        extractor = URLFeatureExtractor()
        
        email = "http://test-site.com/page"
        extractor.fit([email])
        
        features1 = extractor.transform([email])
        features2 = extractor.transform([email])
        
        np.testing.assert_array_equal(features1, features2)
    
    def test_sklearn_compatibility(self):
        """Test sklearn pipeline compatibility."""
        extractor = URLFeatureExtractor()
        
        emails = ["http://example.com", "http://test.org"]
        
        # fit should return self
        result = extractor.fit(emails)
        assert result is extractor
