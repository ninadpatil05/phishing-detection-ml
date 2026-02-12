"""
Text Feature Extraction Module V2 for Phishing Detection

Enhanced version with additional features for improved accuracy.
Extends the original TextFeatureExtractor with 5 new features.
"""

import numpy as np
import pandas as pd
import re
import pickle
from pathlib import Path
from typing import Union, List
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
import scipy.sparse as sp

# Import base extractor
from feature_engineering.text_features import TextFeatureExtractor


class TextFeatureExtractorV2(TextFeatureExtractor):
    """
    Enhanced text feature extractor with additional features.
    
    New Features (on top of original 9):
    ------------------------------------
    1. Email sender domain pattern (has suspicious TLD)
    2. Cryptocurrency keywords (bitcoin, ethereum, crypto, wallet)
    3. HTML tag count
    4. Suspicious anchor text patterns
    5. Time-based urgency phrases
    
    Total custom features: 14 (9 original + 5 new)
    """
    
    def __init__(self, max_tfidf_features: int = 5000):
        """
        Initialize TextFeatureExtractorV2.
        
        Parameters:
        -----------
        max_tfidf_features : int, default=5000
            Maximum number of TF-IDF features to extract
        """
        super().__init__(max_tfidf_features)
        
        # New keyword lists for enhanced features
        self.crypto_keywords = ['bitcoin', 'btc', 'ethereum', 'eth', 'crypto', 'cryptocurrency', 'wallet', 'blockchain']
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.online']
        self.anchor_text_patterns = [
            r'click\s+here',
            r'verify\s+now',
            r'act\s+now',
            r'download\s+now',
            r'update\s+now'
        ]
        self.time_urgency_patterns = [
            r'\d+\s+hours?',
            r'24\s*hours?',
            r'expires?\s+(today|tonight|soon)',
            r'act\s+now',
            r'immediately',
            r'right\s+now'
        ]
    
    def _extract_custom_features(self, text: str) -> np.ndarray:
        """
        Extract custom features from a single email text.
        
        Extends parent class to add 5 new features.
        
        Parameters:
        -----------
        text : str
            Email text
            
        Returns:
        --------
        features : np.ndarray
            Array of 14 custom features (9 original + 5 new)
        """
        # Get original 9 features from parent class
        original_features = super()._extract_custom_features(text)
        
        # Handle missing/null text
        if not isinstance(text, str) or text.strip() == '':
            new_features = np.zeros(5)
            return np.concatenate([original_features, new_features])
        
        text_lower = text.lower()
        
        # NEW FEATURE 1: Suspicious email domain in sender pattern
        # Look for email addresses and check their TLD
        email_pattern = r'[\w\.-]+@[\w\.-]+\.[\w]+'
        emails_found = re.findall(email_pattern, text_lower)
        has_suspicious_tld = 0
        if emails_found:
            for email in emails_found:
                for tld in self.suspicious_tlds:
                    if tld in email:
                        has_suspicious_tld = 1
                        break
                if has_suspicious_tld:
                    break
        
        # NEW FEATURE 2: Cryptocurrency keywords
        has_crypto = int(any(keyword in text_lower for keyword in self.crypto_keywords))
        
        # NEW FEATURE 3: HTML tag count
        html_tags = re.findall(r'<[^>]+>', text)
        html_tag_count = len(html_tags)
        
        # NEW FEATURE 4: Suspicious anchor text patterns
        has_suspicious_anchor = 0
        for pattern in self.anchor_text_patterns:
            if re.search(pattern, text_lower):
                has_suspicious_anchor = 1
                break
        
        # NEW FEATURE 5: Time-based urgency phrases
        has_time_urgency = 0
        for pattern in self.time_urgency_patterns:
            if re.search(pattern, text_lower):
                has_time_urgency = 1
                break
        
        # Combine new features
        new_features = np.array([
            has_suspicious_tld,
            has_crypto,
            html_tag_count,
            has_suspicious_anchor,
            has_time_urgency
        ])
        
        # Concatenate with original features
        return np.concatenate([original_features, new_features])
    
    def _build_feature_names(self):
        """Build list of all feature names including new features."""
        tfidf_names = [f'tfidf_{word}' for word in self.tfidf_vectorizer.get_feature_names_out()]
        
        # Original 9 custom features
        custom_names = [
            'email_length',
            'word_count',
            'exclamation_count',
            'has_urgency_words',
            'has_financial_words',
            'capital_ratio',
            'special_char_ratio',
            'avg_word_length',
            'url_count',
            # New 5 features
            'has_suspicious_tld',
            'has_crypto',
            'html_tag_count',
            'has_suspicious_anchor',
            'has_time_urgency'
        ]
        
        self.feature_names_ = tfidf_names + custom_names


# Example usage
if __name__ == "__main__":
    # Sample data with various phishing indicators
    sample_emails = [
        "URGENT! Your Bitcoin wallet has been suspended. Verify within 24 hours: <a href='http://phishing.com'>Click here</a>",
        "Hi, just checking in about our meeting tomorrow. Let me know if you're still available.",
        "VERIFY YOUR ACCOUNT NOW!!! Download immediately from verify@suspicious.tk or your account expires today!",
        "Thanks for your email. I'll send you the report by end of day."
    ]
    
    # Create and fit the V2 extractor
    extractor = TextFeatureExtractorV2(max_tfidf_features=100)
    features = extractor.fit_transform(sample_emails)
    
    print(f"Extracted feature matrix shape: {features.shape}")
    print(f"Number of features: {len(extractor.get_feature_names())}")
    print(f"\nCustom features for first email:")
    print(f"Email: {sample_emails[0][:70]}...")
    print(f"Last 14 features (custom): {features[0, -14:]}")
    
    # Save example
    extractor.save("text_extractor_v2.pkl")
    print("\n✓ TextFeatureExtractorV2 saved!")
