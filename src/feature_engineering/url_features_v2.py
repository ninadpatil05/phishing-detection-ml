"""
URL Feature Extraction Module V2 for Phishing Detection

Enhanced version with additional features for improved accuracy.
Extends the original URLFeatureExtractor with 4 new features.
"""

import numpy as np
import pandas as pd
import re
import pickle
import math
from pathlib import Path
from typing import Union, List, Optional
from urllib.parse import urlparse
from sklearn.base import BaseEstimator, TransformerMixin

# Import base extractor
from feature_engineering.url_features import URLFeatureExtractor


class URLFeatureExtractorV2(URLFeatureExtractor):
    """
    Enhanced URL feature extractor with additional features.
    
    New Features (on top of original 15):
    -------------------------------------
    1. URL shortener service detection
    2. Typosquatting detection (Levenshtein distance to known brands)
    3. SSL certificate age (placeholder - would need external API)
    4. Deep path nesting indicator
    
    Total features: 19 (15 original + 4 new)
    """
    
    def __init__(self):
        """Initialize URLFeatureExtractorV2."""
        super().__init__()
        
        # Known URL shortener domains
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.ie',
            'tiny.cc', 'cutt.ly', 'rebrand.ly'
        ]
        
        # Common brand names for typosquatting detection
        self.known_brands = [
            'paypal', 'google', 'amazon', 'microsoft', 'facebook',
            'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
            'ebay', 'walmart', 'chase', 'wellsfargo', 'bankofamerica'
        ]
    
    def fit(self, X: Union[pd.Series, np.ndarray, List[str]], y=None):
        """
        Fit the feature extractor on training data.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
        y : array-like, optional
            Target labels (not used, for sklearn compatibility)
            
        Returns:
        --------
        self : URLFeatureExtractorV2
            Fitted transformer
        """
        # Build feature names (extended)
        self.feature_names_ = [
            'url_length',
            'domain_length',
            'num_dots',
            'num_hyphens',
            'num_underscores',
            'num_digits',
            'num_special_chars',
            'has_ip_address',
            'has_https',
            'url_entropy',
            'num_subdomains',
            'has_suspicious_keywords',
            'url_depth',
            'has_port_number',
            'has_url',
            # New features
            'is_url_shortener',
            'typosquatting_score',
            'ssl_age_indicator',
            'deep_path_nesting'
        ]
        
        self.is_fitted_ = True
        return self
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings.
        
        Parameters:
        -----------
        s1, s2 : str
            Strings to compare
            
        Returns:
        --------
        distance : int
            Edit distance between strings
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_typosquatting(self, domain: str) -> int:
        """
        Check if domain is similar to known brands (typosquatting).
        
        Returns minimum Levenshtein distance to known brands.
        Lower score = more similar = more suspicious.
        
        Parameters:
        -----------
        domain : str
            Domain name to check
            
        Returns:
        --------
        min_distance : int
            Minimum edit distance to known brands (0-10 scale)
        """
        if not domain:
            return 10  # High value = not suspicious
        
        # Remove TLD and www
        domain_clean = domain.lower()
        domain_clean = re.sub(r'^www\.', '', domain_clean)
        domain_clean = re.sub(r'\.[a-z]{2,}$', '', domain_clean)
        
        min_distance = 10
        for brand in self.known_brands:
            distance = self._levenshtein_distance(domain_clean, brand)
            if distance < min_distance:
                min_distance = distance
        
        # Return capped at 10 for feature normalization
        return min(min_distance, 10)
    
    def _extract_url_features(self, email_text: str) -> np.ndarray:
        """
        Extract all URL features from email text (including new features).
        
        Parameters:
        -----------
        email_text : str
            Email text content
            
        Returns:
        --------
        features : np.ndarray
            Array of 19 URL features (15 original + 4 new)
        """
        # Get original 15 features
        url = self._extract_first_url(email_text)
        
        # If no URL found, return zeros
        if url is None:
            return np.zeros(19)
        
        # Initialize features dict
        features = {
            'url_length': 0,
            'domain_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_digits': 0,
            'num_special_chars': 0,
            'has_ip_address': 0,
            'has_https': 0,
            'url_entropy': 0.0,
            'num_subdomains': 0,
            'has_suspicious_keywords': 0,
            'url_depth': 0,
            'has_port_number': 0,
            'has_url': 1,
            # New features
            'is_url_shortener': 0,
            'typosquatting_score': 10,
            'ssl_age_indicator': 0,
            'deep_path_nesting': 0
        }
        
        try:
            # Extract original features
            features['url_length'] = len(url)
            parsed = urlparse(url)
            domain = parsed.netloc
            features['domain_length'] = len(domain)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_digits'] = sum(c.isdigit() for c in url)
            
            special_chars = ['@', '?', '=', '&']
            features['num_special_chars'] = sum(url.count(char) for char in special_chars)
            
            features['has_ip_address'] = self._has_ip_address(url)
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            features['url_entropy'] = self._calculate_entropy(url)
            
            domain_without_port = domain.split(':')[0]
            domain_parts = domain_without_port.split('.')
            features['num_subdomains'] = max(0, len(domain_parts) - 2)
            
            url_lower = url.lower()
            features['has_suspicious_keywords'] = int(
                any(keyword in url_lower for keyword in self.suspicious_keywords)
            )
            
            path = parsed.path
            features['url_depth'] = path.count('/')
            features['has_port_number'] = 1 if parsed.port is not None else 0
            
            # NEW FEATURE 1: URL Shortener Detection
            domain_lower = domain.lower()
            features['is_url_shortener'] = int(
                any(shortener in domain_lower for shortener in self.url_shorteners)
            )
            
            # NEW FEATURE 2: Typosquatting Score
            features['typosquatting_score'] = self._check_typosquatting(domain_without_port)
            
            # NEW FEATURE 3: SSL Certificate Age (Placeholder)
            # In production, this would call an external API to check cert age
            # For now, detect if domain is very new-looking (many digits, random chars)
            # High entropy + many digits = likely new domain
            digit_ratio = features['num_digits'] / max(len(domain), 1)
            if digit_ratio > 0.3 and features['url_entropy'] > 3.5:
                features['ssl_age_indicator'] = 1  # Likely new/suspicious
            else:
                features['ssl_age_indicator'] = 0  # Likely established
            
            # NEW FEATURE 4: Deep Path Nesting
            # Detect unusually deep path structures (>5 levels)
            features['deep_path_nesting'] = 1 if features['url_depth'] > 5 else 0
            
        except Exception as e:
            # If any error occurs, keep has_url=1 and defaults for others
            features['has_url'] = 1
        
        # Convert to array in correct order
        return np.array([
            features['url_length'],
            features['domain_length'],
            features['num_dots'],
            features['num_hyphens'],
            features['num_underscores'],
            features['num_digits'],
            features['num_special_chars'],
            features['has_ip_address'],
            features['has_https'],
            features['url_entropy'],
            features['num_subdomains'],
            features['has_suspicious_keywords'],
            features['url_depth'],
            features['has_port_number'],
            features['has_url'],
            features['is_url_shortener'],
            features['typosquatting_score'],
            features['ssl_age_indicator'],
            features['deep_path_nesting']
        ])


# Example usage
if __name__ == "__main__":
    # Sample emails with various URL patterns
    sample_emails = [
        "Click here: https://bit.ly/3xYz123 to verify your account!",
        "Hi, check out this article: https://www.legitsite.com/blog/post",
        "URGENT! Visit https://paypa1-secure.com/verify/account/update/now/confirm to avoid suspension!",
        "Check: http://192.168.1.1:8080/admin/panel/login",
        "No URLs in this email at all."
    ]
    
    # Create and fit the V2 extractor
    extractor = URLFeatureExtractorV2()
    features = extractor.fit_transform(sample_emails)
    
    print(f"Extracted feature matrix shape: {features.shape}")
    print(f"Number of features: {len(extractor.get_feature_names())}")
    print(f"\n--- Email Analysis ---")
    for i, email in enumerate(sample_emails):
        print(f"\nEmail {i+1}: {email[:60]}...")
        print(f"  - Has URL: {int(features[i][-4])}")
        print(f"  - Is Shortener: {int(features[i][-4])}")
        print(f"  - Typosquatting Score: {features[i][-3]:.1f}")
        print(f"  - Deep Path Nesting: {int(features[i][-1])}")
    
    # Save example
    extractor.save("url_extractor_v2.pkl")
    print("\n✓ URLFeatureExtractorV2 saved!")
