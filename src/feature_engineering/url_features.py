"""
URL Feature Extraction Module for Phishing Detection

This module provides URLFeatureExtractor class for extracting features
from URLs found in email text to help identify phishing attempts.
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


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extract comprehensive URL features from email content for phishing detection.
    
    IMPORTANT: This extractor works with email text (not separate URL columns).
    URLs are extracted from email_text using regex pattern.
    
    Features Extracted (from FIRST URL in email):
    ----------------------------------------------
    1. URL Total Length
       - Phishing URLs are often very long to hide malicious domain
       - Attackers use long URLs to obscure true destination
       - Legitimate URLs tend to be concise and readable
    
    2. Domain Length
       - Phishing domains can be unusually short (hacked) or long (generated)
       - Long randomized domains indicate automated phishing infrastructure
       - Short domains might be compromised legitimate sites
    
    3. Number of Dots
       - Excessive dots suggest subdomain manipulation
       - Phishers create fake subdomains like "paypal.secure.login.fake-site.com"
       - Creates illusion of legitimacy through subdomain names
    
    4. Number of Hyphens
       - Legitimate domains rarely use multiple hyphens
       - Phishers use hyphens to create convincing fake domains
       - Example: "secure-paypal-login.com" (suspicious)
    
    5. Number of Underscores
       - Underscores are uncommon in legitimate URLs
       - Often used in phishing to bypass filters
       - May indicate parameter manipulation or obfuscation
    
    6. Number of Digits
       - Random digits suggest auto-generated phishing URLs
       - Legitimate URLs use meaningful numbers (dates, versions)
       - High digit count indicates temporary/throwaway domains
    
    7. Special Characters (@, ?, =, &)
       - @ symbol can hide real domain (http://google.com@evil.com)
       - Excessive query parameters suggest tracking/manipulation
       - Used for session hijacking and parameter injection
    
    8. Has IP Address Instead of Domain
       - Legitimate sites use domain names, not raw IPs
       - IP addresses indicate quick setup/temporary infrastructure
       - Bypasses domain reputation systems
       - Clear red flag for phishing
    
    9. Has HTTPS
       - Lack of HTTPS indicates insecure connection
       - However, phishers now commonly use HTTPS too
       - Still useful as one of many indicators
       - Modern phishing sites get free SSL certificates
    
    10. URL Entropy (Randomness Score)
        - High entropy = random/generated characters
        - Legitimate URLs are human-readable and memorable
        - Phishing URLs often use random strings for uniqueness
        - Helps identify auto-generated malicious URLs
    
    11. Number of Subdomains
        - Excessive subdomains create false legitimacy
        - Example: "login.secure.paypal.verification.evil.com"
        - Legitimate sites use 0-2 subdomains typically
        - High count suggests domain spoofing attempt
    
    12. Suspicious Keywords in URL
        - Keywords: login, secure, verify, account, update
        - Phishers use these to appear legitimate
        - Creates urgency and trust simultaneously
        - Legitimate sites don't overuse security terms in URLs
    
    13. URL Depth (Number of Slashes)
        - Very deep paths can hide malicious pages
        - Phishers use deep paths to evade detection
        - Many slashes suggest complex redirect chains
        - Legitimate URLs tend to have shallow, clean structures
    
    14. Has Port Number
        - Non-standard ports are suspicious
        - Legitimate sites use standard ports (80, 443)
        - Custom ports may indicate testing/development servers
        - Or compromised systems running backdoor services
    
    15. Has URL Flag
        - Binary indicator if URL was found in email
        - Legitimate emails may not contain URLs
        - Phishing emails almost always include malicious links
        - Helps distinguish spam/phishing from regular emails
    
    The class is sklearn pipeline compatible.
    """
    
    def __init__(self):
        """Initialize URLFeatureExtractor."""
        self.feature_names_ = None
        self.is_fitted_ = False
        
        # Suspicious keywords to look for in URLs
        self.suspicious_keywords = ['login', 'secure', 'verify', 'account', 'update']
    
    def fit(self, X: Union[pd.Series, np.ndarray, List[str]], y=None):
        """
        Fit the feature extractor on training data.
        
        Note: This extractor is stateless (no fitting required),
        but fit() is provided for sklearn pipeline compatibility.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
        y : array-like, optional
            Target labels (not used, for sklearn compatibility)
            
        Returns:
        --------
        self : URLFeatureExtractor
            Fitted transformer
        """
        # Build feature names
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
            'has_url'
        ]
        
        self.is_fitted_ = True
        return self
    
    def transform(self, X: Union[pd.Series, np.ndarray, List[str]]) -> np.ndarray:
        """
        Transform email text into URL feature vectors.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
            
        Returns:
        --------
        features : np.ndarray
            Feature matrix with shape (n_samples, 15)
        """
        if not self.is_fitted_:
            raise ValueError("Transformer must be fitted before calling transform()")
        
        # Convert to list of strings
        X_texts = self._ensure_list(X)
        
        # Extract URL features for each email
        features = []
        for text in X_texts:
            features.append(self._extract_url_features(text))
        
        return np.array(features)
    
    def fit_transform(self, X: Union[pd.Series, np.ndarray, List[str]], y=None) -> np.ndarray:
        """
        Fit the transformer and transform the data in one step.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
        y : array-like, optional
            Target labels (not used, for sklearn compatibility)
            
        Returns:
        --------
        features : np.ndarray
            Feature matrix with shape (n_samples, 15)
        """
        return self.fit(X, y).transform(X)
    
    def _ensure_list(self, X: Union[pd.Series, np.ndarray, List[str]]) -> List[str]:
        """Convert input to list of strings."""
        if isinstance(X, pd.Series):
            return X.tolist()
        elif isinstance(X, np.ndarray):
            return X.tolist()
        elif isinstance(X, list):
            return X
        else:
            raise ValueError(f"Unsupported input type: {type(X)}")
    
    def _extract_first_url(self, email_text: str) -> Optional[str]:
        """
        Extract the first URL from email text using regex.
        
        Parameters:
        -----------
        email_text : str
            Email text content
            
        Returns:
        --------
        url : str or None
            First URL found, or None if no URL found
        """
        if not isinstance(email_text, str) or email_text.strip() == '':
            return None
        
        # Extract all URLs using the specified regex pattern
        urls = re.findall(r'http[s]?://\S+', email_text)
        
        # Return first URL if any found
        return urls[0] if urls else None
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text (measure of randomness).
        
        Higher entropy = more random/unpredictable
        Lower entropy = more structured/predictable
        
        Parameters:
        -----------
        text : str
            Text to calculate entropy for
            
        Returns:
        --------
        entropy : float
            Shannon entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0.0
        for count in char_freq.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_ip_address(self, url: str) -> int:
        """
        Check if URL uses IP address instead of domain name.
        
        Parameters:
        -----------
        url : str
            URL to check
            
        Returns:
        --------
        has_ip : int
            1 if IP address detected, 0 otherwise
        """
        # Pattern to match IPv4 addresses
        ipv4_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            
            # Check if netloc matches IP pattern
            ip_match = re.search(ipv4_pattern, netloc)
            return 1 if ip_match else 0
        except:
            return 0
    
    def _extract_url_features(self, email_text: str) -> np.ndarray:
        """
        Extract all URL features from email text.
        
        Parameters:
        -----------
        email_text : str
            Email text content
            
        Returns:
        --------
        features : np.ndarray
            Array of 15 URL features
        """
        # Extract first URL from email
        url = self._extract_first_url(email_text)
        
        # If no URL found, return zeros with has_url=0
        if url is None:
            return np.zeros(15)
        
        # Initialize default values (in case of parsing errors)
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
            'has_url': 1  # URL was found
        }
        
        try:
            # 1. URL total length
            features['url_length'] = len(url)
            
            # Parse URL
            parsed = urlparse(url)
            
            # 2. Domain length
            domain = parsed.netloc
            features['domain_length'] = len(domain)
            
            # 3. Number of dots
            features['num_dots'] = url.count('.')
            
            # 4. Number of hyphens
            features['num_hyphens'] = url.count('-')
            
            # 5. Number of underscores
            features['num_underscores'] = url.count('_')
            
            # 6. Number of digits
            features['num_digits'] = sum(c.isdigit() for c in url)
            
            # 7. Number of special characters (@, ?, =, &)
            special_chars = ['@', '?', '=', '&']
            features['num_special_chars'] = sum(url.count(char) for char in special_chars)
            
            # 8. Has IP address instead of domain
            features['has_ip_address'] = self._has_ip_address(url)
            
            # 9. Has HTTPS
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            
            # 10. URL entropy (randomness)
            features['url_entropy'] = self._calculate_entropy(url)
            
            # 11. Number of subdomains
            # Remove port if present
            domain_without_port = domain.split(':')[0]
            # Count dots in domain (subdomains = dots - 1 for typical .com/.org)
            # For example: www.example.com has 1 subdomain (www)
            domain_parts = domain_without_port.split('.')
            features['num_subdomains'] = max(0, len(domain_parts) - 2)
            
            # 12. Suspicious keywords in URL
            url_lower = url.lower()
            features['has_suspicious_keywords'] = int(
                any(keyword in url_lower for keyword in self.suspicious_keywords)
            )
            
            # 13. URL depth (number of slashes in path)
            path = parsed.path
            features['url_depth'] = path.count('/')
            
            # 14. Has port number
            features['has_port_number'] = 1 if parsed.port is not None else 0
            
        except Exception as e:
            # If any error occurs during feature extraction, return defaults
            # but keep has_url=1 since a URL was found
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
            features['has_url']
        ])
    
    def get_feature_names(self) -> List[str]:
        """
        Get list of all feature names.
        
        Returns:
        --------
        feature_names : list of str
            Names of all features
        """
        if self.feature_names_ is None:
            raise ValueError("Transformer must be fitted before getting feature names")
        return self.feature_names_
    
    def save(self, path: Union[str, Path]):
        """
        Save the fitted transformer to disk.
        
        Parameters:
        -----------
        path : str or Path
            Path to save the transformer
        """
        if not self.is_fitted_:
            raise ValueError("Cannot save unfitted transformer")
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save the entire object
        with open(path, 'wb') as f:
            pickle.dump(self, f)
        
        print(f"✓ URLFeatureExtractor saved to {path}")
    
    @classmethod
    def load(cls, path: Union[str, Path]) -> 'URLFeatureExtractor':
        """
        Load a fitted transformer from disk.
        
        Parameters:
        -----------
        path : str or Path
            Path to the saved transformer
            
        Returns:
        --------
        extractor : URLFeatureExtractor
            Loaded transformer
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"No transformer found at {path}")
        
        with open(path, 'rb') as f:
            extractor = pickle.load(f)
        
        print(f"✓ URLFeatureExtractor loaded from {path}")
        return extractor


# Example usage
if __name__ == "__main__":
    # Sample email texts with URLs
    sample_emails = [
        "URGENT! Your account has been suspended. Click here to verify: http://192.168.1.1:8080/secure-login/verify?account=12345&token=abc",
        "Hi, check out this article: https://www.legitsite.com/blog/interesting-post",
        "VERIFY NOW! Visit https://paypal-secure-login-verify.suspicious-domain.com/update/account for immediate action!",
        "Thanks for your email. Our website is https://example.com",
        "No URLs in this email at all."
    ]
    
    # Create and fit the extractor
    extractor = URLFeatureExtractor()
    features = extractor.fit_transform(sample_emails)
    
    print(f"Extracted feature matrix shape: {features.shape}")
    print(f"Number of features: {len(extractor.get_feature_names())}")
    print(f"\nFeature names:")
    for i, name in enumerate(extractor.get_feature_names()):
        print(f"  {i+1:2d}. {name}")
    
    print(f"\n--- Email Analysis ---")
    for i, email in enumerate(sample_emails):
        print(f"\nEmail {i+1}: {email[:70]}...")
        print(f"Features: {features[i]}")
        print(f"  - Has URL: {int(features[i][-1])}")
        print(f"  - URL Length: {int(features[i][0])}")
        print(f"  - Has HTTPS: {int(features[i][8])}")
        print(f"  - Has IP Address: {int(features[i][7])}")
        print(f"  - Suspicious Keywords: {int(features[i][11])}")
    
    # Save and load example
    extractor.save("url_extractor.pkl")
    loaded_extractor = URLFeatureExtractor.load("url_extractor.pkl")
    print("\n✓ Save/load test successful!")
