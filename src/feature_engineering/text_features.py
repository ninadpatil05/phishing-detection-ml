"""
Text Feature Extraction Module for Phishing Detection

This module provides TextFeatureExtractor class for extracting features
from email text that help identify phishing attempts.
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


class TextFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extract comprehensive text features from email content for phishing detection.
    
    Features Extracted:
    -------------------
    1. TF-IDF Vectors (max 5000 features)
       - Captures important words/phrases unique to phishing emails
       - Identifies common phishing terminology and patterns
    
    2. Email Length (character count)
       - Phishing emails often have unusual lengths
       - Very short (urgent scams) or very long (detailed fake stories)
    
    3. Word Count
       - Related to length but focuses on vocabulary density
       - Helps identify sparse vs. dense communication patterns
    
    4. Exclamation Mark Count
       - Phishing emails often use excessive punctuation for urgency
       - Creates artificial sense of emergency or excitement
    
    5. Presence of Urgency Words
       - Keywords: urgent, verify, suspend, click, immediately
       - Phishers create time pressure to bypass rational thinking
       - Forces quick action before victim realizes it's fake
    
    6. Presence of Financial Words
       - Keywords: bank, account, password, credit, login
       - Directly targets financial motivation of phishing
       - Common in credential theft and banking scams
    
    7. Capital Letter Ratio
       - Excessive caps indicate shouting/urgency
       - Unprofessional communication style
       - Used to grab attention and create alarm
    
    8. Special Character Ratio
       - Unusual symbols may indicate obfuscation attempts
       - Can signal automated/templated content
       - May include encoding tricks to bypass filters
    
    9. Average Word Length
       - Very short words may indicate rushed/simple language
       - Can distinguish formal vs. informal communication
       - Phishing often uses simpler vocabulary for broad targeting
    
    10. URL Count (found in email body)
        - Phishing emails typically contain suspicious links
        - Multiple URLs often indicate spam/phishing
        - Legitimate emails usually have fewer, trusted links
    
    The class is sklearn pipeline compatible.
    """
    
    def __init__(self, max_tfidf_features: int = 5000):
        """
        Initialize TextFeatureExtractor.
        
        Parameters:
        -----------
        max_tfidf_features : int, default=5000
            Maximum number of TF-IDF features to extract
        """
        self.max_tfidf_features = max_tfidf_features
        self.tfidf_vectorizer = None
        self.feature_names_ = None
        
        # Define keyword lists
        self.urgency_words = ['urgent', 'verify', 'suspend', 'click', 'immediately']
        self.financial_words = ['bank', 'account', 'password', 'credit', 'login']
        
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
        self : TextFeatureExtractor
            Fitted transformer
        """
        # Convert to list of strings
        X_texts = self._ensure_list(X)
        
        # Fit TF-IDF vectorizer
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=self.max_tfidf_features,
            lowercase=True,
            stop_words='english',
            ngram_range=(1, 2),  # Unigrams and bigrams
            min_df=2,  # Ignore terms that appear in less than 2 documents
            max_df=0.95  # Ignore terms that appear in more than 95% of documents
        )
        self.tfidf_vectorizer.fit(X_texts)
        
        # Build feature names list
        self._build_feature_names()
        
        return self
    
    def transform(self, X: Union[pd.Series, np.ndarray, List[str]]) -> np.ndarray:
        """
        Transform email text into feature vectors.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
            
        Returns:
        --------
        features : np.ndarray
            Feature matrix with shape (n_samples, n_features)
        """
        if self.tfidf_vectorizer is None:
            raise ValueError("Transformer must be fitted before calling transform()")
        
        # Convert to list of strings
        X_texts = self._ensure_list(X)
        
        # Extract TF-IDF features
        tfidf_features = self.tfidf_vectorizer.transform(X_texts)
        
        # Extract custom features
        custom_features = []
        for text in X_texts:
            custom_features.append(self._extract_custom_features(text))
        
        custom_features = np.array(custom_features)
        
        # Combine TF-IDF and custom features
        # Convert sparse TF-IDF to dense for concatenation
        features = np.hstack([tfidf_features.toarray(), custom_features])
        
        return features
    
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
            Feature matrix with shape (n_samples, n_features)
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
    
    def _extract_custom_features(self, text: str) -> np.ndarray:
        """
        Extract custom features from a single email text.
        
        Parameters:
        -----------
        text : str
            Email text
            
        Returns:
        --------
        features : np.ndarray
            Array of 9 custom features
        """
        # Handle missing/null text
        if not isinstance(text, str) or text.strip() == '':
            return np.zeros(9)
        
        # 1. Email length (character count)
        email_length = len(text)
        
        # 2. Word count
        words = text.split()
        word_count = len(words)
        
        # 3. Exclamation mark count
        exclamation_count = text.count('!')
        
        # 4. Presence of urgency words (binary: 0 or 1)
        text_lower = text.lower()
        has_urgency = int(any(word in text_lower for word in self.urgency_words))
        
        # 5. Presence of financial words (binary: 0 or 1)
        has_financial = int(any(word in text_lower for word in self.financial_words))
        
        # 6. Capital letter ratio
        if email_length > 0:
            capital_count = sum(1 for c in text if c.isupper())
            capital_ratio = capital_count / email_length
        else:
            capital_ratio = 0.0
        
        # 7. Special character ratio
        if email_length > 0:
            special_chars = re.findall(r'[^a-zA-Z0-9\s]', text)
            special_ratio = len(special_chars) / email_length
        else:
            special_ratio = 0.0
        
        # 8. Average word length
        if word_count > 0:
            total_word_length = sum(len(word) for word in words)
            avg_word_length = total_word_length / word_count
        else:
            avg_word_length = 0.0
        
        # 9. URL count (find URLs in email body)
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        url_count = len(urls)
        
        return np.array([
            email_length,
            word_count,
            exclamation_count,
            has_urgency,
            has_financial,
            capital_ratio,
            special_ratio,
            avg_word_length,
            url_count
        ])
    
    def _build_feature_names(self):
        """Build list of all feature names."""
        tfidf_names = [f'tfidf_{word}' for word in self.tfidf_vectorizer.get_feature_names_out()]
        
        custom_names = [
            'email_length',
            'word_count',
            'exclamation_count',
            'has_urgency_words',
            'has_financial_words',
            'capital_ratio',
            'special_char_ratio',
            'avg_word_length',
            'url_count'
        ]
        
        self.feature_names_ = tfidf_names + custom_names
    
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
        if self.tfidf_vectorizer is None:
            raise ValueError("Cannot save unfitted transformer")
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save the entire object
        with open(path, 'wb') as f:
            pickle.dump(self, f)
        
        print(f"✓ TextFeatureExtractor saved to {path}")
    
    @classmethod
    def load(cls, path: Union[str, Path]) -> 'TextFeatureExtractor':
        """
        Load a fitted transformer from disk.
        
        Parameters:
        -----------
        path : str or Path
            Path to the saved transformer
            
        Returns:
        --------
        extractor : TextFeatureExtractor
            Loaded transformer
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"No transformer found at {path}")
        
        with open(path, 'rb') as f:
            extractor = pickle.load(f)
        
        print(f"✓ TextFeatureExtractor loaded from {path}")
        return extractor


# Example usage
if __name__ == "__main__":
    # Sample data
    sample_emails = [
        "URGENT! Your bank account has been suspended. Click here immediately to verify your password!",
        "Hi, just checking in about our meeting tomorrow. Let me know if you're still available.",
        "VERIFY YOUR ACCOUNT NOW!!! Your credit card will be charged unless you login immediately.",
        "Thanks for your email. I'll send you the report by end of day."
    ]
    
    # Create and fit the extractor
    extractor = TextFeatureExtractor(max_tfidf_features=100)
    features = extractor.fit_transform(sample_emails)
    
    print(f"Extracted feature matrix shape: {features.shape}")
    print(f"Number of features: {len(extractor.get_feature_names())}")
    print(f"\nCustom features for first email:")
    print(f"Email: {sample_emails[0][:50]}...")
    print(f"Features: {features[0, -9:]}")  # Last 9 features are custom features
    
    # Save and load example
    extractor.save("text_extractor.pkl")
    loaded_extractor = TextFeatureExtractor.load("text_extractor.pkl")
    print("\n✓ Save/load test successful!")
