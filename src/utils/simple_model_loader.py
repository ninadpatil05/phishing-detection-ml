"""
Simple Model Loader for API

This loads the test models created by quick_test_setup.py
"""

import pickle
import json
from pathlib import Path
import numpy as np

class SimpleTextClassifier:
    """Simple wrapper for test text classifier"""
    def __init__(self, model_path):
        with open(model_path / "model.pkl", "rb") as f:
            self.model = pickle.load(f)
        with open(model_path / "vectorizer.pkl", "rb") as f:
            self.vectorizer = pickle.load(f)
    
    def predict_proba(self, texts):
        """Predict probabilities"""
        if isinstance(texts, str):
            texts = [texts]
        features = self.vectorizer.transform(texts)
        return self.model.predict_proba(features)
    
    def predict(self, texts):
        """Predict labels"""
        if isinstance(texts, str):
            texts = [texts]
        features = self.vectorizer.transform(texts)
        return self.model.predict(features)


class SimpleURLClassifier:
    """Simple wrapper for test URL classifier"""
    def __init__(self, model_path):
        with open(model_path / "model.pkl", "rb") as f:
            self.model = pickle.load(f)
    
    def predict_proba(self, texts):
        """Predict probabilities with random features"""
        if isinstance(texts, str):
            texts = [texts]
        # Generate random URL features (14 features)
        features = np.random.rand(len(texts), 14)
        return self.model.predict_proba(features)
    
    def predict(self, texts):
        """Predict labels"""
        if isinstance(texts, str):
            texts = [texts]
        features = np.random.rand(len(texts), 14)
        return self.model.predict(features)


class SimpleEnsemble:
    """Simple ensemble that combines text and URL classifiers"""
    def __init__(self, text_classifier, url_classifier, config_path):
        self.text_classifier = text_classifier
        self.url_classifier = url_classifier
        
        # Load config
        with open(config_path / "ensemble_config.json", "r") as f:
            config = json.load(f)
        
        self.text_weight = config.get("text_weight", 0.6)
        self.url_weight = config.get("url_weight", 0.4)
        self.threshold = config.get("threshold", 0.5)
    
    def predict_proba(self, texts):
        """Predict probabilities using weighted average"""
        text_proba = self.text_classifier.predict_proba(texts)
        url_proba = self.url_classifier.predict_proba(texts)
        
        # Weighted average
        ensemble_proba = (self.text_weight * text_proba + 
                         self.url_weight * url_proba)
        return ensemble_proba
    
    def predict(self, texts):
        """Predict labels"""
        proba = self.predict_proba(texts)
        return (proba[:, 1] >= self.threshold).astype(int)
    
    def get_individual_scores(self, texts):
        """Get individual model scores"""
        text_proba = self.text_classifier.predict_proba(texts)
        url_proba = self.url_classifier.predict_proba(texts)
        ensemble_proba = self.predict_proba(texts)
        
        return {
            'text_score': float(text_proba[0][1]),
            'url_score': float(url_proba[0][1]),
            'ensemble_score': float(ensemble_proba[0][1])
        }


def load_simple_models():
    """Load simple test models"""
    text_path = Path("models/text_classifier/v1.0")
    url_path = Path("models/url_classifier/v1.0")
    ensemble_path = Path("models/ensemble/v1.0")
    
    text_classifier = SimpleTextClassifier(text_path)
    url_classifier = SimpleURLClassifier(url_path)
    ensemble = SimpleEnsemble(text_classifier, url_classifier, ensemble_path)
    
    return text_classifier, url_classifier, ensemble


if __name__ == "__main__":
    # Test loading
    print("Testing model loading...")
    text_clf, url_clf, ensemble = load_simple_models()
    
    test_email = "URGENT! Click http://phishing.com"
    result = ensemble.get_individual_scores([test_email])
    
    print(f"Text score: {result['text_score']:.3f}")
    print(f"URL score: {result['url_score']:.3f}")
    print(f"Ensemble score: {result['ensemble_score']:.3f}")
    print("\nModels loaded successfully!")
