"""
Explainability Module for Phishing Detection

This module provides PhishingExplainer class that uses SHAP (SHapley Additive exPlanations)
to explain model predictions in human-readable terms.
"""

import numpy as np
import pandas as pd
import shap
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Union, Dict, List, Optional, Tuple

# Custom imports
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from training.text_classifier import TextClassifier
from training.url_classifier import URLClassifier
from training.ensemble import EnsembleModel


class PhishingExplainer:
    """
    SHAP-based explainer for phishing detection models.
    
    What are SHAP Values? (Plain English)
    --------------------------------------
    Imagine you're on a sports team, and you win a game. SHAP values tell you
    how much each player contributed to the win (or loss).
    
    In our case:
    - The "game" is whether an email is phishing or safe
    - The "players" are features (urgency words, URL length, etc.)
    - SHAP values tell us which features pushed the prediction toward phishing
      and which ones pushed it toward safe
    
    Example:
    - Email has urgency words: +0.15 (pushes toward phishing)
    - Email has HTTPS: -0.05 (pushes toward safe)
    - High URL entropy: +0.20 (pushes toward phishing)
    - Final prediction: 0.75 (phishing)
    
    SHAP values are:
    ✓ Additive: They sum up to explain the final prediction
    ✓ Fair: Based on game theory (Shapley values)
    ✓ Local: Explain individual predictions, not general patterns
    ✓ Consistent: Similar features get similar importance
    
    How to Read SHAP Values:
    ------------------------
    - Positive SHAP value (+): Feature pushes toward PHISHING
    - Negative SHAP value (-): Feature pushes toward SAFE
    - Larger magnitude: Stronger influence on prediction
    
    Example:
    Feature: "has_urgency_words" with SHAP value +0.25
    → This feature STRONGLY pushes prediction toward phishing
    
    Feature: "has_https" with SHAP value -0.10
    → This feature moderately pushes prediction toward safe
    """
    
    def __init__(self,
                 text_classifier: Optional[TextClassifier] = None,
                 url_classifier: Optional[URLClassifier] = None,
                 ensemble: Optional[EnsembleModel] = None):
        """
        Initialize PhishingExplainer.
        
        Parameters:
        -----------
        text_classifier : TextClassifier, optional
            Trained text classifier
        url_classifier : URLClassifier, optional
            Trained URL classifier
        ensemble : EnsembleModel, optional
            Trained ensemble model
        """
        self.text_classifier = text_classifier
        self.url_classifier = url_classifier
        self.ensemble = ensemble
        
        # SHAP explainers (initialized on first use)
        self._text_explainer = None
        self._url_explainer = None
    
    def _get_text_explainer(self):
        """Lazy initialization of text classifier SHAP explainer."""
        if self._text_explainer is None and self.text_classifier is not None:
            # Create a wrapper function for SHAP
            def text_predict_fn(X):
                return self.text_classifier.model.predict_proba(X)[:, 1]
            
            # Use TreeExplainer for tree-based models (XGBoost, RandomForest)
            self._text_explainer = shap.TreeExplainer(self.text_classifier.model)
        
        return self._text_explainer
    
    def _get_url_explainer(self):
        """Lazy initialization of URL classifier SHAP explainer."""
        if self._url_explainer is None and self.url_classifier is not None:
            # Use TreeExplainer for tree-based models
            self._url_explainer = shap.TreeExplainer(self.url_classifier.model)
        
        return self._url_explainer
    
    def explain_text(self, email_text: Union[str, List[str]], 
                    save_plot: bool = True,
                    output_dir: str = "outputs/reports/") -> Dict:
        """
        Explain text classifier prediction using SHAP.
        
        Parameters:
        -----------
        email_text : str or list of str
            Email text to explain (single email or batch)
        save_plot : bool, default=True
            Whether to save SHAP waterfall plot
        output_dir : str, default="outputs/reports/"
            Directory to save plots
            
        Returns:
        --------
        explanation : dict
            Dictionary containing:
            - 'shap_values': SHAP values for each feature
            - 'feature_names': Names of features
            - 'top_positive': Top 5 features pushing toward phishing
            - 'top_negative': Top 5 features pushing toward safe
            - 'base_value': Model's base prediction
            - 'prediction': Final prediction probability
        """
        if self.text_classifier is None:
            raise ValueError("Text classifier not loaded")
        
        # Convert to list if single string
        if isinstance(email_text, str):
            email_text = [email_text]
            single_input = True
        else:
            single_input = False
        
        # Extract features
        X_features = self.text_classifier.feature_extractor.transform(email_text)
        
        # Get SHAP explainer
        explainer = self._get_text_explainer()
        
        # Calculate SHAP values
        shap_values = explainer.shap_values(X_features)
        
        # For single input, get first sample
        if single_input:
            shap_vals = shap_values[0] if len(shap_values.shape) > 1 else shap_values
            features = X_features[0]
            
            # Get feature names
            feature_names = self.text_classifier.feature_extractor.get_feature_names()
            
            # Get top positive and negative features
            top_positive, top_negative = self._get_top_features(shap_vals, feature_names)
            
            # Get prediction
            prediction = self.text_classifier.model.predict_proba(X_features)[0, 1]
            
            # Save waterfall plot
            if save_plot:
                self._save_waterfall_plot(
                    shap_vals, features, feature_names,
                    f"{output_dir}/text_shap_waterfall.png",
                    "Text Features"
                )
            
            return {
                'shap_values': shap_vals.tolist(),
                'feature_names': feature_names,
                'top_positive': top_positive,
                'top_negative': top_negative,
                'base_value': float(explainer.expected_value),
                'prediction': float(prediction)
            }
        else:
            # Batch processing
            return {
                'shap_values': shap_values.tolist(),
                'feature_names': self.text_classifier.feature_extractor.get_feature_names(),
                'base_value': float(explainer.expected_value)
            }
    
    def explain_url_features(self, email_text: Union[str, List[str]],
                            save_plot: bool = True,
                            output_dir: str = "outputs/reports/") -> Dict:
        """
        Explain URL classifier prediction using SHAP.
        
        Parameters:
        -----------
        email_text : str or list of str
            Email text to explain (URLs extracted automatically)
        save_plot : bool, default=True
            Whether to save SHAP waterfall plot
        output_dir : str, default="outputs/reports/"
            Directory to save plots
            
        Returns:
        --------
        explanation : dict
            Dictionary containing SHAP analysis for URL features
        """
        if self.url_classifier is None:
            raise ValueError("URL classifier not loaded")
        
        # Convert to list if single string
        if isinstance(email_text, str):
            email_text = [email_text]
            single_input = True
        else:
            single_input = False
        
        # Extract URL features
        X_features = self.url_classifier.feature_extractor.transform(email_text)
        
        # Get SHAP explainer
        explainer = self._get_url_explainer()
        
        # Calculate SHAP values
        shap_values = explainer.shap_values(X_features)
        
        # For single input
        if single_input:
            shap_vals = shap_values[0] if len(shap_values.shape) > 1 else shap_values
            features = X_features[0]
            
            # Get feature names
            feature_names = self.url_classifier.feature_extractor.get_feature_names()
            
            # Get top positive and negative features
            top_positive, top_negative = self._get_top_features(shap_vals, feature_names)
            
            # Get prediction
            prediction = self.url_classifier.model.predict_proba(X_features)[0, 1]
            
            # Save waterfall plot
            if save_plot:
                self._save_waterfall_plot(
                    shap_vals, features, feature_names,
                    f"{output_dir}/url_shap_waterfall.png",
                    "URL Features"
                )
            
            return {
                'shap_values': shap_vals.tolist(),
                'feature_names': feature_names,
                'top_positive': top_positive,
                'top_negative': top_negative,
                'base_value': float(explainer.expected_value),
                'prediction': float(prediction)
            }
        else:
            return {
                'shap_values': shap_values.tolist(),
                'feature_names': self.url_classifier.feature_extractor.get_feature_names(),
                'base_value': float(explainer.expected_value)
            }
    
    def explain_combined(self, email_text: str,
                        save_plot: bool = True,
                        output_dir: str = "outputs/reports/") -> Dict:
        """
        Explain predictions from both text and URL classifiers.
        
        Parameters:
        -----------
        email_text : str
            Email text to explain
        save_plot : bool, default=True
            Whether to save SHAP plots
        output_dir : str, default="outputs/reports/"
            Directory to save plots
            
        Returns:
        --------
        combined_explanation : dict
            Dictionary containing explanations from both models
        """
        text_explanation = self.explain_text(email_text, save_plot, output_dir)
        url_explanation = self.explain_url_features(email_text, save_plot, output_dir)
        
        # Get ensemble prediction if available
        ensemble_pred = None
        if self.ensemble is not None:
            ensemble_pred = float(self.ensemble.predict_proba([email_text])[0, 1])
        
        return {
            'text_explanation': text_explanation,
            'url_explanation': url_explanation,
            'ensemble_prediction': ensemble_pred
        }
    
    def get_risk_factors(self, email_text: str) -> Dict:
        """
        Get human-readable risk factors for an email.
        
        Parameters:
        -----------
        email_text : str
            Email text to analyze
            
        Returns:
        --------
        risk_report : dict
            Dictionary containing:
            - 'risk_score': Overall phishing probability (0-1)
            - 'verdict': "SAFE" or "PHISHING"
            - 'confidence': "LOW", "MEDIUM", or "HIGH"
            - 'top_reasons': List of human-readable risk factors
        """
        # Get predictions and explanations
        if self.ensemble is not None:
            risk_score = float(self.ensemble.predict_proba([email_text])[0, 1])
        elif self.text_classifier is not None:
            risk_score = float(self.text_classifier.predict_proba([email_text])[0, 1])
        else:
            raise ValueError("No classifier loaded")
        
        # Get SHAP explanations
        text_exp = self.explain_text(email_text, save_plot=False)
        url_exp = self.explain_url_features(email_text, save_plot=False)
        
        # Determine verdict
        verdict = "PHISHING" if risk_score >= 0.5 else "SAFE"
        
        # Determine confidence
        if risk_score >= 0.8 or risk_score <= 0.2:
            confidence = "HIGH"
        elif risk_score >= 0.6 or risk_score <= 0.4:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        # Generate human-readable reasons
        reasons = []
        
        # Text features reasons
        for feat_name, shap_val in text_exp['top_positive'][:3]:
            reason = self._feature_to_reason(feat_name, shap_val, "text")
            if reason:
                reasons.append(reason)
        
        # URL features reasons
        for feat_name, shap_val in url_exp['top_positive'][:3]:
            reason = self._feature_to_reason(feat_name, shap_val, "url")
            if reason:
                reasons.append(reason)
        
        # Limit to top reasons
        reasons = reasons[:5]
        
        return {
            'risk_score': float(risk_score),
            'verdict': verdict,
            'confidence': confidence,
            'top_reasons': reasons if reasons else ["No significant risk factors detected"]
        }
    
    def _get_top_features(self, shap_values: np.ndarray, 
                         feature_names: List[str],
                         top_n: int = 5) -> Tuple[List, List]:
        """Get top N positive and negative features by SHAP value."""
        # Create feature-value pairs
        feature_pairs = list(zip(feature_names, shap_values))
        
        # Sort by SHAP value
        sorted_pairs = sorted(feature_pairs, key=lambda x: x[1], reverse=True)
        
        # Top positive (toward phishing)
        top_positive = [(name, float(val)) for name, val in sorted_pairs[:top_n] if val > 0]
        
        # Top negative (toward safe)
        top_negative = [(name, float(val)) for name, val in sorted_pairs[-top_n:] if val < 0]
        top_negative.reverse()  # Most negative first
        
        return top_positive, top_negative
    
    def _feature_to_reason(self, feature_name: str, shap_value: float, 
                          feature_type: str) -> Optional[str]:
        """Convert technical feature name to human-readable reason."""
        # Text features
        if feature_type == "text":
            if "has_urgency" in feature_name:
                return "Contains urgency words (verify, suspend, click, immediately)"
            elif "has_financial" in feature_name:
                return "Contains financial keywords (bank, account, password, login)"
            elif "exclamation" in feature_name:
                return "Excessive exclamation marks indicating urgency"
            elif "capital_ratio" in feature_name:
                return "Unusually high capital letter ratio (SHOUTING)"
            elif "special_char_ratio" in feature_name:
                return "High special character ratio"
            elif "url_count" in feature_name:
                return "Multiple URLs found in email body"
            elif shap_value > 0.1:  # Only include significant TF-IDF terms
                # Extract word from tfidf_xxx
                if feature_name.startswith("tfidf_"):
                    word = feature_name.replace("tfidf_", "")
                    return f"Contains suspicious word: '{word}'"
        
        # URL features
        elif feature_type == "url":
            if "has_ip_address" in feature_name:
                return "URL uses IP address instead of domain name"
            elif "url_entropy" in feature_name:
                return "URL contains random/generated characters"
            elif "num_dots" in feature_name:
                return "Excessive dots in URL (subdomain manipulation)"
            elif "has_suspicious_keywords" in feature_name:
                return "Suspicious keywords in URL (login, verify, account)"
            elif "url_length" in feature_name:
                return "Unusually long URL (hiding malicious intent)"
            elif "num_hyphens" in feature_name:
                return "Multiple hyphens in URL (fake domain)"
            elif "has_https" in feature_name and shap_value < 0:
                return "URL uses HTTPS (secure connection)"
            elif "num_subdomains" in feature_name:
                return "Excessive subdomains creating false legitimacy"
        
        return None
    
    def _save_waterfall_plot(self, shap_values: np.ndarray, 
                            features: np.ndarray,
                            feature_names: List[str],
                            save_path: str,
                            title: str):
        """Save SHAP waterfall plot."""
        output_path = Path(save_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create explanation object for waterfall plot
        # Note: For TreeExplainer, we need to create an Explanation object
        base_value = self._get_text_explainer().expected_value if "text" in save_path.lower() else self._get_url_explainer().expected_value
        
        explanation = shap.Explanation(
            values=shap_values,
            base_values=base_value,
            data=features,
            feature_names=feature_names
        )
        
        # Create waterfall plot
        plt.figure(figsize=(10, 8))
        shap.waterfall_plot(explanation, max_display=15, show=False)
        plt.title(f"SHAP Explanation - {title}", fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✓ SHAP waterfall plot saved to {save_path}")


# Example usage
if __name__ == "__main__":
    print("Phishing Explainability Module")
    print("=" * 70)
    print("\nThis module requires trained classifiers to demonstrate.")
    print("Please use this class with actual trained models.")
    print("\nExample usage:")
    print("""
    # Load models
    text_clf = TextClassifier.load('models/text_classifier/v1.0/')
    url_clf = URLClassifier.load('models/url_classifier/v1.0/')
    ensemble = EnsembleModel.load('models/ensemble/v1.0/')
    
    # Create explainer
    explainer = PhishingExplainer(
        text_classifier=text_clf,
        url_classifier=url_clf,
        ensemble=ensemble
    )
    
    # Explain a prediction
    email = "URGENT! Your account suspended. Click http://192.168.1.1/verify now!"
    
    # Get risk factors (human-readable)
    risk_report = explainer.get_risk_factors(email)
    print(f"Risk Score: {risk_report['risk_score']:.2f}")
    print(f"Verdict: {risk_report['verdict']}")
    print(f"Confidence: {risk_report['confidence']}")
    print("Top Reasons:")
    for reason in risk_report['top_reasons']:
        print(f"  - {reason}")
    
    # Get detailed SHAP explanations
    text_exp = explainer.explain_text(email)
    print(f"\\nTop features pushing toward PHISHING:")
    for feat, val in text_exp['top_positive']:
        print(f"  {feat}: +{val:.4f}")
    
    # Combined explanation
    combined = explainer.explain_combined(email)
    """)
