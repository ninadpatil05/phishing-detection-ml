"""
URL Classifier Module for Phishing Detection

This module provides URLClassifier class that trains and evaluates
machine learning models on URL features for phishing detection.
"""

import numpy as np
import pandas as pd
import pickle
import json
from pathlib import Path
from typing import Union, Dict, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ML libraries
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

# Plotting
import matplotlib.pyplot as plt
import seaborn as sns

# Custom imports
import sys
from pathlib import Path
# Add parent directory to path to import feature extractors
sys.path.append(str(Path(__file__).parent.parent))
from feature_engineering.url_features import URLFeatureExtractor


class URLClassifier:
    """
    URL-based phishing classifier using XGBoost and Random Forest.
    
    IMPORTANT: This classifier works with email text (not separate URL columns).
    URLs are extracted from email_text using URLFeatureExtractor.
    
    Key Features:
    -------------
    1. Trains both XGBoost and Random Forest on URL features
    2. Uses 5-fold cross-validation to compare performance
    3. Automatically selects the better performing model
    4. Handles emails with no URLs gracefully (has_url=0)
    5. Provides feature importance analysis
    6. Evaluates on test set with comprehensive metrics
    7. Saves best model and metrics
    
    Why Feature Importance Matters:
    --------------------------------
    Understanding which URL features are most predictive helps us:
    - Identify the strongest phishing indicators
    - Validate our feature engineering decisions
    - Explain model predictions to stakeholders
    - Focus detection efforts on key patterns
    
    Expected Top Important Features:
    ---------------------------------
    1. **has_ip_address** - Strongest indicator; legitimate sites use domains
    2. **url_entropy** - High randomness suggests generated malicious URLs
    3. **num_dots** - Excessive dots indicate subdomain spoofing
    4. **has_suspicious_keywords** - Keywords like 'login', 'verify' in URL
    5. **url_length** - Very long URLs often hide malicious intent
    6. **num_hyphens** - Multiple hyphens create fake convincing domains
    7. **has_https** - Absence indicates insecurity (though less reliable now)
    8. **num_special_chars** - @ symbol and query params for obfuscation
    9. **num_subdomains** - Excessive subdomains for false legitimacy
    10. **has_url** - Binary indicator if URL exists in email
    
    Target Accuracy: >82%
    Note: Lower than text classifier because many safe emails have no URLs
    """
    
    def __init__(self, feature_extractor: Optional[URLFeatureExtractor] = None):
        """
        Initialize URLClassifier.
        
        Parameters:
        -----------
        feature_extractor : URLFeatureExtractor, optional
            Pre-fitted feature extractor. If None, a new one will be created.
        """
        self.feature_extractor = feature_extractor
        self.model = None
        self.model_name = None
        self.xgb_model = None
        self.rf_model = None
        self.cv_results = {}
        self.test_metrics = {}
        self.feature_importance_ = None
        self.is_fitted_ = False
    
    def train(self, X_train: Union[pd.Series, np.ndarray], y_train: np.ndarray,
              n_folds: int = 5, verbose: bool = True) -> Dict:
        """
        Train both XGBoost and Random Forest models, compare with cross-validation,
        and select the best performer.
        
        Parameters:
        -----------
        X_train : pd.Series or np.ndarray
            Training email text data
        y_train : np.ndarray
            Training labels (0=safe, 1=phishing)
        n_folds : int, default=5
            Number of cross-validation folds
        verbose : bool, default=True
            Print training progress
            
        Returns:
        --------
        cv_results : dict
            Cross-validation results for both models
        """
        if verbose:
            print("=" * 70)
            print("TRAINING URL CLASSIFIER")
            print("=" * 70)
        
        # Fit feature extractor if not already fitted
        if self.feature_extractor is None:
            if verbose:
                print("\n[1/4] Fitting URLFeatureExtractor...")
            self.feature_extractor = URLFeatureExtractor()
            X_train_features = self.feature_extractor.fit_transform(X_train)
        else:
            if verbose:
                print("\n[1/4] Using pre-fitted URLFeatureExtractor...")
            X_train_features = self.feature_extractor.transform(X_train)
        
        if verbose:
            print(f"      ✓ Extracted {X_train_features.shape[1]} features from {X_train_features.shape[0]} samples")
            # Count emails with URLs
            has_url_count = int(X_train_features[:, -1].sum())
            no_url_count = len(X_train_features) - has_url_count
            print(f"      ✓ Emails with URLs: {has_url_count} ({has_url_count/len(X_train_features)*100:.1f}%)")
            print(f"      ✓ Emails without URLs: {no_url_count} ({no_url_count/len(X_train_features)*100:.1f}%)")
        
        # Initialize models
        if verbose:
            print("\n[2/4] Initializing models...")
        
        self.xgb_model = XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            use_label_encoder=False
        )
        
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        if verbose:
            print("      ✓ XGBoost initialized")
            print("      ✓ Random Forest initialized")
        
        # Cross-validation comparison
        if verbose:
            print(f"\n[3/4] Running {n_folds}-fold cross-validation...")
        
        cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
        
        # Evaluate XGBoost
        xgb_cv_scores = cross_val_score(
            self.xgb_model, X_train_features, y_train,
            cv=cv, scoring='f1', n_jobs=-1
        )
        xgb_mean_f1 = xgb_cv_scores.mean()
        xgb_std_f1 = xgb_cv_scores.std()
        
        if verbose:
            print(f"      XGBoost      | F1: {xgb_mean_f1:.4f} (±{xgb_std_f1:.4f})")
        
        # Evaluate Random Forest
        rf_cv_scores = cross_val_score(
            self.rf_model, X_train_features, y_train,
            cv=cv, scoring='f1', n_jobs=-1
        )
        rf_mean_f1 = rf_cv_scores.mean()
        rf_std_f1 = rf_cv_scores.std()
        
        if verbose:
            print(f"      RandomForest | F1: {rf_mean_f1:.4f} (±{rf_std_f1:.4f})")
        
        # Store CV results
        self.cv_results = {
            'xgboost': {
                'mean_f1': float(xgb_mean_f1),
                'std_f1': float(xgb_std_f1),
                'cv_scores': xgb_cv_scores.tolist()
            },
            'random_forest': {
                'mean_f1': float(rf_mean_f1),
                'std_f1': float(rf_std_f1),
                'cv_scores': rf_cv_scores.tolist()
            }
        }
        
        # Select best model
        if xgb_mean_f1 > rf_mean_f1:
            self.model = self.xgb_model
            self.model_name = 'xgboost'
            if verbose:
                print(f"\n      → Selected: XGBoost (better F1 score)")
        else:
            self.model = self.rf_model
            self.model_name = 'random_forest'
            if verbose:
                print(f"\n      → Selected: Random Forest (better F1 score)")
        
        # Train selected model on full training set
        if verbose:
            print(f"\n[4/4] Training final {self.model_name} model on full training set...")
        
        self.model.fit(X_train_features, y_train)
        
        # Extract feature importance
        self._extract_feature_importance()
        
        self.is_fitted_ = True
        
        if verbose:
            print("      ✓ Training complete!")
            print("=" * 70)
        
        return self.cv_results
    
    def _extract_feature_importance(self):
        """Extract and store feature importance from trained model."""
        if self.model is None:
            return
        
        # Get feature names
        feature_names = self.feature_extractor.get_feature_names()
        
        # Get importance scores based on model type
        if self.model_name == 'xgboost':
            importance_scores = self.model.feature_importances_
        elif self.model_name == 'random_forest':
            importance_scores = self.model.feature_importances_
        else:
            importance_scores = np.zeros(len(feature_names))
        
        # Create sorted list of (feature_name, importance_score)
        feature_importance_pairs = list(zip(feature_names, importance_scores))
        feature_importance_pairs.sort(key=lambda x: x[1], reverse=True)
        
        self.feature_importance_ = feature_importance_pairs
    
    def get_top_features(self, n: int = 10) -> list:
        """
        Get top N most important features.
        
        Parameters:
        -----------
        n : int, default=10
            Number of top features to return
            
        Returns:
        --------
        top_features : list of tuples
            List of (feature_name, importance_score) tuples
        """
        if self.feature_importance_ is None:
            raise ValueError("Model must be trained before getting feature importance")
        
        return self.feature_importance_[:n]
    
    def evaluate(self, X_test: Union[pd.Series, np.ndarray], y_test: np.ndarray,
                 save_plots: bool = True, 
                 output_dir: Optional[str] = None,
                 verbose: bool = True) -> Dict:
        """
        Evaluate the trained model on test set.
        
        Parameters:
        -----------
        X_test : pd.Series or np.ndarray
            Test email text data
        y_test : np.ndarray
            Test labels (0=safe, 1=phishing)
        save_plots : bool, default=True
            Whether to save confusion matrix and feature importance plots
        output_dir : str, optional
            Directory to save plots (default: outputs/reports/)
        verbose : bool, default=True
            Print evaluation results
            
        Returns:
        --------
        metrics : dict
            Dictionary of evaluation metrics
        """
        if not self.is_fitted_:
            raise ValueError("Model must be trained before evaluation")
        
        # Transform features
        X_test_features = self.feature_extractor.transform(X_test)
        
        # Make predictions
        y_pred = self.model.predict(X_test_features)
        y_pred_proba = self.model.predict_proba(X_test_features)[:, 1]
        
        # Calculate metrics
        self.test_metrics = {
            'model': self.model_name,
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1_score': float(f1_score(y_test, y_pred)),
            'roc_auc': float(roc_auc_score(y_test, y_pred_proba)),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }
        
        if verbose:
            print("\n" + "=" * 70)
            print("TEST SET EVALUATION RESULTS")
            print("=" * 70)
            print(f"Model: {self.model_name.upper()}")
            print(f"\nMetrics:")
            print(f"  Accuracy:  {self.test_metrics['accuracy']:.4f} ({self.test_metrics['accuracy']*100:.2f}%)")
            print(f"  Precision: {self.test_metrics['precision']:.4f}")
            print(f"  Recall:    {self.test_metrics['recall']:.4f}")
            print(f"  F1 Score:  {self.test_metrics['f1_score']:.4f}")
            print(f"  ROC-AUC:   {self.test_metrics['roc_auc']:.4f}")
            print(f"\nConfusion Matrix:")
            cm = np.array(self.test_metrics['confusion_matrix'])
            print(f"  TN: {cm[0,0]:4d}  |  FP: {cm[0,1]:4d}")
            print(f"  FN: {cm[1,0]:4d}  |  TP: {cm[1,1]:4d}")
            
            # Display top 10 features
            print(f"\n{'-' * 70}")
            print("TOP 10 MOST IMPORTANT URL FEATURES")
            print(f"{'-' * 70}")
            top_features = self.get_top_features(10)
            for i, (feature_name, importance) in enumerate(top_features, 1):
                print(f"  {i:2d}. {feature_name:30s} | Importance: {importance:.4f}")
            print("=" * 70)
        
        # Save plots
        if save_plots:
            if output_dir is None:
                output_dir = "outputs/reports"
            self._plot_confusion_matrix(y_test, y_pred, output_dir)
            self._plot_feature_importance(output_dir)
        
        return self.test_metrics
    
    def predict(self, X: Union[pd.Series, np.ndarray]) -> np.ndarray:
        """
        Predict class labels for samples.
        
        Parameters:
        -----------
        X : pd.Series or np.ndarray
            Email text data
            
        Returns:
        --------
        predictions : np.ndarray
            Predicted class labels (0=safe, 1=phishing)
        """
        if not self.is_fitted_:
            raise ValueError("Model must be trained before prediction")
        
        X_features = self.feature_extractor.transform(X)
        return self.model.predict(X_features)
    
    def predict_proba(self, X: Union[pd.Series, np.ndarray]) -> np.ndarray:
        """
        Predict class probabilities for samples.
        
        Parameters:
        -----------
        X : pd.Series or np.ndarray
            Email text data
            
        Returns:
        --------
        probabilities : np.ndarray
            Predicted probabilities for each class [P(safe), P(phishing)]
        """
        if not self.is_fitted_:
            raise ValueError("Model must be trained before prediction")
        
        X_features = self.feature_extractor.transform(X)
        return self.model.predict_proba(X_features)
    
    def _plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray, 
                               output_dir: str):
        """Plot and save confusion matrix."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Plot
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Greens', 
                   xticklabels=['Safe', 'Phishing'],
                   yticklabels=['Safe', 'Phishing'],
                   cbar_kws={'label': 'Count'})
        plt.title(f'URL Classifier Confusion Matrix - {self.model_name.upper()}', 
                 fontsize=14, fontweight='bold')
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        
        # Save
        save_path = output_path / 'url_confusion_matrix.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"\n✓ Confusion matrix saved to {save_path}")
    
    def _plot_feature_importance(self, output_dir: str, top_n: int = 10):
        """Plot and save feature importance bar chart."""
        if self.feature_importance_ is None:
            return
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Get top N features
        top_features = self.feature_importance_[:top_n]
        features, importances = zip(*top_features)
        
        # Create bar chart
        plt.figure(figsize=(10, 6))
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(features)))
        bars = plt.barh(range(len(features)), importances, color=colors)
        plt.yticks(range(len(features)), features)
        plt.xlabel('Importance Score', fontsize=12, fontweight='bold')
        plt.ylabel('URL Features', fontsize=12, fontweight='bold')
        plt.title(f'Top {top_n} Most Important URL Features - {self.model_name.upper()}', 
                 fontsize=14, fontweight='bold')
        plt.gca().invert_yaxis()  # Highest importance on top
        
        # Add value labels on bars
        for i, (bar, imp) in enumerate(zip(bars, importances)):
            plt.text(imp + 0.001, i, f'{imp:.4f}', 
                    va='center', fontsize=9)
        
        plt.tight_layout()
        
        # Save
        save_path = output_path / 'url_feature_importance.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✓ Feature importance chart saved to {save_path}")
    
    def save(self, model_dir: Union[str, Path], metrics_path: Optional[Union[str, Path]] = None):
        """
        Save the trained model, feature extractor, and metrics.
        
        Parameters:
        -----------
        model_dir : str or Path
            Directory to save model files
        metrics_path : str or Path, optional
            Path to save metrics JSON (default: outputs/metrics/url_metrics.json)
        """
        if not self.is_fitted_:
            raise ValueError("Cannot save unfitted model")
        
        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model
        model_path = model_dir / 'model.pkl'
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"✓ Model saved to {model_path}")
        
        # Save feature extractor
        extractor_path = model_dir / 'feature_extractor.pkl'
        self.feature_extractor.save(extractor_path)
        
        # Save metadata with feature importance
        metadata = {
            'model_name': self.model_name,
            'n_features': len(self.feature_extractor.get_feature_names()),
            'cv_results': self.cv_results,
            'feature_importance': [
                {'feature': feat, 'importance': float(imp)} 
                for feat, imp in self.feature_importance_
            ]
        }
        metadata_path = model_dir / 'metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Metadata saved to {metadata_path}")
        
        # Save metrics if test metrics available
        if self.test_metrics and metrics_path:
            metrics_path = Path(metrics_path)
            metrics_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Combine CV and test metrics
            all_metrics = {
                'model': self.model_name,
                'cross_validation': self.cv_results,
                'test_set': self.test_metrics,
                'top_10_features': [
                    {'feature': feat, 'importance': float(imp)}
                    for feat, imp in self.feature_importance_[:10]
                ]
            }
            
            with open(metrics_path, 'w') as f:
                json.dump(all_metrics, f, indent=2)
            print(f"✓ Metrics saved to {metrics_path}")
    
    @classmethod
    def load(cls, model_dir: Union[str, Path]) -> 'URLClassifier':
        """
        Load a trained model from disk.
        
        Parameters:
        -----------
        model_dir : str or Path
            Directory containing saved model files
            
        Returns:
        --------
        classifier : URLClassifier
            Loaded classifier
        """
        model_dir = Path(model_dir)
        
        if not model_dir.exists():
            raise FileNotFoundError(f"Model directory not found: {model_dir}")
        
        # Load feature extractor
        extractor_path = model_dir / 'feature_extractor.pkl'
        feature_extractor = URLFeatureExtractor.load(extractor_path)
        
        # Load model
        model_path = model_dir / 'model.pkl'
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        print(f"✓ Model loaded from {model_path}")
        
        # Load metadata
        metadata_path = model_dir / 'metadata.json'
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Create classifier instance
        classifier = cls(feature_extractor=feature_extractor)
        classifier.model = model
        classifier.model_name = metadata['model_name']
        classifier.cv_results = metadata['cv_results']
        classifier.feature_importance_ = [
            (item['feature'], item['importance']) 
            for item in metadata['feature_importance']
        ]
        classifier.is_fitted_ = True
        
        print(f"✓ URLClassifier loaded successfully (model: {classifier.model_name})")
        
        return classifier


# Example usage
if __name__ == "__main__":
    print("URL Classifier Module for Phishing Detection")
    print("=" * 70)
    print("\nThis module requires training data to demonstrate.")
    print("Please use this class in your training pipeline with actual data.")
    print("\nExample usage:")
    print("""
    # Initialize classifier
    classifier = URLClassifier()
    
    # Train with cross-validation
    cv_results = classifier.train(X_train, y_train)
    
    # Evaluate on test set (with feature importance analysis)
    metrics = classifier.evaluate(X_test, y_test)
    
    # Get top features
    top_features = classifier.get_top_features(n=10)
    
    # Save model and metrics
    classifier.save(
        model_dir='models/url_classifier/v1.0/',
        metrics_path='outputs/metrics/url_metrics.json'
    )
    
    # Load trained model
    loaded_classifier = URLClassifier.load('models/url_classifier/v1.0/')
    
    # Make predictions
    predictions = loaded_classifier.predict(new_emails)
    probabilities = loaded_classifier.predict_proba(new_emails)
    """)
