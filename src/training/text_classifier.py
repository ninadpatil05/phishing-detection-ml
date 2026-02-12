"""
Text Classifier Module for Phishing Detection

This module provides TextClassifier class that trains and evaluates
machine learning models on text features for phishing detection.
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
from feature_engineering.text_features import TextFeatureExtractor


class TextClassifier:
    """
    Text-based phishing classifier using XGBoost and Random Forest.
    
    This classifier:
    1. Trains both XGBoost and Random Forest on text features
    2. Uses 5-fold cross-validation to compare performance
    3. Automatically selects the better performing model
    4. Evaluates on test set with comprehensive metrics
    5. Saves best model and metrics
    
    XGBoost vs Random Forest:
    -------------------------
    
    **XGBoost (Extreme Gradient Boosting)**:
    - Sequential ensemble: builds trees one at a time
    - Each tree corrects errors of previous trees
    - Uses gradient descent optimization
    - Generally more accurate but slower to train
    - Better at handling complex non-linear patterns
    - More prone to overfitting if not tuned properly
    - Excellent for structured/tabular data
    
    **Random Forest**:
    - Parallel ensemble: builds all trees independently
    - Each tree trained on random subset of data/features
    - Averages predictions from all trees
    - More robust and less prone to overfitting
    - Faster to train (can parallelize)
    - Simpler to tune (fewer hyperparameters)
    - Good baseline for classification tasks
    
    **Why one might win**:
    - XGBoost likely wins if: data has complex patterns, features interact 
      in non-linear ways, we need maximum accuracy
    - Random Forest likely wins if: data is noisy, features are redundant,
      we need robustness and speed
    
    For phishing detection:
    - XGBoost often performs better because phishing patterns are subtle
      and require capturing complex feature interactions
    - Random Forest is excellent baseline and may win if text features
      are highly discriminative on their own
    """
    
    def __init__(self, feature_extractor: Optional[TextFeatureExtractor] = None):
        """
        Initialize TextClassifier.
        
        Parameters:
        -----------
        feature_extractor : TextFeatureExtractor, optional
            Pre-fitted feature extractor. If None, a new one will be created.
        """
        self.feature_extractor = feature_extractor
        self.model = None
        self.model_name = None
        self.xgb_model = None
        self.rf_model = None
        self.cv_results = {}
        self.test_metrics = {}
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
            print("TRAINING TEXT CLASSIFIER")
            print("=" * 70)
        
        # Fit feature extractor if not already fitted
        if self.feature_extractor is None:
            if verbose:
                print("\n[1/4] Fitting TextFeatureExtractor...")
            self.feature_extractor = TextFeatureExtractor(max_tfidf_features=5000)
            X_train_features = self.feature_extractor.fit_transform(X_train)
        else:
            if verbose:
                print("\n[1/4] Using pre-fitted TextFeatureExtractor...")
            X_train_features = self.feature_extractor.transform(X_train)
        
        if verbose:
            print(f"      ✓ Extracted {X_train_features.shape[1]} features from {X_train_features.shape[0]} samples")
        
        # Initialize models
        if verbose:
            print("\n[2/4] Initializing models...")
        
        self.xgb_model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            use_label_encoder=False
        )
        
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
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
            print(f"      XGBoost    | F1: {xgb_mean_f1:.4f} (±{xgb_std_f1:.4f})")
        
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
        self.is_fitted_ = True
        
        if verbose:
            print("      ✓ Training complete!")
            print("=" * 70)
        
        return self.cv_results
    
    def evaluate(self, X_test: Union[pd.Series, np.ndarray], y_test: np.ndarray,
                 save_confusion_matrix: bool = True, 
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
        save_confusion_matrix : bool, default=True
            Whether to save confusion matrix plot
        output_dir : str, optional
            Directory to save confusion matrix (default: outputs/reports/)
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
            print("=" * 70)
        
        # Save confusion matrix plot
        if save_confusion_matrix:
            if output_dir is None:
                output_dir = "outputs/reports"
            self._plot_confusion_matrix(y_test, y_pred, output_dir)
        
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
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Safe', 'Phishing'],
                   yticklabels=['Safe', 'Phishing'],
                   cbar_kws={'label': 'Count'})
        plt.title(f'Confusion Matrix - {self.model_name.upper()}', fontsize=14, fontweight='bold')
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        
        # Save
        save_path = output_path / 'text_confusion_matrix.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"\n✓ Confusion matrix saved to {save_path}")
    
    def save(self, model_dir: Union[str, Path], metrics_path: Optional[Union[str, Path]] = None):
        """
        Save the trained model, feature extractor, and metrics.
        
        Parameters:
        -----------
        model_dir : str or Path
            Directory to save model files
        metrics_path : str or Path, optional
            Path to save metrics JSON (default: outputs/metrics/text_metrics.json)
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
        
        # Save metadata
        metadata = {
            'model_name': self.model_name,
            'n_features': len(self.feature_extractor.get_feature_names()),
            'cv_results': self.cv_results
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
                'test_set': self.test_metrics
            }
            
            with open(metrics_path, 'w') as f:
                json.dump(all_metrics, f, indent=2)
            print(f"✓ Metrics saved to {metrics_path}")
    
    @classmethod
    def load(cls, model_dir: Union[str, Path]) -> 'TextClassifier':
        """
        Load a trained model from disk.
        
        Parameters:
        -----------
        model_dir : str or Path
            Directory containing saved model files
            
        Returns:
        --------
        classifier : TextClassifier
            Loaded classifier
        """
        model_dir = Path(model_dir)
        
        if not model_dir.exists():
            raise FileNotFoundError(f"Model directory not found: {model_dir}")
        
        # Load feature extractor
        extractor_path = model_dir / 'feature_extractor.pkl'
        feature_extractor = TextFeatureExtractor.load(extractor_path)
        
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
        classifier.is_fitted_ = True
        
        print(f"✓ TextClassifier loaded successfully (model: {classifier.model_name})")
        
        return classifier


# Example usage
if __name__ == "__main__":
    print("Text Classifier Module for Phishing Detection")
    print("=" * 70)
    print("\nThis module requires training data to demonstrate.")
    print("Please use this class in your training pipeline with actual data.")
    print("\nExample usage:")
    print("""
    # Initialize classifier
    classifier = TextClassifier()
    
    # Train with cross-validation
    cv_results = classifier.train(X_train, y_train)
    
    # Evaluate on test set
    metrics = classifier.evaluate(X_test, y_test)
    
    # Save model and metrics
    classifier.save(
        model_dir='models/text_classifier/v1.0/',
        metrics_path='outputs/metrics/text_metrics.json'
    )
    
    # Load trained model
    loaded_classifier = TextClassifier.load('models/text_classifier/v1.0/')
    
    # Make predictions
    predictions = loaded_classifier.predict(new_emails)
    probabilities = loaded_classifier.predict_proba(new_emails)
    """)
