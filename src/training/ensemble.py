"""
Ensemble Model for Phishing Detection

This module provides EnsembleModel class that combines TextClassifier
and URLClassifier predictions using weighted averaging for improved accuracy.
"""

import numpy as np
import pandas as pd
import pickle
import json
from pathlib import Path
from typing import Union, Dict, Tuple, List, Optional

# Custom imports
import sys
from pathlib import Path
# Add parent directory to path to import classifiers
sys.path.append(str(Path(__file__).parent.parent))
from training.text_classifier import TextClassifier
from training.url_classifier import URLClassifier


class EnsembleModel:
    """
    Ensemble phishing classifier combining text and URL predictions.
    
    How It Works:
    -------------
    1. Takes email_text as input (single source)
    2. TextClassifier extracts text features → text probability
    3. URLClassifier extracts URL features → URL probability
    4. Combines using weighted average: final_score = (text_prob × 0.6) + (url_prob × 0.4)
    5. Classifies as phishing if final_score ≥ 0.5
    
    What is Weighted Average (Plain English):
    -----------------------------------------
    Think of it as asking two experts for their opinion, but trusting one more than the other.
    
    Example:
    - Text expert says: "70% sure it's phishing"
    - URL expert says: "40% sure it's phishing"
    - We trust text expert more (60% weight) and URL expert less (40% weight)
    - Final decision = (70% × 0.6) + (40% × 0.4) = 42% + 16% = 58% → PHISHING ✓
    
    Without weighting (simple average):
    - (70% + 40%) ÷ 2 = 55% → still phishing, but less confident
    
    Weighted averaging lets us give MORE influence to the more reliable expert.
    
    Why 0.6/0.4 Weighting Was Chosen:
    ----------------------------------
    1. **Text features are more universal**
       - Every email has text content
       - Rich features: TF-IDF + 9 custom features (5009 total)
       - Higher target accuracy (>88%)
    
    2. **URL features are more specific**
       - Not all emails contain URLs (~40-60% do)
       - Fewer features: 15 URL features only
       - Lower target accuracy (>82%)
       - More prone to missing data
    
    3. **Empirical reasoning**
       - Text classifier expected to perform better overall
       - URL features provide strong signal WHEN present
       - 60/40 split balances reliability vs. specificity
    
    4. **Conservative approach**
       - Gives primary weight to more robust model
       - URL features still contribute meaningfully (40% is significant)
       - Better than ignoring URL features entirely
    
    Alternative weightings could be:
    - 0.7/0.3 → Even more conservative, trust text heavily
    - 0.5/0.5 → Equal trust (but ignores performance difference)
    - Dynamic weighting → Adjust based on has_url flag (future improvement)
    
    Why Ensemble Typically Beats Individual Models:
    ------------------------------------------------
    - **Complementary strengths**: Text catches one type of phishing, URLs catch another
    - **Reduced errors**: If one model misses, the other might catch it
    - **Balanced decision**: Combines different types of evidence
    - **Improved confidence**: More signals = better predictions
    
    Expected Performance:
    ---------------------
    - Ensemble accuracy: **>90%** (beats both individual models)
    - More robust to edge cases
    - Better precision and recall balance
    """
    
    def __init__(self, 
                 text_classifier: Optional[TextClassifier] = None,
                 url_classifier: Optional[URLClassifier] = None,
                 text_weight: float = 0.6,
                 url_weight: float = 0.4,
                 threshold: float = 0.5):
        """
        Initialize EnsembleModel.
        
        Parameters:
        -----------
        text_classifier : TextClassifier, optional
            Pre-loaded text classifier
        url_classifier : URLClassifier, optional
            Pre-loaded URL classifier
        text_weight : float, default=0.6
            Weight for text classifier predictions
        url_weight : float, default=0.4
            Weight for URL classifier predictions
        threshold : float, default=0.5
            Classification threshold
        """
        self.text_classifier = text_classifier
        self.url_classifier = url_classifier
        self.text_weight = text_weight
        self.url_weight = url_weight
        self.threshold = threshold
        
        # Validate weights sum to 1.0
        if not np.isclose(text_weight + url_weight, 1.0):
            raise ValueError(f"Weights must sum to 1.0, got {text_weight + url_weight}")
    
    def predict(self, X: Union[pd.Series, np.ndarray, List[str]]) -> np.ndarray:
        """
        Predict class labels using ensemble.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
            
        Returns:
        --------
        predictions : np.ndarray
            Predicted class labels (0=safe, 1=phishing)
        """
        probabilities = self.predict_proba(X)
        # Get phishing probability (class 1)
        phishing_probs = probabilities[:, 1]
        # Apply threshold
        return (phishing_probs >= self.threshold).astype(int)
    
    def predict_proba(self, X: Union[pd.Series, np.ndarray, List[str]]) -> np.ndarray:
        """
        Predict class probabilities using weighted ensemble.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
            
        Returns:
        --------
        probabilities : np.ndarray
            Predicted probabilities for each class [P(safe), P(phishing)]
        """
        if self.text_classifier is None or self.url_classifier is None:
            raise ValueError("Both classifiers must be loaded before prediction")
        
        # Get predictions from both classifiers
        text_probs = self.text_classifier.predict_proba(X)
        url_probs = self.url_classifier.predict_proba(X)
        
        # Weighted average
        ensemble_probs = (text_probs * self.text_weight) + (url_probs * self.url_weight)
        
        return ensemble_probs
    
    def get_individual_scores(self, X: Union[pd.Series, np.ndarray, List[str]]) -> Dict[str, np.ndarray]:
        """
        Get individual scores from each classifier plus ensemble.
        
        Parameters:
        -----------
        X : pd.Series, np.ndarray, or list of str
            Email text data
            
        Returns:
        --------
        scores : dict
            Dictionary containing:
            - 'text_probs': Text classifier probabilities
            - 'url_probs': URL classifier probabilities
            - 'ensemble_probs': Ensemble probabilities
            - 'text_preds': Text classifier predictions
            - 'url_preds': URL classifier predictions
            - 'ensemble_preds': Ensemble predictions
        """
        if self.text_classifier is None or self.url_classifier is None:
            raise ValueError("Both classifiers must be loaded before prediction")
        
        # Get probabilities
        text_probs = self.text_classifier.predict_proba(X)
        url_probs = self.url_classifier.predict_proba(X)
        ensemble_probs = self.predict_proba(X)
        
        # Get predictions
        text_preds = self.text_classifier.predict(X)
        url_preds = self.url_classifier.predict(X)
        ensemble_preds = self.predict(X)
        
        return {
            'text_probs': text_probs,
            'url_probs': url_probs,
            'ensemble_probs': ensemble_probs,
            'text_preds': text_preds,
            'url_preds': url_preds,
            'ensemble_preds': ensemble_preds
        }
    
    def evaluate(self, X_test: Union[pd.Series, np.ndarray], y_test: np.ndarray,
                 save_comparison: bool = True,
                 comparison_path: Optional[str] = None,
                 verbose: bool = True) -> Dict:
        """
        Evaluate ensemble and compare with individual models.
        
        Parameters:
        -----------
        X_test : pd.Series or np.ndarray
            Test email text data
        y_test : np.ndarray
            Test labels (0=safe, 1=phishing)
        save_comparison : bool, default=True
            Whether to save comparison results
        comparison_path : str, optional
            Path to save comparison JSON
        verbose : bool, default=True
            Print comparison table
            
        Returns:
        --------
        comparison : dict
            Comparison metrics for all three models
        """
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
        
        # Get predictions from all models
        text_preds = self.text_classifier.predict(X_test)
        text_probs = self.text_classifier.predict_proba(X_test)[:, 1]
        
        url_preds = self.url_classifier.predict(X_test)
        url_probs = self.url_classifier.predict_proba(X_test)[:, 1]
        
        ensemble_preds = self.predict(X_test)
        ensemble_probs = self.predict_proba(X_test)[:, 1]
        
        # Calculate metrics for each model
        def compute_metrics(y_true, y_pred, y_prob):
            return {
                'accuracy': float(accuracy_score(y_true, y_pred)),
                'precision': float(precision_score(y_true, y_pred)),
                'recall': float(recall_score(y_true, y_pred)),
                'f1_score': float(f1_score(y_true, y_pred)),
                'roc_auc': float(roc_auc_score(y_true, y_prob))
            }
        
        text_metrics = compute_metrics(y_test, text_preds, text_probs)
        url_metrics = compute_metrics(y_test, url_preds, url_probs)
        ensemble_metrics = compute_metrics(y_test, ensemble_preds, ensemble_probs)
        
        comparison = {
            'text_classifier': text_metrics,
            'url_classifier': url_metrics,
            'ensemble': ensemble_metrics,
            'weights': {
                'text_weight': self.text_weight,
                'url_weight': self.url_weight
            }
        }
        
        if verbose:
            print("\n" + "=" * 80)
            print("ENSEMBLE MODEL COMPARISON")
            print("=" * 80)
            print(f"\nWeights: Text={self.text_weight:.1f}, URL={self.url_weight:.1f}, Threshold={self.threshold:.2f}")
            print("\n" + "-" * 80)
            print(f"{'Metric':<15} | {'Text Classifier':>15} | {'URL Classifier':>15} | {'Ensemble':>15} | {'Winner':>10}")
            print("-" * 80)
            
            metrics_list = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
            metric_names = ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'ROC-AUC']
            
            for metric, name in zip(metrics_list, metric_names):
                text_val = text_metrics[metric]
                url_val = url_metrics[metric]
                ens_val = ensemble_metrics[metric]
                
                # Determine winner
                max_val = max(text_val, url_val, ens_val)
                if ens_val == max_val:
                    winner = "ENSEMBLE"
                elif text_val == max_val:
                    winner = "Text"
                else:
                    winner = "URL"
                
                print(f"{name:<15} | {text_val:>15.4f} | {url_val:>15.4f} | {ens_val:>15.4f} | {winner:>10}")
            
            print("-" * 80)
            
            # Calculate improvements
            text_acc = text_metrics['accuracy']
            url_acc = url_metrics['accuracy']
            ens_acc = ensemble_metrics['accuracy']
            best_individual = max(text_acc, url_acc)
            
            if ens_acc > best_individual:
                improvement = ((ens_acc - best_individual) / best_individual) * 100
                print(f"\n✓ Ensemble beats best individual model by {improvement:.2f}%")
                print(f"✓ Ensemble accuracy: {ens_acc*100:.2f}% vs Best individual: {best_individual*100:.2f}%")
            else:
                print(f"\n⚠ Note: Best individual model performs slightly better")
            
            print("=" * 80)
        
        # Save comparison
        if save_comparison:
            if comparison_path is None:
                comparison_path = "outputs/reports/ensemble_comparison.json"
            
            comp_path = Path(comparison_path)
            comp_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(comp_path, 'w') as f:
                json.dump(comparison, f, indent=2)
            
            print(f"\n✓ Comparison saved to {comp_path}")
        
        return comparison
    
    def save(self, model_dir: Union[str, Path]):
        """
        Save ensemble configuration.
        
        Note: Individual classifiers should already be saved.
        This only saves the ensemble configuration (weights, threshold).
        
        Parameters:
        -----------
        model_dir : str or Path
            Directory to save ensemble configuration
        """
        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        
        config = {
            'text_weight': self.text_weight,
            'url_weight': self.url_weight,
            'threshold': self.threshold,
            'text_classifier_path': 'models/text_classifier/v1.0/',
            'url_classifier_path': 'models/url_classifier/v1.0/'
        }
        
        config_path = model_dir / 'ensemble_config.json'
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✓ Ensemble configuration saved to {config_path}")
        print(f"  - Text weight: {self.text_weight}")
        print(f"  - URL weight: {self.url_weight}")
        print(f"  - Threshold: {self.threshold}")
    
    @classmethod
    def load(cls, 
             model_dir: Union[str, Path],
             text_classifier_path: Optional[Union[str, Path]] = None,
             url_classifier_path: Optional[Union[str, Path]] = None) -> 'EnsembleModel':
        """
        Load ensemble model with classifiers.
        
        Parameters:
        -----------
        model_dir : str or Path
            Directory containing ensemble configuration
        text_classifier_path : str or Path, optional
            Path to text classifier (overrides config)
        url_classifier_path : str or Path, optional
            Path to URL classifier (overrides config)
            
        Returns:
        --------
        ensemble : EnsembleModel
            Loaded ensemble model
        """
        model_dir = Path(model_dir)
        
        # Load configuration
        config_path = model_dir / 'ensemble_config.json'
        if not config_path.exists():
            raise FileNotFoundError(f"Ensemble config not found: {config_path}")
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Get classifier paths
        if text_classifier_path is None:
            text_classifier_path = config.get('text_classifier_path', 'models/text_classifier/v1.0/')
        if url_classifier_path is None:
            url_classifier_path = config.get('url_classifier_path', 'models/url_classifier/v1.0/')
        
        # Load classifiers
        print(f"Loading text classifier from {text_classifier_path}...")
        text_classifier = TextClassifier.load(text_classifier_path)
        
        print(f"Loading URL classifier from {url_classifier_path}...")
        url_classifier = URLClassifier.load(url_classifier_path)
        
        # Create ensemble
        ensemble = cls(
            text_classifier=text_classifier,
            url_classifier=url_classifier,
            text_weight=config['text_weight'],
            url_weight=config['url_weight'],
            threshold=config['threshold']
        )
        
        print(f"✓ Ensemble model loaded successfully")
        print(f"  - Weights: Text={ensemble.text_weight}, URL={ensemble.url_weight}")
        
        return ensemble


# Example usage
if __name__ == "__main__":
    print("Ensemble Model for Phishing Detection")
    print("=" * 70)
    print("\nThis module requires trained classifiers to demonstrate.")
    print("Please use this class in your training pipeline with actual data.")
    print("\nExample usage:")
    print("""
    # Load individual classifiers
    text_clf = TextClassifier.load('models/text_classifier/v1.0/')
    url_clf = URLClassifier.load('models/url_classifier/v1.0/')
    
    # Create ensemble
    ensemble = EnsembleModel(
        text_classifier=text_clf,
        url_classifier=url_clf,
        text_weight=0.6,
        url_weight=0.4
    )
    
    # Evaluate and compare
    comparison = ensemble.evaluate(X_test, y_test)
    
    # Save configuration
    ensemble.save('models/ensemble/v1.0/')
    
    # Make predictions
    predictions = ensemble.predict(new_emails)
    probabilities = ensemble.predict_proba(new_emails)
    
    # Get individual scores
    scores = ensemble.get_individual_scores(new_emails)
    print(f"Text probability: {scores['text_probs'][0]}")
    print(f"URL probability: {scores['url_probs'][0]}")
    print(f"Ensemble probability: {scores['ensemble_probs'][0]}")
    
    # Load saved ensemble
    loaded_ensemble = EnsembleModel.load('models/ensemble/v1.0/')
    """)
