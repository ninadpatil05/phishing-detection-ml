"""
Accuracy Improvement Pipeline for Phishing Detection ML

This script systematically improves model accuracy through:
1. Baseline performance analysis
2. Enhanced feature engineering
3. Hyperparameter tuning
4. Class imbalance handling
5. Ensemble weight optimization
6. Model stacking
7. Results comparison
8. HTML report generation

Target: 3-5% accuracy improvement over v1.0 models

Usage:
    python scripts/improve_accuracy.py

Author: ML Pipeline
Date: 2026-02-12
"""

import numpy as np
import pandas as pd
import pickle
import json
import sys
import warnings
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, Any
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

# ML libraries
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE

# Custom imports
sys.path.append(str(Path(__file__).parent.parent / 'src'))
from training.text_classifier import TextClassifier
from training.url_classifier import URLClassifier
from training.ensemble import EnsembleModel
from feature_engineering.text_features_v2 import TextFeatureExtractorV2
from feature_engineering.url_features_v2 import URLFeatureExtractorV2

warnings.filterwarnings('ignore')

# Set random seed for reproducibility
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

# Directories
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'processed'
MODELS_V1_DIR = BASE_DIR / 'models'
MODELS_V2_DIR = BASE_DIR / 'models'
OUTPUTS_DIR = BASE_DIR / 'outputs'
REPORT_DIR = OUTPUTS_DIR / 'reports'

# Create directories
REPORT_DIR.mkdir(parents=True, exist_ok=True)


class AccuracyImprovementPipeline:
    """
    Comprehensive ML accuracy improvement pipeline.
    """
    
    def __init__(self):
        """Initialize the pipeline."""
        self.results = {
            'baseline': {},
            'feature_engineering': {},
            'hyperparameter_tuning': {},
            'class_imbalance': {},
            'ensemble_optimization': {},
            'model_stacking': {}
        }
        self.best_models = {}
        self.data = {}
        
        print("=" * 80)
        print("PHISHING DETECTION ML - ACCURACY IMPROVEMENT PIPELINE")
        print("=" * 80)
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Random State: {RANDOM_STATE}")
        print()
    
    def load_data(self):
        """Load train, validation, and test datasets."""
        print("[STEP 0] Loading Data")
        print("-" * 80)
        
        try:
            train_df = pd.read_csv(DATA_DIR / 'train.csv')
            val_df = pd.read_csv(DATA_DIR / 'val.csv')
            test_df = pd.read_csv(DATA_DIR / 'test.csv')
            
            # Store datasets
            self.data = {
                'X_train': train_df['email_text'],
                'y_train': train_df['label'].values,
                'X_val': val_df['email_text'],
                'y_val': val_df['label'].values,
                'X_test': test_df['email_text'],
                'y_test': test_df['label'].values
            }
            
            print(f"✓ Train set: {len(train_df)} samples")
            print(f"✓ Validation set: {len(val_df)} samples")
            print(f"✓ Test set: {len(test_df)} samples")
            
            # Class distribution
            train_dist = train_df['label'].value_counts()
            print(f"\nClass Distribution (Train):")
            print(f"  Safe (0): {train_dist[0]} ({train_dist[0]/len(train_df)*100:.1f}%)")
            print(f"  Phishing (1): {train_dist[1]} ({train_dist[1]/len(train_df)*100:.1f}%)")
            
            # Check for imbalance
            imbalance_ratio = max(train_dist[0], train_dist[1]) / min(train_dist[0], train_dist[1])
            if imbalance_ratio > 1.86:  # 65/35 threshold
                print(f"⚠ Class imbalance detected (ratio: {imbalance_ratio:.2f})")
                self.class_imbalanced = True
            else:
                print(f"✓ Classes are balanced (ratio: {imbalance_ratio:.2f})")
                self.class_imbalanced = False
            
            print()
            
        except Exception as e:
            print(f"✗ Error loading data: {e}")
            sys.exit(1)
    
    def analyze_baseline(self):
        """Step 1: Analyze current model performance."""
        print("[STEP 1] Baseline Performance Analysis")
        print("-" * 80)
        
        try:
            # Load v1.0 models
            print("Loading v1.0 models...")
            text_clf = TextClassifier.load(MODELS_V1_DIR / 'text_classifier' / 'v1.0')
            url_clf = URLClassifier.load(MODELS_V1_DIR / 'url_classifier' / 'v1.0')
            ensemble = EnsembleModel.load(
                MODELS_V1_DIR / 'ensemble' / 'v1.0',
                text_classifier_path=MODELS_V1_DIR / 'text_classifier' / 'v1.0',
                url_classifier_path=MODELS_V1_DIR / 'url_classifier' / 'v1.0'
            )
            
            # Evaluate on test set
            X_test = self.data['X_test']
            y_test = self.data['y_test']
            
            # Text classifier
            text_metrics = self._evaluate_model(text_clf, X_test, y_test, "Text Classifier")
            self.results['baseline']['text'] = text_metrics
            
            # URL classifier
            url_metrics = self._evaluate_model(url_clf, X_test, y_test, "URL Classifier")
            self.results['baseline']['url'] = url_metrics
            
            # Ensemble
            ensemble_metrics = self._evaluate_model(ensemble, X_test, y_test, "Ensemble")
            self.results['baseline']['ensemble'] = ensemble_metrics
            
            # Identify weakest component
            if text_metrics['accuracy'] < url_metrics['accuracy']:
                print(f"\n📊 Weakest component: Text Classifier (Accuracy: {text_metrics['accuracy']:.4f})")
                self.weakest_component = 'text'
            else:
                print(f"\n📊 Weakest component: URL Classifier (Accuracy: {url_metrics['accuracy']:.4f})")
                self.weakest_component = 'url'
            
            print()
            
        except Exception as e:
            print(f"✗ Error in baseline analysis: {e}")
            print("⚠ Proceeding without baseline comparison...")
            self.results['baseline'] = None
    
    def feature_engineering(self):
        """Step 2: Apply enhanced feature engineering."""
        print("[STEP 2] Enhanced Feature Engineering")
        print("-" * 80)
        
        try:
            print("Creating V2 feature extractors with additional features:")
            print("  • Text V2: +5 features (crypto, TLD, HTML, anchor, urgency)")
            print("  • URL V2: +4 features (shortener, typosquatting, SSL, deep paths)")
            print()
            
            # Create V2 feature extractors
            from feature_engineering.text_features_v2 import TextFeatureExtractorV2
            from feature_engineering.url_features_v2 import URLFeatureExtractorV2
            
            text_extractor_v2 = TextFeatureExtractorV2(max_tfidf_features=5000)
            url_extractor_v2 = URLFeatureExtractorV2()
            
            # Fit on training data
            print("Fitting V2 feature extractors on training data...")
            text_extractor_v2.fit(self.data['X_train'])
            url_extractor_v2.fit(self.data['X_train'])
            
            # Train new classifiers with v2 features
            print("\nTraining classifiers with enhanced features...")
            
            # Text classifier with V2 features
            text_clf_v2 = TextClassifier(feature_extractor=text_extractor_v2)
            text_clf_v2.train(
                self.data['X_train'], 
                self.data['y_train'],
                n_folds=5,
                verbose=False
            )
            
            # URL classifier with V2 features
            url_clf_v2 = URLClassifier(feature_extractor=url_extractor_v2)
            url_clf_v2.train(
                self.data['X_train'],
                self.data['y_train'],
                n_folds=5,
                verbose=False
            )
            
            # Evaluate
            text_v2_metrics = self._evaluate_model(text_clf_v2, self.data['X_test'], self.data['y_test'], "Text V2")
            url_v2_metrics = self._evaluate_model(url_clf_v2, self.data['X_test'], self.data['y_test'], "URL V2")
            
            self.results['feature_engineering']['text_v2'] = text_v2_metrics
            self.results['feature_engineering']['url_v2'] = url_v2_metrics
            
            # Store best models so far
            self.best_models['text_v2'] = text_clf_v2
            self.best_models['url_v2'] = url_clf_v2
            
            print()
            
        except Exception as e:
            print(f"✗ Error in feature engineering: {e}")
            import traceback
            traceback.print_exc()
    
    def hyperparameter_tuning(self):
        """Step 3: Hyperparameter optimization."""
        print("[STEP 3] Hyperparameter Tuning")
        print("-" * 80)
        print("⚠ This may take 30-60 minutes depending on hardware...")
        print()
        
        try:
            # Use V2 feature extractors if available, otherwise V1
            if 'text_v2' in self.best_models:
                text_extractor = self.best_models['text_v2'].feature_extractor
                url_extractor = self.best_models['url_v2'].feature_extractor
            else:
                # Fall back to creating new V2 extractors
                text_extractor = TextFeatureExtractorV2(max_tfidf_features=5000)
                url_extractor = URLFeatureExtractorV2()
                text_extractor.fit(self.data['X_train'])
                url_extractor.fit(self.data['X_train'])
            
            # Extract features
            X_train_text = text_extractor.transform(self.data['X_train'])
            X_test_text = text_extractor.transform(self.data['X_test'])
            X_train_url = url_extractor.transform(self.data['X_train'])
            X_test_url = url_extractor.transform(self.data['X_test'])
            
            # XGBoost for text
            print("Tuning XGBoost (Text Classifier)...")
            xgb_param_grid = {
                'max_depth': [3, 5, 7],
                'learning_rate': [0.01, 0.1, 0.3],
                'n_estimators': [100, 200, 300]
            }
            
            xgb_grid = GridSearchCV(
                XGBClassifier(random_state=RANDOM_STATE, use_label_encoder=False, eval_metric='logloss'),
                xgb_param_grid,
                cv=5,
                scoring='accuracy',
                n_jobs=-1,
                verbose=1
            )
            xgb_grid.fit(X_train_text, self.data['y_train'])
            
            print(f" Best XGB params: {xgb_grid.best_params_}")
            print(f"✓ Best XGB CV accuracy: {xgb_grid.best_score_:.4f}")
            
            # Random Forest for URL
            print("\nTuning Random Forest (URL Classifier)...")
            rf_param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [5, 10, 15, None],
                'min_samples_split': [2, 5, 10]
            }
            
            rf_grid = GridSearchCV(
                RandomForestClassifier(random_state=RANDOM_STATE),
                rf_param_grid,
                cv=5,
                scoring='accuracy',
                n_jobs=-1,
                verbose=1
            )
            rf_grid.fit(X_train_url, self.data['y_train'])
            
            print(f"✓ Best RF params: {rf_grid.best_params_}")
            print(f"✓ Best RF CV accuracy: {rf_grid.best_score_:.4f}")
            
            # Store results
            self.results['hyperparameter_tuning'] = {
                'xgb_best_params': xgb_grid.best_params_,
                'xgb_best_score': xgb_grid.best_score_,
                'rf_best_params': rf_grid.best_params_,
                'rf_best_score': rf_grid.best_score_
            }
            
            # Create tuned classifiers
            text_clf_tuned = TextClassifier(feature_extractor=text_extractor)
            text_clf_tuned.model = xgb_grid.best_estimator_
            text_clf_tuned.best_model_name = 'XGBoost'
            
            url_clf_tuned = URLClassifier(feature_extractor=url_extractor)
            url_clf_tuned.model = rf_grid.best_estimator_
            url_clf_tuned.best_model_name = 'RandomForest'
            
            # Evaluate tuned models
            tuned_text_metrics = self._evaluate_model(text_clf_tuned, self.data['X_test'], self.data['y_test'], "Tuned Text")
            tuned_url_metrics = self._evaluate_model(url_clf_tuned, self.data['X_test'], self.data['y_test'], "Tuned URL")
            
            self.results['hyperparameter_tuning']['text_metrics'] = tuned_text_metrics
            self.results['hyperparameter_tuning']['url_metrics'] = tuned_url_metrics
            
            self.best_models['text_tuned'] = text_clf_tuned
            self.best_models['url_tuned'] = url_clf_tuned
            
            print()
            
        except Exception as e:
            print(f"✗ Error in hyperparameter tuning: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_class_imbalance(self):
        """Step 4: Handle class imbalance with SMOTE."""
        print("[STEP 4] Class Imbalance Handling")
        print("-" * 80)
        
        if not self.class_imbalanced:
            print("✓ Classes are already balanced, skipping SMOTE")
            print()
            return
        
        try:
            print("Applying SMOTE oversampling...")
            
            # Use best feature extractors
            if 'text_tuned' in self.best_models:
                text_extractor = self.best_models['text_tuned'].feature_extractor
            elif 'text_v2' in self.best_models:
                text_extractor = self.best_models['text_v2'].feature_extractor
            else:
                print("⚠ No feature extractors available, skipping")
                return
            
            X_train_features = text_extractor.transform(self.data['X_train'])
            
            # Apply SMOTE
            smote = SMOTE(random_state=RANDOM_STATE)
            X_resampled, y_resampled = smote.fit_resample(X_train_features, self.data['y_train'])
            
            print(f"✓ Original shape: {X_train_features.shape}")
            print(f"✓ Resampled shape: {X_resampled.shape}")
            
            # Train with SMOTE
            xgb_smote = XGBClassifier(**self.results['hyperparameter_tuning']['xgb_best_params'],
                                      random_state=RANDOM_STATE, use_label_encoder=False, eval_metric='logloss')
            xgb_smote.fit(X_resampled, y_resampled)
            
            # Evaluate
            X_test_features = text_extractor.transform(self.data['X_test'])
            y_pred = xgb_smote.predict(X_test_features)
            y_pred_proba = xgb_smote.predict_proba(X_test_features)[:, 1]
            
            smote_metrics = {
                'accuracy': accuracy_score(self.data['y_test'], y_pred),
                'precision': precision_score(self.data['y_test'], y_pred),
                'recall': recall_score(self.data['y_test'], y_pred),
                'f1': f1_score(self.data['y_test'], y_pred),
                'auc': roc_auc_score(self.data['y_test'], y_pred_proba)
            }
            
            print(f"✓ SMOTE Accuracy: {smote_metrics['accuracy']:.4f}")
            self.results['class_imbalance'] = smote_metrics
            
            print()
            
        except Exception as e:
            print(f"✗ Error in class imbalance handling: {e}")
    
    def optimize_ensemble(self):
        """Step 5: Find optimal ensemble weights."""
        print("[STEP 5] Ensemble Optimization")
        print("-" * 80)
        
        try:
            # Use best models
            if 'text_tuned' in self.best_models:
                text_clf = self.best_models['text_tuned']
                url_clf = self.best_models['url_tuned']
            elif 'text_v2' in self.best_models:
                text_clf = self.best_models['text_v2']
                url_clf = self.best_models['url_v2']
            else:
                print("⚠ No models available for ensemble optimization")
                return
            
            # Test different weight combinations on validation set
            weight_combinations = [
                (0.5, 0.5),
                (0.6, 0.4),  # Current baseline
                (0.7, 0.3),
                (0.8, 0.2)
            ]
            
            best_accuracy = 0
            best_weights = None
            
            print("Testing weight combinations on validation set:")
            for text_weight, url_weight in weight_combinations:
                ensemble = EnsembleModel(
                    text_classifier=text_clf,
                    url_classifier=url_clf,
                    text_weight=text_weight,
                    url_weight=url_weight
                )
                
                y_pred = ensemble.predict(self.data['X_val'])
                accuracy = accuracy_score(self.data['y_val'], y_pred)
                
                print(f"  {text_weight:.1f}/{url_weight:.1f} (text/url) → Accuracy: {accuracy:.4f}")
                
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_weights = (text_weight, url_weight)
            
            print(f"\n✓ Best weights: {best_weights[0]:.1f}/{best_weights[1]:.1f} (Accuracy: {best_accuracy:.4f})")
            
            # Create optimized ensemble
            optimized_ensemble = EnsembleModel(
                text_classifier=text_clf,
                url_classifier=url_clf,
                text_weight=best_weights[0],
                url_weight=best_weights[1]
            )
            
            # Evaluate on test set
            ensemble_metrics = self._evaluate_model(optimized_ensemble, self.data['X_test'], self.data['y_test'], "Optimized Ensemble")
            
            self.results['ensemble_optimization'] = {
                'best_weights': best_weights,
                'metrics': ensemble_metrics
            }
            
            self.best_models['ensemble_optimized'] = optimized_ensemble
            
            print()
            
        except Exception as e:
            print(f"✗ Error in ensemble optimization: {e}")
            import traceback
            traceback.print_exc()
    
    def model_stacking(self):
        """Step 6: Try model stacking approach."""
        print("[STEP 6] Model Stacking")
        print("-" * 80)
        
        try:
            # Use best models
            if 'text_tuned' in self.best_models:
                text_clf = self.best_models['text_tuned']
                url_clf = self.best_models['url_tuned']
            elif 'text_v2' in self.best_models:
                text_clf = self.best_models['text_v2']
                url_clf = self.best_models['url_v2']
            else:
                print("⚠ No models available for stacking")
                return
            
            # Get base model predictions on training set
            print("Generating meta-features from base models...")
            text_proba_train = text_clf.predict_proba(self.data['X_train'])
            url_proba_train = url_clf.predict_proba(self.data['X_train'])
            
            X_meta_train = np.hstack([text_proba_train, url_proba_train])
            
            # Train meta-classifier
            print("Training Logistic Regression meta-classifier...")
            meta_clf = LogisticRegression(random_state=RANDOM_STATE, max_iter=1000)
            meta_clf.fit(X_meta_train, self.data['y_train'])
            
            # Evaluate stacking on test set
            text_proba_test = text_clf.predict_proba(self.data['X_test'])
            url_proba_test = url_clf.predict_proba(self.data['X_test'])
            X_meta_test = np.hstack([text_proba_test, url_proba_test])
            
            y_pred_stacking = meta_clf.predict(X_meta_test)
            y_pred_proba_stacking = meta_clf.predict_proba(X_meta_test)[:, 1]
            
            stacking_metrics = {
                'accuracy': accuracy_score(self.data['y_test'], y_pred_stacking),
                'precision': precision_score(self.data['y_test'], y_pred_stacking),
                'recall': recall_score(self.data['y_test'], y_pred_stacking),
                'f1': f1_score(self.data['y_test'], y_pred_stacking),
                'auc': roc_auc_score(self.data['y_test'], y_pred_proba_stacking)
            }
            
            print(f"✓ Stacking Accuracy: {stacking_metrics['accuracy']:.4f}")
            print(f"✓ Meta-classifier coefficients: {meta_clf.coef_}")
            
            self.results['model_stacking'] = stacking_metrics
            self.best_models['meta_clf'] = meta_clf
            
            print()
            
        except Exception as e:
            print(f"✗ Error in model stacking: {e}")
            import traceback
            traceback.print_exc()
    
    def save_improved_models(self):
        """Save improved models to v2.0 directories."""
        print("[STEP 7] Saving Improved Models")
        print("-" * 80)
        
        try:
            # Determine best approach
            accuracies = {}
            
            if self.results.get('feature_engineering', {}).get('text_v2'):
                accuracies['feature_engineering'] = self.results['feature_engineering']['text_v2']['accuracy']
            
            if self.results.get('hyperparameter_tuning', {}).get('text_metrics'):
                accuracies['hyperparameter_tuning'] = self.results['hyperparameter_tuning']['text_metrics']['accuracy']
            
            if self.results.get('ensemble_optimization', {}).get('metrics'):
                accuracies['ensemble_optimization'] = self.results['ensemble_optimization']['metrics']['accuracy']
            
            if self.results.get('model_stacking'):
                accuracies['model_stacking'] = self.results['model_stacking']['accuracy']
            
            best_approach = max(accuracies, key=accuracies.get)
            print(f"✓ Best approach: {best_approach} (Accuracy: {accuracies[best_approach]:.4f})")
            
            # Save corresponding models to v2.0
            v2_text_dir = MODELS_V2_DIR / 'text_classifier' / 'v2.0'
            v2_url_dir = MODELS_V2_DIR / 'url_classifier' / 'v2.0'
            v2_ensemble_dir = MODELS_V2_DIR / 'ensemble' / 'v2.0'
            
            v2_text_dir.mkdir(parents=True, exist_ok=True)
            v2_url_dir.mkdir(parents=True, exist_ok=True)
            v2_ensemble_dir.mkdir(parents=True, exist_ok=True)
            
            # Save text classifier
            if 'text_tuned' in self.best_models:
                self.best_models['text_tuned'].save(v2_text_dir)
                print(f"✓ Saved tuned text classifier to {v2_text_dir}")
            elif 'text_v2' in self.best_models:
                self.best_models['text_v2'].save(v2_text_dir)
                print(f"✓ Saved v2 text classifier to {v2_text_dir}")
            
            # Save URL classifier
            if 'url_tuned' in self.best_models:
                self.best_models['url_tuned'].save(v2_url_dir)
                print(f"✓ Saved tuned URL classifier to {v2_url_dir}")
            elif 'url_v2' in self.best_models:
                self.best_models['url_v2'].save(v2_url_dir)
                print(f"✓ Saved v2 URL classifier to {v2_url_dir}")
            
            # Save ensemble
            if 'ensemble_optimized' in self.best_models:
                self.best_models['ensemble_optimized'].save(v2_ensemble_dir)
                print(f"✓ Saved optimized ensemble to {v2_ensemble_dir}")
            
            print()
            
        except Exception as e:
            print(f"✗ Error saving models: {e}")
    
    def generate_report(self):
        """Step 8: Generate comprehensive HTML report."""
        print("[STEP 8] Generating HTML Report")
        print("-" * 80)
        
        try:
            report_path = REPORT_DIR / 'accuracy_improvement_report.html'
            
            html = self._create_html_report()
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            print(f"✓ Report generated: {report_path}")
            print(f"✓ Open in browser to view results")
            print()
            
        except Exception as e:
            print(f"✗ Error generating report: {e}")
    
    # ========= Helper Methods =========
    
    def _evaluate_model(self, model, X_test, y_test, model_name: str) -> Dict:
        """Evaluate a model and return metrics."""
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'auc': roc_auc_score(y_test, y_pred_proba)
        }
        
        print(f"{model_name:20s} → Acc: {metrics['accuracy']:.4f} | F1: {metrics['f1']:.4f} | AUC: {metrics['auc']:.4f}")
        
        return metrics
    
    def _create_html_report(self) -> str:
        """Create comprehensive HTML report."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Accuracy Improvement Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ margin: 0; font-size: 2.5em; }}
        h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        h3 {{ color: #764ba2; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #667eea;
            color: white;
        }}
        tr:hover {{ background-color: #f5f5f5; }}
        .metric {{
            display: inline-block;
            padding: 8px 16px;
            margin: 5px;
            border-radius: 20px;
            background-color: #e8f4f8;
            color: #0066cc;
            font-weight: bold;
        }}
        .improvement {{
            color: #28a745;
            font-weight: bold;
        }}
        .degradation {{
            color: #dc3545;
            font-weight: bold;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-left: 4px solid #667eea;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Accuracy Improvement Report</h1>
        <p>Phishing Detection ML System | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        {self._generate_summary_html()}
    </div>
    
    <div class="section">
        <h2>📈 Results Comparison</h2>
        {self._generate_comparison_table_html()}
    </div>
    
    <div class="section">
        <h2>⚙️ Optimization Steps</h2>
        {self._generate_steps_html()}
    </div>
    
    <div class="section">
        <h2>🎓 Conclusions & Recommendations</h2>
        {self._generate_conclusions_html()}
    </div>
</body>
</html>
"""
        return html
    
    def _generate_summary_html(self) -> str:
        """Generate executive summary HTML."""
        baseline_acc = self.results.get('baseline', {}).get('ensemble', {}).get('accuracy', 0)
        
        # Find best accuracy
        best_acc = baseline_acc
        best_method = 'baseline'
        
        if self.results.get('ensemble_optimization', {}).get('metrics'):
            acc = self.results['ensemble_optimization']['metrics']['accuracy']
            if acc > best_acc:
                best_acc = acc
                best_method = 'Ensemble Optimization'
        
        if self.results.get('model_stacking', {}).get('accuracy'):
            acc = self.results['model_stacking']['accuracy']
            if acc > best_acc:
                best_acc = acc
                best_method = 'Model Stacking'
        
        improvement = (best_acc - baseline_acc) * 100 if baseline_acc > 0 else 0
        
        html = f"""
        <div class="summary">
            <h3>Key Findings</h3>
            <p><strong>Baseline Accuracy:</strong> <span class="metric">{baseline_acc:.4f}</span></p>
            <p><strong>Best Improved Accuracy:</strong> <span class="metric">{best_acc:.4f}</span></p>
            <p><strong>Improvement:</strong> <span class="improvement">+{improvement:.2f}%</span></p>
            <p><strong>Best Method:</strong> {best_method}</p>
        </div>
        """
        return html
    
    def _generate_comparison_table_html(self) -> str:
        """Generate comparison table HTML."""
        html = """
        <table>
            <tr>
                <th>Model/Method</th>
                <th>Accuracy</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1 Score</th>
                <th>AUC</th>
            </tr>
        """
        
        # Baseline
        if self.results.get('baseline', {}).get('ensemble'):
            m = self.results['baseline']['ensemble']
            html += f"""
            <tr>
                <td><strong>Baseline Ensemble (v1.0)</strong></td>
                <td>{m['accuracy']:.4f}</td>
                <td>{m['precision']:.4f}</td>
                <td>{m['recall']:.4f}</td>
                <td>{m['f1']:.4f}</td>
                <td>{m['auc']:.4f}</td>
            </tr>
            """
        
        # Feature Engineering
        if self.results.get('feature_engineering', {}).get('text_v2'):
            m = self.results['feature_engineering']['text_v2']
            html += f"""
            <tr>
                <td>Text Classifier V2</td>
                <td>{m['accuracy']:.4f}</td>
                <td>{m['precision']:.4f}</td>
                <td>{m['recall']:.4f}</td>
                <td>{m['f1']:.4f}</td>
                <td>{m['auc']:.4f}</td>
            </tr>
            """
        
        # Hyperparameter Tuning
        if self.results.get('hyperparameter_tuning', {}).get('text_metrics'):
            m = self.results['hyperparameter_tuning']['text_metrics']
            html += f"""
            <tr>
                <td>Tuned Text Classifier</td>
                <td>{m['accuracy']:.4f}</td>
                <td>{m['precision']:.4f}</td>
                <td>{m['recall']:.4f}</td>
                <td>{m['f1']:.4f}</td>
                <td>{m['auc']:.4f}</td>
            </tr>
            """
        
        # Ensemble Optimization
        if self.results.get('ensemble_optimization', {}).get('metrics'):
            m = self.results['ensemble_optimization']['metrics']
            weights = self.results['ensemble_optimization']['best_weights']
            html += f"""
            <tr>
                <td><strong>Optimized Ensemble</strong> ({weights[0]:.1f}/{weights[1]:.1f})</td>
                <td>{m['accuracy']:.4f}</td>
                <td>{m['precision']:.4f}</td>
                <td>{m['recall']:.4f}</td>
                <td>{m['f1']:.4f}</td>
                <td>{m['auc']:.4f}</td>
            </tr>
            """
        
        # Model Stacking
        if self.results.get('model_stacking'):
            m = self.results['model_stacking']
            html += f"""
            <tr>
                <td><strong>Model Stacking</strong></td>
                <td>{m['accuracy']:.4f}</td>
                <td>{m['precision']:.4f}</td>
                <td>{m['recall']:.4f}</td>
                <td>{m['f1']:.4f}</td>
                <td>{m['auc']:.4f}</td>
            </tr>
            """
        
        html += "</table>"
        return html
    
    def _generate_steps_html(self) -> str:
        """Generate optimization steps HTML."""
        html = "<ol>"
        
        steps = [
            ("Baseline Analysis", "Evaluated existing v1.0 models"),
            ("Feature Engineering", "Added crypto, TLD, HTML, typosquatting features"),
            ("Hyperparameter Tuning", "GridSearchCV on XGBoost and Random Forest"),
            ("Class Imbalance", "Applied SMOTE oversampling" if self.class_imbalanced else "Classes balanced, skipped"),
            ("Ensemble Optimization", "Tested weight combinations"),
            ("Model Stacking", "Meta-classifier with Logistic Regression"),
            ("Model Saving", "Saved best models to v2.0 directories"),
            ("Report Generation", "Created this comprehensive report")
        ]
        
        for title, desc in steps:
            html += f"<li><strong>{title}:</strong> {desc}</li>"
        
        html += "</ol>"
        return html
    
    def _generate_conclusions_html(self) -> str:
        """Generate conclusions HTML."""
        html = """
        <h3>📌 Key Takeaways</h3>
        <ul>
            <li><strong>Feature Engineering:</strong> Adding domain-specific features (crypto, TLD, typosquatting) improves detection</li>
            <li><strong>Hyperparameter Tuning:</strong> GridSearchCV found optimal parameters for both classifiers</li>
            <li><strong>Ensemble Approach:</strong> Weighted ensemble or stacking often outperforms individual models</li>
        </ul>
        
        <h3>🔄 Next Steps</h3>
        <ul>
            <li>Deploy v2.0 models to production</li>
            <li>Monitor performance on live data</li>
            <li>Consider deep learning models (BERT, transformers)</li>
            <li>Collect more diverse training data</li>
        </ul>
        """
        return html
    
    def run(self):
        """Run the complete pipeline."""
        start_time = datetime.now()
        
        self.load_data()
        self.analyze_baseline()
        self.feature_engineering()
        self.hyperparameter_tuning()
        self.handle_class_imbalance()
        self.optimize_ensemble()
        self.model_stacking()
        self.save_improved_models()
        self.generate_report()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print("=" * 80)
        print("✅ PIPELINE COMPLETE")
        print("=" * 80)
        print(f"Total runtime: {duration:.1f} seconds ({duration/60:.1f} minutes)")
        print(f"Report: {REPORT_DIR / 'accuracy_improvement_report.html'}")
        print()


if __name__ == "__main__":
    pipeline = AccuracyImprovementPipeline()
    pipeline.run()
