"""
Configuration settings for the Phishing Detection ML System
"""
import os
from pathlib import Path
from typing import List

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
OUTPUTS_DIR = BASE_DIR / "outputs"
LOGS_DIR = OUTPUTS_DIR / "logs"

# Data Paths
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
TRAINING_DATA_DIR = DATA_DIR / "training"

# Model Paths
TEXT_CLASSIFIER_DIR = MODELS_DIR / "text_classifier"
URL_CLASSIFIER_DIR = MODELS_DIR / "url_classifier"
ENSEMBLE_MODEL_DIR = MODELS_DIR / "ensemble"
MODEL_VERSIONS_DIR = MODELS_DIR / "versions"

# Output Paths
REPORTS_DIR = OUTPUTS_DIR / "reports"
METRICS_DIR = OUTPUTS_DIR / "metrics"

# Create directories if they don't exist
for directory in [
    DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, TRAINING_DATA_DIR,
    MODELS_DIR, TEXT_CLASSIFIER_DIR, URL_CLASSIFIER_DIR, ENSEMBLE_MODEL_DIR,
    MODEL_VERSIONS_DIR, OUTPUTS_DIR, REPORTS_DIR, METRICS_DIR, LOGS_DIR
]:
    directory.mkdir(parents=True, exist_ok=True)

# ====================
# Model Configuration
# ====================

# Text Classifier Settings
TEXT_CLASSIFIER_CONFIG = {
    "model_type": "xgboost",  # Options: xgboost, random_forest, gradient_boosting
    "max_depth": 6,
    "n_estimators": 100,
    "learning_rate": 0.1,
    "min_child_weight": 1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": 42,
    "eval_metric": "logloss",
}

# URL Classifier Settings
URL_CLASSIFIER_CONFIG = {
    "model_type": "random_forest",
    "n_estimators": 200,
    "max_depth": 10,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "random_state": 42,
    "n_jobs": -1,
}

# Ensemble Model Settings
ENSEMBLE_CONFIG = {
    "voting": "soft",  # Options: hard, soft
    "weights": [0.4, 0.35, 0.25],  # [text_weight, url_weight, other_weight]
}

# Feature Engineering Settings
FEATURE_CONFIG = {
    "max_features": 5000,
    "ngram_range": (1, 3),
    "min_df": 2,
    "max_df": 0.95,
    "use_idf": True,
    "use_tfidf": True,
}

# Training Settings
TRAINING_CONFIG = {
    "test_size": 0.2,
    "validation_size": 0.1,
    "random_state": 42,
    "stratify": True,
    "batch_size": 32,
    "epochs": 50,
    "early_stopping_patience": 10,
}

# ====================
# API Configuration
# ====================

API_CONFIG = {
    "title": "Phishing Detection API",
    "description": "REST API for phishing detection using ML models",
    "version": "1.0.0",
    "host": "0.0.0.0",
    "port": 8000,
    "reload": True,
    "workers": 4,
    "log_level": "info",
}

# CORS Settings
CORS_ORIGINS: List[str] = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
]

# API Rate Limiting
RATE_LIMIT_CONFIG = {
    "enabled": True,
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
}

# ====================
# Database Configuration
# ====================

DATABASE_CONFIG = {
    "database_url": os.getenv("DATABASE_URL", "sqlite:///./phishing_detection.db"),
    "echo": False,
    "pool_size": 10,
    "max_overflow": 20,
}

# ====================
# Logging Configuration
# ====================

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "default",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": str(LOGS_DIR / "app.log"),
            "level": "DEBUG",
            "formatter": "detailed",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"],
    },
}

# ====================
# Explainability Configuration
# ====================

EXPLAINABILITY_CONFIG = {
    "shap_enabled": True,
    "lime_enabled": True,
    "max_display_features": 10,
    "cache_explanations": True,
}

# ====================
# Preprocessing Configuration
# ====================

PREPROCESSING_CONFIG = {
    "lowercase": True,
    "remove_html": True,
    "remove_urls": True,
    "remove_special_chars": True,
    "remove_numbers": False,
    "remove_stopwords": True,
    "lemmatization": True,
    "stemming": False,
}

# ====================
# Monitoring & Performance
# ====================

MONITORING_CONFIG = {
    "enabled": True,
    "metrics_port": 9090,
    "track_predictions": True,
    "track_latency": True,
    "track_model_drift": True,
    "alert_threshold": 0.1,  # Alert if accuracy drops by 10%
}

# ====================
# Security Settings
# ====================

SECURITY_CONFIG = {
    "secret_key": os.getenv("SECRET_KEY", "your-secret-key-change-in-production"),
    "algorithm": "HS256",
    "access_token_expire_minutes": 30,
    "api_key_header": "X-API-Key",
}

# ====================
# Feature Flags
# ====================

FEATURE_FLAGS = {
    "enable_caching": True,
    "enable_async_processing": True,
    "enable_model_versioning": True,
    "enable_ab_testing": False,
    "enable_feedback_loop": True,
}

# ====================
# Thresholds
# ====================

DETECTION_THRESHOLDS = {
    "phishing_probability": 0.5,  # Threshold for classifying as phishing
    "high_confidence": 0.8,  # High confidence threshold
    "low_confidence": 0.3,  # Low confidence threshold
}
