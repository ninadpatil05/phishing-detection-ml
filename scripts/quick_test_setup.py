"""
Quick Test Setup - Creates minimal models for API testing

This bypasses full training and creates simple mock models
so you can test the API immediately.
"""

import pickle
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

print("Creating test models...")

# Create directories
Path("models/text_classifier/v1.0").mkdir(parents=True, exist_ok=True)
Path("models/url_classifier/v1.0").mkdir(parents=True, exist_ok=True)
Path("models/ensemble/v1.0").mkdir(parents=True, exist_ok=True)

# Sample training data
phishing_samples = [
    "URGENT! Verify your account at http://phishing.com NOW!",
    "Your bank account suspended! Click http://192.168.1.1",
    "Congratulations! You won! Click http://win-prize.xyz",
]

safe_samples = [
    "Meeting tomorrow at 2pm in conference room",
    "Please review the attached document",
    "Thanks for your email, I'll get back to you soon",
]

X_train = phishing_samples + safe_samples
y_train = [1, 1, 1, 0, 0, 0]

# 1. Create Text Classifier
print("Creating text classifier...")
text_vectorizer = TfidfVectorizer(max_features=100)
text_features = text_vectorizer.fit_transform(X_train)
text_model = RandomForestClassifier(n_estimators=10, random_state=42)
text_model.fit(text_features, y_train)

# Save text classifier components
with open("models/text_classifier/v1.0/model.pkl", "wb") as f:
    pickle.dump(text_model, f)
with open("models/text_classifier/v1.0/vectorizer.pkl", "wb") as f:
    pickle.dump(text_vectorizer, f)

print(f"  Saved to models/text_classifier/v1.0/")

# 2. Create URL Classifier (simple version)
print("Creating URL classifier...")
url_features = np.random.rand(6, 14)  # 14 URL features
url_model = RandomForestClassifier(n_estimators=10, random_state=42)
url_model.fit(url_features, y_train)

with open("models/url_classifier/v1.0/model.pkl", "wb") as f:
    pickle.dump(url_model, f)

print(f"  Saved to models/url_classifier/v1.0/")

# 3. Create Ensemble config
print("Creating ensemble configuration...")
import json
ensemble_config = {
    "text_weight": 0.6,
    "url_weight": 0.4,
    "threshold": 0.5,
    "text_classifier_path": "models/text_classifier/v1.0/",
    "url_classifier_path": "models/url_classifier/v1.0/"
}

with open("models/ensemble/v1.0/ensemble_config.json", "w") as f:
    json.dump(ensemble_config, f, indent=2)

print(f"  Saved to models/ensemble/v1.0/")

print("\n" + "="*70)
print("SUCCESS! Test models created!")
print("="*70)
print("\nYou can now test the API:")
print("  1. API is already running at http://localhost:8000/docs")
print("  2. Try the /predict endpoint with test email")
print("\nTest command:")
print('  curl -X POST http://localhost:8000/api/v1/predict ^')
print('    -H "Content-Type: application/json" ^')
print('    -d "{\\"email_text\\": \\"URGENT! Click http://phishing.com\\"}"')
print("\nOr open http://localhost:8000/docs in your browser!")
