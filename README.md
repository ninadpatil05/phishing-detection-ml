# Phishing Detection ML System

A comprehensive machine learning system for detecting phishing attempts through URL analysis, text content classification, and ensemble methods.

## Overview

This project implements a multi-model approach to phishing detection, combining text classification, URL pattern analysis, and ensemble methods to provide accurate phishing detection with explainable results.

## Tech Stack

- **Backend**: Python 3.10, FastAPI
- **ML Libraries**: scikit-learn, XGBoost
- **Frontend**: React
- **Deployment**: Docker
- **API**: RESTful API with FastAPI

## Project Structure

```
phishing-detection-ml/
├── data/              # Dataset storage
├── models/            # Trained model artifacts
├── src/               # Source code
├── frontend/          # Web dashboard and browser extension
├── demo/              # Sample data for testing
├── scripts/           # Utility scripts
├── tests/             # Test suites
├── docs/              # Documentation
├── outputs/           # Reports and metrics
└── config/            # Configuration files
```

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd phishing-detection-ml

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend/dashboard
npm install
```

## Usage

### Training Models

```bash
# Preprocess data
python scripts/preprocess_data.py

# Train text classifier
python src/training/train_text_classifier.py

# Train URL classifier
python src/training/train_url_classifier.py

# Train ensemble model
python src/training/train_ensemble.py
```

### Running the API

```bash
# Start the FastAPI server
uvicorn src.api.main:app --reload
```

### Running the Dashboard

```bash
cd frontend/dashboard
npm start
```

## API Endpoints

- `POST /api/predict` - Predict if a URL/email is phishing
- `GET /api/explain/{prediction_id}` - Get explanation for a prediction
- `GET /api/metrics` - Get model performance metrics

## Features

- **Multi-model Detection**: Combines text, URL, and ensemble models
- **Real-time Inference**: Fast API for instant predictions
- **Explainability**: SHAP and LIME integration for model interpretability
- **Browser Extension**: Real-time protection while browsing
- **Performance Monitoring**: Track model metrics and drift

## Testing

```bash
# Run unit tests
pytest tests/unit

# Run integration tests
pytest tests/integration

# Run performance tests
pytest tests/performance
```

## Docker Deployment

```bash
# Build Docker image
docker build -t phishing-detection-ml .

# Run container
docker run -p 8000:8000 phishing-detection-ml
```

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- Ninad Patil

## Acknowledgments

- Dataset sources
- Research papers and references
