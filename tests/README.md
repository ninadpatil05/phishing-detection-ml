# Test Suite for Phishing Detection System

Comprehensive test suite targeting >75% code coverage.

## Structure

```
tests/
├── conftest.py              # Shared fixtures
├── unit/                    # Unit tests
│   ├── test_text_features.py    # Text feature extraction (27 tests)
│   ├── test_url_features.py     # URL feature extraction (24 tests)
│   └── test_ensemble.py         # Ensemble model (15 tests)
└── integration/             # Integration tests  
    └── test_api.py              # API endpoints (35+ tests)
```

## Running Tests

### All Tests
```bash
pytest
```

### With Coverage Report
```bash
pytest --cov=src --cov-report=html
```

### Unit Tests Only
```bash
pytest -m unit
```

### Integration Tests Only
```bash
pytest -m integration
```

### Specific Test File
```bash
pytest tests/unit/test_text_features.py
```

### Verbose Output
```bash
pytest -v
```

## Test Coverage

### Unit Tests (66 tests)

**Text Features (27 tests):**
- Initialization and configuration
- fit/transform pipeline
- Edge cases: empty strings, very long text, special characters, non-English
- All 9 custom features: length, word count, exclamation marks, urgency words, financial words, capital ratio, special char ratio, avg word length, URL count
- TF-IDF vectorization
- Input types: list, pandas Series, numpy array

**URL Features (24 tests):**
- URL extraction from email text
- Edge cases: no URL, multiple URLs, malformed URLs, IP-based URLs
- All 14 features: URL length, domain length, dots, hyphens, underscores, digits, special chars, has_ip, has_https, entropy, subdomains, suspicious keywords, depth, port
- Missing URL returns zero features
- Input types: list, pandas Series, numpy array

**Ensemble (15 tests):**
- Weight initialization and validation
- Weight combination (0.6/0.4, 0.5/0.5, custom)
- Threshold classification (0.5 default, custom)
- Weighted averaging calculation
- Individual score retrieval
- email_text input handling

### Integration Tests (35+ tests)

**/api/v1/predict:**
- Phishing email → PHISHING verdict
- Safe email → LEGITIMATE verdict
- Empty input → 422 error
- Missing field → 422 error
- Wrong type → 422 error
- Response structure validation
- Risk score range (0-1)
- Confidence values (HIGH/MEDIUM/LOW)
- Email with/without URLs

**/api/v1/explain:**
- Explanation structure
- Risk factors format
- Safe factors format
- Trigger word detection  
- Empty input → 422 error

**/api/v1/feedback:**
- Submit feedback
- Get feedback stats
- Missing prediction_id → 422
- Invalid label → 422

**/health:**
- Health check endpoint

**Rate Limiting:**
- Rate limit enforcement (slow test)

**Error Handling:**
- Invalid JSON → 422
- Unsupported method → 405
- Non-existent endpoint → 404

## Fixtures

**Email Fixtures:**
- `sample_phishing_email`: Typical phishing email
- `sample_safe_email`: Legitimate business email
- `sample_emails_list`: Mixed set of 5 emails
- `empty_email`: Empty string
- `long_email`: Very long text (1000 words)
- `special_chars_email`: Only special characters
- `non_english_email`: Japanese text
- `email_no_url`: Email without URLs
- `email_multiple_urls`: Email with 3 URLs
- `email_malformed_url`: Broken URL format
- `email_ip_url`: IP-based URL

## Coverage Goals

- **Overall**: >75%
- **Text Features**: >85%
- **URL Features**: >80%
- **Ensemble**: >90%
- **API Routes**: >70%

## Configuration

**pytest.ini:**
- Test discovery patterns
- Coverage thresholds (fail if <75%)
- HTML coverage reports
- Markers: unit, integration, slow

## Dependencies

Install test dependencies:
```bash
pip install pytest pytest-cov httpx
```

Included in requirements.txt:
- pytest==7.4.4
- pytest-cov==4.1.0
- pytest-asyncio==0.23.3
- httpx==0.26.0

## Tips

**Run Fast Tests:**
```bash
pytest -m "not slow"
```

**Run with Print Statements:**
```bash
pytest -s
```

**Stop on First Failure:**
```bash
pytest -x
```

**Run Last Failed:**
```bash
pytest --lf
```

**Generate Coverage Badge:**
```bash
pytest --cov=src --cov-report=term --cov-report=html
# Open htmlcov/index.html
```

## CI/CD Integration

Add to GitHub Actions:
```yaml
- name: Run Tests
  run: |
    pip install -r requirements.txt
    pytest --cov=src --cov-report=xml
    
- name: Check Coverage
  run: |
    coverage report --fail-under=75
```

## Troubleshooting

**Import Errors:**
- Ensure `conftest.py` adds src to Python path
- Check `__init__.py` files exist in test directories

**API Tests Fail:**
- Ensure models are trained and saved  
- Check API dependencies installed
- Verify database migrations run

**Coverage Too Low:**
- Run `pytest --cov=src --cov-report=term-missing`
- Identify uncovered lines
- Add targeted tests
