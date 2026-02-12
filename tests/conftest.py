"""
Shared Pytest Fixtures for Testing Suite

This module contains shared test fixtures used across unit and integration tests.
"""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


@pytest.fixture
def sample_phishing_email():
    """Sample phishing email for testing."""
    return """
    URGENT! Your bank account has been suspended.
    Click here immediately to verify your password: http://192.168.1.1/verify
    Account: 1234567890
    Login now or lose access!
    """

@pytest.fixture
def sample_safe_email():
    """Sample legitimate email for testing."""
    return """
    Hi there,
    
    Just wanted to check in about our meeting tomorrow at 2pm.
    Let me know if you're still available.
    
    Best regards,
    John
    """

@pytest.fixture
def sample_emails_list():
    """List of mixed phishing and safe emails."""
    return [
        "URGENT! Verify your account NOW!!! Click http://evil.com/verify",
        "Hi, thanks for your email. I'll get back to you soon.",
        "Your credit card will be charged unless you login at http://fake-bank.com",
        "Meeting rescheduled to 3pm. See you then!",
        "SUSPENDED ACCOUNT! Update password at https://192.168.0.1/account"
    ]

@pytest.fixture
def empty_email():
    """Empty email string for edge case testing."""
    return ""

@pytest.fixture
def long_email():
    """Very long email for testing performance."""
    return "This is a test email. " * 1000

@pytest.fixture
def special_chars_email():
    """Email with only special characters."""
    return "!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`"

@pytest.fixture
def non_english_email():
    """Non-English text email."""
    return "こんにちは、これはテストメールです。パスワードを確認してください。"

@pytest.fixture
def email_no_url():
    """Email with no URLs."""
    return "This is a simple email with no links whatsoever."

@pytest.fixture
def email_multiple_urls():
    """Email with multiple URLs."""
    return """
    Check these links:
    http://example.com
    https://test.org/page
    http://192.168.1.1:8080/admin
    """

@pytest.fixture
def email_malformed_url():
    """Email with malformed URL."""
    return "Visit our site at htp://broken-url or http:/missing-slash"

@pytest.fixture
def email_ip_url():
    """Email with IP-based URL."""
    return "Click here: http://192.168.1.1/login"
