"""
Sample Email Generator

Creates phishing and legitimate email samples for testing.
"""

import os
from pathlib import Path

# Phishing email templates
PHISHING_TEMPLATES = [
    "URGENT: Your account has been suspended. Click {url} to verify immediately.",
    "Your bank account has been locked. Verify your credentials at {url} now!",
    "Security alert! Suspicious activity detected. Confirm your identity: {url}",
    "Your password will expire in 24 hours. Update it here: {url}",
    "You have won $10,000! Click {url} to claim your prize immediately.",
    "Your package delivery failed. Reschedule at {url} within 48 hours.",
    "IRS Notice: You have unpaid taxes. Pay now at {url} to avoid penalties.",
    "Your PayPal account needs verification. Click {url} to avoid suspension.",
    "FINAL WARNING: Your account will be deleted. Verify at {url} NOW!",
    "Unusual login detected from unknown location. Secure your account: {url}",
]

PHISHING_URLS = [
    "http://192.168.1.1/verify",
    "http://secure-login.suspicious.com/",
    "http://bank-verify-account.net/",
    "http://paypal-security.co/update",
    "http://amazon-prize.info/claim",
]

# Legitimate email templates
LEGIT_TEMPLATES = [
    "Hi {name}, thanks for your email. I'll review the document and get back to you tomorrow.",
    "Meeting scheduled for {day} at 2 PM. See you there!",
    "The quarterly report looks good. Let's discuss the budget allocation next week.",
    "Don't forget about the team lunch on Friday. Looking forward to it!",
    "I've updated the project timeline. Please review when you have a chance.",
    "Great work on the presentation! The client was very impressed.",
    "Reminder: Code review session tomorrow at 10 AM in Conference Room B.",
    "The new feature has been deployed to staging. Please test when possible.",
    "Thanks for the feedback. I've incorporated your suggestions into the draft.",
    "Weekly newsletter: Check out our latest blog posts at https://example.com/blog",
]

NAMES = ["Sarah", "John", "Mike", "Emily", "David", "Lisa", "Tom", "Anna"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

def generate_samples():
    """Generate 50 phishing and 50 legitimate email samples."""
    
    base_dir = Path("demo")
    phishing_dir = base_dir / "phishing_samples"
    legit_dir = base_dir / "legit_samples"
    
    # Create directories
    phishing_dir.mkdir(parents=True, exist_ok=True)
    legit_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate 50 phishing emails
    for i in range(1, 51):
        template = PHISHING_TEMPLATES[i % len(PHISHING_TEMPLATES)]
        url = PHISHING_URLS[i % len(PHISHING_URLS)]
        email_content = template.format(url=url)
        
        # Add some variations
        if i % 3 == 0:
            email_content = email_content.upper()  # All caps (urgency)
        if i % 5 == 0:
            email_content += "\n\nREQUIRED: Submit your password, SSN, and credit card number."
        
        file_path = phishing_dir / f"email_{i:02d}.txt"
        file_path.write_text(email_content)
    
    # Generate 50 legitimate emails
    for i in range(1, 51):
        template = LEGIT_TEMPLATES[i % len(LEGIT_TEMPLATES)]
        name = NAMES[i % len(NAMES)]
        day = DAYS[i % len(DAYS)]
        email_content = template.format(name=name, day=day)
        
        # Add some context
        if i % 4 == 0:
            email_content += "\n\nBest regards,\nThe Team"
        
        file_path = legit_dir / f"email_{i:02d}.txt"
        file_path.write_text(email_content)
    
    print(f"[OK] Generated 50 phishing samples in {phishing_dir}")
    print(f"[OK] Generated 50 legitimate samples in {legit_dir}")

if __name__ == "__main__":
    generate_samples()
