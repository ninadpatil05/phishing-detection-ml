"""
Quick Sample Data Generator for Testing

Creates a small sample dataset to test the phishing detection system.
"""

import pandas as pd
import numpy as np
from pathlib import Path

# Create sample data
sample_data = {
    'Email Text': [
        # Phishing emails (label=1)
        "URGENT! Your bank account has been suspended. Click here to verify: http://192.168.1.1/verify",
        "Congratulations! You won $1,000,000! Click http://evil.com/claim to claim your prize NOW!",
        "VERIFY YOUR ACCOUNT IMMEDIATELY! Login at http://phishing-site.com or lose access!",
        "Your password will expire today. Update it here: http://fake-bank.com/update",
        "SUSPENDED ACCOUNT! Click http://malicious.net/restore to restore access immediately!",
        "Final notice! Your credit card will be charged. Stop it here: http://192.168.0.1/stop",
        "URGENT security alert! Verify your details: http://secure-login-verify.com",
        "Your package is waiting! Track it: http://track-package.xyz/id=12345",
        "Apple ID locked! Unlock now: http://appleid-unlock.com/verify",
        "PayPal: Unusual activity detected. Confirm here: http://paypal-secure.net/confirm",
        
        # Legitimate emails (label=0)
        "Hi, just checking in about our meeting tomorrow at 2pm. Let me know if you're available.",
        "Thanks for your email. I'll send you the report by end of day today.",
        "The project deadline has been extended to next Friday. Please update your timeline accordingly.",
        "Meeting reminder: Team standup at 10am in conference room B.",
        "Your order #12345 has shipped. Expected delivery: 3-5 business days.",
        "Hello, I hope this email finds you well. Looking forward to our collaboration.",
        "Please review the attached document and provide feedback by Thursday.",
        "Congratulations on completing the training program! Your certificate is attached.",
        "Reminder: Monthly team lunch this Friday at 12:30pm.",
        "Thank you for attending the conference. Here are the presentation slides.",
        
        # More phishing
        "FINAL WARNING! Your account will be deleted. Click http://urgent-verify.com NOW!",
        "You have 1 unread message! View it: http://message-center.xyz/view",
        "IRS: You are eligible for a tax refund. Claim here: http://irs-refund.com",
        "Netflix: Your subscription has expired. Renew: http://netflix-renew.net",
        "Microsoft: Unusual sign-in detected. Verify: http://microsoft-security.xyz",
        
        # More legitimate
        "As discussed in our call, I'm sending the contract for your review.",
        "The next team meeting is scheduled for Wednesday at 3pm.",
        "Your subscription renewal was successful. Thank you for your continued support.",
        "Please find attached the quarterly financial report.",
        "Happy birthday! Wishing you all the best on your special day.",
    ],
    'Email Type': [
        # Phishing (1)
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        # Legitimate (0)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        # More phishing
        1, 1, 1, 1, 1,
        # More legitimate
        0, 0, 0, 0, 0
    ]
}

# Create DataFrame
df = pd.DataFrame(sample_data)

# Shuffle the data
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Create output directory
output_dir = Path('data/raw')
output_dir.mkdir(parents=True, exist_ok=True)

# Save to CSV
output_path = output_dir / 'Phishing_Email.csv'
df.to_csv(output_path, index=False)

print("=" * 70)
print("Sample Dataset Generated!")
print("=" * 70)
print(f"\nDataset saved to: {output_path}")
print(f"Total samples: {len(df)}")
print(f"Phishing emails: {(df['Email Type'] == 1).sum()}")
print(f"Legitimate emails: {(df['Email Type'] == 0).sum()}")
print("\nSample data:")
print(df.head())
print("\n✓ Ready for training!")
print("\nNext steps:")
print("  1. python src/preprocessing/data_loader.py")
print("  2. python src/training/text_classifier.py")
print("  3. python src/training/url_classifier.py")
print("  4. python src/training/ensemble.py")
