import React, { useState } from 'react';
import './EmailInput.css';

function EmailInput({ onAnalyze, loading }) {
    const [emailText, setEmailText] = useState('');
    const [withExplanation, setWithExplanation] = useState(false);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!emailText.trim()) {
            alert('Please enter email text');
            return;
        }
        onAnalyze(emailText, withExplanation);
    };

    const sampleEmail = `URGENT: Your account has been suspended

Dear Customer,

We have detected suspicious activity on your account. Your account will be permanently deleted unless you verify your identity immediately.

Click here to verify: http://192.168.1.1/verify

Failure to act within 24 hours will result in account closure.

Security Team`;

    const loadSample = () => {
        setEmailText(sampleEmail);
    };

    return (
        <div className="email-input">
            <h3>Analyze Email</h3>
            <form onSubmit={handleSubmit}>
                <textarea
                    className="email-textarea"
                    placeholder="Paste email content here..."
                    value={emailText}
                    onChange={(e) => setEmailText(e.target.value)}
                    rows={15}
                    disabled={loading}
                />

                <div className="input-actions">
                    <label className="checkbox-label">
                        <input
                            type="checkbox"
                            checked={withExplanation}
                            onChange={(e) => setWithExplanation(e.target.checked)}
                            disabled={loading}
                        />
                        <span>Include Explanation</span>
                    </label>

                    <button
                        type="button"
                        className="btn-secondary"
                        onClick={loadSample}
                        disabled={loading}
                    >
                        Load Sample
                    </button>
                </div>

                <button
                    type="submit"
                    className="btn-primary"
                    disabled={loading || !emailText.trim()}
                >
                    {loading ? 'Analyzing...' : 'Analyze Email'}
                </button>
            </form>
        </div>
    );
}

export default EmailInput;
