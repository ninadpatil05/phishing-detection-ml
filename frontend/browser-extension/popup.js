/**
 * Popup Script
 * 
 * Displays scan results and handles user interactions
 */

let currentTabId = null;
let currentUrl = null;

// Initialize popup when opened
document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTabId = tab.id;
    currentUrl = tab.url;

    // Display current URL
    document.getElementById('currentUrl').textContent = currentUrl;

    // Load and display results
    loadResults();

    // Set up event listeners
    document.getElementById('rescanBtn').addEventListener('click', rescanPage);
    document.getElementById('reportBtn').addEventListener('click', reportFalsePositive);
});

/**
 * Load scan results from storage
 */
function loadResults() {
    chrome.runtime.sendMessage(
        { action: 'getResult', tabId: currentTabId },
        (result) => {
            if (!result) {
                showLoading();
                return;
            }

            if (result.error || result.offline) {
                showError(result.error || 'API is offline');
                return;
            }

            displayResults(result);
        }
    );
}

/**
 * Display scan results
 */
function displayResults(result) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('results').style.display = 'block';

    // Risk score
    const riskPercent = (result.risk_score * 100).toFixed(1);
    document.getElementById('riskScore').textContent = `${riskPercent}%`;

    // Confidence
    document.getElementById('confidence').textContent = result.confidence || 'N/A';

    // Verdict badge
    const verdictBadge = document.getElementById('verdictBadge');
    const verdict = result.verdict;

    if (result.risk_score >= 0.6) {
        verdictBadge.textContent = '⚠️ PHISHING DETECTED';
        verdictBadge.className = 'verdict-badge verdict-phishing';
    } else if (result.risk_score >= 0.4) {
        verdictBadge.textContent = '⚠️ SUSPICIOUS';
        verdictBadge.className = 'verdict-badge verdict-suspicious';
    } else {
        verdictBadge.textContent = '✓ LEGITIMATE';
        verdictBadge.className = 'verdict-badge verdict-safe';
    }

    // Risk factors (show top 3 if available)
    if (result.risk_score >= 0.4) {
        const riskFactors = generateRiskFactors(result);
        if (riskFactors.length > 0) {
            document.getElementById('riskFactors').style.display = 'block';
            const riskList = document.getElementById('riskList');
            riskList.innerHTML = '';

            riskFactors.slice(0, 3).forEach(factor => {
                const li = document.createElement('li');
                li.textContent = factor;
                riskList.appendChild(li);
            });
        }
    }
}

/**
 * Generate risk factor descriptions
 */
function generateRiskFactors(result) {
    const factors = [];

    if (result.risk_score >= 0.7) {
        factors.push('High phishing probability detected');
    }

    if (result.url_score && result.url_score > 0.5) {
        factors.push('Suspicious URL patterns found');
    }

    if (result.text_score && result.text_score > 0.5) {
        factors.push('Contains phishing-like content');
    }

    // Check URL characteristics
    const url = new URL(currentUrl);

    if (url.protocol === 'http:') {
        factors.push('Not using secure HTTPS connection');
    }

    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url.hostname)) {
        factors.push('URL uses IP address instead of domain');
    }

    if (url.hostname.includes('-') || url.hostname.split('.').length > 4) {
        factors.push('Suspicious domain structure');
    }

    return factors;
}

/**
 * Show loading state
 */
function showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
}

/**
 * Show error message
 */
function showError(message) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('results').style.display = 'block';
    document.getElementById('error').style.display = 'block';
    document.getElementById('error').textContent = message;
}

/**
 * Rescan current page
 */
function rescanPage() {
    showLoading();

    chrome.runtime.sendMessage(
        { action: 'scanUrl', tabId: currentTabId, url: currentUrl },
        (result) => {
            if (result && result.error) {
                showError(result.error);
            } else {
                setTimeout(() => loadResults(), 500);
            }
        }
    );
}

/**
 * Report false positive
  */
async function reportFalsePositive() {
    const confirmed = confirm('Report this page as falsely flagged?');
    if (!confirmed) return;

    try {
        const settings = await chrome.storage.sync.get(['settings']);
        const apiUrl = settings.settings?.apiUrl || 'http://localhost:8000/api/v1';

        // Get current prediction ID from result
        chrome.runtime.sendMessage(
            { action: 'getResult', tabId: currentTabId },
            async (result) => {
                if (result && result.prediction_id) {
                    const response = await fetch(`${apiUrl}/feedback`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            prediction_id: result.prediction_id,
                            true_label: 0, // Report as safe
                            comment: `False positive report from browser extension: ${currentUrl}`
                        })
                    });

                    if (response.ok) {
                        alert('Thank you! Your feedback has been recorded.');
                    } else {
                        throw new Error('Failed to submit feedback');
                    }
                } else {
                    alert('No prediction ID available. Please rescan first.');
                }
            }
        );
    } catch (error) {
        alert('Failed to submit feedback. Please try again.');
    }
}
