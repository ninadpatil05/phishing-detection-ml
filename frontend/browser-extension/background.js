/**
 * Background Service Worker (Manifest V3)
 * 
 * This replaces background.html/background.js from Manifest V2.
 * Service workers are event-driven and don't run continuously.
 */

// Default settings
const DEFAULT_SETTINGS = {
    apiUrl: 'http://localhost:8000/api/v1',
    autoScan: true,
    whitelist: []
};

// Initialize settings on install
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.get(['settings'], (result) => {
        if (!result.settings) {
            chrome.storage.sync.set({ settings: DEFAULT_SETTINGS });
        }
    });
});

// Listen for tab updates (page navigation)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only scan when page is fully loaded
    if (changeInfo.status === 'complete' && tab.url) {
        chrome.storage.sync.get(['settings'], (result) => {
            const settings = result.settings || DEFAULT_SETTINGS;

            // Check if auto-scan is enabled
            if (!settings.autoScan) {
                setBadge(tabId, 'gray', '?');
                return;
            }

            // Check whitelist
            const url = new URL(tab.url);
            if (isWhitelisted(url.hostname, settings.whitelist)) {
                setBadge(tabId, 'green', '✓');
                return;
            }

            // Scan the URL
            scanUrl(tabId, tab.url, settings.apiUrl);
        });
    }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanUrl') {
        chrome.storage.sync.get(['settings'], (result) => {
            const settings = result.settings || DEFAULT_SETTINGS;
            scanUrl(request.tabId, request.url, settings.apiUrl)
                .then(sendResponse)
                .catch(error => sendResponse({ error: error.message }));
        });
        return true; // Keep channel open for async response
    }

    if (request.action === 'getResult') {
        chrome.storage.local.get([`result_${request.tabId}`], (result) => {
            sendResponse(result[`result_${request.tabId}`] || null);
        });
        return true;
    }
});

/**
 * Scan URL using the API
 */
async function scanUrl(tabId, url, apiUrl) {
    try {
        setBadge(tabId, 'yellow', '...');

        const response = await fetch(`${apiUrl}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email_text: url }),
            signal: AbortSignal.timeout(10000) // 10s timeout
        });

        if (!response.ok) {
            throw new Error('API request failed');
        }

        const result = await response.json();

        // Store result for popup
        chrome.storage.local.set({ [`result_${tabId}`]: result });

        // Update badge based on risk score
        updateBadgeFromResult(tabId, result);

        return result;

    } catch (error) {
        console.error('Scan error:', error);
        setBadge(tabId, 'gray', '!');

        // Store error for popup
        chrome.storage.local.set({
            [`result_${tabId}`]: {
                error: 'API unavailable. Check settings.',
                offline: true
            }
        });

        throw error;
    }
}

/**
 * Update badge color based on result
 */
function updateBadgeFromResult(tabId, result) {
    const riskScore = result.risk_score;

    if (riskScore >= 0.6) {
        setBadge(tabId, 'red', '!');
    } else if (riskScore >= 0.4) {
        setBadge(tabId, 'yellow', '?');
    } else {
        setBadge(tabId, 'green', '✓');
    }
}

/**
 * Set badge color and text
 */
function setBadge(tabId, color, text) {
    const colors = {
        green: '#22c55e',
        yellow: '#f59e0b',
        red: '#ef4444',
        gray: '#64748b'
    };

    chrome.action.setBadgeBackgroundColor({ color: colors[color], tabId });
    chrome.action.setBadgeText({ text, tabId });
}

/**
 * Check if domain is whitelisted
 */
function isWhitelisted(hostname, whitelist) {
    return whitelist.some(domain => {
        return hostname === domain || hostname.endsWith('.' + domain);
    });
}
