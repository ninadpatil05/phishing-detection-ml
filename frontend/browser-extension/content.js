/**
 * Content Script
 * 
 * Runs on every page. Minimal functionality since most work is in background.js
 * Used for extracting page metadata if needed in the future.
 */

// Send page info to background when loaded
window.addEventListener('load', () => {
    const pageInfo = {
        url: window.location.href,
        title: document.title,
        domain: window.location.hostname
    };

    // Could be used for enhanced scanning in future versions
    chrome.runtime.sendMessage({
        action: 'pageLoaded',
        pageInfo
    });
});
