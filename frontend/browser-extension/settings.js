/**
 * Settings Script
 * 
 * Manages extension configuration
 */

const DEFAULT_SETTINGS = {
    apiUrl: 'http://localhost:8000/api/v1',
    autoScan: true,
    whitelist: []
};

// Load settings on page load
document.addEventListener('DOMContentLoaded', () => {
    loadSettings();

    // Event listeners
    document.getElementById('saveBtn').addEventListener('click', saveSettings);
    document.getElementById('addDomainBtn').addEventListener('click', addDomain);

    // Enter key to add domain
    document.getElementById('newDomain').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            addDomain();
        }
    });
});

/**
 * Load settings from storage
 */
function loadSettings() {
    chrome.storage.sync.get(['settings'], (result) => {
        const settings = result.settings || DEFAULT_SETTINGS;

        document.getElementById('apiUrl').value = settings.apiUrl;
        document.getElementById('autoScan').checked = settings.autoScan;

        renderWhitelist(settings.whitelist);
    });
}

/**
 * Save settings to storage
 */
function saveSettings() {
    const settings = {
        apiUrl: document.getElementById('apiUrl').value,
        autoScan: document.getElementById('autoScan').checked,
        whitelist: getCurrentWhitelist()
    };

    chrome.storage.sync.set({ settings }, () => {
        showSaveMessage();
    });
}

/**
 * Add domain to whitelist
 */
function addDomain() {
    const input = document.getElementById('newDomain');
    const domain = input.value.trim().toLowerCase();

    if (!domain) {
        return;
    }

    // Validate domain format
    if (!isValidDomain(domain)) {
        alert('Please enter a valid domain (e.g., example.com)');
        return;
    }

    // Get current whitelist
    chrome.storage.sync.get(['settings'], (result) => {
        const settings = result.settings || DEFAULT_SETTINGS;

        // Check if already exists
        if (settings.whitelist.includes(domain)) {
            alert('Domain already whitelisted');
            return;
        }

        // Add to whitelist
        settings.whitelist.push(domain);

        // Save and re-render
        chrome.storage.sync.set({ settings }, () => {
            renderWhitelist(settings.whitelist);
            input.value = '';
        });
    });
}

/**
 * Remove domain from whitelist
 */
function removeDomain(domain) {
    chrome.storage.sync.get(['settings'], (result) => {
        const settings = result.settings || DEFAULT_SETTINGS;

        // Remove domain
        settings.whitelist = settings.whitelist.filter(d => d !== domain);

        // Save and re-render
        chrome.storage.sync.set({ settings }, () => {
            renderWhitelist(settings.whitelist);
        });
    });
}

/**
 * Render whitelist domains
 */
function renderWhitelist(whitelist) {
    const list = document.getElementById('whitelistList');
    list.innerHTML = '';

    if (whitelist.length === 0) {
        list.innerHTML = '<li style="color: #64748b; text-align: center;">No whitelisted domains</li>';
        return;
    }

    whitelist.forEach(domain => {
        const li = document.createElement('li');
        li.className = 'whitelist-item';

        const span = document.createElement('span');
        span.textContent = domain;

        const btn = document.createElement('button');
        btn.textContent = 'Remove';
        btn.className = 'btn-danger';
        btn.onclick = () => removeDomain(domain);

        li.appendChild(span);
        li.appendChild(btn);
        list.appendChild(li);
    });
}

/**
 * Get current whitelist from DOM
 */
function getCurrentWhitelist() {
    const items = document.querySelectorAll('.whitelist-item span');
    return Array.from(items).map(span => span.textContent);
}

/**
 * Validate domain format
 */
function isValidDomain(domain) {
    const pattern = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/;
    return pattern.test(domain);
}

/**
 * Show save confirmation message
 */
function showSaveMessage() {
    const message = document.getElementById('saveMessage');
    message.style.display = 'block';

    setTimeout(() => {
        message.style.display = 'none';
    }, 3000);
}
