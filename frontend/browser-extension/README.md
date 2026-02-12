# Phishing Detection Browser Extension

A Chrome browser extension that automatically detects phishing websites using machine learning.

## Features

### Automatic Scanning
- **Real-time Detection**: Scans every page you visit automatically
- **Instant Alerts**: Shows results via color-coded badge on extension icon
- **Badge Colors**:
  - 🟢 **Green**: Legitimate site (risk < 40%)
  - 🟡 **Yellow**: Suspicious site (risk 40-60%)
  - 🔴 **Red**: Phishing detected (risk > 60%)

### Popup Interface
- Current URL and risk score
- Verdict with confidence level
- Top 3 risk indicators
- Rescan button
- Report false positive to API

### Settings
- Configure API base URL
- Enable/disable auto-scan
- Whitelist trusted domains

## Installation

### 1. Prepare Icons
Create three PNG icon files in `icons/` directory:
- `icon16.png` (16×16 px)
- `icon48.png` (48×48 px)
- `icon128.png` (128×128 px)

See `icons/README.md` for design recommendations.

### 2. Load Extension
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `frontend/browser-extension/` directory
5. Extension should appear in your toolbar

### 3. Configure API
1. Click extension icon
2. Click "Settings" (or right-click icon → Options)
3. Set API URL (default: `http://localhost:8000/api/v1`)
4. Configure auto-scan and whitelist as needed
5. Click "Save Settings"

## Usage

### Automatic Scanning
When enabled (default), the extension automatically scans each page you visit:
1. Badge shows yellow "..." while scanning
2. Badge updates to green/yellow/red based on result
3. Click badge to see detailed results

### Manual Actions
- **Rescan**: Click "Rescan" button in popup
- **Report False Positive**: Click "Report False" to send feedback to API
- **Whitelist Domain**: Add trusted domains in Settings

### Whitelisting
Trusted domains bypass scanning and always show green:
1. Open Settings
2. Enter domain (e.g., `google.com`)
3. Click "Add"
4. Domain applies to all subdomains

## How It Works

### Manifest V3 Architecture

```
Page Load
    ↓
Content Script (content.js)
    ↓
Background Service Worker (background.js)
    ↓
API Request (/predict)
    ↓
Update Badge Color
    ↓
Store Result
    ↓
Popup (popup.js) displays result
```

### Scanning Process
1. **Page loads** → Content script notifies background worker
2. **Background worker** → Checks settings (auto-scan, whitelist)
3. **API call** → Sends URL to `/predict` endpoint
4. **Analysis** → ML model returns risk score
5. **Badge update** → Color changes based on risk level
6. **Result storage** → Saved for popup display

## Manifest V3 vs V2: Key Differences

### Background Scripts → Service Workers

**Manifest V2:**
```json
"background": {
  "scripts": ["background.js"],
  "persistent": true
}
```
- Runs continuously in background
- Can maintain state in global variables
- High memory usage

**Manifest V3:**
```json
"background": {
  "service_worker": "background.js"
}
```
- Event-driven, only runs when needed
- Cannot maintain persistent state (use `chrome.storage`)
- Lower memory usage, better performance

### Host Permissions

**Manifest V2:**
```json
"permissions": [
  "<all_urls>"
]
```

**Manifest V3:**
```json
"host_permissions": [
  "<all_urls>"
]
```
- Separated from regular permissions
- More granular control
- User can revoke host access independently

### Browser Action → Action

**Manifest V2:**
```json
"browser_action": { ... }
```

**Manifest V3:**
```json
"action": { ... }
```
- Unified API (combines `browser_action` and `page_action`)
- Simpler configuration

### Other Changes

1. **No Remote Code**: Cannot load external scripts
2. **Service Worker Lifecycle**: Must handle termination/restart
3. **Promises Required**: Many APIs now return promises
4. **CSP Restrictions**: Stricter Content Security Policy

### Why Manifest V3?

**Benefits:**
- Better security (no remote code execution)
- Improved privacy
- Better performance (service workers)
- Future-proof (V2 deprecated in 2024)

**Challenges:**
- Migration effort
- Must rewrite background scripts
- Cannot use `eval()` or inline scripts

## API Endpoints Used

- `POST /api/v1/predict`: Scan URL
  ```json
  { "email_text": "https://example.com" }
  ```

- `POST /api/v1/feedback`: Report false positive
  ```json
  {
    "prediction_id": "pred_xxx",
    "true_label": 0,
    "comment": "False positive report"
  }
  ```

## Error Handling

### API Offline
- Badge shows gray "!"
- Popup displays error message
- Manual rescan available

### Invalid URL
- Skipped automatically
- No badge update
- Chrome internal pages ignored

### Network Timeout
- 10-second timeout
- Falls back to gray badge
- Error stored for popup

## Development

### Testing
1. Make code changes
2. Go to `chrome://extensions/`
3. Click reload icon on extension
4. Test on various URLs

### Debugging
- **Background worker**: `chrome://extensions/` → "Inspect service worker"
- **Popup**: Right-click popup → "Inspect"
- **Content script**: Page DevTools → Console

### Common Issues

**Extension won't load:**
- Check all icon files exist
- Validate manifest.json syntax
- Check console for errors

**Badge not updating:**
- Verify API is running
- Check auto-scan is enabled
- Inspect background worker console

**Popup shows error:**
- Verify API URL in settings
- Check CORS is enabled on API
- Try manual rescan

## Security Considerations

### Privacy
- URLs sent to local API only (default)
- No data collection or tracking
- Whitelist stored locally

### Permissions
- `storage`: Save settings and results
- `tabs`: Access current URL
- `activeTab`: Read page info
- `scripting`: Inject content script
- `host_permissions`: Scan all pages

## Future Enhancements

- [ ] Email content scanning (copy-paste)
- [ ] Historical scan log
- [ ] Export/import settings
- [ ] Custom risk thresholds
- [ ] Dark/light theme toggle
- [ ] Multi-language support

## Troubleshooting

**Q: Badge stays yellow?**
A: API might be slow. Check API server logs.

**Q: All sites show red?**
A: API issue or wrong endpoint. Check settings.

**Q: Whitelist not working?**
A: Ensure exact domain match (no http://, no paths).

## License

MIT
