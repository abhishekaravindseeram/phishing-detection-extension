# Setup & Testing Guide

## Quick Start

### 1. File Verification

First, verify all files are in place:

```
intent-phishing-extension/
├── extension/
│   ├── manifest.json (2KB)
│   ├── background.js (15KB)
│   ├── content.js (12KB)
│   ├── popup.html (5KB)
│   ├── popup.js (6KB)
│   ├── styles.css (8KB)
│   └── icons/
│       └── icon16.svg
│
└── core/
    ├── analyzer.js (15KB)
    ├── intentEngine.js (18KB)
    ├── riskEngine.js (20KB)
    └── utils.js (12KB)
```

### 2. Chrome Extension Installation

#### Step 1: Open Chrome Extensions
- Open Chrome browser
- Navigate to: `chrome://extensions/`
- Or use: Menu (⋮) → More Tools → Extensions

#### Step 2: Enable Developer Mode
- Look for "Developer mode" toggle in top-right
- Turn it **ON** (blue when enabled)

#### Step 3: Load Extension
1. Click **"Load unpacked"** button (top-left area)
2. Navigate to the `extension` folder
3. Select the folder (not individual files)
4. Click "Select Folder" / "Open"

#### Step 4: Verify Installation
- You should see "Intent-Aware Phishing Detection System" in your extensions list
- A shield icon 🛡️ should appear in your toolbar
- Status should show "Enabled"

### 3. Pin the Extension

1. Click the puzzle piece icon 🧩 in Chrome toolbar
2. Find "Intent-Aware Phishing Detection"
3. Click the pin icon 📌 next to it
4. The shield icon should now always be visible

## Testing the Extension

### Method 1: Test URLs

#### Test 1: Typosquatting Detection
**URL:** `https://paypa1-secure-login.xyz/verify?account=update`

**Expected Result:**
- Risk Score: 70-85
- Decision: 🚫 BLOCK
- Detection: Typosquatting ("paypa1" looks like "paypal")
- Attack Type: Authority Attack (fake verification)

**Why:** The URL uses "paypa1" (with number 1) instead of "paypal", combined with urgency keywords.

---

#### Test 2: Urgency Attack
**URL:** `https://amazon-urgent-alert.com/secure?action=required&time=limited`

**Expected Result:**
- Risk Score: 60-75
- Decision: 🚫 BLOCK
- Detection: Multiple urgency keywords
- Attack Type: Urgency Attack

**Why:** Contains "urgent", "alert", "limited", "required" - classic pressure tactics.

---

#### Test 3: Fear/Panic Attack
**URL:** `https://bank-security-alert.com/verify?account=suspended&breach=detected`

**Expected Result:**
- Risk Score: 75-90
- Decision: 🚫 BLOCK
- Detection: Fear-inducing language
- Attack Type: Fear/Panic Attack

**Why:** Uses alarming words like "suspended", "breach", "detected" to trigger panic.

---

#### Test 4: Suspicious TLD
**URL:** `https://legitimate-site.xyz/login`

**Expected Result:**
- Risk Score: 35-45
- Decision: ⚠️ WARNING
- Detection: Suspicious TLD (.xyz)
- Some risk factors present

**Why:** Free hosting TLD combined with login page, but no other strong indicators.

---

#### Test 5: Clean URL
**URL:** `https://www.google.com/search?q=test`

**Expected Result:**
- Risk Score: 0-15
- Decision: ✅ SAFE
- Detection: No risk factors
- Safe to browse

**Why:** Established domain with HTTPS, no suspicious patterns.

---

### Method 2: Console Testing

1. Open Chrome DevTools (F12 or Ctrl+Shift+I)
2. Go to Console tab
3. Navigate to any website
4. Run these commands:

```javascript
// Test URL analysis directly
chrome.runtime.sendMessage({
    action: 'analyzeURL',
    url: 'https://paypa1-secure-login.xYZ/verify'
}, function(response) {
    console.log('Risk Score:', response.riskScore);
    console.log('Level:', response.riskLevel);
    console.log('Attack:', response.primaryAttack);
});

// Get protection statistics
chrome.runtime.sendMessage({
    action: 'getStats'
}, function(stats) {
    console.log('Blocked:', stats.blocked);
    console.log('Warned:', stats.warned);
    console.log('Allowed:', stats.allowed);
});
```

### Method 3: Popup Testing

1. Click the shield icon 🛡️ in toolbar
2. Navigate to test URLs
3. Click extension icon again
4. Verify:
   - Risk score updates
   - Decision changes color
   - Factors list populates
   - URL breakdown shows highlights

## Troubleshooting

### Issue: "Manifest file is missing" error

**Solution:**
- Make sure you're loading the `extension` folder, not the root folder
- Verify `manifest.json` exists inside `extension/`

### Issue: Extension icon not appearing

**Solution:**
1. Check Chrome extensions page (`chrome://extensions`)
2. Look for errors under the extension
3. Click "Reload" (circular arrow icon)
4. If still failing, click "Remove" and re-add

### Issue: Popup shows "Cannot analyze"

**This is normal for:**
- `chrome://` pages
- `about:` pages
- Browser internal pages
- PDF viewers
- Chrome Web Store

### Issue: Content script not running

**Solution:**
1. Verify page is a standard HTTP/HTTPS page
2. Check browser console for errors
3. Reload the extension
4. Refresh the page

### Issue: Risk score seems wrong

**Solution:**
- Check the "Risk Factors" list in popup
- Each factor shows contribution to score
- Different URLs may have different weights

## Advanced Testing

### Test with Real Phishing URLs

**Note:** Only test with known phishing simulation sites or legitimate security testing platforms.

Safe testing resources:
- `phishingquiz.withgoogle.com` (Google's quiz)
- `opentransfert.fr` (French bank simulation)

### Custom Test Creation

Create your own test URLs with these combinations:

| Element | High Risk | Low Risk |
|---------|-----------|----------|
| TLD | .xyz, .top, .tk | .com, .org |
| Domain | paypa1, g00gle | google |
| Path | /verify, /secure | /products |
| Subdomain | secure-login | www |
| Protocol | http | https |
| Brand | google, paypal | example |

Example combinations:
- **High Risk:** `http://secure-paypa1-login.xyz/verify?update=required`
- **Low Risk:** `https://www.example.com/products`

## Extension Development

### Making Changes

1. Edit the source files
2. Go to `chrome://extensions/`
3. Click the reload icon 🔄 on the extension
4. Test your changes

### Debugging

**Background Script:**
- Click "Service Worker" link in extension details
- Opens DevTools for background script

**Content Script:**
- Open any webpage
- Open DevTools (F12)
- Content script console logs appear there

### Logs

Check console for logs:
```
[Intent-Aware Phishing Detection] Service Worker initialized
[Intent-Aware Phishing Detection] Known brands loaded: 127
[Phishing Detection] Content script initialized
```

## Performance Testing

### Measure Analysis Speed

```javascript
const start = performance.now();
chrome.runtime.sendMessage({
    action: 'analyzeURL',
    url: 'https://example.com'
}, (response) => {
    const duration = performance.now() - start;
    console.log(`Analysis completed in ${duration.toFixed(2)}ms`);
});
```

Expected: < 100ms for most URLs

### Memory Usage

Monitor in Chrome Task Manager:
1. Shift+Escape to open Task Manager
2. Look for Chrome extension processes
3. Memory should stay under 50MB

## Uninstalling

1. Go to `chrome://extensions/`
2. Find "Intent-Aware Phishing Detection System"
3. Click "Remove"
4. Confirm removal

## Support

If you encounter issues not covered here:
1. Check the main README.md
2. Review browser console for errors
3. Verify file integrity
4. Try fresh installation

---

**Last Updated:** 2026-03-26
**Version:** 1.0.0
