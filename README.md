
Intent-Aware Phishing Detection System

A production-ready Chrome Extension that detects phishing URLs using intelligent intent analysis, brand impersonation detection, and real-time risk scoring.
Features

1. URL Analysis Engine

·	Domain length analysis

·	Subdomain extraction and analysis

·	Special character detection

·	Entropy calculation for random-looking domains

·	Suspicious pattern detection

·	Typosquatting identification

2. Intent Detection Engine (Core Feature)

·	Brand keyword identification (PayPal, Google, Amazon, etc.)

·	Action word detection (login, verify, update, confirm)

·	Urgency word detection (urgent, now, limited, act fast)

·	Attack type classification:

o	Authority Attack: Impersonates trusted institutions

o	Urgency Attack: Creates artificial time pressure

o	Fear/Panic Attack: Uses threats and alarming language

o	Greed Trap: Offers unrealistic rewards

3. Risk Scoring System

·	Weighted scoring from 0-100

·	Multi-factor analysis

·	Real-time threat assessment

·	Three risk levels:

o	BLOCK (>70): Hard stop, page blurred

o	WARNING (30-70): User choice, inputs protected

o	SAFE (<30): Allow with soft notification

4. Protection Features

·	Sensitive Input Shield: Detects password/credential fields and warns

·	Auto Safe Mode: Blurs page content for high-risk URLs

·	Human Delay Engine: 5-second countdown for urgency-detected URLs
·	Visual URL Breakdown: Highlights suspicious parts of URL

Project Structure


/intent-phishing-extension

├── /extension
│   ├── manifest.json          # Chrome extension manifest (v3)
│   ├── background.js          # Service worker for URL analysis
│   ├── content.js             # Content script for page protection
│   ├── popup.html             # Popup UI interface
│   ├── popup.js               # Popup JavaScript logic
│   ├── styles.css             # Popup styles
│   └── /icons
│       └── icon*.svg          # Extension icons
│
├── /core
│   ├── analyzer.js            # URL structure analysis
│   ├── intentEngine.js        # Intent detection engine
│   ├── riskEngine.js          # Risk scoring system
│   └── utils.js               # Utility functions
│
├── README.md                   # This file
└── SETUP.md                    # Detailed setup instructions

Installation

Step 1: Download/Clone the Project

git clone <repository-url>

cd intent-phishing-extension



Step 2: Open Chrome Extensions Page

1.	Open Chrome browser

2.	Navigate to chrome://extensions

3.	Or: Menu → More Tools → Extensions

Step 3: Enable Developer Mode

·	Toggle the Developer mode switch in the top-right corner

Step 4: Load the Extension

1.	Click Load unpacked

2.	Select the extension folder

3.	The extension icon should appear in your Chrome toolbar

Step 5: Pin the Extension (Optional)

1.	Click the puzzle piece icon in Chrome toolbar

2.	Find "Intent-Aware Phishing Detection"

3.	Click the pin icon to keep it visible

Usage

Automatic Protection

The extension automatically analyzes URLs when you visit them:

·	High Risk (>70): Full page blur, countdown timer, must choose to leave

·	Medium Risk (30-70): Warning banner, input fields protected

·	Low Risk (<30): Minimal notification in popup

Manual Analysis

1.	Click the extension icon in toolbar

2.	View detailed analysis of current URL

3.	See risk factors, attack types, and recommendations

4.	Access external report links (VirusTotal, etc.)

Statistics

The popup shows your protection stats:

·	Number of threats blocked

·	Number of warnings shown

·	Number of sites allowed

Testing

Test URLs

Should Show BLOCK (>70):

https://paypa1-secure-login.xYZ/verify?account=phishing

https://amazon-security-alert.urgent-verify.net/update

https://google-docs.secure-verify.xyz/account

https://192.168.1.1/phishing/login.php

https://xn--80adxhks/bitcoin-rewards/win



Should Show WARNING (30-70):

https://example-freehosting.xyz/login

https://sub.domain.suspicious-tld.com/update

https://legit.site.xyz/account/verify



Should Show SAFE (<30):

https://www.google.com

https://github.com

https://stackoverflow.com



Quick Test Commands

Open Chrome DevTools Console on any page:

// Test the extension is working

chrome.runtime.sendMessage({

    action: 'analyzeURL',
    
    url: 'https://paypa1-secure.login.xYZ/verify'
}, c
onsole.log);



Architecture

Background Service Worker

·	Handles URL analysis requests

·	Manages analysis caching

·	Tracks protection statistics

·	Coordinates with content scripts

Content Script

·	Injected into all web pages

·	Implements protection overlays

·	Shields sensitive input fields

·	Shows warning banners

Core Modules

analyzer.js

URLAnalyzer.analyzeURL(url, knownBrands)

// Returns: { features, suspiciousIndicators, entropy, ... }



intentEngine.js

IntentEngine.analyzeIntent(url, pageTitle, pageText)

// Returns: { intentScore, attackClassification, manipulationAnalysis, ... }



riskEngine.js

RiskEngine.calculateRiskScore(url, urlAnalysis, intentAnalysis)

// Returns: { riskScore, riskLevel, factors, recommendations, ... }



Customization

Adding New Brands

Edit /core/intentEngine.js:

const KNOWN_BRANDS = {

    FINANCIAL: ['paypal', 'venmo', 'newbank', ...],
    
    // Add more categories
};




Adding New Attack Patterns

Edit /core/intentEngine.js:

const ATTACK_PATTERNS = {

    NEW_ATTACK: {
    
        name: 'New Attack Type',
        
        indicators: ['keyword1', 'keyword2', ...],
        
        weight: 1.0,
        
        severity: 'high'
    }
    
};




Adjusting Thresholds

Edit /core/riskEngine.js:

const THRESHOLDS = {

    BLOCK: 70,  // Adjust blocking threshold
    
    WARN: 30,    // Adjust warning threshold
    
    SAFE: 0
};




API Readiness

The extension is designed to integrate with external services:

VirusTotal Integration

Already linked in popup - can be enhanced with API key
Domain Age Lookup

Infrastructure analysis is ready for WHOIS API integration

Real-time Threat Feeds

Can connect to:

·	Google Safe Browsing API

·	PhishTank

·	OpenPhish

·	APIVoid

Browser Compatibility

·	Chrome 88+ (Manifest V3 required)

·	Edge 88+ (Chromium-based)

·	Brave (Chromium-based)

Performance

·	Analysis completes in <100ms

·	Memory footprint: ~2MB

·	No impact on page load times

·	Background caching for repeated URLs

Security Considerations

1.	No external API calls - All analysis is local

2.	No data collection - URLs are never sent anywhere

3.	Minimal permissions - Only requests necessary for functionality

4.	CSP compliant - Follows Chrome security policies

Troubleshooting

Extension Not Loading

1.	Check for errors on chrome://extensions

2.	Ensure Developer mode is enabled

3.	Verify all files are in the correct folders

Popup Not Working

1.	Refresh the extension on chrome://extensions

2.	Reload any open tabs

Content Script Not Running

1.	Check page URL isn't restricted (chrome://, etc.)

2.	Verify manifest permissions are correct

License

MIT License - Free to use, modify, and distribute.

Contributing

1.	Fork the repository

2.	Create a feature branch

3.	Make your changes

4.	Test thoroughly

5.	Submit a pull request

Support

For issues or feature requests, please open a GitHub issue.





