/**
 * Intent-Aware Phishing Detection System
 * Content Script
 * 
 * Handles page protection, input field shielding, and visual overlays.
 * Injected into all web pages to provide real-time protection.
 * 
 * @version 1.0.0
 */

(function() {
    'use strict';

    // ============================================================================
    // CONFIGURATION
    // ============================================================================

    const CONFIG = {
        UI: {
            OVERLAY_Z_INDEX: 2147483647,
            BLUR_INTENSITY: '20px',
            ANIMATION_DURATION: 300,
            COUNTDOWN_SECONDS: 5,
            CHECK_INTERVAL: 1000,
            AUTO_HIDE_DELAY: 10000
        },
        SELECTORS: {
            SENSITIVE_INPUTS: [
                'input[type="password"]',
                'input[name*="password" i]',
                'input[name*="passwd" i]',
                'input[name*="pwd" i]',
                'input[name*="pin" i]',
                'input[name*="credit" i]',
                'input[name*="ssn" i]',
                'input[name*="cvv" i]',
                'input[name*="account" i][type="email"]',
                'input[name*="login" i][type="email"]'
            ]
        }
    };

    // ============================================================================
    // LOGGER
    // ============================================================================

    const Logger = {
        log(level, message, data) {
            const prefix = `[PhishGuard:Content]`;
            const logFn = level === 'error' ? console.error : 
                          level === 'warn' ? console.warn : console.log;
            if (data) {
                logFn(`${prefix} ${message}`, data);
            } else {
                logFn(`${prefix} ${message}`);
            }
        },
        info(msg, data) { this.log('info', msg, data); },
        warn(msg, data) { this.log('warn', msg, data); },
        error(msg, data) { this.log('error', msg, data); }
    };

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    const Utils = {
        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        },

        getRiskColor(score) {
            if (score >= 70) return { color: '#dc3545', gradient: 'linear-gradient(90deg, #dc3545, #ff4757)' };
            if (score >= 30) return { color: '#fd7e14', gradient: 'linear-gradient(90deg, #fd7e14, #ffa502)' };
            return { color: '#198754', gradient: 'linear-gradient(90deg, #198754, #2ed573)' };
        },

        truncateUrl(url, maxLength = 50) {
            if (!url || url.length <= maxLength) return url;
            return url.substring(0, maxLength) + '...';
        }
    };

    // ============================================================================
    // STYLES
    // ============================================================================

    const STYLES = `
        .phishing-protection-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            z-index: ${CONFIG.UI.OVERLAY_Z_INDEX};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: #fff;
            overflow: auto;
            animation: overlayFadeIn ${CONFIG.UI.ANIMATION_DURATION}ms ease;
        }

        @keyframes overlayFadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .phishing-warning-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            padding: 40px;
            max-width: 600px;
            width: 90%;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            animation: cardSlideUp ${CONFIG.UI.ANIMATION_DURATION}ms ease;
        }

        @keyframes cardSlideUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .phishing-warning-icon {
            font-size: 80px;
            margin-bottom: 20px;
            animation: iconPulse 2s ease-in-out infinite;
        }

        @keyframes iconPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }

        .phishing-warning-title {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 15px;
            color: #ff4757;
        }

        .phishing-warning-subtitle {
            font-size: 18px;
            color: #a4b0be;
            margin-bottom: 30px;
        }

        .phishing-risk-meter {
            width: 100%;
            height: 12px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            overflow: hidden;
            margin: 20px 0;
        }

        .phishing-risk-fill {
            height: 100%;
            border-radius: 6px;
            transition: width 0.5s ease;
        }

        .phishing-warning-reasons {
            text-align: left;
            margin: 20px 0;
            padding: 20px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
        }

        .phishing-warning-reasons h4 {
            margin: 0 0 15px 0;
            color: #ff6b6b;
        }

        .phishing-warning-reasons ul {
            margin: 0;
            padding-left: 20px;
        }

        .phishing-warning-reasons li {
            margin: 8px 0;
            color: #dfe4ea;
        }

        .phishing-warning-buttons {
            display: flex;
            gap: 15px;
            margin-top: 30px;
            flex-wrap: wrap;
            justify-content: center;
        }

        .phishing-btn {
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .phishing-btn-danger {
            background: #ff4757;
            color: white;
        }

        .phishing-btn-danger:hover {
            background: #ff6b7a;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255, 71, 87, 0.4);
        }

        .phishing-btn-safe {
            background: #2ed573;
            color: white;
        }

        .phishing-btn-safe:hover {
            background: #7bed9f;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(46, 213, 115, 0.4);
        }

        .phishing-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .phishing-countdown {
            font-size: 48px;
            font-weight: 700;
            color: #ffa502;
            margin: 20px 0;
        }

        .phishing-countdown-text {
            color: #a4b0be;
            font-size: 14px;
        }

        .phishing-input-shield::before {
            content: '⚠️ SENSITIVE FIELD';
            position: absolute;
            top: -25px;
            left: 0;
            background: #ff4757;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            z-index: 1000;
        }

        .phishing-input-shield input,
        .phishing-input-shield textarea {
            border: 2px solid #ff4757 !important;
            background: rgba(255, 71, 87, 0.1) !important;
        }

        .phishing-warning-banner {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(90deg, #ff4757, #ff6b81);
            color: white;
            padding: 10px 20px;
            text-align: center;
            font-weight: 600;
            z-index: ${CONFIG.UI.OVERLAY_Z_INDEX - 1};
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            box-shadow: 0 4px 15px rgba(255, 71, 87, 0.4);
        }

        .phishing-warning-banner .close-btn {
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            font-size: 18px;
            padding: 0 5px;
            opacity: 0.8;
            transition: opacity 0.2s;
        }

        .phishing-warning-banner .close-btn:hover {
            opacity: 1;
        }

        .phishing-url-breakdown {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            font-family: monospace;
            font-size: 13px;
            max-width: 400px;
            z-index: ${CONFIG.UI.OVERLAY_Z_INDEX - 2};
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .phishing-url-breakdown .brand { color: #ffd32a; font-weight: bold; }
        .phishing-url-breakdown .action { color: #ff4757; font-weight: bold; }
        .phishing-url-breakdown .urgency { color: #ff6b81; font-weight: bold; }
        .phishing-url-breakdown .suspicious {
            color: #ff0000;
            background: rgba(255, 0, 0, 0.2);
            padding: 0 4px;
            border-radius: 3px;
        }
    `;

    // ============================================================================
    // STYLE MANAGER
    // ============================================================================

    const StyleManager = {
        styleElement: null,

        inject() {
            if (this.styleElement) return;
            
            this.styleElement = document.createElement('style');
            this.styleElement.id = 'phishguard-protection-styles';
            this.styleElement.textContent = STYLES;
            document.head.appendChild(this.styleElement);
            Logger.info('Styles injected');
        },

        remove() {
            if (this.styleElement) {
                this.styleElement.remove();
                this.styleElement = null;
            }
        }
    };

    // ============================================================================
    // OVERLAY MANAGER
    // ============================================================================

    const OverlayManager = {
        element: null,
        countdownTimer: null,
        isCountingDown: false,

        show(riskData) {
            if (this.element) return;
            
            StyleManager.inject();
            
            const riskScore = riskData.riskScore || 0;
            const { color, gradient } = Utils.getRiskColor(riskScore);
            const factors = riskData.factors || [];

            this.element = document.createElement('div');
            this.element.className = 'phishing-protection-overlay';
            this.element.innerHTML = `
                <div class="phishing-warning-card">
                    <div class="phishing-warning-icon">${riskData.icon || '🚫'}</div>
                    <h1 class="phishing-warning-title">${riskData.riskLevel || 'HIGH RISK'}</h1>
                    <p class="phishing-warning-subtitle">This URL has been flagged as potentially malicious</p>
                    
                    <div class="phishing-risk-meter">
                        <div class="phishing-risk-fill" style="width: ${riskScore}%; background: ${gradient};"></div>
                    </div>
                    <p style="color: ${color}; font-size: 24px; font-weight: 700;">Risk Score: ${riskScore}/100</p>
                    
                    ${factors.length > 0 ? `
                        <div class="phishing-warning-reasons">
                            <h4>⚠️ Risk Factors Detected:</h4>
                            <ul>
                                ${factors.slice(0, 5).map(f => 
                                    `<li>${Utils.escapeHtml(f.name)}: ${Utils.escapeHtml(f.detail || `+${f.score}`)}</li>`
                                ).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    
                    ${riskData.hasUrgency ? `
                        <div class="phishing-countdown-container">
                            <p class="phishing-countdown-text">Human Delay Active - Page access delayed for safety</p>
                            <div class="phishing-countdown" id="phishing-countdown">${CONFIG.UI.COUNTDOWN_SECONDS}</div>
                        </div>
                    ` : ''}
                    
                    <div class="phishing-warning-buttons">
                        <button class="phishing-btn phishing-btn-danger" id="phishing-leave-btn">
                            🚫 Leave Immediately
                        </button>
                        <button class="phishing-btn phishing-btn-safe" id="phishing-proceed-btn" 
                                ${riskData.hasUrgency ? 'disabled' : ''}>
                            ⚠️ Proceed Anyway
                        </button>
                    </div>
                    
                    <p style="margin-top: 20px; font-size: 12px; color: #a4b0be;">
                        Your security is our priority. Take a moment to verify this URL.
                    </p>
                </div>
            `;

            document.body.appendChild(this.element);
            document.body.style.filter = `blur(${CONFIG.UI.BLUR_INTENSITY})`;
            document.body.style.overflow = 'hidden';

            document.getElementById('phishing-leave-btn')
                .addEventListener('click', () => this.leavePage());
            document.getElementById('phishing-proceed-btn')
                .addEventListener('click', () => this.proceedAnyway());

            if (riskData.hasUrgency) {
                this.startCountdown();
            }

            Logger.info('Protection overlay shown', { riskScore });
        },

        startCountdown() {
            if (this.isCountingDown) return;
            this.isCountingDown = true;

            let count = CONFIG.UI.COUNTDOWN_SECONDS;
            const countdownEl = document.getElementById('phishing-countdown');
            const proceedBtn = document.getElementById('phishing-proceed-btn');

            this.countdownTimer = setInterval(() => {
                count--;
                if (countdownEl) {
                    countdownEl.textContent = count;
                }

                if (count <= 0) {
                    clearInterval(this.countdownTimer);
                    this.isCountingDown = false;
                    if (countdownEl) {
                        countdownEl.textContent = '✓';
                        countdownEl.style.color = '#2ed573';
                    }
                    if (proceedBtn) {
                        proceedBtn.disabled = false;
                    }
                }
            }, 1000);
        },

        hide() {
            if (this.element) {
                this.element.remove();
                this.element = null;
            }
            if (this.countdownTimer) {
                clearInterval(this.countdownTimer);
                this.countdownTimer = null;
            }
            document.body.style.filter = 'none';
            document.body.style.overflow = '';
            this.isCountingDown = false;
            Logger.info('Protection overlay hidden');
        },

        leavePage() {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = 'about:blank';
            }
        },

        proceedAnyway() {
            if (this.isCountingDown) {
                alert('Please wait for the countdown to complete for your safety.');
                return;
            }

            chrome.runtime.sendMessage({
                action: 'recordDecision',
                decision: 'proceed',
                url: window.location.href
            });

            this.hide();
            BannerManager.show('You have chosen to proceed. Be extremely careful with any information you share.', 'warning');
        }
    };

    // ============================================================================
    // WARNING BANNER MANAGER
    // ============================================================================

    const BannerManager = {
        element: null,

        show(message, type = 'warning') {
            if (this.element) {
                this.element.remove();
            }

            StyleManager.inject();

            this.element = document.createElement('div');
            this.element.className = 'phishing-warning-banner';

            if (type === 'danger') {
                this.element.style.background = 'linear-gradient(90deg, #ff4757, #ff6b81)';
            } else if (type === 'warning') {
                this.element.style.background = 'linear-gradient(90deg, #ffa502, #ffbe76)';
            }

            this.element.innerHTML = `
                <span>${message}</span>
                <button class="close-btn" onclick="this.parentElement.remove()">×</button>
            `;

            document.body.insertBefore(this.element, document.body.firstChild);

            if (type === 'danger') {
                setTimeout(() => this.hide(), 10000);
            }
        },

        hide() {
            if (this.element) {
                this.element.remove();
                this.element = null;
            }
        }
    };

    // ============================================================================
    // INPUT SHIELD MANAGER
    // ============================================================================

    const InputShieldManager = {
        shieldedInputs: new Set(),

        shield() {
            const selector = CONFIG.SELECTORS.SENSITIVE_INPUTS.join(', ');
            const inputs = document.querySelectorAll(selector);

            inputs.forEach(input => {
                if (this.shieldedInputs.has(input)) return;

                this.shieldedInputs.add(input);
                input.classList.add('phishing-input-shield');

                const originalFocus = input.onfocus;
                input.addEventListener('focus', (e) => {
                    e.preventDefault();
                    input.blur();
                    BannerManager.show('⚠️ This page has been flagged. Do not enter sensitive information!', 'danger');
                    Logger.warn('Blocked focus on sensitive input');
                }, true);
            });
        },

        reset() {
            this.shieldedInputs.forEach(input => {
                input.classList.remove('phishing-input-shield');
            });
            this.shieldedInputs.clear();
        }
    };

    // ============================================================================
    // URL BREAKDOWN DISPLAY
    // ============================================================================

    const URLBreakdownManager = {
        element: null,

        show(url, brandMatches, intentAnalysis) {
            if (this.element) {
                this.element.remove();
            }

            StyleManager.inject();

            try {
                const urlObj = new URL(url);
                let html = `<strong>URL Breakdown:</strong><br>`;
                html += `<span style="color: #3498db;">${Utils.escapeHtml(urlObj.protocol)}://</span>`;
                html += `<span>${Utils.escapeHtml(urlObj.hostname)}</span>`;

                if (brandMatches && brandMatches.length > 0) {
                    html += `<br><span class="brand">⚠️ Typosquatting: ${brandMatches.map(m => m.matchedBrand).join(', ')}</span>`;
                }

                if (intentAnalysis && intentAnalysis.detected) {
                    const keywords = [
                        ...intentAnalysis.detected.URGENCY || [],
                        ...intentAnalysis.detected.FEAR || [],
                        ...intentAnalysis.detected.AUTHORITY || []
                    ].slice(0, 5);

                    if (keywords.length > 0) {
                        html += `<br><span class="urgency">Urgency/Fear words: ${keywords.join(', ')}</span>`;
                    }
                }

                this.element = document.createElement('div');
                this.element.className = 'phishing-url-breakdown';
                this.element.innerHTML = html;
                document.body.appendChild(this.element);

                setTimeout(() => this.hide(), CONFIG.UI.AUTO_HIDE_DELAY);
            } catch (e) {
                Logger.error('Error creating URL breakdown', e);
            }
        },

        hide() {
            if (this.element) {
                this.element.remove();
                this.element = null;
            }
        }
    };

    // ============================================================================
    // FORM PROTECTION
    // ============================================================================

    const FormProtection = {
        protectedForms: new WeakSet(),

        protect() {
            const forms = document.querySelectorAll('form');

            forms.forEach(form => {
                if (this.protectedForms.has(form)) return;

                this.protectedForms.add(form);

                form.addEventListener('submit', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    BannerManager.show('Form submission blocked. This page may be a phishing attempt.', 'danger');
                    Logger.warn('Blocked form submission');
                    return false;
                }, true);
            });
        }
    };

    // ============================================================================
    // MESSAGE HANDLER
    // ============================================================================

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        switch (message.action) {
            case 'updateProtection':
                if (message.level === 'block') {
                    OverlayManager.show(message.data);
                    FormProtection.protect();
                } else if (message.level === 'warn') {
                    BannerManager.show(message.message, 'warning');
                    InputShieldManager.shield();
                } else if (message.level === 'clear') {
                    OverlayManager.hide();
                    BannerManager.hide();
                    InputShieldManager.reset();
                }
                sendResponse({ success: true });
                break;

            case 'showBreakdown':
                URLBreakdownManager.show(message.url, message.brands, message.intent);
                sendResponse({ success: true });
                break;
        }
        return false;
    });

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    function initialize() {
        Logger.info('Content script initializing');

        StyleManager.inject();

        chrome.runtime.sendMessage({
            action: 'analyzeURL',
            url: window.location.href
        }, (response) => {
            if (response && response.success) {
                if (response.shouldBlock) {
                    OverlayManager.show(response);
                    FormProtection.protect();
                } else if (response.shouldWarn) {
                    BannerManager.show('⚠️ This URL has some suspicious indicators. Proceed with caution.', 'warning');
                    InputShieldManager.shield();
                }

                if (response.brandMatches && response.brandMatches.length > 0) {
                    URLBreakdownManager.show(window.location.href, response.brandMatches, response);
                }
            }
        });

        setInterval(() => {
            InputShieldManager.shield();
        }, CONFIG.UI.CHECK_INTERVAL);

        Logger.info('Content script initialized');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

})();
