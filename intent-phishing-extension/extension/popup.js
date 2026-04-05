/**
 * Intent-Aware Phishing Detection System
 * Popup Interface JavaScript
 * 
 * Manages the extension popup UI, displays analysis results,
 * and provides user interaction controls.
 * 
 * @version 1.0.0
 */

(function() {
    'use strict';

    // ============================================================================
    // CONFIGURATION
    // ============================================================================

    const CONFIG = {
        REFRESH_INTERVAL: 30000,
        EXTERNAL_REPORTS: [
            { name: 'VirusTotal', baseUrl: 'https://www.virustotal.com/gui/home/search/' },
            { name: 'Google Safe Browsing', baseUrl: 'https://transparencyreport.google.com/safe-browsing/search?url=' },
            { name: 'URLVoid', baseUrl: 'https://www.urlvoid.com/scan/' }
        ]
    };

    // ============================================================================
    // LOGGER
    // ============================================================================

    const Logger = {
        log(level, message, data) {
            const prefix = `[PhishGuard:Popup]`;
            const logFn = level === 'error' ? console.error : console.log;
            if (data) {
                logFn(`${prefix} ${message}`, data);
            } else {
                logFn(`${prefix} ${message}`);
            }
        },
        info(msg, data) { this.log('info', msg, data); },
        error(msg, data) { this.log('error', msg, data); }
    };

    // ============================================================================
    // UTILITIES
    // ============================================================================

    const Utils = {
        escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        truncateUrl(url, maxLength = 50) {
            if (!url || url.length <= maxLength) return url;
            return url.substring(0, maxLength) + '...';
        },

        getRiskColors(score) {
            if (score >= 70) {
                return { color: '#dc3545', bg: '#f8d7da', text: 'BLOCK' };
            }
            if (score >= 30) {
                return { color: '#fd7e14', bg: '#fff3cd', text: 'WARNING' };
            }
            return { color: '#198754', bg: '#d1e7dd', text: 'SAFE' };
        },

        getRiskIcon(level) {
            const icons = {
                'BLOCK': '🚫',
                'WARNING': '⚠️',
                'SAFE': '✅',
                'unknown': '⏳'
            };
            return icons[level] || icons.unknown;
        }
    };

    // ============================================================================
    // DOM ELEMENTS
    // ============================================================================

    class DOMElements {
        constructor() {
            this.cache = {};
        }

        get(id) {
            if (!this.cache[id]) {
                this.cache[id] = document.getElementById(id);
            }
            return this.cache[id];
        }

        getAll(ids) {
            return ids.map(id => this.get(id));
        }
    }

    // ============================================================================
    // UI MANAGER
    // ============================================================================

    class UIManager {
        constructor(elements) {
            this.elements = elements;
            this.currentAnalysis = null;
            this.currentUrl = '';
        }

        updateStatus(status, text) {
            const badge = this.elements.get('statusBadge');
            if (badge) {
                badge.className = `status-badge ${status}`;
                const textEl = badge.querySelector('.status-text');
                if (textEl) {
                    textEl.textContent = text;
                }
            }
        }

        updateRiskGauge(score) {
            const colors = Utils.getRiskColors(score);

            const scoreEl = this.elements.get('riskScore');
            if (scoreEl) {
                scoreEl.textContent = score;
                scoreEl.style.color = colors.color;
            }

            const circleEl = this.elements.get('riskCircle');
            if (circleEl) {
                circleEl.style.borderColor = colors.color;
                circleEl.style.background = `conic-gradient(${colors.color} ${score}%, transparent ${score}%)`;
            }

            const fillEl = this.elements.get('riskFill');
            if (fillEl) {
                fillEl.style.width = `${score}%`;
                fillEl.style.background = colors.color;
            }
        }

        updateDecisionBanner(analysis) {
            const colors = Utils.getRiskColors(analysis.riskScore);
            const banner = this.elements.get('decisionBanner');
            const icon = this.elements.get('decisionIcon');
            const title = this.elements.get('decisionTitle');
            const desc = this.elements.get('decisionDesc');

            if (banner) {
                banner.style.background = colors.bg;
                banner.style.borderColor = colors.color;
            }

            if (icon) {
                icon.textContent = analysis.icon || Utils.getRiskIcon(analysis.riskLevel);
            }

            if (title) {
                title.textContent = analysis.action || analysis.riskLevel;
                title.style.color = colors.color;
            }

            if (desc) {
                let description = '';
                if (analysis.shouldBlock) {
                    description = 'This URL shows strong indicators of a phishing attempt. Access has been blocked.';
                } else if (analysis.shouldWarn) {
                    description = 'This URL has some suspicious characteristics. Please review carefully before proceeding.';
                } else {
                    description = 'This URL appears to be safe based on our analysis.';
                }
                desc.textContent = description;
            }
        }

        updateFactorsList(factors) {
            const list = this.elements.get('factorsList');
            if (!list) return;

            if (!factors || factors.length === 0) {
                list.innerHTML = '<div class="factor-item empty">No significant risk factors detected</div>';
                return;
            }

            list.innerHTML = factors.map(factor => `
                <div class="factor-item">
                    <div class="factor-icon">⚠️</div>
                    <div class="factor-content">
                        <span class="factor-name">${Utils.escapeHtml(factor.name)}</span>
                        <span class="factor-detail">${Utils.escapeHtml(factor.detail || `+${factor.score} points`)}</span>
                    </div>
                </div>
            `).join('');
        }

        updateAttackSection(attack) {
            const section = this.elements.get('attackSection');
            const cards = this.elements.get('attackCards');
            
            if (!section || !cards) return;

            if (!attack) {
                section.style.display = 'none';
                return;
            }

            section.style.display = 'block';
            cards.innerHTML = `
                <div class="attack-card">
                    <div class="attack-header">
                        <span class="attack-type">${attack.type || 'UNKNOWN'}</span>
                        <span class="attack-confidence">${Math.round(attack.confidence || attack.score || 0)}%</span>
                    </div>
                    <div class="attack-name">${Utils.escapeHtml(attack.name || 'Attack Detected')}</div>
                    <div class="attack-evidence">
                        ${(attack.evidence || []).slice(0, 3).map(e => 
                            `<span>${Utils.escapeHtml(e)}</span>`
                        ).join('')}
                    </div>
                </div>
            `;
        }

        updateURLBreakdown(analysis) {
            if (!analysis || !analysis.parsed) return;

            const parsed = analysis.parsed;
            
            const protocolEl = this.elements.get('partProtocol');
            if (protocolEl) {
                protocolEl.textContent = parsed.protocol.toUpperCase();
                protocolEl.className = `part-value ${parsed.protocol === 'https' ? 'secure' : 'insecure'}`;
            }

            const domainEl = this.elements.get('partDomain');
            if (domainEl) {
                let domainText = parsed.hostname;
                if (analysis.brandMatches && analysis.brandMatches.length > 0) {
                    domainText += ` (impersonating: ${analysis.brandMatches.map(m => m.matchedBrand).join(', ')})`;
                }
                domainEl.textContent = Utils.truncateUrl(domainText, 40);
                domainEl.className = `part-value ${analysis.brandMatches?.length > 0 ? 'suspicious' : ''}`;
            }

            const pathEl = this.elements.get('partPath');
            if (pathEl) {
                pathEl.textContent = Utils.truncateUrl(parsed.pathname, 35);
            }
        }

        updateHighlightedUrl(analysis) {
            const container = this.elements.get('highlightedUrl');
            if (!container || !analysis || !analysis.parsed) return;

            const parsed = analysis.parsed;
            const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking'];
            
            let html = `<span class="hl-protocol">${Utils.escapeHtml(parsed.protocol)}://</span>`;

            if (parsed.subdomain) {
                html += `<span class="hl-subdomain">${Utils.escapeHtml(parsed.subdomain)}.</span>`;
            }

            let domainClass = 'hl-domain';
            if (analysis.exactBrands?.length > 0) {
                domainClass = 'hl-brand';
            } else if (analysis.brandMatches?.length > 0) {
                domainClass = 'hl-typosquat';
            }
            html += `<span class="${domainClass}">${Utils.escapeHtml(parsed.domain)}</span>`;
            html += `<span class="hl-tld">.${Utils.escapeHtml(parsed.tld)}</span>`;

            if (parsed.pathname && parsed.pathname !== '/') {
                const pathParts = parsed.pathname.split('/');
                pathParts.forEach((part, i) => {
                    if (i === 0) return;
                    
                    const lowerPart = part.toLowerCase();
                    let partClass = 'hl-path';
                    
                    if (suspiciousKeywords.some(kw => lowerPart.includes(kw))) {
                        partClass = 'hl-action';
                    }
                    
                    html += `<span class="${partClass}">/${Utils.escapeHtml(part)}</span>`;
                });
            }

            container.innerHTML = html;
        }

        updateRecommendations(analysis) {
            const list = this.elements.get('recommendationsList');
            if (!list) return;

            const recommendations = [];

            if (analysis.shouldBlock) {
                recommendations.push('Do NOT enter any personal information on this page');
                recommendations.push('Close this tab immediately');
                recommendations.push('If you entered credentials, change them on the real site');
                recommendations.push('Report this URL to your IT/security team');
            } else if (analysis.shouldWarn) {
                recommendations.push('Verify the URL matches the official website');
                recommendations.push('Do not enter passwords - use bookmarks instead');
                recommendations.push('Check for HTTPS and valid certificates');
                recommendations.push('Look for spelling errors in the URL');
            } else {
                recommendations.push('Continue to browse safely');
                recommendations.push('Always verify URLs before entering sensitive data');
                recommendations.push('Keep your browser and security software updated');
            }

            list.innerHTML = recommendations.map(r => 
                `<li class="recommendation-item">💡 ${Utils.escapeHtml(r)}</li>`
            ).join('');
        }

        updateStats(stats) {
            const blocked = this.elements.get('statBlocked');
            const warned = this.elements.get('statWarned');
            const allowed = this.elements.get('statAllowed');

            if (blocked) blocked.textContent = stats.blocked || 0;
            if (warned) warned.textContent = stats.warned || 0;
            if (allowed) allowed.textContent = stats.allowed || 0;
        }

        updateURLDisplay(url) {
            const container = this.elements.get('currentUrl');
            if (!container) return;

            if (!url || url.startsWith('chrome://') || url.startsWith('about:')) {
                container.innerHTML = '<span class="url-text">Cannot analyze browser pages</span>';
                return;
            }

            container.innerHTML = `<span class="url-text" title="${Utils.escapeHtml(url)}">${Utils.escapeHtml(Utils.truncateUrl(url, 60))}</span>`;
        }

        showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            document.body.appendChild(notification);

            setTimeout(() => notification.remove(), 3000);
        }
    }

    // ============================================================================
    // ANALYSIS SERVICE
    // ============================================================================

    class AnalysisService {
        static async getCurrentTab() {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            return tab;
        }

        static async analyzeURL(url) {
            return new Promise((resolve) => {
                chrome.runtime.sendMessage({
                    action: 'analyzeURL',
                    url
                }, resolve);
            });
        }

        static async getStats() {
            return new Promise((resolve) => {
                chrome.runtime.sendMessage({ action: 'getStats' }, resolve);
            });
        }

        static async recordDecision(decision, url, riskScore) {
            return new Promise((resolve) => {
                chrome.runtime.sendMessage({
                    action: 'recordDecision',
                    decision,
                    url,
                    riskScore
                }, resolve);
            });
        }
    }

    // ============================================================================
    // REPORT GENERATOR
    // ============================================================================

    class ReportGenerator {
        static generate(analysis, url) {
            if (!analysis) return '';

            const lines = [
                '🛡️ PHISHING DETECTION REPORT',
                '═══════════════════════════════',
                '',
                `URL: ${url}`,
                `Risk Score: ${analysis.riskScore}/100`,
                `Status: ${analysis.riskLevel}`,
                `Decision: ${analysis.action}`,
                '',
                'Risk Factors:',
                ...(analysis.factors || []).map(f => `• ${f.name}: ${f.detail || f.score}`),
                ''
            ];

            if (analysis.primaryAttack) {
                lines.push(`Attack Type: ${analysis.primaryAttack.name}`);
            }

            lines.push('', 'Generated by PhishGuard - Intent-Aware Phishing Detection');

            return lines.filter(Boolean).join('\n');
        }
    }

    // ============================================================================
    // MAIN APPLICATION
    // ============================================================================

    class PopupApp {
        constructor() {
            this.elements = new DOMElements();
            this.ui = new UIManager(this.elements);
            this.currentAnalysis = null;
            this.refreshInterval = null;
        }

        async initialize() {
            Logger.info('Popup initializing');

            this.bindEvents();
            await this.runAnalysis();

            this.refreshInterval = setInterval(
                () => this.runAnalysis(),
                CONFIG.REFRESH_INTERVAL
            );

            Logger.info('Popup initialized');
        }

        bindEvents() {
            const viewDetailsBtn = this.elements.get('btnViewDetails');
            const shareBtn = this.elements.get('btnShare');

            if (viewDetailsBtn) {
                viewDetailsBtn.addEventListener('click', () => this.openExternalReport());
            }

            if (shareBtn) {
                shareBtn.addEventListener('click', () => this.copyReport());
            }
        }

        async runAnalysis() {
            this.ui.updateStatus('analyzing', 'Analyzing...');

            try {
                const tab = await AnalysisService.getCurrentTab();
                const url = tab?.url || '';

                if (!url || url.startsWith('chrome://') || url.startsWith('about:')) {
                    this.ui.updateStatus('unknown', 'N/A');
                    this.ui.updateURLDisplay(url);
                    this.ui.updateRiskGauge(0);
                    return;
                }

                this.ui.updateURLDisplay(url);

                const analysis = await AnalysisService.analyzeURL(url);

                if (!analysis || !analysis.success) {
                    this.ui.updateStatus('error', 'Analysis Error');
                    return;
                }

                this.currentAnalysis = analysis;

                const statusType = analysis.shouldBlock ? 'danger' : 
                                   analysis.shouldWarn ? 'warning' : 'safe';

                this.ui.updateStatus(statusType, analysis.riskLevel || 'Unknown');
                this.ui.updateRiskGauge(analysis.riskScore);
                this.ui.updateDecisionBanner(analysis);
                this.ui.updateFactorsList(analysis.factors);
                this.ui.updateAttackSection(analysis.primaryAttack);
                this.ui.updateURLBreakdown(analysis);
                this.ui.updateHighlightedUrl(analysis);
                this.ui.updateRecommendations(analysis);

                const stats = await AnalysisService.getStats();
                this.ui.updateStats(stats);

            } catch (error) {
                Logger.error('Analysis error', error);
                this.ui.updateStatus('error', 'Error');
            }
        }

        openExternalReport() {
            if (!this.currentAnalysis || !this.currentAnalysis.parsed) return;

            const report = CONFIG.EXTERNAL_REPORTS[0];
            const url = `${report.baseUrl}${encodeURIComponent(window.location.href)}`;
            chrome.tabs.create({ url });
        }

        async copyReport() {
            if (!this.currentAnalysis) return;

            const report = ReportGenerator.generate(
                this.currentAnalysis,
                this.currentAnalysis.parsed?.full || window.location.href
            );

            try {
                await navigator.clipboard.writeText(report);
                this.ui.showNotification('Report copied to clipboard!', 'success');
            } catch (error) {
                Logger.error('Failed to copy report', error);
                this.ui.showNotification('Failed to copy report', 'error');
            }
        }

        destroy() {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
            }
        }
    }

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    document.addEventListener('DOMContentLoaded', () => {
        const app = new PopupApp();
        app.initialize();

        window.addEventListener('unload', () => {
            app.destroy();
        });
    });

})();
