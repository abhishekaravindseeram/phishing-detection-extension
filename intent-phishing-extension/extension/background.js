/**
 * Intent-Aware Phishing Detection System
 * Background Service Worker
 * 
 * Orchestrates URL analysis, manages state, and coordinates
 * communication between popup and content scripts.
 * 
 * @version 1.0.0
 * @author Security Team
 */

(function() {
    'use strict';

    // ============================================================================
    // IMPORTS (Simulated - in production, use proper bundler)
    // ============================================================================

    const CONFIG = window.PHISHGUARD_CONFIG;
    const ALL_BRANDS = window.PHISHGUARD_BRANDS;
    const Logger = window.Logger || {
        defaultLogger: {
            info: (...args) => console.log('[INFO]', ...args),
            warn: (...args) => console.warn('[WARN]', ...args),
            error: (...args) => console.error('[ERROR]', ...args),
            logAnalysis: () => {},
            logThreat: () => {},
            logDecision: () => {},
            logError: () => {}
        }
    };

    const logger = Logger.defaultLogger;

    // ============================================================================
    // STATE MANAGEMENT
    // ============================================================================

    const State = {
        analysisCache: new Map(),
        currentTabAnalysis: new Map(),
        stats: {
            blocked: 0,
            warned: 0,
            allowed: 0,
            totalAnalyzed: 0,
            startTime: Date.now()
        },
        
        getStats() {
            return { ...this.stats };
        },

        incrementStat(type) {
            if (this.stats.hasOwnProperty(type)) {
                this.stats[type]++;
            }
        },

        addToCache(url, result, ttl = 300000) {
            this.analysisCache.set(url, {
                result,
                timestamp: Date.now(),
                ttl
            });
        },

        getFromCache(url) {
            const cached = this.analysisCache.get(url);
            if (cached && (Date.now() - cached.timestamp) < cached.ttl) {
                return cached.result;
            }
            return null;
        },

        clearExpiredCache() {
            const now = Date.now();
            for (const [url, data] of this.analysisCache.entries()) {
                if ((now - data.timestamp) >= data.ttl) {
                    this.analysisCache.delete(url);
                }
            }
        }
    };

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    /**
     * Calculate Shannon entropy of a string
     * @param {string} str - Input string
     * @returns {number} Entropy score (0-8)
     */
    function calculateEntropy(str) {
        if (!str || str.length === 0) return 0;
        
        const charFreq = {};
        const len = str.length;
        
        for (const char of str) {
            charFreq[char] = (charFreq[char] || 0) + 1;
        }
        
        let entropy = 0;
        for (const char in charFreq) {
            const probability = charFreq[char] / len;
            entropy -= probability * Math.log2(probability);
        }
        
        return entropy;
    }

    /**
     * Parse URL into structured components
     * @param {string} url - URL to parse
     * @returns {object|null} Parsed URL or null if invalid
     */
    function parseURL(url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;
            const parts = hostname.split('.');
            
            let subdomain = '', domain = '', tld = '';
            
            if (parts.length >= 3) {
                subdomain = parts.slice(0, -2).join('.');
                domain = parts[parts.length - 2];
                tld = parts[parts.length - 1];
            } else if (parts.length === 2) {
                domain = parts[0];
                tld = parts[1];
            } else {
                domain = hostname;
            }
            
            return {
                full: url,
                protocol: urlObj.protocol.replace(':', ''),
                hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
                pathname: urlObj.pathname,
                search: urlObj.search,
                hash: urlObj.hash,
                username: urlObj.username,
                password: urlObj.password,
                subdomain,
                domain,
                tld,
                pathParts: urlObj.pathname.split('/').filter(p => p.length > 0),
                allParts: parts
            };
        } catch (error) {
            logger.logError('parseURL', error);
            return null;
        }
    }

    /**
     * Calculate Levenshtein distance between two strings
     * @param {string} a - First string
     * @param {string} b - Second string
     * @returns {number} Edit distance
     */
    function levenshteinDistance(a, b) {
        const matrix = [];
        
        for (let i = 0; i <= b.length; i++) {
            matrix[i] = [i];
        }
        
        for (let j = 0; j <= a.length; j++) {
            matrix[0][j] = j;
        }
        
        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) === a.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        
        return matrix[b.length][a.length];
    }

    /**
     * Extract all words from URL for analysis
     * @param {string} url - URL to extract from
     * @returns {string[]} Array of words
     */
    function extractWordsFromURL(url) {
        const parsed = parseURL(url);
        if (!parsed) return [];
        
        const words = [];
        
        if (parsed.subdomain) {
            words.push(...parsed.subdomain.split(/[-._]/));
        }
        if (parsed.domain) {
            words.push(parsed.domain);
        }
        words.push(...parsed.pathParts.flatMap(part => part.split(/[-._]/)));
        
        const queryWords = parsed.search.replace('?', '').split(/[&=]/)
            .flatMap(param => param.split(/[-._]/));
        words.push(...queryWords);
        
        return words.filter(w => w.length > 1);
    }

    /**
     * Find similar brand names in URL (typosquatting detection)
     * @param {string} url - URL to check
     * @param {string[]} brands - Known brand names
     * @param {number} threshold - Maximum edit distance
     * @returns {object[]} Matches with similarity scores
     */
    function findSimilarBrands(url, brands, threshold = 2) {
        const words = extractWordsFromURL(url.toLowerCase());
        const matches = [];
        
        for (const brand of brands) {
            const brandLower = brand.toLowerCase();
            
            for (const word of words) {
                if (word === brandLower) continue;
                
                const distance = levenshteinDistance(word, brandLower);
                
                if (distance <= threshold && distance > 0) {
                    const similarity = 1 - (distance / Math.max(word.length, brandLower.length));
                    matches.push({
                        original: word,
                        matchedBrand: brand,
                        distance,
                        similarity,
                        isTypo: distance <= 1
                    });
                }
            }
        }
        
        return matches;
    }

    /**
     * Check if hostname contains IP address
     * @param {string} hostname - Hostname to check
     * @returns {object} IP info or null
     */
    function extractIPAddress(hostname) {
        const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
        const match = hostname.match(ipPattern);
        
        if (match) {
            const parts = match[1].split('.').map(Number);
            const isPrivate = (parts[0] === 10) ||
                (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
                (parts[0] === 192 && parts[1] === 168) ||
                (parts[0] === 127);
            
            return { found: true, ip: match[1], isPrivate };
        }
        
        return { found: false };
    }

    /**
     * Check for hex encoding in URL
     * @param {string} str - String to check
     * @returns {boolean}
     */
    function hasHexEncoding(str) {
        return /%[0-9A-Fa-f]{2}/.test(str);
    }

    /**
     * Check for punycode encoding
     * @param {string} str - String to check
     * @returns {boolean}
     */
    function detectPunycode(str) {
        return str.includes('xn--');
    }

    // ============================================================================
    // URL ANALYSIS ENGINE
    // ============================================================================

    const URLAnalyzer = {
        analyzeURL(url) {
            const startTime = performance.now();
            const parsed = parseURL(url);
            
            if (!parsed) {
                return {
                    success: false,
                    error: 'Invalid URL format',
                    duration: performance.now() - startTime
                };
            }

            const hostname = parsed.hostname;
            const ipCheck = extractIPAddress(hostname);
            const brandMatches = findSimilarBrands(url, ALL_BRANDS, 2);
            const exactBrands = ALL_BRANDS.filter(brand => 
                url.toLowerCase().includes(brand.toLowerCase())
            );
            
            const indicators = [];
            
            if (ipCheck.found) {
                indicators.push(ipCheck.isPrivate ? 
                    'Uses private IP address' : 
                    'Uses IP address instead of domain'
                );
            }
            
            if (CONFIG.SUSPICIOUS_TLDS.includes(parsed.tld.toLowerCase())) {
                indicators.push(`Suspicious TLD: .${parsed.tld}`);
            }
            
            if (parsed.domain.length > 30) {
                indicators.push('Unusually long domain');
            }
            
            const subdomainCount = parsed.subdomain ? parsed.subdomain.split('.').length : 0;
            if (subdomainCount > 3) {
                indicators.push('Excessive subdomains');
            }
            
            if (detectPunycode(hostname)) {
                indicators.push('Punycode/IDN domain');
            }
            
            const encodedSegments = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
            if (encodedSegments > 5) {
                indicators.push('Heavy URL encoding');
            }
            
            if (parsed.protocol === 'http') {
                indicators.push('Insecure HTTP connection');
            }
            
            if (url.includes('@')) {
                indicators.push('URL contains @ symbol (hides real address)');
            }
            
            brandMatches.forEach(match => {
                indicators.push(`Possible typosquatting: "${match.original}" → "${match.matchedBrand}"`);
            });
            
            const pathLower = parsed.pathname.toLowerCase();
            for (const keyword of CONFIG.ACTION_WORDS) {
                if (pathLower.includes(keyword)) {
                    indicators.push(`Path contains action keyword: "${keyword}"`);
                }
            }

            return {
                success: true,
                parsed,
                ip: ipCheck,
                subdomainCount,
                encodedSegments,
                domainLength: parsed.domain.length,
                brandMatches,
                exactBrands,
                indicators,
                indicatorCount: indicators.length,
                entropy: calculateEntropy(parsed.domain),
                isSuspiciousTLD: CONFIG.SUSPICIOUS_TLDS.includes(parsed.tld.toLowerCase()),
                hasSensitiveParams: CONFIG.SENSITIVE_PARAMS.some(param => 
                    parsed.search.toLowerCase().includes(param)
                ),
                duration: performance.now() - startTime
            };
        }
    };

    // ============================================================================
    // INTENT DETECTION ENGINE
    // ============================================================================

    const IntentEngine = {
        analyzeIntent(url) {
            const startTime = performance.now();
            const lowerURL = url.toLowerCase();
            
            const detected = {
                AUTHORITY: [],
                URGENCY: [],
                FEAR: [],
                GREED: [],
                ACTIONS: []
            };

            for (const type in CONFIG.ATTACK_PATTERNS) {
                const pattern = CONFIG.ATTACK_PATTERNS[type];
                for (const keyword of pattern.indicators) {
                    if (lowerURL.includes(keyword)) {
                        detected[type].push(keyword);
                    }
                }
            }

            for (const word of CONFIG.ACTION_WORDS) {
                if (lowerURL.includes(word)) {
                    detected.ACTIONS.push(word);
                }
            }

            let primaryAttack = null;
            
            if (detected.FEAR.length > 0) {
                primaryAttack = {
                    type: 'FEAR',
                    name: CONFIG.ATTACK_PATTERNS.FEAR.name,
                    confidence: Math.min(100, 30 + detected.FEAR.length * 10)
                };
            } else if (detected.AUTHORITY.length > 0 && detected.ACTIONS.length > 0) {
                primaryAttack = {
                    type: 'AUTHORITY',
                    name: CONFIG.ATTACK_PATTERNS.AUTHORITY.name,
                    confidence: Math.min(100, 25 + detected.AUTHORITY.length * 8)
                };
            } else if (detected.URGENCY.length > 0) {
                primaryAttack = {
                    type: 'URGENCY',
                    name: CONFIG.ATTACK_PATTERNS.URGENCY.name,
                    confidence: Math.min(100, 20 + detected.URGENCY.length * 8)
                };
            } else if (detected.GREED.length > 0) {
                primaryAttack = {
                    type: 'GREED',
                    name: CONFIG.ATTACK_PATTERNS.GREED.name,
                    confidence: Math.min(100, 15 + detected.GREED.length * 8)
                };
            }

            let intentScore = 0;
            intentScore += detected.FEAR.length * 10;
            intentScore += detected.AUTHORITY.length * 6;
            intentScore += detected.URGENCY.length * 8;
            intentScore += detected.GREED.length * 5;
            intentScore += detected.ACTIONS.length * 4;

            return {
                success: true,
                detected,
                primaryAttack,
                intentScore: Math.min(100, intentScore),
                hasUrgency: detected.URGENCY.length > 0,
                hasFear: detected.FEAR.length > 0,
                totalIndicators: detected.FEAR.length + detected.AUTHORITY.length + 
                    detected.URGENCY.length + detected.GREED.length,
                duration: performance.now() - startTime
            };
        }
    };

    // ============================================================================
    // RISK SCORING ENGINE
    // ============================================================================

    const RiskEngine = {
        calculateRiskScore(url) {
            const startTime = performance.now();
            
            const urlAnalysis = URLAnalyzer.analyzeURL(url);
            const intentAnalysis = IntentEngine.analyzeIntent(url);
            
            if (!urlAnalysis.success) {
                return {
                    success: false,
                    error: urlAnalysis.error,
                    duration: performance.now() - startTime
                };
            }

            let totalScore = 0;
            const factors = [];
            
            let structureScore = 0;
            
            if (urlAnalysis.ip.found) {
                structureScore += urlAnalysis.ip.isPrivate ? 15 : 25;
                factors.push({
                    name: 'IP Address Usage',
                    score: urlAnalysis.ip.isPrivate ? 15 : 25,
                    detail: urlAnalysis.ip.isPrivate ? 'Private IP detected' : 'Public IP used'
                });
            }
            
            if (urlAnalysis.isSuspiciousTLD) {
                structureScore += 12;
                factors.push({
                    name: 'Suspicious TLD',
                    score: 12,
                    detail: `.${urlAnalysis.parsed.tld}`
                });
            }
            
            if (urlAnalysis.domainLength > 30) {
                structureScore += 8;
                factors.push({
                    name: 'Long Domain',
                    score: 8,
                    detail: `${urlAnalysis.domainLength} characters`
                });
            }
            
            if (urlAnalysis.subdomainCount > 3) {
                structureScore += 10;
                factors.push({
                    name: 'Excessive Subdomains',
                    score: 10,
                    detail: `${urlAnalysis.subdomainCount} levels`
                });
            }
            
            if (detectPunycode(urlAnalysis.parsed.hostname)) {
                structureScore += 20;
                factors.push({
                    name: 'Punycode Domain',
                    score: 20,
                    detail: 'Internationalized domain'
                });
            }
            
            if (urlAnalysis.encodedSegments > 5) {
                structureScore += 12;
                factors.push({
                    name: 'Heavy Encoding',
                    score: 12,
                    detail: `${urlAnalysis.encodedSegments} segments`
                });
            }
            
            if (urlAnalysis.hasSensitiveParams) {
                structureScore += 8;
                factors.push({
                    name: 'Sensitive Parameters',
                    score: 8,
                    detail: 'Contains sensitive data in URL'
                });
            }
            
            if (urlAnalysis.parsed.protocol === 'http') {
                structureScore += 10;
                factors.push({
                    name: 'Insecure HTTP',
                    score: 10,
                    detail: 'No encryption'
                });
            }
            
            structureScore = Math.min(40, structureScore);
            totalScore += structureScore;
            
            let brandScore = 0;
            for (const match of urlAnalysis.brandMatches) {
                const score = match.distance === 1 ? 25 : 15;
                brandScore += score;
                factors.push({
                    name: 'Typosquatting',
                    score,
                    detail: `"${match.original}" → "${match.matchedBrand}"`
                });
            }
            
            if (urlAnalysis.exactBrands.length > 0) {
                brandScore += urlAnalysis.exactBrands.length * 6;
                factors.push({
                    name: 'Brand Mentions',
                    score: urlAnalysis.exactBrands.length * 6,
                    detail: urlAnalysis.exactBrands.join(', ')
                });
            }
            
            brandScore = Math.min(30, brandScore);
            totalScore += brandScore;
            
            let intentResultScore = Math.min(30, intentAnalysis.intentScore);
            totalScore += intentResultScore;
            
            if (intentAnalysis.primaryAttack) {
                factors.push({
                    name: `${intentAnalysis.primaryAttack.type} Attack`,
                    score: intentResultScore,
                    detail: intentAnalysis.primaryAttack.name
                });
            }
            
            totalScore = Math.min(100, totalScore);
            
            const thresholds = CONFIG.RISK.THRESHOLDS;
            let riskLevel, riskColor, action, icon;
            
            if (totalScore >= thresholds.BLOCK) {
                riskLevel = 'BLOCK';
                riskColor = '#dc3545';
                action = 'BLOCK';
                icon = '🚫';
            } else if (totalScore >= thresholds.WARNING) {
                riskLevel = 'WARNING';
                riskColor = '#fd7e14';
                action = 'PROCEED WITH CAUTION';
                icon = '⚠️';
            } else {
                riskLevel = 'SAFE';
                riskColor = '#198754';
                action = 'SAFE TO PROCEED';
                icon = '✅';
            }

            const result = {
                success: true,
                riskScore: totalScore,
                riskLevel,
                riskColor,
                shouldBlock: totalScore >= thresholds.BLOCK,
                shouldWarn: totalScore >= thresholds.WARNING,
                action,
                icon,
                factors: factors.slice(0, 10),
                indicatorCount: urlAnalysis.indicatorCount,
                primaryAttack: intentAnalysis.primaryAttack,
                indicators: urlAnalysis.indicators,
                hasUrgency: intentAnalysis.hasUrgency,
                hasFear: intentAnalysis.hasFear,
                parsed: urlAnalysis.parsed,
                brandMatches: urlAnalysis.brandMatches,
                exactBrands: urlAnalysis.exactBrands,
                timestamp: new Date().toISOString(),
                duration: performance.now() - startTime
            };

            logger.logAnalysis(url, result);
            
            if (result.shouldBlock) {
                logger.logThreat('HIGH_RISK_URL', {
                    url,
                    score: totalScore,
                    attackType: result.primaryAttack?.type
                });
            }

            return result;
        }
    };

    // ============================================================================
    // MESSAGE HANDLERS
    // ============================================================================

    function handleAnalyzeURL(message, sendResponse) {
        const { url } = message;
        
        if (!url || typeof url !== 'string') {
            sendResponse({ success: false, error: 'Invalid URL' });
            return true;
        }

        try {
            const cachedResult = State.getFromCache(url);
            if (cachedResult) {
                sendResponse(cachedResult);
                return true;
            }

            const result = RiskEngine.calculateRiskScore(url);
            
            if (result.success) {
                State.addToCache(url, result);
                State.stats.totalAnalyzed++;
                
                if (result.shouldBlock) {
                    State.incrementStat('blocked');
                } else if (result.shouldWarn) {
                    State.incrementStat('warned');
                }
            }
            
            sendResponse(result);
        } catch (error) {
            logger.logError('handleAnalyzeURL', error);
            sendResponse({ success: false, error: error.message });
        }
        
        return true;
    }

    function handleGetCurrentAnalysis(sendResponse) {
        sendResponse({ success: true, analysis: null });
        return true;
    }

    function handleGetStats(sendResponse) {
        sendResponse(State.getStats());
        return true;
    }

    function handleRecordDecision(message, sendResponse) {
        const { decision, url } = message;
        
        State.incrementStat(decision === 'proceed' ? 'allowed' : 'blocked');
        logger.logDecision(url, decision, message.riskScore);
        
        sendResponse({ success: true });
        return true;
    }

    function handleLogThreat(message, sendResponse) {
        logger.logThreat(message.type, message.data);
        sendResponse({ success: true });
        return true;
    }

    function handleGetLogs(sendResponse) {
        sendResponse(logger.exportLogs());
        return true;
    }

    // ============================================================================
    // CHROME MESSAGING SETUP
    // ============================================================================

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        const handlers = {
            'analyzeURL': handleAnalyzeURL,
            'getCurrentAnalysis': handleGetCurrentAnalysis,
            'getStats': handleGetStats,
            'recordDecision': handleRecordDecision,
            'logThreat': handleLogThreat,
            'getLogs': handleGetLogs
        };

        const handler = handlers[message.action];
        if (handler) {
            return handler(message, sendResponse);
        }

        return false;
    });

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    function initialize() {
        logger.info('PhishGuard Service Worker initialized', {
            version: CONFIG.VERSION,
            brandsLoaded: ALL_BRANDS.length
        });

        setInterval(() => {
            State.clearExpiredCache();
        }, 60000);

        chrome.runtime.onInstalled.addListener((details) => {
            logger.info('Extension installed/updated', {
                reason: details.reason,
                version: chrome.runtime.getManifest().version
            });
        });
    }

    initialize();

})();
