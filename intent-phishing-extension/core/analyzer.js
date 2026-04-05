/**
 * Intent-Aware Phishing Detection System
 * URL Analysis Engine
 * 
 * Analyzes URL structure, extracts features, and identifies
 * suspicious patterns that indicate potential phishing attempts.
 */

const URLAnalyzer = (function() {
    // ============================================================================
    // CONFIGURATION & CONSTANTS
    // ============================================================================
    
    const CONFIG = {
        MAX_DOMAIN_LENGTH: 50,
        MAX_SUBDOMAIN_LENGTH: 100,
        MAX_PATH_LENGTH: 200,
        SUSPICIOUS_TLDS: [
            'xyz', 'top', 'club', 'online', 'site', 'website', 'work', 
            'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq', 'info', 'biz'
        ],
        KNOWN_CDN_PATTERNS: [
            'cloudfront.net', 'akamai.net', 'fastly.net', 'cloudflare.com',
            'azureedge.net', 'edgecast.net', 'cdn77.net', 'limelight.net'
        ],
        SUSPICIOUS_KEYWORDS: [
            'secure', 'verify', 'login', 'account', 'update', 'confirm',
            'banking', 'wallet', 'password', 'credential', 'authenticate',
            'suspend', 'unusual', 'suspicious', 'alert', 'warning', 'urgent',
            'limited', 'immediate', 'action', 'required', 'important'
        ],
        ENCODING_PATTERNS: [
            { pattern: /%[0-9A-Fa-f]{2}/g, name: 'URL Encoding' },
            { pattern: /\\x[0-9A-Fa-f]{2}/g, name: 'Hex Escape' },
            { pattern: /\0/g, name: 'Null Byte' }
        ],
        DECEPTIVE_PATTERNS: [
            { pattern: /[oO0]{2,}/g, name: 'Double Zero' },
            { pattern: /[lI1]{3,}/g, name: 'Triple I/L/1' },
            { pattern: /[a@4]{3,}/g, name: 'Triple A/@' }
        ]
    };

    // ============================================================================
    // FEATURE EXTRACTORS
    // ============================================================================

    /**
     * Extract all structural features from URL
     * @param {object} parsed - Parsed URL object from utils.parseURL
     * @returns {object} Extracted features
     */
    function extractStructuralFeatures(parsed) {
        if (!parsed) return null;

        return {
            domainLength: parsed.domain.length,
            subdomainLength: parsed.subdomain ? parsed.subdomain.length : 0,
            fullHostnameLength: parsed.hostname.length,
            pathDepth: parsed.pathParts.length,
            totalPathLength: parsed.pathname.length,
            hasSubdomain: parsed.subdomain.length > 0,
            subdomainCount: parsed.subdomain ? parsed.subdomain.split('.').length : 0,
            pathSegmentCount: parsed.pathParts.length,
            queryParamCount: parsed.search ? parsed.search.split('&').length : 0,
            hashPresent: parsed.hash.length > 0,
            hasPort: parsed.port !== '80' && parsed.port !== '443',
            portNumber: parseInt(parsed.port)
        };
    }

    /**
     * Extract character-based features
     * @param {object} parsed - Parsed URL object
     * @returns {object} Character features
     */
    function extractCharacterFeatures(parsed) {
        const hostname = parsed.hostname;
        const pathname = parsed.pathname;
        
        const hostnameChars = countSpecialChars(hostname);
        const fullUrlChars = countSpecialChars(parsed.full);

        return {
            hostnameCharDensity: hostnameChars.total / hostname.length,
            digitRatio: fullUrlChars.digitRatio,
            specialCharCount: fullUrlChars.total,
            hasHexEncoding: hasHexEncoding(parsed.full),
            hexEncodedSegments: (parsed.full.match(/%[0-9A-Fa-f]{2}/g) || []).length,
            hasUnusualChars: /[`~^]/.test(parsed.full),
            hasDataURL: parsed.protocol === 'data',
            hasJavascript: parsed.protocol === 'javascript',
            encodedPath: hasHexEncoding(pathname)
        };
    }

    /**
     * Analyze TLD characteristics
     * @param {string} tld - Top-level domain
     * @returns {object} TLD analysis
     */
    function analyzeTLD(tld) {
        const lowerTld = tld.toLowerCase();
        
        return {
            tld: tld,
            isSuspiciousTLD: CONFIG.SUSPICIOUS_TLDS.includes(lowerTld),
            isFreeTLD: CONFIG.SUSPICIOUS_TLDS.includes(lowerTld),
            tldLength: tld.length,
            isNumericTLD: /^\d+$/.test(tld),
            isMultiCharTLD: tld.length > 4
        };
    }

    /**
     * Check for punycode/IDN attacks
     * @param {string} hostname - Hostname to check
     * @returns {object} IDN analysis
     */
    function analyzeInternationalization(hostname) {
        const punycodeCheck = detectPunycode(hostname);
        
        return {
            isPunycode: punycodeCheck.isPunycode,
            punycodeDetails: punycodeCheck,
            hasMixedScript: hasMixedScripts(hostname),
            looksLikeIDN: /[^\x00-\x7F]/.test(hostname)
        };
    }

    /**
     * Check for mixed character scripts (Cyrillic/Latin lookalikes)
     * @param {string} str - String to check
     * @returns {boolean}
     */
    function hasMixedScripts(str) {
        const hasLatin = /[a-zA-Z]/.test(str);
        const hasCyrillic = /[\u0400-\u04FF]/.test(str);
        const hasGreek = /[\u0370-\u03FF]/.test(str);
        
        return (hasLatin && (hasCyrillic || hasGreek));
    }

    /**
     * Analyze subdomain structure
     * @param {string} subdomain - Subdomain string
     * @returns {object} Subdomain analysis
     */
    function analyzeSubdomain(subdomain) {
        if (!subdomain) {
            return {
                exists: false,
                segments: [],
                segmentCount: 0,
                isSuspicious: false,
                depth: 0
            };
        }

        const segments = subdomain.split('.');
        const suspiciousIndicators = [];

        // Check for excessive subdomains
        if (segments.length > 3) {
            suspiciousIndicators.push('excessive_subdomain_depth');
        }

        // Check for suspicious keywords in subdomains
        for (let segment of segments) {
            const lower = segment.toLowerCase();
            for (let keyword of CONFIG.SUSPICIOUS_KEYWORDS) {
                if (lower.includes(keyword)) {
                    suspiciousIndicators.push(`contains_keyword_${keyword}`);
                }
            }
        }

        // Check for long subdomain segments
        for (let segment of segments) {
            if (segment.length > 30) {
                suspiciousIndicators.push('unusually_long_segment');
                break;
            }
        }

        return {
            exists: true,
            full: subdomain,
            segments: segments,
            segmentCount: segments.length,
            isSuspicious: suspiciousIndicators.length > 0,
            suspiciousReasons: suspiciousIndicators,
            depth: segments.length
        };
    }

    /**
     * Analyze path structure for suspicious patterns
     * @param {string} pathname - URL path
     * @param {string} search - Query string
     * @returns {object} Path analysis
     */
    function analyzePath(pathname, search) {
        const pathParts = pathname.split('/').filter(p => p.length > 0);
        const pathChars = countSpecialChars(pathname);
        
        const suspiciousPaths = [];
        const lowerPath = pathname.toLowerCase();

        // Check for suspicious path keywords
        const pathKeywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking'];
        for (let keyword of pathKeywords) {
            if (lowerPath.includes(keyword)) {
                suspiciousPaths.push(`suspicious_keyword_${keyword}`);
            }
        }

        // Check for encoded segments
        const encodedSegments = pathname.match(/%[0-9A-Fa-f]{2}/g) || [];
        if (encodedSegments.length > 5) {
            suspiciousPaths.push('excessive_encoding');
        }

        // Check for path traversal attempts
        if (pathname.includes('../') || pathname.includes('..\\')) {
            suspiciousPaths.push('path_traversal');
        }

        // Check for data URLs in path
        if (lowerPath.includes('data:') || lowerPath.includes('javascript:')) {
            suspiciousPaths.push('dangerous_protocol_in_path');
        }

        // Analyze query parameters
        const queryParams = [];
        if (search && search.length > 1) {
            const params = search.substring(1).split('&');
            for (let param of params) {
                const [key, value] = param.split('=');
                queryParams.push({
                    key: decodeURIComponent(key || ''),
                    value: decodeURIComponent(value || ''),
                    isEncoded: value ? hasHexEncoding(value) : false
                });
            }
        }

        return {
            pathname: pathname,
            pathParts: pathParts,
            partCount: pathParts.length,
            hasEncoding: pathChars.percent > 0,
            encodedSegments: encodedSegments.length,
            isSuspicious: suspiciousPaths.length > 0,
            suspiciousReasons: suspiciousPaths,
            queryParams: queryParams,
            paramCount: queryParams.length,
            hasSensitiveParams: queryParams.some(p => 
                /password|passwd|pwd|secret|token|key|auth|cred/i.test(p.key)
            )
        };
    }

    /**
     * Analyze protocol security
     * @param {string} protocol - Protocol string
     * @returns {object} Protocol analysis
     */
    function analyzeProtocol(protocol) {
        return {
            protocol: protocol,
            isSecure: protocol === 'https',
            isInsecure: protocol === 'http',
            isDangerous: ['javascript', 'data', 'vbscript'].includes(protocol),
            isFile: protocol === 'file'
        };
    }

    /**
     * Check for IP address usage instead of domain
     * @param {string} hostname - Hostname to check
     * @returns {object} IP analysis
     */
    function analyzeIPAddress(hostname) {
        const ipCheck = extractIPAddress(hostname);
        
        if (ipCheck.found) {
            return {
                usesIP: true,
                ip: ipCheck.ip,
                isPrivate: ipCheck.isPrivate,
                isSuspicious: !ipCheck.isPrivate,
                reason: ipCheck.isPrivate ? 
                    'Using private IP address' : 
                    'Using public IP instead of domain'
            };
        }
        
        return {
            usesIP: false,
            ip: null,
            isPrivate: false,
            isSuspicious: false
        };
    }

    /**
     * Analyze brand-like appearances in URL
     * @param {string} url - Full URL
     * @param {string[]} knownBrands - List of known brand names
     * @returns {object} Brand analysis
     */
    function analyzeBrandAppearance(url, knownBrands) {
        const words = extractWordsFromURL(url.toLowerCase());
        const foundBrands = [];
        const brandMatches = findSimilarBrands(url, knownBrands, 2);
        
        for (let brand of knownBrands) {
            const lowerBrand = brand.toLowerCase();
            
            // Exact match
            for (let word of words) {
                if (word === lowerBrand) {
                    foundBrands.push({
                        brand: brand,
                        matchedText: word,
                        matchType: 'exact',
                        position: 'domain' // would need more complex logic for exact position
                    });
                }
            }
        }
        
        // Check for typosquatting
        const typosquatting = brandMatches.filter(m => m.distance <= 2);
        
        return {
            exactMatches: foundBrands,
            typosquatting: typosquatting,
            hasTyposquatting: typosquatting.length > 0,
            detectedBrands: [...new Set(foundBrands.map(b => b.brand))],
            brandCount: foundBrands.length
        };
    }

    // ============================================================================
    // SUSPICIOUS PATTERN DETECTION
    // ============================================================================

    /**
     * Detect various deception patterns
     * @param {string} url - URL to analyze
     * @returns {object} Detected patterns
     */
    function detectDeceptionPatterns(url) {
        const patterns = {
            visualDeception: [],
            technicalDeception: [],
            socialEngineering: []
        };

        // Visual deception - lookalike characters
        const urlLower = url.toLowerCase();
        
        // Check for @ symbol (often hides real URL)
        if (url.includes('@')) {
            patterns.socialEngineering.push({
                type: 'url_hiding',
                detail: 'Contains @ symbol which can hide the real address',
                severity: 'high'
            });
        }

        // Check for multiple hyphens in domain
        const domainMatch = url.match(/:\/\/([^\/]+)/);
        if (domainMatch) {
            const domain = domainMatch[1];
            const hyphenCount = (domain.match(/-/g) || []).length;
            if (hyphenCount > 3) {
                patterns.visualDeception.push({
                    type: 'excessive_hyphens',
                    detail: `Domain contains ${hyphenCount} hyphens`,
                    severity: 'medium'
                });
            }
        }

        // Check for repeated dots
        if (url.includes('..')) {
            patterns.technicalDeception.push({
                type: 'double_dots',
                detail: 'Contains consecutive dots which may cause path confusion',
                severity: 'medium'
            });
        }

        // Check for misleading keywords in path
        const pathKeywords = ['login', 'secure', 'account', 'verify', 'banking'];
        const pathname = url.match(/\/\/.*?(\/|$)/)?.[0] || '';
        for (let keyword of pathKeywords) {
            if (pathname.toLowerCase().includes(keyword)) {
                if (!urlLower.includes(keyword + '.com') && !urlLower.includes(keyword + '.org')) {
                    patterns.socialEngineering.push({
                        type: 'suspicious_path_keyword',
                        detail: `Path contains "${keyword}" keyword`,
                        severity: 'medium'
                    });
                }
            }
        }

        // Check for brand impersonation via subdomain
        const subdomainPatterns = [
            { brand: 'google', patterns: ['google-docs', 'google-drive', 'google-account'] },
            { brand: 'amazon', patterns: ['amazon-pay', 'amazon-account', 'amazon-verify'] },
            { brand: 'microsoft', patterns: ['microsoft-support', 'microsoft-login'] },
            { brand: 'apple', patterns: ['apple-id', 'apple-account', 'apple-verify'] },
            { brand: 'paypal', patterns: ['paypal-secure', 'paypal-login', 'paypal-verify'] },
            { brand: 'facebook', patterns: ['facebook-login', 'facebook-verify'] },
            { brand: 'netflix', patterns: ['netflix-login', 'netflix-verify'] },
            { brand: 'instagram', patterns: ['instagram-login', 'instagram-verify'] }
        ];

        for (let item of subdomainPatterns) {
            for (let pattern of item.patterns) {
                if (urlLower.includes(pattern + '.') || urlLower.includes(pattern + '-')) {
                    patterns.visualDeception.push({
                        type: 'brand_impersonation',
                        detail: `May be impersonating ${item.brand}`,
                        severity: 'high'
                    });
                }
            }
        }

        return {
            detected: patterns,
            totalPatterns: patterns.visualDeception.length + 
                          patterns.technicalDeception.length + 
                          patterns.socialEngineering.length,
            isSuspicious: patterns.visualDeception.length > 0 || 
                         patterns.socialEngineering.length > 0,
            highestSeverity: getHighestSeverity(patterns)
        };
    }

    /**
     * Get highest severity from pattern groups
     * @param {object} patterns - Pattern groups
     * @returns {string} Highest severity level
     */
    function getHighestSeverity(patterns) {
        const allPatterns = [
            ...patterns.visualDeception,
            ...patterns.technicalDeception,
            ...patterns.socialEngineering
        ];
        
        if (allPatterns.some(p => p.severity === 'high')) return 'high';
        if (allPatterns.some(p => p.severity === 'medium')) return 'medium';
        if (allPatterns.some(p => p.severity === 'low')) return 'low';
        return 'none';
    }

    // ============================================================================
    // MAIN ANALYSIS FUNCTION
    // ============================================================================

    /**
     * Perform comprehensive URL analysis
     * @param {string} url - URL to analyze
     * @param {string[]} knownBrands - Known brand names for comparison
     * @returns {object} Complete analysis results
     */
    function analyzeURL(url, knownBrands = []) {
        const startTime = now();
        
        // Parse URL
        const parsed = parseURL(url);
        if (!parsed) {
            return {
                success: false,
                error: 'Invalid URL format',
                analysisTime: now() - startTime
            };
        }

        // Extract all features
        const structural = extractStructuralFeatures(parsed);
        const characters = extractCharacterFeatures(parsed);
        const tld = analyzeTLD(parsed.tld);
        const idn = analyzeInternationalization(parsed.hostname);
        const subdomain = analyzeSubdomain(parsed.subdomain);
        const path = analyzePath(parsed.pathname, parsed.search);
        const protocol = analyzeProtocol(parsed.protocol);
        const ipAnalysis = analyzeIPAddress(parsed.hostname);
        const brandAnalysis = analyzeBrandAppearance(url, knownBrands);
        const entropy = analyzeDomainEntropy(parsed.hostname);
        const deception = detectDeceptionPatterns(url);

        // Compile suspicious indicators
        const suspiciousIndicators = [];
        
        if (structural.domainLength > CONFIG.MAX_DOMAIN_LENGTH) {
            suspiciousIndicators.push('Unusually long domain name');
        }
        if (structural.hasSubdomain && structural.subdomainLength > CONFIG.MAX_SUBDOMAIN_LENGTH) {
            suspiciousIndicators.push('Unusually long subdomain');
        }
        if (tld.isSuspiciousTLD) {
            suspiciousIndicators.push(`Suspicious TLD: .${tld.tld}`);
        }
        if (idn.isPunycode) {
            suspiciousIndicators.push('Internationalized domain (punycode)');
        }
        if (idn.hasMixedScript) {
            suspiciousIndicators.push('Mixed character scripts detected');
        }
        if (ipAnalysis.usesIP && !ipAnalysis.isPrivate) {
            suspiciousIndicators.push('Using IP address instead of domain');
        }
        if (characters.hasHexEncoding && characters.hexEncodedSegments > 10) {
            suspiciousIndicators.push('Excessive URL encoding detected');
        }
        if (path.hasSensitiveParams) {
            suspiciousIndicators.push('URL contains sensitive parameters');
        }
        if (deception.hasSuspicious) {
            suspiciousIndicators.push(...deception.detected.socialEngineering.map(p => p.detail));
        }
        if (brandAnalysis.hasTyposquatting) {
            suspiciousIndicators.push(...brandAnalysis.typosquatting.map(t => 
                `Possible typosquatting: "${t.original}" looks like "${t.matchedBrand}"`
            ));
        }

        return {
            success: true,
            url: url,
            parsed: parsed,
            features: {
                structural: structural,
                characters: characters,
                tld: tld,
                idn: idn,
                subdomain: subdomain,
                path: path,
                protocol: protocol,
                ip: ipAnalysis,
                brand: brandAnalysis,
                entropy: entropy,
                deception: deception
            },
            suspiciousIndicators: suspiciousIndicators,
            indicatorCount: suspiciousIndicators.length,
            analysisTime: now() - startTime
        };
    }

    // ============================================================================
    // PUBLIC API
    // ============================================================================

    return {
        analyzeURL,
        extractStructuralFeatures,
        extractCharacterFeatures,
        analyzeTLD,
        analyzeInternationalization,
        analyzeSubdomain,
        analyzePath,
        analyzeProtocol,
        analyzeIPAddress,
        analyzeBrandAppearance,
        detectDeceptionPatterns,
        CONFIG
    };

})();

// Export for various environments
if (typeof chrome !== 'undefined') {
    window.URLAnalyzer = URLAnalyzer;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = URLAnalyzer;
}
