/**
 * Intent-Aware Phishing Detection System
 * Core Utility Module
 * 
 * Provides helper functions for URL parsing, entropy calculation,
 * string matching, and common utilities used across the system.
 */

// ============================================================================
// STRING ENTROPY CALCULATOR
// ============================================================================

/**
 * Calculate Shannon entropy of a string
 * Higher entropy suggests random/encoded content often found in phishing URLs
 * @param {string} str - Input string to analyze
 * @returns {number} Entropy score (0-8, where 8 is highest randomness)
 */
function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    
    const charFreq = {};
    const len = str.length;
    
    // Count frequency of each character
    for (let char of str) {
        charFreq[char] = (charFreq[char] || 0) + 1;
    }
    
    // Calculate Shannon entropy
    let entropy = 0;
    for (let char in charFreq) {
        const probability = charFreq[char] / len;
        entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
}

/**
 * Calculate domain-specific entropy focusing on suspicious patterns
 * @param {string} domain - Domain to analyze
 * @returns {object} Entropy metrics
 */
function analyzeDomainEntropy(domain) {
    const parts = domain.split('.');
    let totalEntropy = 0;
    const partEntropies = [];
    
    for (let part of parts) {
        const partEntropy = calculateEntropy(part);
        partEntropies.push({
            part: part,
            entropy: partEntropy,
            isSuspicious: partEntropy > 3.5
        });
        totalEntropy += partEntropy;
    }
    
    return {
        average: totalEntropy / parts.length,
        max: Math.max(...partEntropies.map(p => p.entropy)),
        parts: partEntropies,
        isSuspicious: totalEntropy / parts.length > 3.5
    };
}

// ============================================================================
// URL PARSING UTILITIES
// ============================================================================

/**
 * Parse URL into structured components
 * @param {string} url - Full URL to parse
 * @returns {object} Parsed URL components
 */
function parseURL(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const parts = hostname.split('.');
        
        // Extract subdomain
        let subdomain = '';
        let domain = '';
        let tld = '';
        
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
            hostname: hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
            pathname: urlObj.pathname,
            search: urlObj.search,
            hash: urlObj.hash,
            username: urlObj.username,
            password: urlObj.password,
            subdomain: subdomain,
            domain: domain,
            tld: tld,
            pathParts: urlObj.pathname.split('/').filter(p => p.length > 0),
            allParts: parts
        };
    } catch (e) {
        return null;
    }
}

/**
 * Extract all words from URL for analysis
 * @param {string} url - URL to extract words from
 * @returns {string[]} Array of words
 */
function extractWordsFromURL(url) {
    const parsed = parseURL(url);
    if (!parsed) return [];
    
    const words = [];
    
    // Add domain parts
    if (parsed.subdomain) {
        words.push(...parsed.subdomain.split(/[-._]/));
    }
    if (parsed.domain) {
        words.push(parsed.domain);
    }
    
    // Add path parts
    words.push(...parsed.pathParts.flatMap(part => part.split(/[-._]/)));
    
    // Add query parameters
    const queryWords = parsed.search.replace('?', '').split(/[&=]/)
        .flatMap(param => param.split(/[-._]/));
    words.push(...queryWords);
    
    return words.filter(w => w.length > 1);
}

// ============================================================================
// LEVENSHTEIN DISTANCE FOR TYPOSQUATTING
// ============================================================================

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
 * Find similar brand names in URL (typosquatting detection)
 * @param {string} url - URL to check
 * @param {string[]} brands - Known brand names
 * @param {number} threshold - Maximum edit distance (default: 2)
 * @returns {object[]} Matches with similarity scores
 */
function findSimilarBrands(url, brands, threshold = 2) {
    const words = extractWordsFromURL(url.toLowerCase());
    const matches = [];
    
    for (let brand of brands) {
        const brandLower = brand.toLowerCase();
        
        for (let word of words) {
            if (word === brandLower) continue;
            
            const distance = levenshteinDistance(word, brandLower);
            
            if (distance <= threshold && distance > 0) {
                const similarity = 1 - (distance / Math.max(word.length, brandLower.length));
                matches.push({
                    original: word,
                    matchedBrand: brand,
                    distance: distance,
                    similarity: similarity,
                    isTypo: distance <= 1
                });
            }
        }
    }
    
    return matches;
}

// ============================================================================
// PATTERN MATCHING UTILITIES
// ============================================================================

/**
 * Check if string contains IP address
 * @param {string} str - String to check
 * @returns {boolean|object} False or matched IP info
 */
function extractIPAddress(str) {
    const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
    const matches = str.match(ipPattern);
    
    if (matches) {
        return {
            found: true,
            ip: matches[0],
            isPrivate: isPrivateIP(matches[0])
        };
    }
    return false;
}

/**
 * Check if IP is in private range
 * @param {string} ip - IP address to check
 * @returns {boolean}
 */
function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    
    // 10.0.0.0 - 10.255.255.255
    if (parts[0] === 10) return true;
    
    // 172.16.0.0 - 172.31.255.255
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0 - 192.168.255.255
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0 - 127.255.255.255 (localhost)
    if (parts[0] === 127) return true;
    
    return false;
}

/**
 * Detect hexadecimal encoding in string
 * @param {string} str - String to check
 * @returns {boolean}
 */
function hasHexEncoding(str) {
    const hexPattern = /%[0-9A-Fa-f]{2}/;
    return hexPattern.test(str);
}

/**
 * Detect punycode encoding (internationalized domains)
 * @param {string} str - String to check
 * @returns {boolean|object}
 */
function detectPunycode(str) {
    if (str.includes('xn--')) {
        return {
            isPunycode: true,
            encoded: str
        };
    }
    return { isPunycode: false };
}

/**
 * Count special characters in string
 * @param {string} str - String to analyze
 * @returns {object} Special character counts
 */
function countSpecialChars(str) {
    const counts = {
        dots: (str.match(/\./g) || []).length,
        hyphens: (str.match(/-/g) || []).length,
        underscores: (str.match(/_/g) || []).length,
        atSigns: (str.match(/@/g) || []).length,
        slashes: (str.match(/\//g) || []).length,
        equals: (str.match(/=/g) || []).length,
        questionMarks: (str.match(/\?/g) || []).length,
        percent: (str.match(/%/g) || []).length,
        digits: (str.match(/\d/g) || []).length,
        uppercase: (str.match(/[A-Z]/g) || []).length,
        lowercase: (str.match(/[a-z]/g) || []).length
    };
    
    counts.total = Object.values(counts).reduce((a, b) => a + b, 0);
    counts.digitRatio = str.length > 0 ? counts.digits / str.length : 0;
    
    return counts;
}

// ============================================================================
// DATA UTILITIES
// ============================================================================

/**
 * Deep clone an object
 * @param {any} obj - Object to clone
 * @returns {any} Cloned object
 */
function deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj);
    if (obj instanceof Array) return obj.map(item => deepClone(item));
    
    const cloned = {};
    for (let key in obj) {
        if (obj.hasOwnProperty(key)) {
            cloned[key] = deepClone(obj[key]);
        }
    }
    return cloned;
}

/**
 * Debounce function execution
 * @param {function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @returns {function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function execution
 * @param {function} func - Function to throttle
 * @param {number} limit - Time limit in ms
 * @returns {function} Throttled function
 */
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ============================================================================
// TIME UTILITIES
// ============================================================================

/**
 * Get current timestamp
 * @returns {number} Unix timestamp in milliseconds
 */
function now() {
    return Date.now();
}

/**
 * Format date for display
 * @param {Date|number} date - Date to format
 * @returns {string} Formatted date string
 */
function formatDate(date) {
    const d = date instanceof Date ? date : new Date(date);
    return d.toLocaleString();
}

// ============================================================================
// EXPORT FOR VARIOUS ENVIRONMENTS
// ============================================================================

// For Chrome Extension (background/content scripts)
if (typeof chrome !== 'undefined') {
    // Extend chrome.runtime to allow cross-script communication
    window.PhishingDetectionUtils = {
        calculateEntropy,
        analyzeDomainEntropy,
        parseURL,
        extractWordsFromURL,
        levenshteinDistance,
        findSimilarBrands,
        extractIPAddress,
        isPrivateIP,
        hasHexEncoding,
        detectPunycode,
        countSpecialChars,
        deepClone,
        debounce,
        throttle,
        now,
        formatDate
    };
}

// For Node.js (testing)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        calculateEntropy,
        analyzeDomainEntropy,
        parseURL,
        extractWordsFromURL,
        levenshteinDistance,
        findSimilarBrands,
        extractIPAddress,
        isPrivateIP,
        hasHexEncoding,
        detectPunycode,
        countSpecialChars,
        deepClone,
        debounce,
        throttle,
        now,
        formatDate
    };
}
