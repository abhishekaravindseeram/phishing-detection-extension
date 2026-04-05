/**
 * Intent-Aware Phishing Detection System
 * Configuration Module
 * 
 * Centralized configuration management for the extension.
 * Environment-aware settings with validation.
 */

const CONFIG = Object.freeze({
    VERSION: '1.0.0',
    NAME: 'PhishGuard',
    
    RISK: Object.freeze({
        THRESHOLDS: Object.freeze({
            BLOCK: 70,
            WARNING: 30,
            SAFE: 0
        }),
        SCORE_MAX: 100,
        SCORE_MIN: 0
    }),

    TIMING: Object.freeze({
        ANALYSIS_TIMEOUT_MS: 2000,
        COUNTDOWN_SECONDS: 5,
        REFRESH_INTERVAL_MS: 30000,
        DEBOUNCE_MS: 500
    }),

    UI: Object.freeze({
        OVERLAY_Z_INDEX: 2147483647,
        BLUR_INTENSITY: '20px',
        ANIMATION_DURATION_MS: 300
    }),

    STORAGE: Object.freeze({
        KEYS: Object.freeze({
            STATS: 'phishguard_stats',
            LOGS: 'phishguard_logs',
            SETTINGS: 'phishguard_settings'
        }),
        MAX_LOGS: 100
    }),

    BRANDS: Object.freeze({
        FINANCIAL: [
            'paypal', 'venmo', 'cashapp', 'stripe', 'square', 'chase', 'bankofamerica',
            'wellsfargo', 'citi', 'capitalone', 'amex', 'americanexpress', 'discover',
            'mastercard', 'visa', 'coinbase', 'binance', 'revolut', 'wise', 'transferwise',
            'sbi', 'icici', 'hdfc', 'paytm', 'phonepe', 'gpay'
        ],
        TECH_GIANT: [
            'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'instagram',
            'twitter', 'xcom', 'linkedin', 'github', 'dropbox', 'adobe', 'netflix',
            'spotify', 'slack', 'zoom', 'teams', 'icloud', 'onedrive', 'dropbox'
        ],
        SOCIAL: [
            'facebook', 'instagram', 'twitter', 'tiktok', 'snapchat', 'pinterest',
            'reddit', 'whatsapp', 'telegram', 'discord', 'onlyfans', 'tinder'
        ],
        GAMING: [
            'steam', 'epicgames', 'playstation', 'xbox', 'nintendo', 'roblox',
            'fortnite', 'minecraft', 'twitch', 'discord', 'origin', 'ubisoft'
        ],
        GOVERNMENT: [
            'irs', 'ssa', 'dmv', 'usps', 'uscis', 'fbi', 'cia', 'nsa', 'police',
            'courts', 'medicare', 'medicaid', 'socialsecurity', 'gov', 'govt'
        ],
        RETAIL: [
            'amazon', 'ebay', 'walmart', 'target', 'bestbuy', 'etsy', 'shopify',
            'aliexpress', 'wish', 'flipkart', 'myntra'
        ],
        UTILITY: [
            'dhl', 'fedex', 'ups', 'usps', 'electric', 'water', 'gas', 'internet',
            'phone', 'mobile', 'at&t', 'verizon', 't-mobile', 'sprint', 'jio'
        ]
    }),

    SUSPICIOUS_TLDS: Object.freeze([
        'xyz', 'top', 'club', 'online', 'site', 'website', 'work', 'ru', 'cn', 'tk',
        'ml', 'ga', 'cf', 'gq', 'info', 'biz', 'pw', 'cc', 'su', 'pro'
    ]),

    ATTACK_PATTERNS: Object.freeze({
        AUTHORITY: {
            name: 'Authority Attack',
            description: 'Impersonates trusted institutions',
            indicators: [
                'bank', 'gov', 'irs', 'fbi', 'police', 'security', 'admin',
                'support', 'helpdesk', 'service', 'official', 'verified'
            ],
            severity: 'high'
        },
        URGENCY: {
            name: 'Urgency Attack',
            description: 'Creates artificial time pressure',
            indicators: [
                'urgent', 'immediately', 'now', 'today', 'hours', 'deadline',
                'expires', 'limited', 'only', 'hurry', 'act', 'fast', 'quick'
            ],
            severity: 'high'
        },
        FEAR: {
            name: 'Fear/Panic Attack',
            description: 'Uses threats and alarming language',
            indicators: [
                'alert', 'warning', 'danger', 'suspended', 'locked', 'compromised',
                'breach', 'hack', 'stolen', 'unauthorized', 'terminate', 'violation',
                'penalty', 'legal', 'arrest', 'lawsuit'
            ],
            severity: 'critical'
        },
        GREED: {
            name: 'Greed Trap',
            description: 'Offers unrealistic rewards',
            indicators: [
                'win', 'winner', 'prize', 'reward', 'gift', 'free', 'bonus',
                'claim', 'offer', 'deal', 'discount', 'save', 'cash', 'money',
                'million', 'bitcoin', 'crypto', 'investment', 'returns'
            ],
            severity: 'medium'
        }
    }),

    ACTION_WORDS: Object.freeze([
        'login', 'signin', 'sign-in', 'verify', 'confirm', 'update', 'reset',
        'unlock', 'activate', 'validate', 'authorize', 'account', 'password',
        'credential', 'recover', 'restore'
    ]),

    SENSITIVE_PARAMS: Object.freeze([
        'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth',
        'cred', 'credential', 'pin', 'ssn', 'social', 'credit', 'cvv'
    ])
});

const ALL_BRANDS = Object.freeze([
    ...CONFIG.BRANDS.FINANCIAL,
    ...CONFIG.BRANDS.TECH_GIANT,
    ...CONFIG.BRANDS.SOCIAL,
    ...CONFIG.BRANDS.GAMING,
    ...CONFIG.BRANDS.GOVERNMENT,
    ...CONFIG.BRANDS.RETAIL,
    ...CONFIG.BRANDS.UTILITY
].map(b => b.toLowerCase()));

if (typeof chrome !== 'undefined') {
    window.PHISHGUARD_CONFIG = CONFIG;
    window.PHISHGUARD_BRANDS = ALL_BRANDS;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CONFIG, ALL_BRANDS };
}
