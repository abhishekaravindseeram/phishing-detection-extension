/**
 * Intent-Aware Phishing Detection System
 * Intent Detection Engine (CORE COMPONENT)
 * 
 * Identifies the psychological attack vectors being used in URLs
 * and classifies the type of social engineering attempt.
 */

const IntentEngine = (function() {
    // ============================================================================
    // ATTACK PATTERN DEFINITIONS
    // ============================================================================

    const ATTACK_PATTERNS = {
        AUTHORITY: {
            name: 'Authority Attack',
            description: 'Impersonates trusted institutions (banks, government, tech companies)',
            indicators: [
                'bank', 'gov', 'irs', 'fbi', 'police', 'security', 'admin',
                'support', 'helpdesk', 'service', 'official', 'verified'
            ],
            weight: 1.0,
            severity: 'high'
        },
        URGENCY: {
            name: 'Urgency Attack',
            description: 'Creates artificial time pressure to prevent careful evaluation',
            indicators: [
                'urgent', 'immediately', 'now', 'today', 'hours', 'deadline',
                'expires', 'limited', 'only', 'hurry', 'act', 'fast', 'quick'
            ],
            weight: 0.9,
            severity: 'high'
        },
        FEAR: {
            name: 'Fear/Panic Attack',
            description: 'Uses threats and alarming language to trigger instinctive reactions',
            indicators: [
                'alert', 'warning', 'danger', 'suspended', 'locked', 'compromised',
                'breach', 'hack', 'stolen', 'unauthorized', 'terminate', 'violation',
                'penalty', 'legal', 'arrest', 'lawsuit'
            ],
            weight: 0.95,
            severity: 'critical'
        },
        GREED: {
            name: 'Greed Trap',
            description: 'Offers unrealistic rewards to exploit desire for easy gains',
            indicators: [
                'win', 'winner', 'prize', 'reward', 'gift', 'free', 'bonus',
                'claim', 'offer', 'deal', 'discount', 'save', 'cash', 'money',
                'million', 'bitcoin', 'crypto', 'investment', 'returns'
            ],
            weight: 0.85,
            severity: 'medium'
        },
        CURIOUSITY: {
            name: 'Curiosity Lure',
            description: 'Exploits curiosity with sensational or intriguing content',
            indicators: [
                'exclusive', 'secret', 'leaked', 'shocking', 'breaking',
                'revealed', 'exclusive', 'private', 'hidden', 'classified'
            ],
            weight: 0.7,
            severity: 'low'
        }
    };

    // ============================================================================
    // BRAND DATABASE
    // ============================================================================

    const KNOWN_BRANDS = {
        FINANCIAL: [
            'paypal', 'venmo', 'cashapp', 'stripe', 'square', 'chase', 'bankofamerica',
            'wellsfargo', 'citi', 'capitalone', 'amex', 'americanexpress', 'discover',
            'mastercard', 'visa', 'coinbase', 'binance', 'revolut', 'wise', 'transferwise'
        ],
        TECH_GIANT: [
            'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'instagram',
            'twitter', 'xcom', 'linkedin', 'github', 'dropbox', 'adobe', 'netflix',
            'spotify', 'slack', 'zoom', 'teams', 'icloud', 'onedrive'
        ],
        SOCIAL: [
            'facebook', 'instagram', 'twitter', 'tiktok', 'snapchat', 'pinterest',
            'reddit', 'whatsapp', 'telegram', 'discord', 'onlyfans'
        ],
        GAMING: [
            'steam', 'epicgames', 'playstation', 'xbox', 'nintendo', 'roblox',
            'fortnite', 'minecraft', 'twitch', 'discord'
        ],
        GOVERNMENT: [
            'irs', 'ssa', 'dmv', 'usps', 'uscis', 'fbi', 'cia', 'nsa', 'police',
            'courts', 'medicare', 'medicaid', 'socialsecurity'
        ],
        RETAIL: [
            'amazon', 'ebay', 'walmart', 'target', 'bestbuy', 'etsy', 'shopify',
            'aliexpress', 'wish'
        ],
        UTILITY: [
            'dhl', 'fedex', 'ups', 'usps', 'electric', 'water', 'gas', 'internet',
            'phone', 'mobile', 'at&t', 'verizon', 't-mobile', 'sprint'
        ]
    };

    // Flatten all brands
    const ALL_BRANDS = Object.values(KNOWN_BRANDS).flat();

    // ============================================================================
    // ACTION WORDS DATABASE
    // ============================================================================

    const ACTION_WORDS = {
        CRITICAL: [
            'login', 'signin', 'verify', 'confirm', 'update', 'reset',
            'unlock', 'activate', 'validate', 'authorize'
        ],
        WARNING: [
            'check', 'review', 'secure', 'protect', 'safeguard', 'backup'
        ],
        TRANSACTION: [
            'pay', 'send', 'transfer', 'withdraw', 'deposit', 'receive',
            'buy', 'purchase', 'subscribe', 'donate'
        ],
        ACCOUNT: [
            'account', 'profile', 'settings', 'preferences', 'notifications',
            'subscription', 'membership', 'member'
        ]
    };

    // ============================================================================
    // URGENCY KEYWORDS DATABASE
    // ============================================================================

    const URGENCY_KEYWORDS = {
        TIME_CRITICAL: [
            'now', 'immediately', 'urgent', 'asap', 'instantly', 'today',
            'expires', 'deadline', 'hours', 'minutes', 'limited', 'remaining'
        ],
        PRESSURE: [
            'action', 'required', 'must', 'need', 'necessary', 'compulsory',
            'mandatory', 'obligatory', 'forced', 'required'
        ],
        CONSEQUENCE: [
            'suspended', 'terminated', 'locked', 'closed', 'deleted', 'lost',
            'blocked', 'restricted', 'disabled', 'expired', 'cancelled'
        ],
        ALERT: [
            'alert', 'warning', 'notice', 'notification', 'important',
            'attention', 'warning', 'urgent', 'critical', 'emergency'
        ]
    };

    // ============================================================================
    // INTENT ANALYSIS FUNCTIONS
    // ============================================================================

    /**
     * Analyze text for brand mentions (legitimate and impersonated)
     * @param {string} text - Text to analyze
     * @returns {object} Brand analysis
     */
    function analyzeBrandMentions(text) {
        const lowerText = text.toLowerCase();
        const mentions = [];
        const impersonationRisks = [];

        for (let brand of ALL_BRANDS) {
            const brandLower = brand.toLowerCase();
            
            // Check for exact mention
            if (lowerText.includes(brandLower)) {
                const index = lowerText.indexOf(brandLower);
                mentions.push({
                    brand: brand,
                    position: index,
                    context: text.substring(Math.max(0, index - 20), index + brand.length + 20),
                    isLegitimate: false // Will be determined by domain analysis
                });
            }
            
            // Check for variations/suspicious modifications
            const variations = generateBrandVariations(brand);
            for (let variation of variations) {
                if (lowerText.includes(variation) && variation !== brandLower) {
                    impersonationRisks.push({
                        original: brand,
                        variation: variation,
                        type: 'variation'
                    });
                }
            }
        }

        return {
            exactMentions: mentions,
            totalMentions: mentions.length,
            impersonationRisks: impersonationRisks,
            hasImpersonationRisk: impersonationRisks.length > 0,
            detectedBrands: [...new Set(mentions.map(m => m.brand))]
        };
    }

    /**
     * Generate common variations of brand names for detection
     * @param {string} brand - Brand name
     * @returns {string[]} Variations
     */
    function generateBrandVariations(brand) {
        const variations = [];
        const lower = brand.toLowerCase();
        
        // Common character substitutions
        const substitutions = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', 'l', '!'],
            'o': ['0'],
            's': ['$', '5'],
            'l': ['1', 'i'],
            't': ['7', '+'],
            'g': ['9', '6']
        };

        // Generate single-char variations
        for (let char of lower) {
            if (substitutions[char]) {
                for (let sub of substitutions[char]) {
                    variations.push(lower.replace(char, sub));
                }
            }
        }

        // Generate hyphenated variations
        if (lower.length > 3) {
            variations.push(lower.substring(0, Math.floor(lower.length / 2)) + '-' + 
                           lower.substring(Math.floor(lower.length / 2)));
        }

        return variations;
    }

    /**
     * Detect action words in text
     * @param {string} text - Text to analyze
     * @returns {object} Action word analysis
     */
    function detectActionWords(text) {
        const lowerText = text.toLowerCase();
        const found = {
            CRITICAL: [],
            WARNING: [],
            TRANSACTION: [],
            ACCOUNT: []
        };
        const riskScores = {
            CRITICAL: 3,
            WARNING: 2,
            TRANSACTION: 2,
            ACCOUNT: 1
        };

        for (let category in ACTION_WORDS) {
            for (let word of ACTION_WORDS[category]) {
                if (lowerText.includes(word)) {
                    found[category].push(word);
                }
            }
        }

        const totalScore = Object.keys(found).reduce((sum, cat) => {
            return sum + (found[cat].length * riskScores[cat]);
        }, 0);

        return {
            detected: found,
            totalCount: Object.values(found).flat().length,
            urgencyScore: totalScore,
            highestCategory: Object.keys(found).find(cat => found[cat].length > 0) || null
        };
    }

    /**
     * Analyze urgency indicators
     * @param {string} text - Text to analyze
     * @returns {object} Urgency analysis
     */
    function detectUrgency(text) {
        const lowerText = text.toLowerCase();
        const found = {
            TIME_CRITICAL: [],
            PRESSURE: [],
            CONSEQUENCE: [],
            ALERT: []
        };

        for (let category in URGENCY_KEYWORDS) {
            for (let keyword of URGENCY_KEYWORDS[category]) {
                if (lowerText.includes(keyword)) {
                    found[category].push({
                        keyword: keyword,
                        position: lowerText.indexOf(keyword)
                    });
                }
            }
        }

        const totalUrgencyIndicators = Object.values(found).flat().length;
        
        // Calculate urgency level
        let urgencyLevel = 'none';
        if (totalUrgencyIndicators >= 5) urgencyLevel = 'critical';
        else if (totalUrgencyIndicators >= 3) urgencyLevel = 'high';
        else if (totalUrgencyIndicators >= 1) urgencyLevel = 'medium';

        return {
            detected: found,
            totalIndicators: totalUrgencyIndicators,
            urgencyLevel: urgencyLevel,
            hasTimePressure: found.TIME_CRITICAL.length > 0,
            hasConsequenceThreat: found.CONSEQUENCE.length > 0,
            hasAlertLanguage: found.ALERT.length > 0,
            combinedIndicators: [...found.TIME_CRITICAL, ...found.PRESSURE, 
                               ...found.CONSEQUENCE, ...found.ALERT].map(i => i.keyword)
        };
    }

    /**
     * Identify attack type based on patterns
     * @param {object} brandAnalysis - Brand mention analysis
     * @param {object} actionAnalysis - Action word analysis
     * @param {object} urgencyAnalysis - Urgency analysis
     * @param {object} urlAnalysis - URL structure analysis
     * @returns {object} Attack classification
     */
    function classifyAttackType(brandAnalysis, actionAnalysis, urgencyAnalysis, urlAnalysis) {
        const classifications = [];
        const scores = {};

        // Authority Attack: Brand + Login/Verify
        if (brandAnalysis.totalMentions > 0 && actionAnalysis.detected.CRITICAL.length > 0) {
            const score = Math.min(100, 50 + (brandAnalysis.totalMentions * 15) + 
                                   (actionAnalysis.detected.CRITICAL.length * 10));
            scores.AUTHORITY = score;
            classifications.push({
                type: 'AUTHORITY',
                name: ATTACK_PATTERNS.AUTHORITY.name,
                confidence: score,
                evidence: [
                    `${brandAnalysis.totalMentions} brand impersonation(s)`,
                    ...actionAnalysis.detected.CRITICAL.map(w => `Action: "${w}"`)
                ]
            });
        }

        // Fear Attack: Consequence keywords + urgency
        if (urgencyAnalysis.hasConsequenceThreat && urgencyAnalysis.totalIndicators >= 2) {
            const score = Math.min(100, 40 + (urgencyAnalysis.totalIndicators * 15) +
                                   (urgencyAnalysis.hasAlertLanguage ? 20 : 0));
            scores.FEAR = score;
            classifications.push({
                type: 'FEAR',
                name: ATTACK_PATTERNS.FEAR.name,
                confidence: score,
                evidence: [
                    ...urgencyAnalysis.detected.CONSEQUENCE.map(i => `Threat: "${i.keyword}"`),
                    ...urgencyAnalysis.detected.ALERT.map(i => `Alert: "${i.keyword}"`)
                ]
            });
        }

        // Urgency Attack: Time pressure keywords
        if (urgencyAnalysis.hasTimePressure && urgencyAnalysis.totalIndicators >= 2) {
            const score = Math.min(100, 35 + (urgencyAnalysis.totalIndicators * 12));
            scores.URGENCY = score;
            classifications.push({
                type: 'URGENCY',
                name: ATTACK_PATTERNS.URGENCY.name,
                confidence: score,
                evidence: urgencyAnalysis.detected.TIME_CRITICAL.map(i => 
                    `Time pressure: "${i.keyword}"`
                )
            });
        }

        // Greed Attack: Reward keywords + brand (for fake giveaways)
        if (urgencyAnalysis.detected.hasOwnProperty('TIME_CRITICAL') &&
            brandAnalysis.totalMentions > 0) {
            // Check for greedy patterns
            const greedyPatterns = ['win', 'prize', 'gift', 'winner', 'congratulations'];
            const hasGreedy = greedyPatterns.some(p => urlAnalysis.toLowerCase().includes(p));
            
            if (hasGreedy) {
                const score = 60;
                scores.GREED = score;
                classifications.push({
                    type: 'GREED',
                    name: ATTACK_PATTERNS.GREED.name,
                    confidence: score,
                    evidence: brandAnalysis.detectedBrands.map(b => 
                        `Fake ${b} giveaway/gift`
                    )
                });
            }
        }

        // Sort by confidence
        classifications.sort((a, b) => b.confidence - a.confidence);

        return {
            classifications: classifications,
            primaryAttack: classifications[0] || null,
            isMultiVector: classifications.length > 1,
            attackTypes: Object.keys(scores),
            maxConfidence: Math.max(...Object.values(scores), 0)
        };
    }

    /**
     * Analyze text for emotional manipulation techniques
     * @param {string} text - Text to analyze
     * @returns {object} Manipulation analysis
     */
    function analyzeEmotionalManipulation(text) {
        const lowerText = text.toLowerCase();
        const techniques = {
            artificialUrgency: [],
            fearInduction: [],
            rewardPromises: [],
            authorityImpersonation: [],
            socialProof: []
        };

        const manipulationPhrases = {
            artificialUrgency: [
                'act now', 'limited time', 'don\'t miss', 'expires today',
                'only a few left', 'running out', 'last chance', 'ending soon'
            ],
            fearInduction: [
                'account will be closed', 'will be suspended', 'unauthorized access',
                'security breach', 'compromised', 'data stolen', 'immediate action'
            ],
            rewardPromises: [
                'you\'ve won', 'congratulations', 'free gift', 'claim your prize',
                'special offer', 'exclusive deal', 'act now', 'limited offer'
            ],
            authorityImpersonation: [
                'verification required', 'update your information', 'confirm your identity',
                'security check', 'mandatory', 'required action'
            ],
            socialProof: [
                'thousands have', 'hurry', 'everyone is', 'most popular'
            ]
        };

        for (let technique in manipulationPhrases) {
            for (let phrase of manipulationPhrases[technique]) {
                if (lowerText.includes(phrase)) {
                    techniques[technique].push(phrase);
                }
            }
        }

        return {
            techniques: techniques,
            totalTechniques: Object.values(techniques).flat().length,
            manipulationLevel: calculateManipulationLevel(techniques),
            isHighlyManipulative: Object.values(techniques).flat().length >= 4
        };
    }

    /**
     * Calculate manipulation level from detected techniques
     * @param {object} techniques - Detected manipulation techniques
     * @returns {string} Manipulation level
     */
    function calculateManipulationLevel(techniques) {
        const total = Object.values(techniques).flat().length;
        const categoriesUsed = Object.values(techniques).filter(v => v.length > 0).length;

        if (total >= 5 || categoriesUsed >= 4) return 'critical';
        if (total >= 3 || categoriesUsed >= 3) return 'high';
        if (total >= 1 || categoriesUsed >= 1) return 'medium';
        return 'low';
    }

    /**
     * Extract intent from URL and page content
     * @param {string} url - URL to analyze
     * @param {string} pageTitle - Page title (optional)
     * @param {string} pageText - Page text content (optional)
     * @returns {object} Complete intent analysis
     */
    function analyzeIntent(url, pageTitle = '', pageText = '') {
        const startTime = now();
        
        // Combine all text sources
        const fullText = `${url} ${pageTitle} ${pageText}`.toLowerCase();

        // Run all analyses
        const brandAnalysis = analyzeBrandMentions(fullText);
        const actionAnalysis = detectActionWords(fullText);
        const urgencyAnalysis = detectUrgency(fullText);
        const manipulationAnalysis = analyzeEmotionalManipulation(fullText);
        
        // Perform attack classification
        const attackClassification = classifyAttackType(
            brandAnalysis,
            actionAnalysis,
            urgencyAnalysis,
            url
        );

        // Calculate overall intent score
        let intentScore = 0;
        const factors = [];

        // Brand impersonation factor
        if (brandAnalysis.hasImpersonationRisk) {
            intentScore += 25;
            factors.push('Brand impersonation detected');
        }
        if (brandAnalysis.totalMentions > 0) {
            intentScore += brandAnalysis.totalMentions * 5;
            factors.push(`${brandAnalysis.totalMentions} brand mention(s)`);
        }

        // Action words factor
        if (actionAnalysis.totalCount > 0) {
            intentScore += actionAnalysis.urgencyScore * 3;
            factors.push(`${actionAnalysis.totalCount} action word(s)`);
        }

        // Urgency factor
        if (urgencyAnalysis.totalIndicators > 0) {
            intentScore += urgencyAnalysis.totalIndicators * 8;
            factors.push(`${urgencyAnalysis.totalIndicators} urgency indicator(s)`);
        }

        // Manipulation factor
        const manipulationMultiplier = {
            'critical': 2.5,
            'high': 2.0,
            'medium': 1.5,
            'low': 1.0
        };
        intentScore *= manipulationMultiplier[manipulationAnalysis.manipulationLevel];
        factors.push(`Manipulation level: ${manipulationAnalysis.manipulationLevel}`);

        // Attack type factor
        if (attackClassification.primaryAttack) {
            intentScore += attackClassification.primaryAttack.confidence * 0.3;
            factors.push(`Primary attack: ${attackClassification.primaryAttack.name}`);
        }

        // Normalize to 0-100
        intentScore = Math.min(100, Math.round(intentScore));

        return {
            success: true,
            timestamp: new Date().toISOString(),
            analysisTime: now() - startTime,
            
            intentScore: intentScore,
            intentLevel: getIntentLevel(intentScore),
            
            brandAnalysis: brandAnalysis,
            actionAnalysis: actionAnalysis,
            urgencyAnalysis: urgencyAnalysis,
            manipulationAnalysis: manipulationAnalysis,
            
            attackClassification: attackClassification,
            
            intentFactors: factors,
            summary: generateIntentSummary(intentScore, attackClassification, manipulationAnalysis),
            
            recommendations: generateRecommendations(intentScore, attackClassification, urgencyAnalysis)
        };
    }

    /**
     * Get intent level from score
     * @param {number} score - Intent score
     * @returns {string} Intent level
     */
    function getIntentLevel(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'medium';
        if (score >= 20) return 'low';
        return 'minimal';
    }

    /**
     * Generate human-readable summary
     * @param {number} score - Intent score
     * @param {object} classification - Attack classification
     * @param {object} manipulation - Manipulation analysis
     * @returns {string} Summary text
     */
    function generateIntentSummary(score, classification, manipulation) {
        if (score >= 80) {
            return `CRITICAL: This URL exhibits ${manipulation.manipulationLevel} psychological manipulation with multiple attack vectors.`;
        }
        if (score >= 60) {
            const attackName = classification.primaryAttack?.name || 'social engineering';
            return `HIGH RISK: This URL shows signs of ${attackName.toLowerCase()} attack patterns.`;
        }
        if (score >= 40) {
            return `MEDIUM RISK: Some suspicious patterns detected. Proceed with caution.`;
        }
        if (score >= 20) {
            return `LOW RISK: Minor concerns detected, but appears relatively safe.`;
        }
        return `MINIMAL RISK: No significant phishing indicators found.`;
    }

    /**
     * Generate safety recommendations
     * @param {number} score - Intent score
     * @param {object} classification - Attack classification
     * @param {object} urgency - Urgency analysis
     * @returns {string[]} Array of recommendations
     */
    function generateRecommendations(score, classification, urgency) {
        const recommendations = [];

        if (score >= 60) {
            recommendations.push('DO NOT enter any credentials');
            recommendations.push('Close this page immediately');
            recommendations.push('Navigate directly to the official site instead');
        }

        if (urgency.hasTimePressure) {
            recommendations.push('Be wary of time pressure tactics - legitimate sites rarely require immediate action');
        }

        if (classification.primaryAttack?.type === 'AUTHORITY') {
            recommendations.push('Verify the URL matches the official domain exactly');
            recommendations.push('Contact the organization directly through official channels');
        }

        if (recommendations.length === 0) {
            recommendations.push('Always verify URLs before entering sensitive information');
            recommendations.push('Enable two-factor authentication on all accounts');
        }

        return recommendations;
    }

    // ============================================================================
    // PUBLIC API
    // ============================================================================

    return {
        analyzeIntent,
        analyzeBrandMentions,
        detectActionWords,
        detectUrgency,
        classifyAttackType,
        analyzeEmotionalManipulation,
        KNOWN_BRANDS,
        ALL_BRANDS,
        ATTACK_PATTERNS,
        getIntentLevel,
        generateIntentSummary,
        generateRecommendations
    };

})();

// Export for various environments
if (typeof chrome !== 'undefined') {
    window.IntentEngine = IntentEngine;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = IntentEngine;
}
