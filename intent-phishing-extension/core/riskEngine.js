/**
 * Intent-Aware Phishing Detection System
 * Risk Scoring Engine
 * 
 * Combines URL analysis, intent detection, and infrastructure intelligence
 * to produce a unified risk score (0-100) with detailed breakdown.
 */

const RiskEngine = (function() {
    // ============================================================================
    // SCORING CONFIGURATION
    // ============================================================================

    const SCORING_WEIGHTS = {
        // URL Structure factors
        URL_STRUCTURE: {
            IP_ADDRESS: 25,
            SUSPICIOUS_TLD: 15,
            LONG_DOMAIN: 10,
            EXCESSIVE_SUBDOMAINS: 12,
            SUSPICIOUS_PATH: 10,
            ENCODED_PATH: 15,
            UNUSUAL_PORT: 8,
            DATA_PROTOCOL: 30
        },
        
        // Brand/Intent factors
        BRAND_IMPERSONATION: {
            EXACT_MATCH: 20,
            TYPOSQUATTING: 30,
            MIXED_SCRIPTS: 25
        },
        
        // Intent factors
        INTENT: {
            AUTHORITY_ATTACK: 25,
            FEAR_ATTACK: 30,
            URGENCY_ATTACK: 20,
            GREED_TRAP: 15,
            MANIPULATION_CRITICAL: 25,
            MANIPULATION_HIGH: 18,
            MANIPULATION_MEDIUM: 10
        },
        
        // Infrastructure factors
        INFRASTRUCTURE: {
            NEW_DOMAIN: 20,
            NO_SSL: 15,
            FREE_HOSTING: 18,
            KNOWN_BAD_IPS: 35,
            PROXY_CDN: 5
        },
        
        // Pattern factors
        PATTERNS: {
            SUSPICIOUS_CHARS: 10,
            EXCESSIVE_ENCODING: 15,
            DECEPTION_PATTERNS: 20,
            PUNYCODE: 25
        }
    };

    // ============================================================================
    // DECISION THRESHOLDS
    // ============================================================================

    const THRESHOLDS = {
        BLOCK: 70,
        WARN: 30,
        SAFE: 0
    };

    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================

    /**
     * Clamp value between min and max
     * @param {number} value - Value to clamp
     * @param {number} min - Minimum value
     * @param {number} max - Maximum value
     * @returns {number} Clamped value
     */
    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    /**
     * Calculate weighted score
     * @param {number} score - Base score
     * @param {number} weight - Weight multiplier
     * @returns {number} Weighted score
     */
    function weightedScore(score, weight) {
        return score * (weight / 100);
    }

    /**
     * Get risk level from score
     * @param {number} score - Risk score
     * @returns {object} Risk level info
     */
    function getRiskLevel(score) {
        if (score >= THRESHOLDS.BLOCK) {
            return {
                level: 'BLOCK',
                color: '#dc3545',
                bgColor: '#f8d7da',
                icon: '🚫',
                action: 'BLOCK',
                description: 'High probability of phishing - Access blocked'
            };
        }
        if (score >= THRESHOLDS.WARN) {
            return {
                level: 'WARNING',
                color: '#fd7e14',
                bgColor: '#fff3cd',
                icon: '⚠️',
                action: 'PROCEED WITH CAUTION',
                description: 'Some suspicious indicators detected'
            };
        }
        return {
            level: 'SAFE',
            color: '#198754',
            bgColor: '#d1e7dd',
            icon: '✅',
            action: 'SAFE TO PROCEED',
            description: 'No significant threats detected'
        };
    }

    // ============================================================================
    // SCORE CALCULATORS
    // ============================================================================

    /**
     * Calculate URL structure risk
     * @param {object} urlAnalysis - URL analyzer results
     * @returns {object} Structure score breakdown
     */
    function calculateStructureScore(urlAnalysis) {
        const features = urlAnalysis.features;
        let totalScore = 0;
        const factors = [];

        // IP Address usage
        if (features.ip.usesIP) {
            const ipScore = features.ip.isPrivate ? 
                SCORING_WEIGHTS.URL_STRUCTURE.IP_ADDRESS * 0.5 : 
                SCORING_WEIGHTS.URL_STRUCTURE.IP_ADDRESS;
            totalScore += ipScore;
            factors.push({
                name: 'IP Address Usage',
                score: ipScore,
                detail: features.ip.isPrivate ? 
                    'Using private IP (suspicious)' : 
                    'Using public IP instead of domain'
            });
        }

        // Suspicious TLD
        if (features.tld.isSuspiciousTLD) {
            const tldScore = SCORING_WEIGHTS.URL_STRUCTURE.SUSPICIOUS_TLD;
            totalScore += tldScore;
            factors.push({
                name: 'Suspicious TLD',
                score: tldScore,
                detail: `Free hosting TLD: .${features.tld.tld}`
            });
        }

        // Long domain
        if (features.structural.domainLength > 30) {
            const longScore = Math.min(SCORING_WEIGHTS.URL_STRUCTURE.LONG_DOMAIN, 
                                       (features.structural.domainLength - 30) * 2);
            totalScore += longScore;
            factors.push({
                name: 'Unusually Long Domain',
                score: longScore,
                detail: `Domain length: ${features.structural.domainLength} characters`
            });
        }

        // Excessive subdomains
        if (features.subdomain.exists && features.subdomain.segmentCount > 3) {
            const subScore = Math.min(SCORING_WEIGHTS.URL_STRUCTURE.EXCESSIVE_SUBDOMAINS,
                                      features.subdomain.segmentCount * 4);
            totalScore += subScore;
            factors.push({
                name: 'Excessive Subdomains',
                score: subScore,
                detail: `${features.subdomain.segmentCount} subdomain levels`
            });
        }

        // Suspicious path
        if (features.path.isSuspicious) {
            totalScore += SCORING_WEIGHTS.URL_STRUCTURE.SUSPICIOUS_PATH;
            factors.push({
                name: 'Suspicious Path',
                score: SCORING_WEIGHTS.URL_STRUCTURE.SUSPICIOUS_PATH,
                detail: features.path.suspiciousReasons.join(', ')
            });
        }

        // Encoded path
        if (features.path.hasEncoding && features.path.encodedSegments > 3) {
            const encScore = Math.min(SCORING_WEIGHTS.URL_STRUCTURE.ENCODED_PATH,
                                      features.path.encodedSegments * 3);
            totalScore += encScore;
            factors.push({
                name: 'Excessive URL Encoding',
                score: encScore,
                detail: `${features.path.encodedSegments} encoded segments`
            });
        }

        // Data protocol
        if (features.protocol.isDangerous) {
            totalScore += SCORING_WEIGHTS.URL_STRUCTURE.DATA_PROTOCOL;
            factors.push({
                name: 'Dangerous Protocol',
                score: SCORING_WEIGHTS.URL_STRUCTURE.DATA_PROTOCOL,
                detail: `Protocol: ${features.protocol.protocol}`
            });
        }

        // Sensitive parameters
        if (features.path.hasSensitiveParams) {
            totalScore += 8;
            factors.push({
                name: 'Sensitive Parameters',
                score: 8,
                detail: 'URL contains password/token parameters'
            });
        }

        return {
            totalScore: clamp(totalScore, 0, 100),
            factors: factors,
            maxPossibleScore: 100
        };
    }

    /**
     * Calculate brand impersonation score
     * @param {object} urlAnalysis - URL analyzer results
     * @returns {object} Brand score breakdown
     */
    function calculateBrandScore(urlAnalysis) {
        const features = urlAnalysis.features;
        let totalScore = 0;
        const factors = [];

        // Exact brand matches in suspicious context
        if (features.brand.exactMatches.length > 0) {
            const exactScore = features.brand.exactMatches.length * 
                              SCORING_WEIGHTS.BRAND_IMPERSONATION.EXACT_MATCH;
            totalScore += exactScore;
            factors.push({
                name: 'Brand Mentions',
                score: exactScore,
                detail: `Detected: ${features.brand.detectedBrands.join(', ')}`
            });
        }

        // Typosquatting
        if (features.brand.hasTyposquatting) {
            for (let typo of features.brand.typosquatting) {
                const typoScore = typo.distance === 1 ? 
                    SCORING_WEIGHTS.BRAND_IMPERSONATION.TYPOSQUATTING :
                    SCORING_WEIGHTS.BRAND_IMPERSONATION.TYPOSQUATTING * 0.7;
                totalScore += typoScore;
                factors.push({
                    name: 'Typosquatting Detected',
                    score: typoScore,
                    detail: `"${typo.original}" → "${typo.matchedBrand}" (distance: ${typo.distance})`
                });
            }
        }

        // Mixed scripts (Cyrillic/Latin lookalikes)
        if (features.idn.hasMixedScript) {
            totalScore += SCORING_WEIGHTS.BRAND_IMPERSONATION.MIXED_SCRIPTS;
            factors.push({
                name: 'Mixed Character Scripts',
                score: SCORING_WEIGHTS.BRAND_IMPERSONATION.MIXED_SCRIPTS,
                detail: 'May contain lookalike characters'
            });
        }

        // Punycode
        if (features.idn.isPunycode) {
            totalScore += SCORING_WEIGHTS.PATTERNS.PUNYCODE;
            factors.push({
                name: 'Punycode Domain',
                score: SCORING_WEIGHTS.PATTERNS.PUNYCODE,
                detail: 'Internationalized domain encoding detected'
            });
        }

        return {
            totalScore: clamp(totalScore, 0, 100),
            factors: factors,
            maxPossibleScore: 100
        };
    }

    /**
     * Calculate intent-based score
     * @param {object} intentAnalysis - Intent engine results
     * @returns {object} Intent score breakdown
     */
    function calculateIntentScore(intentAnalysis) {
        let totalScore = 0;
        const factors = [];

        // Primary attack type
        if (intentAnalysis.attackClassification.primaryAttack) {
            const attack = intentAnalysis.attackClassification.primaryAttack;
            let attackScore = 0;

            switch (attack.type) {
                case 'FEAR':
                    attackScore = SCORING_WEIGHTS.INTENT.FEAR_ATTACK;
                    break;
                case 'AUTHORITY':
                    attackScore = SCORING_WEIGHTS.INTENT.AUTHORITY_ATTACK;
                    break;
                case 'URGENCY':
                    attackScore = SCORING_WEIGHTS.INTENT.URGENCY_ATTACK;
                    break;
                case 'GREED':
                    attackScore = SCORING_WEIGHTS.INTENT.GREED_TRAP;
                    break;
                default:
                    attackScore = 15;
            }

            // Scale by confidence
            attackScore = (attackScore * attack.confidence) / 100;
            totalScore += attackScore;
            factors.push({
                name: 'Attack Type',
                score: attackScore,
                detail: `${attack.name} (${Math.round(attack.confidence)}% confidence)`
            });
        }

        // Manipulation level
        const manipLevel = intentAnalysis.manipulationAnalysis.manipulationLevel;
        let manipScore = 0;

        switch (manipLevel) {
            case 'critical':
                manipScore = SCORING_WEIGHTS.INTENT.MANIPULATION_CRITICAL;
                break;
            case 'high':
                manipScore = SCORING_WEIGHTS.INTENT.MANIPULATION_HIGH;
                break;
            case 'medium':
                manipScore = SCORING_WEIGHTS.INTENT.MANIPULATION_MEDIUM;
                break;
        }

        if (manipScore > 0) {
            totalScore += manipScore;
            factors.push({
                name: 'Psychological Manipulation',
                score: manipScore,
                detail: `Level: ${manipLevel.toUpperCase()}`
            });
        }

        // Urgency indicators
        if (intentAnalysis.urgencyAnalysis.totalIndicators > 0) {
            const urgencyScore = Math.min(15, intentAnalysis.urgencyAnalysis.totalIndicators * 4);
            totalScore += urgencyScore;
            factors.push({
                name: 'Urgency Tactics',
                score: urgencyScore,
                detail: `${intentAnalysis.urgencyAnalysis.totalIndicators} urgency indicators`
            });
        }

        // Action words (especially critical ones)
        if (intentAnalysis.actionAnalysis.detected.CRITICAL.length > 0) {
            const actionScore = intentAnalysis.actionAnalysis.detected.CRITICAL.length * 5;
            totalScore += actionScore;
            factors.push({
                name: 'Suspicious Action Keywords',
                score: actionScore,
                detail: intentAnalysis.actionAnalysis.detected.CRITICAL.join(', ')
            });
        }

        return {
            totalScore: clamp(totalScore, 0, 100),
            factors: factors,
            maxPossibleScore: 100
        };
    }

    /**
     * Calculate infrastructure risk score
     * @param {object} infraAnalysis - Infrastructure analysis
     * @returns {object} Infrastructure score breakdown
     */
    function calculateInfrastructureScore(infraAnalysis) {
        let totalScore = 0;
        const factors = [];

        // Protocol security
        if (!infraAnalysis.isSecure) {
            totalScore += SCORING_WEIGHTS.INFRASTRUCTURE.NO_SSL;
            factors.push({
                name: 'Insecure Connection',
                score: SCORING_WEIGHTS.INFRASTRUCTURE.NO_SSL,
                detail: 'Using HTTP instead of HTTPS'
            });
        }

        // Domain age (if available)
        if (infraAnalysis.domainAge) {
            if (infraAnalysis.domainAge.days < 30) {
                const ageScore = Math.max(0, SCORING_WEIGHTS.INFRASTRUCTURE.NEW_DOMAIN - 
                                          (infraAnalysis.domainAge.days / 30) * 10);
                totalScore += ageScore;
                factors.push({
                    name: 'New Domain',
                    score: ageScore,
                    detail: `Domain age: ${infraAnalysis.domainAge.days} days`
                });
            }
        }

        // Known hosting patterns
        if (infraAnalysis.isFreeHosting) {
            totalScore += SCORING_WEIGHTS.INFRASTRUCTURE.FREE_HOSTING;
            factors.push({
                name: 'Free Hosting Service',
                score: SCORING_WEIGHTS.INFRASTRUCTURE.FREE_HOSTING,
                detail: infraAnalysis.hostingProvider || 'Free hosting detected'
            });
        }

        // Proxy/CDN usage
        if (infraAnalysis.isProxyOrCDN) {
            totalScore += SCORING_WEIGHTS.INFRASTRUCTURE.PROXY_CDN;
            factors.push({
                name: 'CDN/Proxy Usage',
                score: SCORING_WEIGHTS.INFRASTRUCTURE.PROXY_CDN,
                detail: infraAnalysis.provider || 'Using CDN or proxy'
            });
        }

        return {
            totalScore: clamp(totalScore, 0, 100),
            factors: factors,
            maxPossibleScore: 100
        };
    }

    /**
     * Calculate deception pattern score
     * @param {object} urlAnalysis - URL analyzer results
     * @returns {object} Pattern score breakdown
     */
    function calculatePatternScore(urlAnalysis) {
        const features = urlAnalysis.features;
        let totalScore = 0;
        const factors = [];

        // Deception patterns
        if (features.deception.isSuspicious) {
            const patternCount = features.deception.totalPatterns;
            const patternScore = Math.min(SCORING_WEIGHTS.PATTERNS.DECEPTION_PATTERNS,
                                          patternCount * 8);
            totalScore += patternScore;
            factors.push({
                name: 'Deception Patterns',
                score: patternScore,
                detail: `${patternCount} pattern(s) detected`
            });
        }

        // High entropy (random-looking)
        if (features.entropy.isSuspicious) {
            const entropyScore = Math.round(features.entropy.max * 5);
            totalScore += entropyScore;
            factors.push({
                name: 'High Domain Entropy',
                score: entropyScore,
                detail: `Max entropy: ${features.entropy.max.toFixed(2)}`
            });
        }

        // Special character density
        if (features.characters.hostnameCharDensity > 0.3) {
            const charScore = Math.round(features.characters.hostnameCharDensity * 20);
            totalScore += charScore;
            factors.push({
                name: 'Excessive Special Characters',
                score: charScore,
                detail: `${Math.round(features.characters.hostnameCharDensity * 100)}% density`
            });
        }

        // Excessive encoding
        if (features.characters.hasHexEncoding && features.characters.hexEncodedSegments > 5) {
            const encScore = Math.min(SCORING_WEIGHTS.PATTERNS.EXCESSIVE_ENCODING,
                                      features.characters.hexEncodedSegments * 2);
            totalScore += encScore;
            factors.push({
                name: 'Heavy URL Obfuscation',
                score: encScore,
                detail: `${features.characters.hexEncodedSegments} encoded segments`
            });
        }

        return {
            totalScore: clamp(totalScore, 0, 100),
            factors: factors,
            maxPossibleScore: 100
        };
    }

    // ============================================================================
    // MAIN RISK CALCULATION
    // ============================================================================

    /**
     * Calculate comprehensive risk score
     * @param {string} url - URL to analyze
     * @param {object} urlAnalysis - URL analyzer results
     * @param {object} intentAnalysis - Intent engine results
     * @param {object} infraAnalysis - Infrastructure analysis (optional)
     * @returns {object} Complete risk assessment
     */
    function calculateRiskScore(url, urlAnalysis, intentAnalysis, infraAnalysis = {}) {
        const startTime = now();

        // Calculate individual component scores
        const structureScore = calculateStructureScore(urlAnalysis);
        const brandScore = calculateBrandScore(urlAnalysis);
        const intentScore = calculateIntentScore(intentAnalysis);
        const infraScore = calculateInfrastructureScore(infraAnalysis || {});
        const patternScore = calculatePatternScore(urlAnalysis);

        // Define category weights
        const weights = {
            structure: 0.25,
            brand: 0.25,
            intent: 0.30,
            infrastructure: 0.10,
            patterns: 0.10
        };

        // Calculate weighted total
        const totalScore = Math.round(
            (structureScore.totalScore * weights.structure) +
            (brandScore.totalScore * weights.brand) +
            (intentScore.totalScore * weights.intent) +
            (infraScore.totalScore * weights.infrastructure) +
            (patternScore.totalScore * weights.patterns)
        );

        const riskLevel = getRiskLevel(totalScore);

        // Compile all risk factors
        const allFactors = [
            ...structureScore.factors,
            ...brandScore.factors,
            ...intentScore.factors,
            ...infraScore.factors,
            ...patternScore.factors
        ];

        // Sort by score descending
        allFactors.sort((a, b) => b.score - a.score);

        // Generate explanation
        const explanation = generateExplanation(totalScore, riskLevel, allFactors, urlAnalysis, intentAnalysis);

        // Generate recommendations
        const recommendations = generateRiskRecommendations(totalScore, riskLevel, allFactors);

        return {
            success: true,
            timestamp: new Date().toISOString(),
            calculationTime: now() - startTime,

            // Core risk assessment
            riskScore: clamp(totalScore, 0, 100),
            riskLevel: riskLevel.level,
            riskColor: riskLevel.color,
            shouldBlock: totalScore >= THRESHOLDS.BLOCK,
            shouldWarn: totalScore >= THRESHOLDS.WARN,

            // Detailed breakdown
            breakdown: {
                structure: structureScore,
                brand: brandScore,
                intent: intentScore,
                infrastructure: infraScore,
                patterns: patternScore
            },

            // Score components for display
            components: {
                urlStructure: structureScore.totalScore,
                brandImpersonation: brandScore.totalScore,
                intentAttack: intentScore.totalScore,
                infrastructure: infraScore.totalScore,
                deceptionPatterns: patternScore.totalScore
            },

            // All contributing factors
            riskFactors: allFactors,
            factorCount: allFactors.length,

            // Human-readable output
            explanation: explanation,
            recommendations: recommendations,
            summary: generateSummary(totalScore, riskLevel),

            // Decision info
            decision: {
                action: riskLevel.action,
                color: riskLevel.color,
                icon: riskLevel.icon,
                description: riskLevel.description
            },

            // URLs to check
            analysisUrls: {
                whois: `https://www.whois.com/whois/${urlAnalysis.parsed?.hostname}`,
                virustotal: `https://www.virustotal.com/gui/home/search/${encodeURIComponent(url)}`,
                googleSafeBrowsing: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`
            }
        };
    }

    /**
     * Generate human-readable explanation
     * @param {number} score - Risk score
     * @param {object} riskLevel - Risk level info
     * @param {array} factors - All risk factors
     * @param {object} urlAnalysis - URL analysis
     * @param {object} intentAnalysis - Intent analysis
     * @returns {string} Explanation text
     */
    function generateExplanation(score, riskLevel, factors, urlAnalysis, intentAnalysis) {
        const parts = [];

        // Overall assessment
        parts.push(`${riskLevel.icon} ${riskLevel.description}`);

        // Key findings
        if (factors.length > 0) {
            parts.push('\n\nKey Risk Indicators:');
            const topFactors = factors.slice(0, 5);
            for (let factor of topFactors) {
                parts.push(`• ${factor.name}: ${factor.detail}`);
            }
        }

        // Brand impersonation details
        if (urlAnalysis.features?.brand?.hasTyposquatting) {
            parts.push('\n\n⚠️ Brand Impersonation Detected:');
            for (let typo of urlAnalysis.features.brand.typosquatting) {
                parts.push(`  "${typo.original}" looks like "${typo.matchedBrand}"`);
            }
        }

        // Attack type details
        if (intentAnalysis.attackClassification?.primaryAttack) {
            const attack = intentAnalysis.attackClassification.primaryAttack;
            parts.push(`\n\n🎯 Attack Type: ${attack.name}`);
            if (attack.evidence.length > 0) {
                parts.push(`   Evidence: ${attack.evidence.slice(0, 3).join(', ')}`);
            }
        }

        // Manipulation details
        if (intentAnalysis.manipulationAnalysis?.isHighlyManipulative) {
            parts.push('\n\n⚠️ Psychological manipulation techniques detected');
            const techniques = intentAnalysis.manipulationAnalysis.techniques;
            const active = Object.entries(techniques)
                .filter(([_, v]) => v.length > 0])
                .map(([k, _]) => k);
            if (active.length > 0) {
                parts.push(`   Techniques: ${active.join(', ')}`);
            }
        }

        return parts.join('\n');
    }

    /**
     * Generate safety recommendations
     * @param {number} score - Risk score
     * @param {object} riskLevel - Risk level
     * @param {array} factors - Risk factors
     * @returns {string[]} Recommendations
     */
    function generateRiskRecommendations(score, riskLevel, factors) {
        const recommendations = [];

        // Block-level recommendations
        if (score >= THRESHOLDS.BLOCK) {
            recommendations.push('Do NOT enter any personal information');
            recommendations.push('Do NOT click any links on this page');
            recommendations.push('Close this tab immediately');
            recommendations.push('If you entered credentials, change them immediately');
            recommendations.push('Report this URL to your security team');
        }
        // Warn-level recommendations
        else if (score >= THRESHOLDS.WARN) {
            recommendations.push('Verify the URL is the official domain');
            recommendations.push('Do not enter passwords - use bookmarks instead');
            recommendations.push('Check for HTTPS certificate validity');
            recommendations.push('Look for spelling errors in the URL');
            recommendations.push('When in doubt, navigate directly to the official site');
        }
        // Safe-level recommendations
        else {
            recommendations.push('Continue to browse safely');
            recommendations.push('Always verify URLs before entering sensitive data');
            recommendations.push('Keep your browser and security software updated');
        }

        // Add specific recommendations based on factors
        const hasUrgency = factors.some(f => f.name.includes('Urgency'));
        if (hasUrgency) {
            recommendations.push('Be cautious of time-pressure tactics');
        }

        const hasBrandRisk = factors.some(f => f.name.includes('Brand') || f.name.includes('Typo'));
        if (hasBrandRisk) {
            recommendations.push('Double-check the domain spelling carefully');
        }

        return recommendations;
    }

    /**
     * Generate short summary
     * @param {number} score - Risk score
     * @param {object} riskLevel - Risk level
     * @returns {string} Summary
     */
    function generateSummary(score, riskLevel) {
        return `${riskLevel.icon} Risk Score: ${score}/100 - ${riskLevel.level}`;
    }

    // ============================================================================
    // URL VISUALIZATION
    // ============================================================================

    /**
     * Generate highlighted URL breakdown
     * @param {string} url - Original URL
     * @param {object} urlAnalysis - URL analysis results
     * @param {object} intentAnalysis - Intent analysis results
     * @returns {object} Highlighted segments
     */
    function highlightURLComponents(url, urlAnalysis, intentAnalysis) {
        const parsed = parseURL(url);
        if (!parsed) return null;

        const segments = {
            protocol: {
                text: parsed.protocol + '://',
                type: 'protocol',
                isSafe: parsed.protocol === 'https',
                isSuspicious: parsed.protocol === 'http' || parsed.protocol === 'javascript'
            },
            subdomain: {
                text: parsed.subdomain ? parsed.subdomain + '.' : '',
                type: 'subdomain',
                isSuspicious: urlAnalysis?.features?.subdomain?.isSuspicious
            },
            domain: {
                text: parsed.domain,
                type: 'domain',
                isSuspicious: urlAnalysis?.features?.brand?.hasTyposquatting,
                brand: urlAnalysis?.features?.brand?.detectedBrands[0] || null
            },
            tld: {
                text: '.' + parsed.tld,
                type: 'tld',
                isSuspicious: urlAnalysis?.features?.tld?.isSuspiciousTLD
            },
            path: {
                text: parsed.pathname,
                type: 'path',
                isSuspicious: urlAnalysis?.features?.path?.isSuspicious
            },
            query: {
                text: parsed.search,
                type: 'query',
                isSuspicious: urlAnalysis?.features?.path?.hasSensitiveParams
            }
        };

        // Add brand/action/urgency word highlighting
        const highlights = [];
        const words = extractWordsFromURL(url);

        for (let word of words) {
            const lowerWord = word.toLowerCase();
            
            // Check if it's a brand
            if (IntentEngine.ALL_BRANDS.includes(lowerWord)) {
                highlights.push({
                    word: word,
                    type: 'brand',
                    description: 'Known brand name'
                });
            }
            
            // Check if it's an action word
            for (let category in IntentEngine.ATTACK_PATTERNS) {
                const pattern = IntentEngine.ATTACK_PATTERNS[category];
                if (pattern.indicators.some(ind => lowerWord.includes(ind))) {
                    highlights.push({
                        word: word,
                        type: 'attack',
                        category: category,
                        description: `${pattern.name} indicator`
                    });
                }
            }
        }

        return {
            segments: segments,
            highlights: highlights,
            original: url
        };
    }

    // ============================================================================
    // PUBLIC API
    // ============================================================================

    return {
        calculateRiskScore,
        calculateStructureScore,
        calculateBrandScore,
        calculateIntentScore,
        calculateInfrastructureScore,
        calculatePatternScore,
        getRiskLevel,
        highlightURLComponents,
        THRESHOLDS
    };

})();

// Export for various environments
if (typeof chrome !== 'undefined') {
    window.RiskEngine = RiskEngine;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = RiskEngine;
}
