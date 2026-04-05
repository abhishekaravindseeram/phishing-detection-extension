/**
 * Intent-Aware Phishing Detection System
 * Logger Module
 * 
 * Centralized logging with levels, persistence, and performance tracking.
 */

const Logger = (function() {
    'use strict';

    const LEVELS = Object.freeze({
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3,
        CRITICAL: 4
    });

    const LEVEL_NAMES = Object.freeze({
        [LEVELS.DEBUG]: 'DEBUG',
        [LEVELS.INFO]: 'INFO',
        [LEVELS.WARN]: 'WARN',
        [LEVELS.ERROR]: 'ERROR',
        [LEVELS.CRITICAL]: 'CRITICAL'
    });

    class Logger {
        constructor(namespace = 'PhishGuard') {
            this.namespace = namespace;
            this.minLevel = LEVELS.INFO;
            this.logs = [];
            this.maxLogs = 100;
            this.enableConsole = true;
            this.enableStorage = false;
            this.listeners = [];
        }

        setMinLevel(level) {
            if (typeof level === 'string') {
                this.minLevel = LEVELS[level.toUpperCase()] ?? LEVELS.INFO;
            } else {
                this.minLevel = level;
            }
        }

        setStorageEnabled(enabled, maxLogs = 100) {
            this.enableStorage = enabled;
            this.maxLogs = maxLogs;
        }

        addListener(callback) {
            this.listeners.push(callback);
        }

        removeListener(callback) {
            const index = this.listeners.indexOf(callback);
            if (index > -1) {
                this.listeners.splice(index, 1);
            }
        }

        _createLogEntry(level, message, data = null) {
            return {
                timestamp: new Date().toISOString(),
                level: LEVEL_NAMES[level],
                namespace: this.namespace,
                message: String(message),
                data: data,
                performance: performance.now ? performance.now() : null
            };
        }

        _log(level, message, ...args) {
            if (level < this.minLevel) return;

            const hasData = args.length > 0;
            const data = hasData ? (args.length === 1 ? args[0] : args) : null;
            const entry = this._createLogEntry(level, message, data);

            if (this.enableConsole) {
                const prefix = `[${entry.timestamp}] [${entry.level}] [${this.namespace}]`;
                const logMethod = level >= LEVELS.ERROR ? 'error' : level === LEVELS.WARN ? 'warn' : 'log';
                
                if (data) {
                    console[logMethod](`${prefix} ${message}`, data);
                } else {
                    console[logMethod](`${prefix} ${message}`);
                }
            }

            if (this.enableStorage && this.logs.length < this.maxLogs) {
                this.logs.push(entry);
            }

            this.listeners.forEach(listener => {
                try {
                    listener(entry);
                } catch (e) {
                    console.error('Logger listener error:', e);
                }
            });

            return entry;
        }

        debug(message, ...data) {
            return this._log(LEVELS.DEBUG, message, ...data);
        }

        info(message, ...data) {
            return this._log(LEVELS.INFO, message, ...data);
        }

        warn(message, ...data) {
            return this._log(LEVELS.WARN, message, ...data);
        }

        error(message, ...data) {
            return this._log(LEVELS.ERROR, message, ...data);
        }

        critical(message, ...data) {
            return this._log(LEVELS.CRITICAL, message, ...data);
        }

        logAnalysis(url, result) {
            this.info('URL Analysis Complete', {
                url: url,
                riskScore: result.riskScore,
                riskLevel: result.riskLevel,
                decision: result.action,
                attackType: result.primaryAttack?.type || 'None',
                factorCount: result.factors?.length || 0,
                duration: result.duration || 0
            });
        }

        logThreat(type, details) {
            this.warn(`Threat Detected: ${type}`, details);
        }

        logDecision(url, decision, riskScore) {
            this.info('User Decision', {
                url: url,
                decision: decision,
                riskScore: riskScore,
                timestamp: new Date().toISOString()
            });
        }

        logError(context, error) {
            this.error(`Error in ${context}`, {
                message: error.message,
                stack: error.stack,
                timestamp: new Date().toISOString()
            });
        }

        async persistToStorage() {
            if (!this.enableStorage || typeof chrome === 'undefined') return;

            try {
                const stored = await chrome.storage.local.get(CONFIG.STORAGE.KEYS.LOGS);
                let logs = stored[CONFIG.STORAGE.KEYS.LOGS] || [];
                
                logs = [...logs, ...this.logs].slice(-this.maxLogs);
                
                await chrome.storage.local.set({
                    [CONFIG.STORAGE.KEYS.LOGS]: logs
                });
                
                this.logs = [];
            } catch (error) {
                console.error('Failed to persist logs:', error);
            }
        }

        async getStoredLogs() {
            if (typeof chrome === 'undefined') return [];

            try {
                const stored = await chrome.storage.local.get(CONFIG.STORAGE.KEYS.LOGS);
                return stored[CONFIG.STORAGE.KEYS.LOGS] || [];
            } catch (error) {
                console.error('Failed to retrieve logs:', error);
                return [];
            }
        }

        async clearLogs() {
            this.logs = [];
            if (typeof chrome !== 'undefined') {
                try {
                    await chrome.storage.local.remove(CONFIG.STORAGE.KEYS.LOGS);
                } catch (error) {
                    console.error('Failed to clear logs:', error);
                }
            }
        }

        exportLogs() {
            const allLogs = [...this.logs];
            return {
                exportedAt: new Date().toISOString(),
                count: allLogs.length,
                logs: allLogs
            };
        }

        getFilteredLogs(level = null, namespace = null) {
            return this.logs.filter(log => {
                if (level && log.level !== LEVEL_NAMES[level]) return false;
                if (namespace && log.namespace !== namespace) return false;
                return true;
            });
        }
    }

    const defaultLogger = new Logger('PhishGuard');
    defaultLogger.setMinLevel(LEVELS.INFO);

    return {
        Logger,
        LEVELS,
        LEVEL_NAMES,
        getLogger: (namespace) => new Logger(namespace),
        defaultLogger
    };

})();

if (typeof chrome !== 'undefined') {
    window.Logger = Logger;
    window.logger = Logger.defaultLogger;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = Logger;
}
