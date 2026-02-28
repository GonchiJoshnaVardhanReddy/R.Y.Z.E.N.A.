/**
 * R.Y.Z.E.N.A. - Phishing Detection Service
 * 
 * Simulates a pre-trained phishing classifier using weighted heuristic scoring.
 * Designed to be modular and easily replaceable with ML models in Phase 3.
 */

import { createLogger } from '../../shared/logger.js';
import { config } from '../../shared/config.js';
import { detectDomainMismatch } from '../email/email.parser.js';
import type { ParsedEmail } from '../email/email.types.js';
import type { PhishingResult, PhishingSignalConfig } from './threat.types.js';

const logger = createLogger({ module: 'phishing-service' });

/**
 * Urgency keywords that indicate potential phishing
 */
const URGENCY_KEYWORDS = [
  'urgent',
  'immediately',
  'action required',
  'act now',
  'limited time',
  'expires',
  'suspended',
  'verify now',
  'confirm now',
  'within 24 hours',
  'within 48 hours',
  'account will be',
  'failure to',
  'unauthorized',
  'security alert',
  'unusual activity',
  'your account has been',
];

/**
 * Credential harvesting phrases
 */
const CREDENTIAL_PHRASES = [
  'verify your account',
  'confirm your identity',
  'update your information',
  'update your password',
  'reset your password',
  'enter your credentials',
  'login credentials',
  'sign in to verify',
  'confirm your details',
  'provide your',
  'enter your ssn',
  'social security',
  'bank account',
  'credit card',
  'card number',
];

/**
 * Financial urgency language
 */
const FINANCIAL_PHRASES = [
  'wire transfer',
  'bank transfer',
  'payment pending',
  'invoice attached',
  'overdue payment',
  'payment required',
  'claim your prize',
  'you have won',
  'lottery',
  'inheritance',
  'million dollars',
  'bitcoin',
  'cryptocurrency',
  'investment opportunity',
];

/**
 * Suspicious top-level domains
 */
const SUSPICIOUS_TLDS = [
  '.xyz',
  '.top',
  '.click',
  '.link',
  '.info',
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',
  '.buzz',
  '.work',
  '.loan',
  '.win',
  '.racing',
  '.download',
  '.stream',
  '.science',
  '.party',
  '.review',
  '.trade',
  '.bid',
  '.accountant',
  '.cricket',
  '.date',
  '.faith',
  '.men',
  '.webcam',
];

/**
 * Phishing signal definitions with weights
 */
const PHISHING_SIGNALS: PhishingSignalConfig[] = [
  {
    id: 'urgency_keywords',
    name: 'Urgency Keywords Detected',
    weight: 0.15,
    detect: (email) => {
      const content = `${email.subject} ${email.bodyText}`.toLowerCase();
      return URGENCY_KEYWORDS.some(keyword => content.includes(keyword));
    },
  },
  {
    id: 'credential_harvesting',
    name: 'Credential Harvesting Language',
    weight: 0.2,
    detect: (email) => {
      const content = `${email.subject} ${email.bodyText}`.toLowerCase();
      return CREDENTIAL_PHRASES.some(phrase => content.includes(phrase));
    },
  },
  {
    id: 'financial_urgency',
    name: 'Financial Urgency Language',
    weight: 0.15,
    detect: (email) => {
      const content = `${email.subject} ${email.bodyText}`.toLowerCase();
      return FINANCIAL_PHRASES.some(phrase => content.includes(phrase));
    },
  },
  {
    id: 'suspicious_tld',
    name: 'Suspicious TLD in Sender Domain',
    weight: 0.2,
    detect: (email) => {
      return SUSPICIOUS_TLDS.some(tld => email.senderDomain.endsWith(tld));
    },
  },
  {
    id: 'domain_mismatch',
    name: 'Domain Mismatch (Reply-To/Return-Path)',
    weight: 0.25,
    detect: (email) => {
      return detectDomainMismatch(email.senderDomain, email.metadata);
    },
  },
  {
    id: 'url_domain_mismatch',
    name: 'URLs with Different Domains than Sender',
    weight: 0.15,
    detect: (email) => {
      if (email.urls.length === 0) return false;
      
      return email.urls.some(url => {
        try {
          const urlDomain = new URL(url).hostname.toLowerCase();
          // Check if URL domain doesn't match sender domain
          return !urlDomain.includes(email.senderDomain) && 
                 !email.senderDomain.includes(urlDomain);
        } catch {
          return false;
        }
      });
    },
  },
  {
    id: 'suspicious_url_tld',
    name: 'URLs with Suspicious TLDs',
    weight: 0.18,
    detect: (email) => {
      return email.urls.some(url => {
        try {
          const urlDomain = new URL(url).hostname.toLowerCase();
          return SUSPICIOUS_TLDS.some(tld => urlDomain.endsWith(tld));
        } catch {
          return false;
        }
      });
    },
  },
  {
    id: 'excessive_links',
    name: 'Excessive Number of Links',
    weight: 0.1,
    detect: (email) => {
      return email.urls.length > 10;
    },
  },
  {
    id: 'generic_greeting',
    name: 'Generic Greeting',
    weight: 0.08,
    detect: (email) => {
      const content = email.bodyText.toLowerCase();
      const genericGreetings = [
        'dear customer',
        'dear user',
        'dear sir',
        'dear madam',
        'dear valued',
        'dear member',
        'dear account holder',
      ];
      return genericGreetings.some(greeting => content.includes(greeting));
    },
  },
  {
    id: 'spoofed_brand',
    name: 'Potential Brand Spoofing',
    weight: 0.2,
    detect: (email) => {
      const brandNames = [
        'paypal',
        'microsoft',
        'apple',
        'google',
        'amazon',
        'netflix',
        'bank of america',
        'wells fargo',
        'chase',
        'facebook',
        'instagram',
        'linkedin',
        'dropbox',
        'office365',
      ];
      const content = `${email.subject} ${email.bodyText}`.toLowerCase();
      
      // Check if content mentions brand but sender domain doesn't match
      return brandNames.some(brand => {
        const mentionsBrand = content.includes(brand);
        const senderMatchesBrand = email.senderDomain.includes(brand.replace(/\s/g, ''));
        return mentionsBrand && !senderMatchesBrand;
      });
    },
  },
  {
    id: 'failed_auth',
    name: 'Failed Email Authentication',
    weight: 0.15,
    detect: (email) => {
      const { spfResult, dkimResult, dmarcResult } = email.metadata;
      const failedResults = ['fail', 'softfail', 'none', 'temperror', 'permerror'];
      
      return Boolean(
        (spfResult && failedResults.includes(spfResult.toLowerCase())) ||
        (dkimResult && failedResults.includes(dkimResult.toLowerCase())) ||
        (dmarcResult && failedResults.includes(dmarcResult.toLowerCase()))
      );
    },
  },
];

/**
 * Analyze email for phishing indicators
 * @param email - Parsed email to analyze
 * @returns Phishing analysis result with probability and signals
 */
export function analyzePhishing(email: ParsedEmail): PhishingResult {
  const startTime = Date.now();
  const detectedSignals: string[] = [];
  const signalWeights: Record<string, number> = {};
  let totalWeight = 0;
  
  // Run each signal detector
  for (const signal of PHISHING_SIGNALS) {
    try {
      if (signal.detect(email)) {
        detectedSignals.push(signal.name);
        signalWeights[signal.id] = signal.weight;
        totalWeight += signal.weight;
      }
    } catch (error) {
      logger.warn({
        action: 'signal_detection_error',
        signalId: signal.id,
        emailId: email.emailId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  
  // Calculate probability (capped at 1.0)
  const probability = Math.min(totalWeight, 1.0);
  
  // Round to 3 decimal places
  const roundedProbability = Math.round(probability * 1000) / 1000;
  
  logger.info({
    action: 'phishing_analysis_complete',
    emailId: email.emailId,
    probability: roundedProbability,
    signalsDetected: detectedSignals.length,
    signals: detectedSignals,
    durationMs: Date.now() - startTime,
  });
  
  return {
    probability: roundedProbability,
    signals: detectedSignals,
    signalWeights,
  };
}

/**
 * Check if phishing probability exceeds threshold
 */
export function isPhishingThreat(result: PhishingResult): boolean {
  return result.probability > config.thresholds.phishing;
}

/**
 * Get configured phishing signals (for testing/debugging)
 */
export function getPhishingSignals(): PhishingSignalConfig[] {
  return [...PHISHING_SIGNALS];
}

export default {
  analyzePhishing,
  isPhishingThreat,
  getPhishingSignals,
  URGENCY_KEYWORDS,
  CREDENTIAL_PHRASES,
  FINANCIAL_PHRASES,
  SUSPICIOUS_TLDS,
};
