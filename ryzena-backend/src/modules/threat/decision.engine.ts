/**
 * R.Y.Z.E.N.A. - Zero-Trust Decision Engine
 * 
 * Applies Zero-Trust security principles to determine email safety.
 * Computes trust scores and takes protective actions.
 */

import { createLogger } from '../../shared/logger.js';
import { config } from '../../shared/config.js';
import type {
  DecisionInput,
  SecurityAnalysisResult,
  SecurityStatus,
  PhishingResult,
  URLScanResult,
  MalwareResult,
} from './threat.types.js';

const logger = createLogger({ module: 'decision-engine' });

/**
 * URL sanitization pattern replacement
 */
const URL_SANITIZE_REPLACEMENT = '[URL BLOCKED FOR SECURITY]';

/**
 * Sanitize URLs in HTML content
 */
function sanitizeUrlsInHtml(html: string, riskyUrls: string[]): string {
  let sanitized = html;
  
  for (const url of riskyUrls) {
    // Escape special regex characters in URL
    const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // Replace in href attributes
    const hrefPattern = new RegExp(`href=["']${escapedUrl}["']`, 'gi');
    sanitized = sanitized.replace(hrefPattern, `href="#" data-blocked-url="${url}" title="Blocked for security"`);
    
    // Replace in src attributes
    const srcPattern = new RegExp(`src=["']${escapedUrl}["']`, 'gi');
    sanitized = sanitized.replace(srcPattern, `src="" data-blocked-url="${url}" alt="Blocked content"`);
    
    // Replace plain text URLs
    const plainPattern = new RegExp(escapedUrl, 'gi');
    sanitized = sanitized.replace(plainPattern, URL_SANITIZE_REPLACEMENT);
  }
  
  return sanitized;
}

/**
 * Calculate trust score based on analysis results
 * Score ranges from 0 (completely untrusted) to 100 (fully trusted)
 */
function calculateTrustScore(
  phishingResult: PhishingResult,
  urlResults: URLScanResult[],
  malwareResult: MalwareResult
): number {
  // Start with base score derived from phishing probability
  let score = (1 - phishingResult.probability) * 100;
  
  // Reduce score based on URL risks
  const highRiskUrls = urlResults.filter(r => r.riskLevel === 'high').length;
  const mediumRiskUrls = urlResults.filter(r => r.riskLevel === 'medium').length;
  
  score -= highRiskUrls * 15;
  score -= mediumRiskUrls * 5;
  
  // Reduce score for malware risk
  if (malwareResult.hasRisk) {
    score -= malwareResult.flaggedFiles.length * 20;
  }
  
  // Ensure score is within bounds
  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Determine security status based on Zero-Trust rules
 */
function determineStatus(
  phishingResult: PhishingResult,
  urlResults: URLScanResult[],
  malwareResult: MalwareResult
): SecurityStatus {
  // Rule 1: High phishing probability
  if (phishingResult.probability > config.thresholds.phishing) {
    return 'SUSPICIOUS';
  }
  
  // Rule 2: Any high-risk URL
  if (urlResults.some(r => r.riskLevel === 'high')) {
    return 'SUSPICIOUS';
  }
  
  // Rule 3: Malware risk detected
  if (malwareResult.hasRisk) {
    return 'SUSPICIOUS';
  }
  
  return 'SAFE';
}

/**
 * Get URLs that should be blocked
 */
function getBlockedUrls(urlResults: URLScanResult[]): string[] {
  return urlResults
    .filter(r => r.riskLevel === 'high' || r.riskLevel === 'medium')
    .map(r => r.url);
}

/**
 * Determine actions taken during analysis
 */
function determineActions(
  status: SecurityStatus,
  blockedUrls: string[],
  malwareResult: MalwareResult
): string[] {
  const actions: string[] = [];
  
  if (status === 'SUSPICIOUS') {
    actions.push('Email flagged as suspicious');
    
    if (blockedUrls.length > 0) {
      actions.push(`${blockedUrls.length} URL(s) blocked`);
    }
    
    if (malwareResult.hasRisk) {
      actions.push(`${malwareResult.flaggedFiles.length} attachment(s) flagged`);
    }
    
    actions.push('Forwarded to AI explanation service');
  }
  
  return actions;
}

/**
 * Stub for AI explanation service
 * This will be implemented in Phase 3 with Ollama integration
 */
export function forwardToAIExplanationService(
  result: SecurityAnalysisResult
): void {
  logger.info({
    action: 'ai_explanation_stub',
    emailId: result.emailId,
    status: result.status,
    trustScore: result.trustScore,
    message: 'AI explanation service will be integrated in Phase 3',
    phishingSignals: result.phishingSignals,
    urlFindings: result.urlFindings.length,
    malwareRisk: result.malwareFindings.hasRisk,
  });
  
  // Stub: In Phase 3, this will call Ollama to generate
  // natural language explanations of the threat analysis
}

/**
 * Main decision engine function
 * Analyzes all threat signals and produces final security verdict
 */
export function analyzeAndDecide(input: DecisionInput): SecurityAnalysisResult {
  const startTime = Date.now();
  const { parsedEmail, phishingResult, urlScanResults, malwareResult } = input;
  
  // Determine security status
  const status = determineStatus(phishingResult, urlScanResults, malwareResult);
  
  // Calculate trust score
  const trustScore = calculateTrustScore(phishingResult, urlScanResults, malwareResult);
  
  // Get URLs to block
  const blockedUrls = status === 'SUSPICIOUS' ? getBlockedUrls(urlScanResults) : [];
  
  // Sanitize body if suspicious
  const sanitizedBody = status === 'SUSPICIOUS' && blockedUrls.length > 0
    ? sanitizeUrlsInHtml(parsedEmail.bodyHtml, blockedUrls)
    : parsedEmail.bodyHtml;
  
  // Determine actions taken
  const actionsTaken = determineActions(status, blockedUrls, malwareResult);
  
  const result: SecurityAnalysisResult = {
    emailId: parsedEmail.emailId,
    status,
    trustScore,
    phishingSignals: phishingResult.signals,
    phishingProbability: phishingResult.probability,
    urlFindings: urlScanResults,
    malwareFindings: malwareResult,
    sanitizedBody,
    originalBody: parsedEmail.bodyHtml,
    securityFlag: status === 'SUSPICIOUS',
    analyzedAt: new Date().toISOString(),
    actionsTaken,
  };
  
  // Forward to AI service if suspicious
  if (status === 'SUSPICIOUS') {
    forwardToAIExplanationService(result);
  }
  
  logger.info({
    action: 'decision_complete',
    emailId: parsedEmail.emailId,
    status,
    trustScore,
    phishingProbability: phishingResult.probability,
    urlsAnalyzed: urlScanResults.length,
    urlsBlocked: blockedUrls.length,
    malwareRisk: malwareResult.hasRisk,
    durationMs: Date.now() - startTime,
  });
  
  return result;
}

/**
 * Quick threat check without full analysis
 */
export function quickThreatCheck(input: DecisionInput): boolean {
  const { phishingResult, urlScanResults, malwareResult } = input;
  
  return (
    phishingResult.probability > config.thresholds.phishing ||
    urlScanResults.some(r => r.riskLevel === 'high') ||
    malwareResult.hasRisk
  );
}

export default {
  analyzeAndDecide,
  forwardToAIExplanationService,
  quickThreatCheck,
  calculateTrustScore,
  determineStatus,
};
