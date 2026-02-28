/**
 * R.Y.Z.E.N.A. - URL Scan Service
 * 
 * Analyzes URLs for potential security risks.
 * Simulates domain reputation checks and pattern detection.
 */

import { createLogger } from '../../shared/logger.js';
import type { URLScanResult, URLRiskLevel, URLFindings } from './threat.types.js';

const logger = createLogger({ module: 'url-scan-service' });

/**
 * Suspicious TLDs commonly used in malicious URLs
 */
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'link', 'info', 'tk', 'ml', 'ga', 'cf', 'gq',
  'buzz', 'work', 'loan', 'win', 'racing', 'download', 'stream', 'science',
  'party', 'review', 'trade', 'bid', 'accountant', 'cricket', 'date',
  'faith', 'men', 'webcam', 'zip', 'mov', 'icu', 'cyou', 'site', 'online',
]);

/**
 * Patterns indicating potential redirect/phishing URLs
 */
const REDIRECT_PATTERNS = [
  /\bredirect\b/i,
  /\burl=/i,
  /\bgoto=/i,
  /\bnext=/i,
  /\breturn=/i,
  /\bcontinue=/i,
  /\bforward=/i,
  /\blink=/i,
  /bit\.ly/i,
  /tinyurl/i,
  /t\.co\//i,
  /goo\.gl/i,
  /is\.gd/i,
  /buff\.ly/i,
  /ow\.ly/i,
  /short\./i,
];

/**
 * Suspicious URL patterns
 */
const MALICIOUS_PATTERNS = [
  /login[.-]/i,
  /signin[.-]/i,
  /account[.-]verify/i,
  /secure[.-]/i,
  /update[.-]info/i,
  /confirm[.-]/i,
  /verify[.-]account/i,
  /suspended/i,
  /\.php\?/i,
  /password/i,
  /credential/i,
  /@.*@/, // Multiple @ signs
  /[^\w]0[^\w]/, // Zero in suspicious contexts
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP address in URL
];

/**
 * Known safe domains (simplified whitelist)
 */
const TRUSTED_DOMAINS = new Set([
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'github.com', 'linkedin.com', 'facebook.com', 'twitter.com',
  'youtube.com', 'wikipedia.org', 'edu', 'gov',
]);

/**
 * Check if a string is an IP address
 */
function isIpAddress(str: string): boolean {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Pattern.test(str) || ipv6Pattern.test(str);
}

/**
 * Extract TLD from domain
 */
function extractTld(domain: string): string {
  const parts = domain.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

/**
 * Check if domain is trusted
 */
function isTrustedDomain(domain: string): boolean {
  const lowerDomain = domain.toLowerCase();
  
  // Check exact match
  if (TRUSTED_DOMAINS.has(lowerDomain)) return true;
  
  // Check if subdomain of trusted domain
  for (const trusted of TRUSTED_DOMAINS) {
    if (lowerDomain.endsWith(`.${trusted}`)) return true;
  }
  
  // Check .edu and .gov TLDs
  if (lowerDomain.endsWith('.edu') || lowerDomain.endsWith('.gov')) return true;
  
  return false;
}

/**
 * Calculate URL path depth
 */
function getPathDepth(pathname: string): number {
  return pathname.split('/').filter(p => p.length > 0).length;
}

/**
 * Analyze URL findings
 */
function analyzeUrl(url: string): URLFindings | null {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const tld = extractTld(domain);
    
    return {
      isHttps: parsed.protocol === 'https:',
      isIpBased: isIpAddress(domain),
      domain,
      tld,
      isSuspiciousTld: SUSPICIOUS_TLDS.has(tld),
      hasRedirectPattern: REDIRECT_PATTERNS.some(p => p.test(url)),
      pathDepth: getPathDepth(parsed.pathname),
    };
  } catch {
    return null;
  }
}

/**
 * Determine risk level based on findings
 */
function determineRiskLevel(
  url: string, 
  findings: URLFindings
): { level: URLRiskLevel; reason: string } {
  const reasons: string[] = [];
  let riskScore = 0;
  
  // IP-based URL is high risk
  if (findings.isIpBased) {
    riskScore += 0.6;
    reasons.push('IP-based URL');
  }
  
  // No HTTPS
  if (!findings.isHttps) {
    riskScore += 0.2;
    reasons.push('No HTTPS');
  }
  
  // Suspicious TLD
  if (findings.isSuspiciousTld) {
    riskScore += 0.3;
    reasons.push(`Suspicious TLD (.${findings.tld})`);
  }
  
  // Redirect pattern detected
  if (findings.hasRedirectPattern) {
    riskScore += 0.25;
    reasons.push('Redirect/shortener pattern');
  }
  
  // Deep path
  if (findings.pathDepth > 5) {
    riskScore += 0.15;
    reasons.push('Unusually deep URL path');
  }
  
  // Check for malicious patterns
  const maliciousMatches = MALICIOUS_PATTERNS.filter(p => p.test(url));
  if (maliciousMatches.length > 0) {
    riskScore += 0.3 * maliciousMatches.length;
    reasons.push('Suspicious URL pattern');
  }
  
  // Trusted domain reduces risk
  if (isTrustedDomain(findings.domain)) {
    riskScore = Math.max(0, riskScore - 0.5);
    if (reasons.length > 0) {
      reasons.push('(Trusted domain)');
    }
  }
  
  // Determine level
  let level: URLRiskLevel;
  if (riskScore >= 0.6) {
    level = 'high';
  } else if (riskScore >= 0.3) {
    level = 'medium';
  } else {
    level = 'low';
  }
  
  const reason = reasons.length > 0 ? reasons.join(', ') : 'No issues detected';
  
  return { level, reason };
}

/**
 * Scan a single URL for security risks
 * @param url - URL to scan
 * @returns Scan result with risk level and reason
 */
export function scanUrl(url: string): URLScanResult {
  const findings = analyzeUrl(url);
  
  if (!findings) {
    return {
      url,
      riskLevel: 'high',
      reason: 'Invalid or malformed URL',
    };
  }
  
  const { level, reason } = determineRiskLevel(url, findings);
  
  return {
    url,
    riskLevel: level,
    reason,
    findings,
  };
}

/**
 * Scan multiple URLs
 * @param urls - Array of URLs to scan
 * @returns Array of scan results
 */
export function scanUrls(urls: string[]): URLScanResult[] {
  const startTime = Date.now();
  const results: URLScanResult[] = [];
  
  for (const url of urls) {
    try {
      results.push(scanUrl(url));
    } catch (error) {
      logger.warn({
        action: 'url_scan_error',
        url,
        error: error instanceof Error ? error.message : String(error),
      });
      
      results.push({
        url,
        riskLevel: 'medium',
        reason: 'Error scanning URL',
      });
    }
  }
  
  // Log summary
  const highRiskCount = results.filter(r => r.riskLevel === 'high').length;
  const mediumRiskCount = results.filter(r => r.riskLevel === 'medium').length;
  
  logger.info({
    action: 'url_scan_complete',
    totalUrls: urls.length,
    highRisk: highRiskCount,
    mediumRisk: mediumRiskCount,
    lowRisk: urls.length - highRiskCount - mediumRiskCount,
    durationMs: Date.now() - startTime,
  });
  
  return results;
}

/**
 * Check if any URL has high risk
 */
export function hasHighRiskUrl(results: URLScanResult[]): boolean {
  return results.some(r => r.riskLevel === 'high');
}

/**
 * Sanitize URL for display (replace with warning)
 */
export function sanitizeUrl(url: string): string {
  return `[BLOCKED: ${url.substring(0, 50)}...]`;
}

export default {
  scanUrl,
  scanUrls,
  hasHighRiskUrl,
  sanitizeUrl,
  SUSPICIOUS_TLDS: [...SUSPICIOUS_TLDS],
  TRUSTED_DOMAINS: [...TRUSTED_DOMAINS],
};
