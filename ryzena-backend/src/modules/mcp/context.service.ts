/**
 * R.Y.Z.E.N.A. - MCP Context Service
 * 
 * Provides structured context injection for LLM prompts.
 * Implements secure data access patterns following MCP principles.
 */

import { createLogger } from '../../shared/logger.js';
import type { SecurityAnalysisResult } from '../threat/threat.types.js';
import type { ParsedEmail } from '../email/email.types.js';
import type {
  MCPContextBundle,
  MCPEmailContext,
  MCPSecurityContext,
  MCPUserContext,
  MCPSystemContext,
  MCPURLFinding,
  MCPContextOptions,
} from './context.types.js';

const logger = createLogger({ module: 'mcp-context' });

/**
 * Default context options
 */
const DEFAULT_OPTIONS: MCPContextOptions = {
  includeFullBody: false,
  includeUrlDetails: true,
  includeAttachmentDetails: true,
  permissions: {
    canAccessFullEmail: false,
    canAccessUserProfile: false,
    canAccessHistoricalData: false,
    canAccessSensitiveFields: false,
  },
};

/**
 * Maximum body preview length
 */
const MAX_BODY_PREVIEW = 500;

/**
 * Extract domain from URL safely
 */
function extractUrlDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

/**
 * Build email context from parsed email
 */
function buildEmailContext(
  email: ParsedEmail,
  options: MCPContextOptions
): MCPEmailContext {
  const bodyPreview = email.bodyText.substring(0, MAX_BODY_PREVIEW);
  
  return {
    id: email.emailId,
    sender: {
      address: email.sender,
      domain: email.senderDomain,
    },
    recipient: {
      address: email.recipient,
      domain: email.recipient.split('@')[1] || 'unknown',
    },
    subject: email.subject,
    bodyPreview: options.includeFullBody ? email.bodyText : bodyPreview,
    bodyLength: email.bodyText.length,
    urls: {
      count: email.urls.length,
      domains: [...new Set(email.urls.map(extractUrlDomain))],
    },
    attachments: {
      count: email.attachments.length,
      types: [...new Set(email.attachments.map(a => a.extension))],
      names: email.attachments.map(a => a.filename),
    },
    headers: {
      replyTo: email.metadata.replyTo,
      returnPath: email.metadata.returnPath,
      hasAuthFailures: Boolean(
        email.metadata.spfResult === 'fail' ||
        email.metadata.dkimResult === 'fail' ||
        email.metadata.dmarcResult === 'fail'
      ),
    },
    receivedAt: email.timestamp,
  };
}

/**
 * Build security context from analysis result
 */
function buildSecurityContext(
  result: SecurityAnalysisResult,
  options: MCPContextOptions
): MCPSecurityContext {
  const urlFindings: MCPURLFinding[] = options.includeUrlDetails
    ? result.urlFindings.map(f => ({
        url: f.url,
        domain: extractUrlDomain(f.url),
        riskLevel: f.riskLevel,
        reasons: [f.reason],
      }))
    : [];

  return {
    verdict: result.status,
    trustScore: result.trustScore,
    phishing: {
      probability: result.phishingProbability,
      signals: result.phishingSignals,
      signalCount: result.phishingSignals.length,
    },
    urls: {
      scanned: result.urlFindings.length,
      highRisk: result.urlFindings.filter(f => f.riskLevel === 'high').length,
      mediumRisk: result.urlFindings.filter(f => f.riskLevel === 'medium').length,
      lowRisk: result.urlFindings.filter(f => f.riskLevel === 'low').length,
      findings: urlFindings,
    },
    malware: {
      detected: result.malwareFindings.hasRisk,
      flaggedFiles: result.malwareFindings.flaggedFiles,
      risks: result.malwareFindings.findings?.flatMap(f => f.risks) || [],
    },
    actions: result.actionsTaken,
  };
}

/**
 * Build user context (stub for future implementation)
 */
function buildUserContext(): MCPUserContext {
  // Stub implementation - will be expanded in future phases
  return {
    type: 'student',
    experienceLevel: 'novice',
    preferredLanguage: 'en',
    accessLevel: 'standard',
  };
}

/**
 * Build system context
 */
function buildSystemContext(): MCPSystemContext {
  return {
    serviceName: 'R.Y.Z.E.N.A.',
    version: '3.0.0',
    environment: process.env.NODE_ENV || 'development',
    capabilities: [
      'phishing_detection',
      'url_scanning',
      'malware_detection',
      'ai_explanation',
      'educational_content',
    ],
    constraints: [
      'no_external_api_calls',
      'local_llm_only',
      'no_pii_storage',
      'deterministic_prompts',
    ],
  };
}

/**
 * Build complete MCP context bundle
 */
export function buildContext(
  email: ParsedEmail,
  securityResult: SecurityAnalysisResult,
  options: MCPContextOptions = DEFAULT_OPTIONS
): MCPContextBundle {
  const startTime = Date.now();
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options };

  const context: MCPContextBundle = {
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    email: buildEmailContext(email, mergedOptions),
    security: buildSecurityContext(securityResult, mergedOptions),
    user: buildUserContext(),
    system: buildSystemContext(),
  };

  logger.debug({
    action: 'context_built',
    emailId: email.emailId,
    contextSize: JSON.stringify(context).length,
    durationMs: Date.now() - startTime,
  });

  return context;
}

/**
 * Build context from SecurityAnalysisResult only
 * (when ParsedEmail is not available)
 */
export function buildContextFromAnalysis(
  result: SecurityAnalysisResult,
  options: MCPContextOptions = DEFAULT_OPTIONS
): MCPContextBundle {
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options };

  // Create minimal email context from what we have
  const emailContext: MCPEmailContext = {
    id: result.emailId,
    sender: { address: 'unknown', domain: 'unknown' },
    recipient: { address: 'unknown', domain: 'unknown' },
    subject: 'Unknown',
    bodyPreview: result.originalBody.substring(0, MAX_BODY_PREVIEW),
    bodyLength: result.originalBody.length,
    urls: {
      count: result.urlFindings.length,
      domains: [...new Set(result.urlFindings.map(f => extractUrlDomain(f.url)))],
    },
    attachments: {
      count: result.malwareFindings.flaggedFiles.length,
      types: [],
      names: result.malwareFindings.flaggedFiles,
    },
    headers: {
      hasAuthFailures: false,
    },
    receivedAt: result.analyzedAt,
  };

  return {
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    email: emailContext,
    security: buildSecurityContext(result, mergedOptions),
    user: buildUserContext(),
    system: buildSystemContext(),
  };
}

/**
 * Serialize context to string for prompt injection
 */
export function serializeContext(context: MCPContextBundle): string {
  const sections: string[] = [];

  // Email section
  sections.push(`## Email Information
- ID: ${context.email.id}
- From: ${context.email.sender.address} (domain: ${context.email.sender.domain})
- To: ${context.email.recipient.address}
- Subject: ${context.email.subject}
- URLs found: ${context.email.urls.count}
- Attachments: ${context.email.attachments.count}
- Body preview: ${context.email.bodyPreview.substring(0, 200)}...`);

  // Security section
  sections.push(`## Security Analysis
- Verdict: ${context.security.verdict}
- Trust Score: ${context.security.trustScore}/100
- Phishing Probability: ${(context.security.phishing.probability * 100).toFixed(1)}%
- Detected Signals: ${context.security.phishing.signals.join(', ') || 'None'}
- URLs Scanned: ${context.security.urls.scanned} (High Risk: ${context.security.urls.highRisk}, Medium: ${context.security.urls.mediumRisk})
- Malware Detected: ${context.security.malware.detected ? 'Yes' : 'No'}
- Flagged Files: ${context.security.malware.flaggedFiles.join(', ') || 'None'}`);

  // User section
  sections.push(`## User Context
- Type: ${context.user.type}
- Experience Level: ${context.user.experienceLevel}
- Language: ${context.user.preferredLanguage}`);

  return sections.join('\n\n');
}

/**
 * Get risk level description
 */
export function getRiskLevelDescription(context: MCPContextBundle): string {
  const { trustScore, phishing, malware } = context.security;
  
  if (trustScore < 20 || malware.detected || phishing.probability > 0.8) {
    return 'CRITICAL - This email poses a severe security threat';
  }
  if (trustScore < 50 || phishing.probability > 0.6) {
    return 'HIGH - This email shows strong indicators of being malicious';
  }
  if (trustScore < 70 || phishing.probability > 0.4) {
    return 'MEDIUM - This email has some suspicious characteristics';
  }
  return 'LOW - This email appears to be legitimate';
}

export default {
  buildContext,
  buildContextFromAnalysis,
  serializeContext,
  getRiskLevelDescription,
};
