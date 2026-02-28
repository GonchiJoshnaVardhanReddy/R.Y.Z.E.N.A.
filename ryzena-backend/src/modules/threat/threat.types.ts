/**
 * R.Y.Z.E.N.A. - Threat Module Types
 * 
 * Type definitions for threat detection services.
 */

import type { ParsedEmail } from '../email/email.types.js';

/**
 * Phishing detection result
 */
export interface PhishingResult {
  /** Probability score from 0 to 1 */
  probability: number;
  /** List of detected phishing signals */
  signals: string[];
  /** Breakdown of signal weights for debugging */
  signalWeights?: Record<string, number>;
}

/**
 * URL risk level classification
 */
export type URLRiskLevel = 'low' | 'medium' | 'high';

/**
 * URL scan result for a single URL
 */
export interface URLScanResult {
  /** The scanned URL */
  url: string;
  /** Risk level classification */
  riskLevel: URLRiskLevel;
  /** Human-readable reason for risk level */
  reason: string;
  /** Additional findings */
  findings?: URLFindings;
}

/**
 * Detailed URL findings
 */
export interface URLFindings {
  /** Whether URL uses HTTPS */
  isHttps: boolean;
  /** Whether URL appears to be an IP address */
  isIpBased: boolean;
  /** Extracted domain */
  domain: string;
  /** Top-level domain */
  tld: string;
  /** Whether domain is on suspicious TLD list */
  isSuspiciousTld: boolean;
  /** Whether URL contains redirect patterns */
  hasRedirectPattern: boolean;
  /** URL path depth */
  pathDepth: number;
}

/**
 * Malware detection result
 */
export interface MalwareResult {
  /** Whether any malware risk was detected */
  hasRisk: boolean;
  /** List of flagged filenames */
  flaggedFiles: string[];
  /** Detailed findings per file */
  findings?: MalwareFindings[];
}

/**
 * Detailed malware findings for a file
 */
export interface MalwareFindings {
  filename: string;
  risks: string[];
  extension: string;
  isExecutable: boolean;
  hasDoubleExtension: boolean;
  isMacroEnabled: boolean;
  isScript: boolean;
}

/**
 * Security status classification
 */
export type SecurityStatus = 'SAFE' | 'SUSPICIOUS';

/**
 * Complete security analysis result
 */
export interface SecurityAnalysisResult {
  /** Email identifier */
  emailId: string;
  /** Overall security status */
  status: SecurityStatus;
  /** Trust score (0-100) */
  trustScore: number;
  /** Detected phishing signals */
  phishingSignals: string[];
  /** Phishing probability */
  phishingProbability: number;
  /** URL scan findings */
  urlFindings: URLScanResult[];
  /** Malware detection findings */
  malwareFindings: MalwareResult;
  /** Sanitized email body (URLs replaced if suspicious) */
  sanitizedBody: string;
  /** Original body for reference */
  originalBody: string;
  /** Security flag indicating if action was taken */
  securityFlag: boolean;
  /** Timestamp of analysis */
  analyzedAt: string;
  /** Actions taken during analysis */
  actionsTaken: string[];
}

/**
 * Input for the decision engine
 */
export interface DecisionInput {
  parsedEmail: ParsedEmail;
  phishingResult: PhishingResult;
  urlScanResults: URLScanResult[];
  malwareResult: MalwareResult;
}

/**
 * Phishing signal configuration
 */
export interface PhishingSignalConfig {
  /** Signal identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Weight contribution to probability */
  weight: number;
  /** Detection function */
  detect: (email: ParsedEmail) => boolean;
}

/**
 * URL reputation configuration
 */
export interface URLReputationConfig {
  /** Suspicious TLDs */
  suspiciousTlds: string[];
  /** Known malicious patterns */
  maliciousPatterns: RegExp[];
  /** Trusted domains whitelist */
  trustedDomains: string[];
}

/**
 * Malware detection configuration
 */
export interface MalwareDetectionConfig {
  /** Executable extensions */
  executableExtensions: string[];
  /** Script extensions */
  scriptExtensions: string[];
  /** Macro-enabled document extensions */
  macroExtensions: string[];
  /** Archive extensions that may contain threats */
  archiveExtensions: string[];
}
