/**
 * R.Y.Z.E.N.A. - Email Module Types
 * 
 * Type definitions for email processing and parsing.
 */

/**
 * Attachment metadata extracted from email
 */
export interface Attachment {
  filename: string;
  extension: string;
  size: number;
  contentType?: string;
  contentId?: string;
}

/**
 * Parsed email structure after normalization
 */
export interface ParsedEmail {
  /** Deterministic hash-based email identifier */
  emailId: string;
  /** Original sender email address */
  sender: string;
  /** Extracted sender domain */
  senderDomain: string;
  /** Recipient email address */
  recipient: string;
  /** Email subject line */
  subject: string;
  /** All extracted URLs from body */
  urls: string[];
  /** Attachment metadata */
  attachments: Attachment[];
  /** Original HTML body */
  bodyHtml: string;
  /** Original text body */
  bodyText: string;
  /** Additional metadata from headers */
  metadata: EmailMetadata;
  /** Timestamp of email */
  timestamp: string;
}

/**
 * Email metadata extracted from headers
 */
export interface EmailMetadata {
  /** Reply-To address if different from sender */
  replyTo?: string;
  /** Reply-To domain */
  replyToDomain?: string;
  /** Message-ID header */
  messageId?: string;
  /** Return-Path header */
  returnPath?: string;
  /** X-Originating-IP if present */
  originatingIp?: string;
  /** Received headers chain */
  receivedChain?: string[];
  /** SPF result if available */
  spfResult?: string;
  /** DKIM result if available */
  dkimResult?: string;
  /** DMARC result if available */
  dmarcResult?: string;
  /** Any additional headers */
  [key: string]: unknown;
}

/**
 * Raw email input from webhook
 */
export interface RawEmailInput {
  sender: string;
  recipient: string;
  subject: string;
  body_html: string;
  body_text: string;
  attachments: RawAttachment[];
  headers: Record<string, unknown>;
  timestamp?: string;
}

/**
 * Raw attachment from webhook
 */
export interface RawAttachment {
  filename: string;
  content_type?: string;
  size?: number;
  content_id?: string;
  content?: string;
}

/**
 * Email processing result returned to webhook
 */
export interface EmailProcessingResult {
  success: boolean;
  emailId: string;
  status: 'SAFE' | 'SUSPICIOUS';
  trustScore: number;
  processingTimeMs: number;
  analysis: SecurityAnalysisSummary;
}

/**
 * Summary of security analysis for API response
 */
export interface SecurityAnalysisSummary {
  phishingProbability: number;
  phishingSignals: string[];
  urlsScanned: number;
  urlsHighRisk: number;
  attachmentsScanned: number;
  attachmentsFlagged: number;
  actionsTaken: string[];
}
