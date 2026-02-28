/**
 * R.Y.Z.E.N.A. - Email Parser
 * 
 * Parses and normalizes raw email input for threat analysis.
 * Extracts URLs, attachment metadata, and generates deterministic IDs.
 */

import { createHash } from 'crypto';
import { createLogger } from '../../shared/logger.js';
import { EmailParsingError } from '../../shared/errors.js';
import type { 
  ParsedEmail, 
  Attachment, 
  EmailMetadata, 
  RawEmailInput,
  RawAttachment 
} from './email.types.js';

const logger = createLogger({ module: 'email-parser' });

/**
 * URL extraction regex patterns
 */
const URL_PATTERNS = {
  /** Standard URL pattern for HTTP/HTTPS */
  standard: /https?:\/\/[^\s<>"')\]]+/gi,
  /** URLs in href attributes */
  href: /href=["']([^"']+)["']/gi,
  /** URLs in src attributes */
  src: /src=["']([^"']+)["']/gi,
};

/**
 * Extract domain from email address
 */
export function extractDomain(email: string): string {
  const parts = email.toLowerCase().split('@');
  return parts.length === 2 ? parts[1] : '';
}

/**
 * Generate deterministic email ID using SHA-256 hash
 */
export function generateEmailId(email: RawEmailInput): string {
  const hashInput = [
    email.sender,
    email.recipient,
    email.subject,
    email.timestamp || new Date().toISOString(),
    email.body_text.substring(0, 1000),
  ].join('|');
  
  return createHash('sha256')
    .update(hashInput)
    .digest('hex')
    .substring(0, 16);
}

/**
 * Extract all URLs from HTML and text content
 */
export function extractUrls(bodyHtml: string, bodyText: string): string[] {
  const urls = new Set<string>();
  
  // Extract from plain text body
  const textMatches = bodyText.match(URL_PATTERNS.standard) || [];
  textMatches.forEach(url => urls.add(normalizeUrl(url)));
  
  // Extract from HTML body - standard URLs
  const htmlMatches = bodyHtml.match(URL_PATTERNS.standard) || [];
  htmlMatches.forEach(url => urls.add(normalizeUrl(url)));
  
  // Extract from href attributes
  let hrefMatch;
  const hrefRegex = new RegExp(URL_PATTERNS.href.source, 'gi');
  while ((hrefMatch = hrefRegex.exec(bodyHtml)) !== null) {
    if (hrefMatch[1] && hrefMatch[1].startsWith('http')) {
      urls.add(normalizeUrl(hrefMatch[1]));
    }
  }
  
  // Extract from src attributes
  let srcMatch;
  const srcRegex = new RegExp(URL_PATTERNS.src.source, 'gi');
  while ((srcMatch = srcRegex.exec(bodyHtml)) !== null) {
    if (srcMatch[1] && srcMatch[1].startsWith('http')) {
      urls.add(normalizeUrl(srcMatch[1]));
    }
  }
  
  return Array.from(urls);
}

/**
 * Normalize URL by removing trailing punctuation and fragments
 */
function normalizeUrl(url: string): string {
  return url
    .replace(/[.,;:!?)>\]]+$/, '') // Remove trailing punctuation
    .replace(/#.*$/, ''); // Remove fragments
}

/**
 * Parse attachment metadata
 */
export function parseAttachments(rawAttachments: RawAttachment[]): Attachment[] {
  return rawAttachments.map(attachment => {
    const filename = attachment.filename || 'unknown';
    const extension = extractExtension(filename);
    
    return {
      filename,
      extension,
      size: attachment.size || 0,
      contentType: attachment.content_type,
      contentId: attachment.content_id,
    };
  });
}

/**
 * Extract file extension from filename
 */
export function extractExtension(filename: string): string {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

/**
 * Extract metadata from email headers
 */
export function extractMetadata(headers: Record<string, unknown>): EmailMetadata {
  const metadata: EmailMetadata = {};
  
  // Reply-To extraction
  if (headers['reply-to'] || headers['Reply-To']) {
    const replyTo = String(headers['reply-to'] || headers['Reply-To']);
    metadata.replyTo = replyTo;
    metadata.replyToDomain = extractDomain(replyTo);
  }
  
  // Message-ID
  if (headers['message-id'] || headers['Message-ID']) {
    metadata.messageId = String(headers['message-id'] || headers['Message-ID']);
  }
  
  // Return-Path
  if (headers['return-path'] || headers['Return-Path']) {
    metadata.returnPath = String(headers['return-path'] || headers['Return-Path']);
  }
  
  // X-Originating-IP
  if (headers['x-originating-ip'] || headers['X-Originating-IP']) {
    metadata.originatingIp = String(headers['x-originating-ip'] || headers['X-Originating-IP']);
  }
  
  // Authentication results
  if (headers['authentication-results'] || headers['Authentication-Results']) {
    const authResults = String(headers['authentication-results'] || headers['Authentication-Results']);
    
    // Extract SPF result
    const spfMatch = authResults.match(/spf=(\w+)/i);
    if (spfMatch) metadata.spfResult = spfMatch[1];
    
    // Extract DKIM result
    const dkimMatch = authResults.match(/dkim=(\w+)/i);
    if (dkimMatch) metadata.dkimResult = dkimMatch[1];
    
    // Extract DMARC result
    const dmarcMatch = authResults.match(/dmarc=(\w+)/i);
    if (dmarcMatch) metadata.dmarcResult = dmarcMatch[1];
  }
  
  // Received chain
  if (headers['received'] || headers['Received']) {
    const received = headers['received'] || headers['Received'];
    if (Array.isArray(received)) {
      metadata.receivedChain = received.map(String);
    } else {
      metadata.receivedChain = [String(received)];
    }
  }
  
  return metadata;
}

/**
 * Detect domain mismatch (potential spoofing)
 */
export function detectDomainMismatch(
  senderDomain: string, 
  metadata: EmailMetadata
): boolean {
  // Check Reply-To domain mismatch
  if (metadata.replyToDomain && metadata.replyToDomain !== senderDomain) {
    return true;
  }
  
  // Check Return-Path domain mismatch
  if (metadata.returnPath) {
    const returnPathDomain = extractDomain(metadata.returnPath);
    if (returnPathDomain && returnPathDomain !== senderDomain) {
      return true;
    }
  }
  
  return false;
}

/**
 * Main email parser function
 * @param rawEmail - Raw email input from webhook
 * @returns Parsed and normalized email structure
 */
export function parseEmail(rawEmail: RawEmailInput): ParsedEmail {
  const startTime = Date.now();
  
  try {
    const emailId = generateEmailId(rawEmail);
    const senderDomain = extractDomain(rawEmail.sender);
    
    if (!senderDomain) {
      throw new EmailParsingError('Invalid sender email address', {
        sender: rawEmail.sender,
      });
    }
    
    const urls = extractUrls(rawEmail.body_html, rawEmail.body_text);
    const attachments = parseAttachments(rawEmail.attachments);
    const metadata = extractMetadata(rawEmail.headers);
    
    const parsedEmail: ParsedEmail = {
      emailId,
      sender: rawEmail.sender.toLowerCase(),
      senderDomain,
      recipient: rawEmail.recipient.toLowerCase(),
      subject: rawEmail.subject,
      urls,
      attachments,
      bodyHtml: rawEmail.body_html,
      bodyText: rawEmail.body_text,
      metadata,
      timestamp: rawEmail.timestamp || new Date().toISOString(),
    };
    
    logger.info({
      action: 'email_parsed',
      emailId,
      urlsExtracted: urls.length,
      attachmentsCount: attachments.length,
      durationMs: Date.now() - startTime,
    });
    
    return parsedEmail;
  } catch (error) {
    logger.error({
      action: 'email_parse_failed',
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

export default {
  parseEmail,
  extractDomain,
  extractUrls,
  parseAttachments,
  extractMetadata,
  generateEmailId,
  detectDomainMismatch,
};
