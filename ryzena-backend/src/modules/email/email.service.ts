/**
 * R.Y.Z.E.N.A. - Email Service
 * 
 * Orchestrates the email processing pipeline.
 * Coordinates parsing, threat detection, and decision making.
 */

import { createLogger } from '../../shared/logger.js';
import { ThreatAnalysisError } from '../../shared/errors.js';
import { parseEmail } from './email.parser.js';
import { analyzePhishing } from '../threat/phishing.service.js';
import { scanUrls } from '../threat/url-scan.service.js';
import { scanAttachments } from '../threat/malware.service.js';
import { analyzeAndDecide } from '../threat/decision.engine.js';
import type { RawEmailInput, EmailProcessingResult, ParsedEmail } from './email.types.js';
import type { SecurityAnalysisResult } from '../threat/threat.types.js';

const logger = createLogger({ module: 'email-service' });

/**
 * Process email through the complete threat detection pipeline
 * @param rawEmail - Raw email input from webhook
 * @returns Processing result with security analysis
 */
export async function processEmail(rawEmail: RawEmailInput): Promise<EmailProcessingResult> {
  const startTime = Date.now();
  let parsedEmail: ParsedEmail | undefined;
  
  try {
    // Step 1: Parse and normalize email
    logger.debug({ action: 'pipeline_start', step: 'parsing' });
    parsedEmail = parseEmail(rawEmail);
    
    // Step 2: Run phishing analysis
    logger.debug({ action: 'pipeline_step', step: 'phishing_analysis', emailId: parsedEmail.emailId });
    const phishingResult = analyzePhishing(parsedEmail);
    
    // Step 3: Scan URLs
    logger.debug({ action: 'pipeline_step', step: 'url_scanning', emailId: parsedEmail.emailId });
    const urlScanResults = scanUrls(parsedEmail.urls);
    
    // Step 4: Scan attachments
    logger.debug({ action: 'pipeline_step', step: 'malware_scanning', emailId: parsedEmail.emailId });
    const malwareResult = scanAttachments(parsedEmail.attachments);
    
    // Step 5: Run decision engine
    logger.debug({ action: 'pipeline_step', step: 'decision_making', emailId: parsedEmail.emailId });
    const analysisResult = analyzeAndDecide({
      parsedEmail,
      phishingResult,
      urlScanResults,
      malwareResult,
    });
    
    // Build response
    const processingTimeMs = Date.now() - startTime;
    
    const result: EmailProcessingResult = {
      success: true,
      emailId: parsedEmail.emailId,
      status: analysisResult.status,
      trustScore: analysisResult.trustScore,
      processingTimeMs,
      analysis: {
        phishingProbability: analysisResult.phishingProbability,
        phishingSignals: analysisResult.phishingSignals,
        urlsScanned: urlScanResults.length,
        urlsHighRisk: urlScanResults.filter(r => r.riskLevel === 'high').length,
        attachmentsScanned: parsedEmail.attachments.length,
        attachmentsFlagged: malwareResult.flaggedFiles.length,
        actionsTaken: analysisResult.actionsTaken,
      },
    };
    
    logger.info({
      action: 'pipeline_complete',
      emailId: parsedEmail.emailId,
      status: result.status,
      trustScore: result.trustScore,
      processingTimeMs,
    });
    
    return result;
  } catch (error) {
    const processingTimeMs = Date.now() - startTime;
    
    logger.error({
      action: 'pipeline_failed',
      emailId: parsedEmail?.emailId,
      error: error instanceof Error ? error.message : String(error),
      processingTimeMs,
    });
    
    throw new ThreatAnalysisError(
      'Email processing pipeline failed',
      {
        emailId: parsedEmail?.emailId,
        error: error instanceof Error ? error.message : String(error),
      }
    );
  }
}

/**
 * Process email and return full analysis details
 * For internal/admin use with more detailed output
 */
export async function processEmailDetailed(
  rawEmail: RawEmailInput
): Promise<SecurityAnalysisResult> {
  const startTime = Date.now();
  
  try {
    const parsedEmail = parseEmail(rawEmail);
    const phishingResult = analyzePhishing(parsedEmail);
    const urlScanResults = scanUrls(parsedEmail.urls);
    const malwareResult = scanAttachments(parsedEmail.attachments);
    
    const analysisResult = analyzeAndDecide({
      parsedEmail,
      phishingResult,
      urlScanResults,
      malwareResult,
    });
    
    logger.info({
      action: 'detailed_analysis_complete',
      emailId: parsedEmail.emailId,
      processingTimeMs: Date.now() - startTime,
    });
    
    return analysisResult;
  } catch (error) {
    logger.error({
      action: 'detailed_analysis_failed',
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

/**
 * Health check for the email service
 */
export function getServiceHealth(): { status: string; version: string } {
  return {
    status: 'healthy',
    version: '2.0.0',
  };
}

export default {
  processEmail,
  processEmailDetailed,
  getServiceHealth,
};
