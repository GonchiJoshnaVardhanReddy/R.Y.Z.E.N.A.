/**
 * R.Y.Z.E.N.A. - Decision Engine Tests
 */

import { describe, it, expect } from 'vitest';
import { analyzeAndDecide, quickThreatCheck } from '../src/modules/threat/decision.engine.js';
import type { ParsedEmail } from '../src/modules/email/email.types.js';
import type { DecisionInput, PhishingResult, URLScanResult, MalwareResult } from '../src/modules/threat/threat.types.js';

/**
 * Create base test email
 */
function createTestEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: 'test123',
    sender: 'sender@example.com',
    senderDomain: 'example.com',
    recipient: 'recipient@university.edu',
    subject: 'Test Email',
    urls: [],
    attachments: [],
    bodyHtml: '<p>Test email body</p>',
    bodyText: 'Test email body',
    metadata: {},
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Create test decision input
 */
function createDecisionInput(overrides: Partial<{
  email: Partial<ParsedEmail>;
  phishing: Partial<PhishingResult>;
  urls: URLScanResult[];
  malware: Partial<MalwareResult>;
}> = {}): DecisionInput {
  return {
    parsedEmail: createTestEmail(overrides.email),
    phishingResult: {
      probability: 0,
      signals: [],
      ...overrides.phishing,
    },
    urlScanResults: overrides.urls || [],
    malwareResult: {
      hasRisk: false,
      flaggedFiles: [],
      ...overrides.malware,
    },
  };
}

describe('Decision Engine', () => {
  describe('analyzeAndDecide', () => {
    it('should mark clean email as SAFE', () => {
      const input = createDecisionInput();
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SAFE');
      expect(result.trustScore).toBeGreaterThan(90);
      expect(result.securityFlag).toBe(false);
      expect(result.actionsTaken).toHaveLength(0);
    });

    it('should mark email as SUSPICIOUS when phishing probability > 0.7', () => {
      const input = createDecisionInput({
        phishing: {
          probability: 0.8,
          signals: ['Urgency Keywords Detected', 'Credential Harvesting Language'],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.trustScore).toBeLessThan(30);
      expect(result.securityFlag).toBe(true);
      expect(result.phishingSignals).toContain('Urgency Keywords Detected');
    });

    it('should mark email as SUSPICIOUS when high-risk URL detected', () => {
      const input = createDecisionInput({
        urls: [
          { url: 'https://safe.com', riskLevel: 'low', reason: 'Safe' },
          { url: 'http://192.168.1.1/admin', riskLevel: 'high', reason: 'IP-based URL' },
        ],
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.securityFlag).toBe(true);
    });

    it('should mark email as SUSPICIOUS when malware detected', () => {
      const input = createDecisionInput({
        malware: {
          hasRisk: true,
          flaggedFiles: ['malware.exe'],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.securityFlag).toBe(true);
      expect(result.malwareFindings.flaggedFiles).toContain('malware.exe');
    });

    it('should sanitize URLs in suspicious emails', () => {
      const input = createDecisionInput({
        email: {
          bodyHtml: '<a href="http://evil.xyz/login">Click here</a>',
        },
        urls: [
          { url: 'http://evil.xyz/login', riskLevel: 'high', reason: 'Suspicious' },
        ],
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.sanitizedBody).not.toContain('http://evil.xyz/login');
      expect(result.sanitizedBody).toContain('data-blocked-url');
    });

    it('should not sanitize URLs in safe emails', () => {
      const input = createDecisionInput({
        email: {
          bodyHtml: '<a href="https://google.com">Google</a>',
        },
        urls: [
          { url: 'https://google.com', riskLevel: 'low', reason: 'Trusted domain' },
        ],
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SAFE');
      expect(result.sanitizedBody).toContain('https://google.com');
    });

    it('should calculate trust score correctly', () => {
      // High phishing probability should reduce trust score
      const highPhishingInput = createDecisionInput({
        phishing: { probability: 0.9, signals: [] },
      });
      const highPhishingResult = analyzeAndDecide(highPhishingInput);
      
      // Low phishing probability should have high trust score
      const lowPhishingInput = createDecisionInput({
        phishing: { probability: 0.1, signals: [] },
      });
      const lowPhishingResult = analyzeAndDecide(lowPhishingInput);
      
      expect(highPhishingResult.trustScore).toBeLessThan(lowPhishingResult.trustScore);
    });

    it('should include actions taken for suspicious emails', () => {
      const input = createDecisionInput({
        phishing: {
          probability: 0.8,
          signals: ['Test signal'],
        },
        urls: [
          { url: 'http://evil.xyz', riskLevel: 'high', reason: 'Dangerous' },
        ],
        malware: {
          hasRisk: true,
          flaggedFiles: ['virus.exe'],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.actionsTaken).toContain('Email flagged as suspicious');
      expect(result.actionsTaken.some(a => a.includes('URL'))).toBe(true);
      expect(result.actionsTaken.some(a => a.includes('attachment'))).toBe(true);
      expect(result.actionsTaken).toContain('Forwarded to AI explanation service');
    });

    it('should preserve original body', () => {
      const originalHtml = '<p>Original content with <a href="http://evil.xyz">link</a></p>';
      const input = createDecisionInput({
        email: { bodyHtml: originalHtml },
        urls: [{ url: 'http://evil.xyz', riskLevel: 'high', reason: 'Bad' }],
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.originalBody).toBe(originalHtml);
      expect(result.sanitizedBody).not.toBe(originalHtml);
    });

    it('should include analysis timestamp', () => {
      const input = createDecisionInput();
      const beforeTime = new Date().toISOString();
      
      const result = analyzeAndDecide(input);
      
      expect(result.analyzedAt).toBeDefined();
      expect(new Date(result.analyzedAt).getTime()).toBeGreaterThanOrEqual(new Date(beforeTime).getTime());
    });
  });

  describe('quickThreatCheck', () => {
    it('should return false for clean input', () => {
      const input = createDecisionInput();
      expect(quickThreatCheck(input)).toBe(false);
    });

    it('should return true for high phishing probability', () => {
      const input = createDecisionInput({
        phishing: { probability: 0.8, signals: [] },
      });
      expect(quickThreatCheck(input)).toBe(true);
    });

    it('should return true for high-risk URL', () => {
      const input = createDecisionInput({
        urls: [{ url: 'http://evil.xyz', riskLevel: 'high', reason: 'Bad' }],
      });
      expect(quickThreatCheck(input)).toBe(true);
    });

    it('should return true for malware risk', () => {
      const input = createDecisionInput({
        malware: { hasRisk: true, flaggedFiles: ['bad.exe'] },
      });
      expect(quickThreatCheck(input)).toBe(true);
    });
  });
});


// Test scenarios as described in requirements

describe('Mock Scenarios', () => {
  describe('Scenario 1: Clean Email', () => {
    it('should process clean email correctly', () => {
      const input = createDecisionInput({
        email: {
          sender: 'professor@university.edu',
          senderDomain: 'university.edu',
          subject: 'Course Schedule Update',
          bodyHtml: '<p>Please review the attached course schedule for next semester.</p>',
          bodyText: 'Please review the attached course schedule for next semester.',
        },
        phishing: {
          probability: 0.05,
          signals: [],
        },
        urls: [],
        malware: {
          hasRisk: false,
          flaggedFiles: [],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SAFE');
      expect(result.trustScore).toBeGreaterThan(90);
      expect(result.securityFlag).toBe(false);
    });
  });

  describe('Scenario 2: Phishing Email', () => {
    it('should detect phishing email correctly', () => {
      const input = createDecisionInput({
        email: {
          sender: 'security@university-verify.xyz',
          senderDomain: 'university-verify.xyz',
          subject: 'URGENT: Your Account Will Be Suspended',
          bodyHtml: '<p>Dear Customer, verify your account immediately: <a href="http://192.168.1.100/login">Click here</a></p>',
          bodyText: 'Dear Customer, verify your account immediately by clicking this link.',
          urls: ['http://192.168.1.100/login'],
        },
        phishing: {
          probability: 0.85,
          signals: [
            'Urgency Keywords Detected',
            'Credential Harvesting Language',
            'Suspicious TLD in Sender Domain',
            'Generic Greeting',
          ],
        },
        urls: [
          { url: 'http://192.168.1.100/login', riskLevel: 'high', reason: 'IP-based URL, No HTTPS' },
        ],
        malware: {
          hasRisk: false,
          flaggedFiles: [],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.trustScore).toBeLessThan(20);
      expect(result.phishingSignals.length).toBeGreaterThan(0);
      expect(result.securityFlag).toBe(true);
    });
  });

  describe('Scenario 3: Malware Attachment Email', () => {
    it('should detect malware attachment correctly', () => {
      const input = createDecisionInput({
        email: {
          sender: 'colleague@partner-company.com',
          senderDomain: 'partner-company.com',
          subject: 'Invoice for Last Month',
          bodyText: 'Please find attached the invoice for your review.',
          attachments: [
            { filename: 'invoice.pdf.exe', extension: 'exe', size: 50000 },
          ],
        },
        phishing: {
          probability: 0.3,
          signals: ['Financial Urgency Language'],
        },
        urls: [],
        malware: {
          hasRisk: true,
          flaggedFiles: ['invoice.pdf.exe'],
          findings: [
            {
              filename: 'invoice.pdf.exe',
              risks: ['Executable file type', 'Double extension detected'],
              extension: 'exe',
              isExecutable: true,
              hasDoubleExtension: true,
              isMacroEnabled: false,
              isScript: false,
            },
          ],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.malwareFindings.hasRisk).toBe(true);
      expect(result.malwareFindings.flaggedFiles).toContain('invoice.pdf.exe');
      expect(result.securityFlag).toBe(true);
    });
  });

  describe('Scenario 4: Mixed Threat Signals', () => {
    it('should handle mixed threat signals correctly', () => {
      const input = createDecisionInput({
        email: {
          sender: 'hr@company.xyz',
          senderDomain: 'company.xyz',
          subject: 'Important: Update Your Benefits Information',
          bodyHtml: '<p>Click <a href="https://suspicious-site.top/benefits">here</a> to update.</p>',
          bodyText: 'Click here to update your benefits information.',
          urls: ['https://suspicious-site.top/benefits'],
          attachments: [
            { filename: 'benefits_form.xlsm', extension: 'xlsm', size: 25000 },
          ],
        },
        phishing: {
          probability: 0.55,
          signals: [
            'Suspicious TLD in Sender Domain',
            'Credential Harvesting Language',
          ],
        },
        urls: [
          { url: 'https://suspicious-site.top/benefits', riskLevel: 'medium', reason: 'Suspicious TLD' },
        ],
        malware: {
          hasRisk: true,
          flaggedFiles: ['benefits_form.xlsm'],
          findings: [
            {
              filename: 'benefits_form.xlsm',
              risks: ['Macro-enabled document'],
              extension: 'xlsm',
              isExecutable: false,
              hasDoubleExtension: false,
              isMacroEnabled: true,
              isScript: false,
            },
          ],
        },
      });
      
      const result = analyzeAndDecide(input);
      
      // Should be suspicious due to malware risk even though phishing is below threshold
      expect(result.status).toBe('SUSPICIOUS');
      expect(result.securityFlag).toBe(true);
      // Trust score should be reduced
      expect(result.trustScore).toBeLessThan(60);
    });
  });
});
