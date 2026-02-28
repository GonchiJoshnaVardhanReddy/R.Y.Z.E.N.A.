/**
 * R.Y.Z.E.N.A. - Phishing Service Tests
 */

import { describe, it, expect } from 'vitest';
import { analyzePhishing, isPhishingThreat } from '../src/modules/threat/phishing.service.js';
import type { ParsedEmail } from '../src/modules/email/email.types.js';

/**
 * Create a base test email
 */
function createTestEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: 'test123',
    sender: 'sender@example.com',
    senderDomain: 'example.com',
    recipient: 'recipient@university.edu',
    subject: 'Test Email Subject',
    urls: [],
    attachments: [],
    bodyHtml: '<p>Test body</p>',
    bodyText: 'Test body',
    metadata: {},
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('Phishing Service', () => {
  describe('analyzePhishing', () => {
    it('should return low probability for clean email', () => {
      const email = createTestEmail({
        subject: 'Meeting Notes from Yesterday',
        bodyText: 'Hi team, here are the meeting notes we discussed.',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.probability).toBeLessThan(0.3);
      expect(result.signals).toHaveLength(0);
    });

    it('should detect urgency keywords', () => {
      const email = createTestEmail({
        subject: 'URGENT: Action Required Immediately',
        bodyText: 'Your account will be suspended within 24 hours if you do not verify.',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.probability).toBeGreaterThan(0);
      expect(result.signals).toContain('Urgency Keywords Detected');
    });

    it('should detect credential harvesting language', () => {
      const email = createTestEmail({
        subject: 'Verify Your Account',
        bodyText: 'Please confirm your identity by entering your credentials on this page.',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Credential Harvesting Language');
    });

    it('should detect suspicious TLDs', () => {
      const email = createTestEmail({
        sender: 'admin@suspicious.xyz',
        senderDomain: 'suspicious.xyz',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Suspicious TLD in Sender Domain');
    });

    it('should detect domain mismatch', () => {
      const email = createTestEmail({
        sender: 'support@legitimate.com',
        senderDomain: 'legitimate.com',
        metadata: {
          replyTo: 'hacker@evil.xyz',
          replyToDomain: 'evil.xyz',
        },
      });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Domain Mismatch (Reply-To/Return-Path)');
    });

    it('should detect financial urgency language', () => {
      const email = createTestEmail({
        subject: 'Invoice Attached - Payment Required',
        bodyText: 'Please process this wire transfer immediately. Overdue payment.',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Financial Urgency Language');
    });

    it('should detect brand spoofing', () => {
      const email = createTestEmail({
        sender: 'paypal-support@random-domain.com',
        senderDomain: 'random-domain.com',
        subject: 'PayPal Security Alert',
        bodyText: 'Your PayPal account needs verification.',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Potential Brand Spoofing');
    });

    it('should detect generic greetings', () => {
      const email = createTestEmail({
        bodyText: 'Dear Customer, we have detected unusual activity on your account.',
      });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Generic Greeting');
    });

    it('should detect excessive links', () => {
      const urls = Array.from({ length: 15 }, (_, i) => `https://example${i}.com`);
      const email = createTestEmail({ urls });
      
      const result = analyzePhishing(email);
      
      expect(result.signals).toContain('Excessive Number of Links');
    });

    it('should cap probability at 1.0', () => {
      const email = createTestEmail({
        sender: 'paypal@evil.xyz',
        senderDomain: 'evil.xyz',
        subject: 'URGENT: Verify Your PayPal Account Immediately',
        bodyText: 'Dear Customer, your account will be suspended. Confirm your identity and enter your credentials now. Wire transfer required.',
        metadata: {
          replyTo: 'hacker@attacker.xyz',
          replyToDomain: 'attacker.xyz',
        },
        urls: Array.from({ length: 12 }, (_, i) => `https://evil${i}.xyz/login`),
      });
      
      const result = analyzePhishing(email);
      
      expect(result.probability).toBeLessThanOrEqual(1.0);
    });
  });

  describe('isPhishingThreat', () => {
    it('should return true when probability exceeds threshold', () => {
      const result = { probability: 0.8, signals: ['Test signal'] };
      expect(isPhishingThreat(result)).toBe(true);
    });

    it('should return false when probability is below threshold', () => {
      const result = { probability: 0.3, signals: [] };
      expect(isPhishingThreat(result)).toBe(false);
    });
  });
});
