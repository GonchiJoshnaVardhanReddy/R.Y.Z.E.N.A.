/**
 * R.Y.Z.E.N.A. - URL Scan Service Tests
 */

import { describe, it, expect } from 'vitest';
import { scanUrl, scanUrls, hasHighRiskUrl } from '../src/modules/threat/url-scan.service.js';

describe('URL Scan Service', () => {
  describe('scanUrl', () => {
    it('should classify safe HTTPS URL as low risk', () => {
      const result = scanUrl('https://www.google.com/search?q=test');
      
      expect(result.riskLevel).toBe('low');
      expect(result.findings?.isHttps).toBe(true);
      expect(result.findings?.isSuspiciousTld).toBe(false);
    });

    it('should flag HTTP URLs without TLS', () => {
      const result = scanUrl('http://example.com/page');
      
      expect(result.reason).toContain('No HTTPS');
    });

    it('should flag IP-based URLs as high risk', () => {
      const result = scanUrl('http://192.168.1.100/admin');
      
      expect(result.riskLevel).toBe('high');
      expect(result.reason).toContain('IP-based URL');
      expect(result.findings?.isIpBased).toBe(true);
    });

    it('should flag suspicious TLDs', () => {
      const result = scanUrl('https://login-page.xyz/account');
      
      expect(result.riskLevel).toBeOneOf(['medium', 'high']);
      expect(result.reason).toContain('Suspicious TLD');
      expect(result.findings?.isSuspiciousTld).toBe(true);
    });

    it('should detect redirect patterns', () => {
      const result = scanUrl('https://bit.ly/3xYzAbc');
      
      expect(result.reason).toContain('Redirect/shortener');
      expect(result.findings?.hasRedirectPattern).toBe(true);
    });

    it('should detect suspicious URL patterns', () => {
      const result = scanUrl('https://account-verify.suspicious.xyz/login.php?id=123');
      
      expect(result.riskLevel).toBe('high');
    });

    it('should handle trusted domains with lower risk', () => {
      const result = scanUrl('https://docs.microsoft.com/en-us/help');
      
      expect(result.riskLevel).toBe('low');
    });

    it('should flag .edu and .gov domains as trusted', () => {
      const eduResult = scanUrl('https://www.stanford.edu/research');
      const govResult = scanUrl('https://www.whitehouse.gov/administration');
      
      expect(eduResult.riskLevel).toBe('low');
      expect(govResult.riskLevel).toBe('low');
    });

    it('should handle malformed URLs', () => {
      const result = scanUrl('not-a-valid-url');
      
      expect(result.riskLevel).toBe('high');
      expect(result.reason).toContain('Invalid');
    });

    it('should detect URLs with suspicious keywords', () => {
      const result = scanUrl('https://unknown-site.com/login-password-verify');
      
      expect(result.riskLevel).toBeOneOf(['medium', 'high']);
    });
  });

  describe('scanUrls', () => {
    it('should scan multiple URLs', () => {
      const urls = [
        'https://google.com',
        'http://suspicious.xyz/login',
        'https://192.168.1.1/admin',
      ];
      
      const results = scanUrls(urls);
      
      expect(results).toHaveLength(3);
      expect(results[0].riskLevel).toBe('low');
      expect(results[2].riskLevel).toBe('high');
    });

    it('should handle empty URL array', () => {
      const results = scanUrls([]);
      
      expect(results).toHaveLength(0);
    });
  });

  describe('hasHighRiskUrl', () => {
    it('should return true when high risk URL exists', () => {
      const results = [
        { url: 'https://safe.com', riskLevel: 'low' as const, reason: 'Safe' },
        { url: 'http://192.168.1.1', riskLevel: 'high' as const, reason: 'IP-based' },
      ];
      
      expect(hasHighRiskUrl(results)).toBe(true);
    });

    it('should return false when no high risk URLs', () => {
      const results = [
        { url: 'https://safe.com', riskLevel: 'low' as const, reason: 'Safe' },
        { url: 'https://medium.com', riskLevel: 'medium' as const, reason: 'Medium' },
      ];
      
      expect(hasHighRiskUrl(results)).toBe(false);
    });
  });
});
