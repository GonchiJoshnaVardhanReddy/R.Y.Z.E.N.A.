/**
 * R.Y.Z.E.N.A. - Phase 6: Privacy Service Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  PrivacyService,
  getPrivacyService,
  resetPrivacyService,
} from '../../src/modules/admin/privacy.service.js';
import { DepartmentMetrics } from '../../src/modules/admin/admin.types.js';

describe('PrivacyService', () => {
  let service: PrivacyService;

  beforeEach(() => {
    resetPrivacyService();
    service = new PrivacyService();
  });

  describe('checkKAnonymity', () => {
    it('should allow data when group size meets threshold', () => {
      const result = service.checkKAnonymity(10);
      expect(result.isAllowed).toBe(true);
      expect(result.sampleSize).toBe(10);
      expect(result.threshold).toBe(5);
    });

    it('should reject data when group size below threshold', () => {
      const result = service.checkKAnonymity(3);
      expect(result.isAllowed).toBe(false);
      expect(result.reason).toContain('below k-anonymity threshold');
    });

    it('should allow data at exactly threshold', () => {
      const result = service.checkKAnonymity(5);
      expect(result.isAllowed).toBe(true);
    });

    it('should reject zero size', () => {
      const result = service.checkKAnonymity(0);
      expect(result.isAllowed).toBe(false);
    });
  });

  describe('canReturnData', () => {
    it('should return true for sufficient sample size', () => {
      expect(service.canReturnData(100)).toBe(true);
    });

    it('should return false for insufficient sample size', () => {
      expect(service.canReturnData(2)).toBe(false);
    });
  });

  describe('stripProhibitedFields', () => {
    it('should remove prohibited fields', () => {
      const data = {
        studentId: 'stu-123',
        email: 'test@test.com',
        riskScore: 50,
        department: 'Engineering',
      };

      const result = service.stripProhibitedFields(data);
      expect(result.data.studentId).toBeUndefined();
      expect(result.data.email).toBeUndefined();
      expect(result.data.riskScore).toBe(50);
      expect(result.data.department).toBe('Engineering');
      expect(result.removedFields).toContain('studentId');
      expect(result.removedFields).toContain('email');
      expect(result.wasSuppressed).toBe(true);
    });

    it('should not modify data without prohibited fields', () => {
      const data = {
        riskScore: 75,
        count: 100,
      };

      const result = service.stripProhibitedFields(data);
      expect(result.data).toEqual(data);
      expect(result.wasSuppressed).toBe(false);
    });

    it('should handle nested objects', () => {
      const data = {
        metrics: {
          studentId: 'stu-456',
          value: 10,
        },
      };

      const result = service.stripProhibitedFields(data);
      expect((result.data.metrics as Record<string, unknown>).studentId).toBeUndefined();
      expect((result.data.metrics as Record<string, unknown>).value).toBe(10);
    });

    it('should handle arrays', () => {
      const data = {
        items: [
          { email: 'a@test.com', value: 1 },
          { email: 'b@test.com', value: 2 },
        ],
      };

      const result = service.stripProhibitedFields(data);
      const items = result.data.items as Array<Record<string, unknown>>;
      expect(items[0].email).toBeUndefined();
      expect(items[0].value).toBe(1);
    });
  });

  describe('isProhibitedField', () => {
    it('should detect prohibited field names', () => {
      expect(service.isProhibitedField('studentId')).toBe(true);
      expect(service.isProhibitedField('email')).toBe(true);
      expect(service.isProhibitedField('ssn')).toBe(true);
    });

    it('should be case-insensitive', () => {
      expect(service.isProhibitedField('STUDENTID')).toBe(true);
      expect(service.isProhibitedField('Email')).toBe(true);
    });

    it('should detect partial matches', () => {
      expect(service.isProhibitedField('userEmail')).toBe(true);
      expect(service.isProhibitedField('studentIdHash')).toBe(true);
    });

    it('should allow non-prohibited fields', () => {
      expect(service.isProhibitedField('riskScore')).toBe(false);
      expect(service.isProhibitedField('department')).toBe(false);
    });
  });

  describe('roundPercentage', () => {
    it('should round to configured precision', () => {
      expect(service.roundPercentage(12.3456)).toBe(12.3);
      expect(service.roundPercentage(99.999)).toBe(100);
    });

    it('should handle whole numbers', () => {
      expect(service.roundPercentage(50)).toBe(50);
    });
  });

  describe('suppressDepartmentData', () => {
    it('should suppress departments below threshold', () => {
      const departments: DepartmentMetrics[] = [
        {
          department: 'Engineering',
          studentCount: 100,
          averageRiskScore: 45,
          riskDistribution: { low: 30, medium: 50, high: 15, critical: 5, total: 100 },
          phishingCount: 50,
          clickRate: 5,
          isSuppressed: false,
        },
        {
          department: 'Small Dept',
          studentCount: 3, // Below threshold
          averageRiskScore: 60,
          riskDistribution: { low: 1, medium: 1, high: 1, critical: 0, total: 3 },
          phishingCount: 2,
          clickRate: 10,
          isSuppressed: false,
        },
      ];

      const result = service.suppressDepartmentData(departments);

      // Large department unchanged
      expect(result[0].department).toBe('Engineering');
      expect(result[0].isSuppressed).toBe(false);
      expect(result[0].averageRiskScore).toBe(45);

      // Small department suppressed
      expect(result[1].isSuppressed).toBe(true);
      expect(result[1].averageRiskScore).toBe(0);
      expect(result[1].phishingCount).toBe(0);
      expect(result[1].department).toMatch(/^Department-/);
    });
  });

  describe('validateNoPII', () => {
    it('should pass for clean data', () => {
      const data = {
        riskScore: 50,
        count: 100,
        department: 'Engineering',
      };

      const result = service.validateNoPII(data);
      expect(result.isValid).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('should detect email addresses', () => {
      const data = {
        contact: 'test@example.com',
      };

      const result = service.validateNoPII(data);
      expect(result.isValid).toBe(false);
      expect(result.violations).toContain('Potential email found in response');
    });

    it('should detect SSN patterns', () => {
      const data = {
        id: '123-45-6789',
      };

      const result = service.validateNoPII(data);
      expect(result.isValid).toBe(false);
    });
  });

  describe('generatePrivacyNotice', () => {
    it('should generate notice for small data size', () => {
      const notice = service.generatePrivacyNotice({ dataSize: 3 });
      expect(notice).toContain('suppressed');
    });

    it('should generate notice for suppressed departments', () => {
      const notice = service.generatePrivacyNotice({
        dataSize: 100,
        hasSuppressedDepartments: true,
      });
      expect(notice).toContain('department');
    });

    it('should return undefined for no issues', () => {
      const notice = service.generatePrivacyNotice({ dataSize: 100 });
      expect(notice).toBeUndefined();
    });
  });

  describe('configuration', () => {
    it('should allow custom configuration', () => {
      const customService = new PrivacyService({
        kAnonymityThreshold: 10,
        percentagePrecision: 2,
      });

      expect(customService.getKAnonymityThreshold()).toBe(10);
      expect(customService.roundPercentage(12.345)).toBe(12.35);
    });

    it('should update configuration', () => {
      service.updateConfig({ kAnonymityThreshold: 15 });
      expect(service.getKAnonymityThreshold()).toBe(15);
    });
  });

  describe('singleton', () => {
    it('should return same instance', () => {
      const instance1 = getPrivacyService();
      const instance2 = getPrivacyService();
      expect(instance1).toBe(instance2);
    });

    it('should create new instance after reset', () => {
      const instance1 = getPrivacyService();
      resetPrivacyService();
      const instance2 = getPrivacyService();
      expect(instance1).not.toBe(instance2);
    });
  });
});
