/**
 * R.Y.Z.E.N.A. - Phase 6: Admin Types Tests
 */

import { describe, it, expect } from 'vitest';
import {
  DEFAULT_PRIVACY_CONFIG,
  DEFAULT_ANOMALY_THRESHOLDS,
} from '../../src/modules/admin/admin.types.js';

describe('Admin Types', () => {
  describe('DEFAULT_PRIVACY_CONFIG', () => {
    it('should have k-anonymity threshold of 5', () => {
      expect(DEFAULT_PRIVACY_CONFIG.kAnonymityThreshold).toBe(5);
    });

    it('should allow department breakdown by default', () => {
      expect(DEFAULT_PRIVACY_CONFIG.allowDepartmentBreakdown).toBe(true);
    });

    it('should have percentage precision of 1', () => {
      expect(DEFAULT_PRIVACY_CONFIG.percentagePrecision).toBe(1);
    });

    it('should include required prohibited fields', () => {
      const prohibited = DEFAULT_PRIVACY_CONFIG.prohibitedFields;
      expect(prohibited).toContain('studentId');
      expect(prohibited).toContain('email');
      expect(prohibited).toContain('name');
      expect(prohibited).toContain('ssn');
      expect(prohibited).toContain('phone');
      expect(prohibited).toContain('address');
      expect(prohibited).toContain('ipAddress');
    });
  });

  describe('DEFAULT_ANOMALY_THRESHOLDS', () => {
    it('should have phishing spike threshold of 50%', () => {
      expect(DEFAULT_ANOMALY_THRESHOLDS.phishingSpikePercent).toBe(50);
    });

    it('should have risk score drop threshold of 20%', () => {
      expect(DEFAULT_ANOMALY_THRESHOLDS.riskScoreDropPercent).toBe(20);
    });

    it('should have consent approval surge threshold of 100%', () => {
      expect(DEFAULT_ANOMALY_THRESHOLDS.consentApprovalSurgePercent).toBe(100);
    });

    it('should have click rate increase threshold of 30%', () => {
      expect(DEFAULT_ANOMALY_THRESHOLDS.clickRateIncreasePercent).toBe(30);
    });

    it('should have standard deviation threshold of 2', () => {
      expect(DEFAULT_ANOMALY_THRESHOLDS.standardDeviationThreshold).toBe(2);
    });
  });
});
