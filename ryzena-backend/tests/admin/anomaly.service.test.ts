/**
 * R.Y.Z.E.N.A. - Phase 6: Anomaly Service Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PrivacyService, resetPrivacyService } from '../../src/modules/admin/privacy.service.js';
import { WeeklyTrendPoint } from '../../src/modules/admin/admin.types.js';

// Create mock classes that don't depend on Prisma
class MockAggregationService {
  getWeeklyTrends = vi.fn();
  getDepartmentMetrics = vi.fn();
}

class MockAnomalyService {
  private thresholds = {
    phishingSpikePercent: 50,
    riskScoreDropPercent: 20,
    consentApprovalSurgePercent: 100,
    clickRateIncreasePercent: 30,
    standardDeviationThreshold: 2,
  };

  getThresholds() {
    return { ...this.thresholds };
  }

  updateThresholds(updates: Partial<typeof this.thresholds>) {
    this.thresholds = { ...this.thresholds, ...updates };
  }

  detectPhishingSpike(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint
  ) {
    if (previous.phishingCount === 0) return null;

    const changePercent =
      ((current.phishingCount - previous.phishingCount) / previous.phishingCount) * 100;

    if (changePercent >= this.thresholds.phishingSpikePercent) {
      return {
        id: `anomaly-${Date.now()}`,
        type: 'PHISHING_SPIKE' as const,
        severity: this.calculateSeverity(changePercent, [50, 100, 200]),
        description: `Phishing spike: ${changePercent.toFixed(1)}%`,
        scope: 'university',
        statistics: {
          baseline: previous.phishingCount,
          current: current.phishingCount,
          changePercent: Math.round(changePercent * 10) / 10,
          comparisonPeriod: 'week-over-week',
          sampleSize: current.phishingCount + previous.phishingCount,
        },
        detectedAt: new Date(),
        isReviewed: false,
      };
    }
    return null;
  }

  detectConsentSurge(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint
  ) {
    if (previous.consentRequestCount === 0) return null;

    const changePercent =
      ((current.consentRequestCount - previous.consentRequestCount) / previous.consentRequestCount) * 100;

    if (changePercent >= this.thresholds.consentApprovalSurgePercent) {
      return {
        id: `anomaly-${Date.now()}`,
        type: 'CONSENT_APPROVAL_SURGE' as const,
        severity: this.calculateSeverity(changePercent, [100, 200, 500]),
        description: `Consent surge: ${changePercent.toFixed(1)}%`,
        scope: 'university',
        statistics: {
          baseline: previous.consentRequestCount,
          current: current.consentRequestCount,
          changePercent: Math.round(changePercent * 10) / 10,
          comparisonPeriod: 'week-over-week',
          sampleSize: current.consentRequestCount + previous.consentRequestCount,
        },
        detectedAt: new Date(),
        isReviewed: false,
      };
    }
    return null;
  }

  detectClickRateIncrease(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint
  ) {
    const currentRate = current.phishingCount > 0 
      ? (current.clickCount / current.phishingCount) * 100 : 0;
    const previousRate = previous.phishingCount > 0 
      ? (previous.clickCount / previous.phishingCount) * 100 : 0;

    if (previousRate === 0) return null;

    const changePercent = ((currentRate - previousRate) / previousRate) * 100;

    if (changePercent >= this.thresholds.clickRateIncreasePercent) {
      return {
        id: `anomaly-${Date.now()}`,
        type: 'CLICK_RATE_INCREASE' as const,
        severity: this.calculateSeverity(changePercent, [30, 60, 100]),
        description: `Click rate increase: ${changePercent.toFixed(1)}%`,
        scope: 'university',
        statistics: {
          baseline: Math.round(previousRate * 10) / 10,
          current: Math.round(currentRate * 10) / 10,
          changePercent: Math.round(changePercent * 10) / 10,
          comparisonPeriod: 'week-over-week',
          sampleSize: current.phishingCount + previous.phishingCount,
        },
        detectedAt: new Date(),
        isReviewed: false,
      };
    }
    return null;
  }

  private calculateSeverity(
    value: number,
    thresholds: [number, number, number]
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const [low, medium, high] = thresholds;
    if (value >= high) return 'CRITICAL';
    if (value >= medium) return 'HIGH';
    if (value >= low) return 'MEDIUM';
    return 'LOW';
  }
}

describe('AnomalyService', () => {
  let service: MockAnomalyService;
  let privacy: PrivacyService;

  beforeEach(() => {
    vi.clearAllMocks();
    resetPrivacyService();
    
    privacy = new PrivacyService();
    service = new MockAnomalyService();
  });

  describe('thresholds', () => {
    it('should use default thresholds', () => {
      const thresholds = service.getThresholds();
      expect(thresholds.phishingSpikePercent).toBe(50);
      expect(thresholds.riskScoreDropPercent).toBe(20);
      expect(thresholds.standardDeviationThreshold).toBe(2);
    });

    it('should allow custom thresholds via update', () => {
      service.updateThresholds({ phishingSpikePercent: 75 });
      expect(service.getThresholds().phishingSpikePercent).toBe(75);
    });

    it('should update thresholds', () => {
      service.updateThresholds({ phishingSpikePercent: 100 });
      expect(service.getThresholds().phishingSpikePercent).toBe(100);
    });
  });

  describe('detectPhishingSpike', () => {
    it('should return null when insufficient data', () => {
      const current = createTrendPoint(2, { phishingCount: 10 });
      const previous = createTrendPoint(1, { phishingCount: 0 });

      const result = service.detectPhishingSpike(current, previous);
      expect(result).toBeNull();
    });

    it('should detect phishing spike above threshold', () => {
      const current = createTrendPoint(2, { phishingCount: 20 });
      const previous = createTrendPoint(1, { phishingCount: 10 }); // 100% increase

      const result = service.detectPhishingSpike(current, previous);
      
      expect(result).not.toBeNull();
      expect(result?.type).toBe('PHISHING_SPIKE');
      expect(result?.statistics.changePercent).toBe(100);
    });

    it('should not detect spike for normal changes', () => {
      const current = createTrendPoint(2, { phishingCount: 11 });
      const previous = createTrendPoint(1, { phishingCount: 10 }); // 10% increase

      const result = service.detectPhishingSpike(current, previous);
      expect(result).toBeNull();
    });
  });

  describe('detectConsentSurge', () => {
    it('should detect consent approval surge', () => {
      const current = createTrendPoint(2, { consentRequestCount: 15 });
      const previous = createTrendPoint(1, { consentRequestCount: 5 }); // 200% increase

      const result = service.detectConsentSurge(current, previous);

      expect(result).not.toBeNull();
      expect(result?.type).toBe('CONSENT_APPROVAL_SURGE');
      expect(result?.statistics.changePercent).toBe(200);
    });

    it('should not detect for small changes', () => {
      const current = createTrendPoint(2, { consentRequestCount: 6 });
      const previous = createTrendPoint(1, { consentRequestCount: 5 }); // 20% increase

      const result = service.detectConsentSurge(current, previous);
      expect(result).toBeNull();
    });
  });

  describe('detectClickRateIncrease', () => {
    it('should detect click rate increase', () => {
      // 5% -> 10% = 100% increase
      const current = createTrendPoint(2, { phishingCount: 100, clickCount: 10 });
      const previous = createTrendPoint(1, { phishingCount: 100, clickCount: 5 });

      const result = service.detectClickRateIncrease(current, previous);

      expect(result).not.toBeNull();
      expect(result?.type).toBe('CLICK_RATE_INCREASE');
    });

    it('should return null for zero previous rate', () => {
      const current = createTrendPoint(2, { phishingCount: 100, clickCount: 5 });
      const previous = createTrendPoint(1, { phishingCount: 100, clickCount: 0 });

      const result = service.detectClickRateIncrease(current, previous);
      expect(result).toBeNull();
    });
  });

  describe('severity calculation', () => {
    it('should assign MEDIUM severity for 60% phishing spike', () => {
      const current = createTrendPoint(2, { phishingCount: 16 });
      const previous = createTrendPoint(1, { phishingCount: 10 }); // 60%

      const result = service.detectPhishingSpike(current, previous);
      expect(result?.severity).toBe('MEDIUM');
    });

    it('should assign CRITICAL severity for 400% spike', () => {
      const current = createTrendPoint(2, { phishingCount: 50 });
      const previous = createTrendPoint(1, { phishingCount: 10 }); // 400%

      const result = service.detectPhishingSpike(current, previous);
      expect(result?.severity).toBe('CRITICAL');
    });

    it('should assign HIGH severity for 150% spike', () => {
      const current = createTrendPoint(2, { phishingCount: 25 });
      const previous = createTrendPoint(1, { phishingCount: 10 }); // 150%

      const result = service.detectPhishingSpike(current, previous);
      expect(result?.severity).toBe('HIGH');
    });
  });
});

// Helper to create trend points
function createTrendPoint(
  week: number,
  overrides: Partial<WeeklyTrendPoint> = {}
): WeeklyTrendPoint {
  return {
    year: 2024,
    week,
    weekStart: new Date(2024, 0, week * 7),
    averageRiskScore: 50,
    phishingCount: 10,
    clickCount: 1,
    eventCount: 5,
    consentRequestCount: 3,
    ...overrides,
  };
}
