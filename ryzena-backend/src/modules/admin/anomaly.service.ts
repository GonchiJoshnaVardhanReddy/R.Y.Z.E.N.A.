/**
 * R.Y.Z.E.N.A. - Phase 6: Anomaly Detection Service
 * Detects unusual patterns using deterministic statistical thresholds
 */

import { PrismaClient, AnomalyType as PrismaAnomalyType, AnomalySeverity as PrismaSeverity } from '../../generated/prisma/index.js';
import { getDbClient } from '../../database/client.js';
import { logger } from '../../shared/logger.js';
import { getPrivacyService, PrivacyService } from './privacy.service.js';
import { getAggregationService, AggregationService } from './aggregation.service.js';
import {
  AnomalyThresholds,
  DEFAULT_ANOMALY_THRESHOLDS,
  AnomalyReport,
  AnomalyType,
  AnomalySeverity,
  AnomalyStatistics,
  AnomalyDetectionInput,
  WeeklyTrendPoint,
} from './admin.types.js';

/**
 * Anomaly detection service using deterministic statistical analysis
 */
export class AnomalyService {
  private prisma: PrismaClient;
  private privacy: PrivacyService;
  private aggregation: AggregationService;
  private thresholds: AnomalyThresholds;
  private log = logger.child({ module: 'anomaly-service' });

  constructor(
    prisma?: PrismaClient,
    privacy?: PrivacyService,
    aggregation?: AggregationService,
    thresholds?: Partial<AnomalyThresholds>
  ) {
    this.prisma = prisma || getDbClient();
    this.privacy = privacy || getPrivacyService();
    this.aggregation = aggregation || getAggregationService();
    this.thresholds = { ...DEFAULT_ANOMALY_THRESHOLDS, ...thresholds };
    this.log.info({ thresholds: this.thresholds }, 'Anomaly service initialized');
  }

  /**
   * Get current thresholds
   */
  getThresholds(): AnomalyThresholds {
    return { ...this.thresholds };
  }

  /**
   * Update thresholds
   */
  updateThresholds(updates: Partial<AnomalyThresholds>): void {
    this.thresholds = { ...this.thresholds, ...updates };
    this.log.info({ thresholds: this.thresholds }, 'Anomaly thresholds updated');
  }

  /**
   * Run full anomaly detection and return reports
   */
  async detectAnomalies(): Promise<AnomalyReport[]> {
    this.log.info('Running anomaly detection');
    const anomalies: AnomalyReport[] = [];

    try {
      // Get trend data for analysis
      const trends = await this.aggregation.getWeeklyTrends(8);
      
      if (trends.length < 2) {
        this.log.debug('Not enough trend data for anomaly detection');
        return anomalies;
      }

      const current = trends[trends.length - 1];
      const previous = trends[trends.length - 2];
      const historical = this.calculateHistoricalBaseline(trends.slice(0, -1));

      // Check for phishing spike
      const phishingAnomaly = this.detectPhishingSpike(current, previous, historical);
      if (phishingAnomaly) {
        anomalies.push(phishingAnomaly);
        await this.persistAnomaly(phishingAnomaly);
      }

      // Check for risk score drop
      const riskDropAnomaly = this.detectRiskScoreDrop(current, previous, historical);
      if (riskDropAnomaly) {
        anomalies.push(riskDropAnomaly);
        await this.persistAnomaly(riskDropAnomaly);
      }

      // Check for consent approval surge
      const consentAnomaly = this.detectConsentApprovalSurge(current, previous, historical);
      if (consentAnomaly) {
        anomalies.push(consentAnomaly);
        await this.persistAnomaly(consentAnomaly);
      }

      // Check for click rate increase
      const clickAnomaly = this.detectClickRateIncrease(current, previous, historical);
      if (clickAnomaly) {
        anomalies.push(clickAnomaly);
        await this.persistAnomaly(clickAnomaly);
      }

      // Check department-level anomalies
      const deptAnomalies = await this.detectDepartmentAnomalies();
      for (const anomaly of deptAnomalies) {
        anomalies.push(anomaly);
        await this.persistAnomaly(anomaly);
      }

      this.log.info({ count: anomalies.length }, 'Anomaly detection complete');
    } catch (error) {
      this.log.error({ error }, 'Error during anomaly detection');
    }

    return anomalies;
  }

  /**
   * Detect sudden spike in phishing attempts
   */
  private detectPhishingSpike(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint,
    historical: { avg: number; stdDev: number }
  ): AnomalyReport | null {
    if (previous.phishingCount === 0) return null;

    const changePercent =
      ((current.phishingCount - previous.phishingCount) / previous.phishingCount) * 100;

    const stdDeviations =
      historical.stdDev > 0
        ? (current.phishingCount - historical.avg) / historical.stdDev
        : 0;

    if (
      changePercent >= this.thresholds.phishingSpikePercent ||
      stdDeviations >= this.thresholds.standardDeviationThreshold
    ) {
      const severity = this.calculateSeverity(changePercent, [50, 100, 200]);

      return {
        id: this.generateId(),
        type: 'PHISHING_SPIKE',
        severity,
        description: `Phishing attempts increased by ${changePercent.toFixed(1)}% compared to last week (${current.phishingCount} vs ${previous.phishingCount})`,
        scope: 'university',
        statistics: {
          baseline: previous.phishingCount,
          current: current.phishingCount,
          changePercent: Math.round(changePercent * 10) / 10,
          standardDeviations: Math.round(stdDeviations * 100) / 100,
          comparisonPeriod: 'week-over-week',
          sampleSize: current.phishingCount + previous.phishingCount,
        },
        detectedAt: new Date(),
        isReviewed: false,
      };
    }

    return null;
  }

  /**
   * Detect abnormal drop in average risk score
   */
  private detectRiskScoreDrop(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint,
    historical: { avg: number; stdDev: number }
  ): AnomalyReport | null {
    if (previous.averageRiskScore === 0) return null;

    const changePercent =
      ((previous.averageRiskScore - current.averageRiskScore) /
        previous.averageRiskScore) *
      100;

    // Note: Drop is actually good, but unusual drops might indicate data issues
    if (changePercent >= this.thresholds.riskScoreDropPercent) {
      return {
        id: this.generateId(),
        type: 'RISK_SCORE_DROP',
        severity: 'LOW', // Drops are generally good
        description: `Average risk score dropped by ${changePercent.toFixed(1)}% (${current.averageRiskScore} vs ${previous.averageRiskScore})`,
        scope: 'university',
        statistics: {
          baseline: previous.averageRiskScore,
          current: current.averageRiskScore,
          changePercent: Math.round(changePercent * 10) / 10,
          comparisonPeriod: 'week-over-week',
          sampleSize: 0, // Would need student count
        },
        detectedAt: new Date(),
        isReviewed: false,
      };
    }

    return null;
  }

  /**
   * Detect unusual consent approval surge
   */
  private detectConsentApprovalSurge(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint,
    _historical: { avg: number; stdDev: number }
  ): AnomalyReport | null {
    if (previous.consentRequestCount === 0) return null;

    const changePercent =
      ((current.consentRequestCount - previous.consentRequestCount) /
        previous.consentRequestCount) *
      100;

    if (changePercent >= this.thresholds.consentApprovalSurgePercent) {
      const severity = this.calculateSeverity(changePercent, [100, 200, 500]);

      return {
        id: this.generateId(),
        type: 'CONSENT_APPROVAL_SURGE',
        severity,
        description: `Consent requests increased by ${changePercent.toFixed(1)}% (${current.consentRequestCount} vs ${previous.consentRequestCount})`,
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

  /**
   * Detect increase in phishing click rate
   */
  private detectClickRateIncrease(
    current: WeeklyTrendPoint,
    previous: WeeklyTrendPoint,
    _historical: { avg: number; stdDev: number }
  ): AnomalyReport | null {
    const currentClickRate =
      current.phishingCount > 0
        ? (current.clickCount / current.phishingCount) * 100
        : 0;

    const previousClickRate =
      previous.phishingCount > 0
        ? (previous.clickCount / previous.phishingCount) * 100
        : 0;

    if (previousClickRate === 0) return null;

    const changePercent =
      ((currentClickRate - previousClickRate) / previousClickRate) * 100;

    if (changePercent >= this.thresholds.clickRateIncreasePercent) {
      const severity = this.calculateSeverity(changePercent, [30, 60, 100]);

      return {
        id: this.generateId(),
        type: 'CLICK_RATE_INCREASE',
        severity,
        description: `Phishing click rate increased by ${changePercent.toFixed(1)}% (${currentClickRate.toFixed(1)}% vs ${previousClickRate.toFixed(1)}%)`,
        scope: 'university',
        statistics: {
          baseline: Math.round(previousClickRate * 10) / 10,
          current: Math.round(currentClickRate * 10) / 10,
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

  /**
   * Detect department-level risk spikes
   */
  private async detectDepartmentAnomalies(): Promise<AnomalyReport[]> {
    const anomalies: AnomalyReport[] = [];

    if (!this.privacy.isDepartmentBreakdownAllowed()) {
      return anomalies;
    }

    const departments = await this.aggregation.getDepartmentMetrics();
    const universityAvg = await this.getUniversityAverageRiskScore();

    for (const dept of departments) {
      if (dept.isSuppressed) continue;

      // Check if department risk is significantly higher than university average
      const deviation = dept.averageRiskScore - universityAvg;
      const deviationPercent = (deviation / universityAvg) * 100;

      if (deviationPercent > 30) {
        // 30% higher than university average
        anomalies.push({
          id: this.generateId(),
          type: 'DEPARTMENT_RISK_SPIKE',
          severity: this.calculateSeverity(deviationPercent, [30, 50, 80]),
          description: `${dept.department} has ${deviationPercent.toFixed(1)}% higher risk score than university average`,
          scope: dept.department,
          statistics: {
            baseline: universityAvg,
            current: dept.averageRiskScore,
            changePercent: Math.round(deviationPercent * 10) / 10,
            comparisonPeriod: 'current snapshot',
            sampleSize: dept.studentCount,
          },
          detectedAt: new Date(),
          isReviewed: false,
        });
      }
    }

    return anomalies;
  }

  /**
   * Get university average risk score
   */
  private async getUniversityAverageRiskScore(): Promise<number> {
    const result = await this.prisma.riskProfile.aggregate({
      _avg: { riskScore: true },
    });
    return result._avg.riskScore ?? 50;
  }

  /**
   * Calculate historical baseline from trend data
   */
  private calculateHistoricalBaseline(
    trends: WeeklyTrendPoint[]
  ): { avg: number; stdDev: number } {
    if (trends.length === 0) {
      return { avg: 0, stdDev: 0 };
    }

    const values = trends.map((t) => t.phishingCount);
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map((v) => Math.pow(v - avg, 2));
    const variance = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    const stdDev = Math.sqrt(variance);

    return { avg, stdDev };
  }

  /**
   * Calculate severity based on thresholds
   */
  private calculateSeverity(
    value: number,
    thresholds: [number, number, number]
  ): AnomalySeverity {
    const [low, medium, high] = thresholds;
    if (value >= high) return 'CRITICAL';
    if (value >= medium) return 'HIGH';
    if (value >= low) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Generate unique ID for anomaly
   */
  private generateId(): string {
    return `anomaly-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Persist anomaly to database
   */
  private async persistAnomaly(anomaly: AnomalyReport): Promise<void> {
    try {
      await this.prisma.anomalyReport.create({
        data: {
          anomalyType: anomaly.type as PrismaAnomalyType,
          severity: anomaly.severity as PrismaSeverity,
          description: anomaly.description,
          scope: anomaly.scope,
          statistics: anomaly.statistics as object,
          detectedAt: anomaly.detectedAt,
          isReviewed: false,
        },
      });
      this.log.debug({ type: anomaly.type }, 'Anomaly persisted');
    } catch (error) {
      this.log.error({ error, anomaly }, 'Failed to persist anomaly');
    }
  }

  /**
   * Get stored anomaly reports
   */
  async getAnomalyReports(options: {
    severity?: AnomalySeverity;
    type?: AnomalyType;
    unreviewedOnly?: boolean;
    limit?: number;
  } = {}): Promise<AnomalyReport[]> {
    const where: Record<string, unknown> = {};

    if (options.severity) {
      where.severity = options.severity;
    }
    if (options.type) {
      where.anomalyType = options.type;
    }
    if (options.unreviewedOnly) {
      where.isReviewed = false;
    }

    const reports = await this.prisma.anomalyReport.findMany({
      where,
      orderBy: { detectedAt: 'desc' },
      take: options.limit || 50,
    });

    return reports.map((r) => ({
      id: r.id,
      type: r.anomalyType as AnomalyType,
      severity: r.severity as AnomalySeverity,
      description: r.description,
      scope: r.scope,
      statistics: r.statistics as AnomalyStatistics,
      detectedAt: r.detectedAt,
      isReviewed: r.isReviewed,
      reviewedBy: r.reviewedBy ?? undefined,
      reviewedAt: r.reviewedAt ?? undefined,
    }));
  }

  /**
   * Mark anomaly as reviewed
   */
  async markAsReviewed(anomalyId: string, adminId: string): Promise<void> {
    await this.prisma.anomalyReport.update({
      where: { id: anomalyId },
      data: {
        isReviewed: true,
        reviewedBy: adminId,
        reviewedAt: new Date(),
      },
    });
    this.log.info({ anomalyId, adminId }, 'Anomaly marked as reviewed');
  }

  /**
   * Get anomaly counts by severity
   */
  async getAnomalyCounts(): Promise<{
    total: number;
    unreviewed: number;
    bySeverity: Record<AnomalySeverity, number>;
  }> {
    const total = await this.prisma.anomalyReport.count();
    const unreviewed = await this.prisma.anomalyReport.count({
      where: { isReviewed: false },
    });

    const bySeverity = await this.prisma.anomalyReport.groupBy({
      by: ['severity'],
      _count: { id: true },
    });

    const severityCounts: Record<AnomalySeverity, number> = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    for (const entry of bySeverity) {
      severityCounts[entry.severity as AnomalySeverity] = entry._count.id;
    }

    return { total, unreviewed, bySeverity: severityCounts };
  }
}

// Singleton instance
let anomalyServiceInstance: AnomalyService | null = null;

/**
 * Get the anomaly service instance
 */
export function getAnomalyService(
  prisma?: PrismaClient,
  privacy?: PrivacyService,
  aggregation?: AggregationService,
  thresholds?: Partial<AnomalyThresholds>
): AnomalyService {
  if (!anomalyServiceInstance) {
    anomalyServiceInstance = new AnomalyService(
      prisma,
      privacy,
      aggregation,
      thresholds
    );
  }
  return anomalyServiceInstance;
}

/**
 * Reset the anomaly service (for testing)
 */
export function resetAnomalyService(): void {
  anomalyServiceInstance = null;
}
