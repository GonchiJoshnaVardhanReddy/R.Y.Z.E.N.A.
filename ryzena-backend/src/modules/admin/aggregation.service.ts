/**
 * R.Y.Z.E.N.A. - Phase 6: Aggregation Service
 * Performs privacy-preserving statistical queries
 */

import { PrismaClient, RiskLevel, ThreatStatus, ConsentStatus } from '../../generated/prisma/index.js';
import { getDbClient } from '../../database/client.js';
import { logger } from '../../shared/logger.js';
import { getPrivacyService, PrivacyService } from './privacy.service.js';
import {
  UniversityOverview,
  RiskDistribution,
  RiskDistributionWithPercent,
  DepartmentMetrics,
  WeeklyTrendPoint,
  PhishingSignalFrequency,
  ConsentAnalytics,
  StatisticalSummary,
  TimeRange,
} from './admin.types.js';

/**
 * Aggregation service for computing privacy-preserving statistics
 */
export class AggregationService {
  private prisma: PrismaClient;
  private privacy: PrivacyService;
  private log = logger.child({ module: 'aggregation-service' });

  constructor(prisma?: PrismaClient, privacy?: PrivacyService) {
    this.prisma = prisma || getDbClient();
    this.privacy = privacy || getPrivacyService();
    this.log.info('Aggregation service initialized');
  }

  /**
   * Get university-wide overview metrics
   */
  async getUniversityOverview(): Promise<UniversityOverview | null> {
    this.log.debug('Computing university overview');

    // Get total student count
    const totalStudents = await this.prisma.riskProfile.count();

    // Check k-anonymity
    if (!this.privacy.canReturnData(totalStudents)) {
      this.log.warn(
        { totalStudents },
        'University overview suppressed due to k-anonymity'
      );
      return null;
    }

    // Get risk score statistics
    const riskStats = await this.prisma.riskProfile.aggregate({
      _avg: { riskScore: true },
      _min: { riskScore: true },
      _max: { riskScore: true },
    });

    // Get all risk scores for median and stddev calculation
    const allScores = await this.prisma.riskProfile.findMany({
      select: { riskScore: true },
      orderBy: { riskScore: 'asc' },
    });

    const scores = allScores.map((p) => p.riskScore);
    const medianRiskScore = this.calculateMedian(scores);
    const riskScoreStdDev = this.calculateStdDev(scores);

    // Get risk distribution
    const riskDistribution = await this.getRiskDistribution();

    // Get phishing statistics
    const threatStats = await this.prisma.threatLog.aggregate({
      _count: { id: true },
      _avg: { trustScore: true },
      where: { status: ThreatStatus.SUSPICIOUS },
    });

    const totalEmails = await this.prisma.threatLog.count();
    const phishingDetectionRate =
      totalEmails > 0
        ? (threatStats._count.id / totalEmails) * 100
        : 0;

    // Get consent statistics
    const activeGrants = await this.prisma.consentGrant.count({
      where: {
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
    });

    const pendingRequests = await this.prisma.consentRequest.count({
      where: { status: ConsentStatus.PENDING },
    });

    return {
      totalStudents,
      averageRiskScore: this.privacy.roundPercentage(
        riskStats._avg.riskScore ?? 50
      ),
      medianRiskScore,
      riskScoreStdDev: this.privacy.roundPercentage(riskScoreStdDev),
      riskDistribution,
      totalPhishingDetected: threatStats._count.id,
      phishingDetectionRate: this.privacy.roundPercentage(phishingDetectionRate),
      averageThreatTrustScore: this.privacy.roundPercentage(
        threatStats._avg.trustScore ?? 0
      ),
      activeConsentGrants: activeGrants,
      pendingConsentRequests: pendingRequests,
      dataAsOf: new Date(),
      meetsPrivacyThreshold: true,
    };
  }

  /**
   * Get risk level distribution across university
   */
  async getRiskDistribution(): Promise<RiskDistributionWithPercent> {
    const counts = await this.prisma.riskProfile.groupBy({
      by: ['riskLevel'],
      _count: { id: true },
    });

    const distribution: RiskDistribution = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
      total: 0,
    };

    for (const entry of counts) {
      const count = entry._count.id;
      distribution.total += count;
      
      switch (entry.riskLevel) {
        case RiskLevel.LOW:
          distribution.low = count;
          break;
        case RiskLevel.MEDIUM:
          distribution.medium = count;
          break;
        case RiskLevel.HIGH:
          distribution.high = count;
          break;
        case RiskLevel.CRITICAL:
          distribution.critical = count;
          break;
      }
    }

    // Calculate percentages
    const total = distribution.total || 1; // Prevent division by zero
    return {
      ...distribution,
      lowPercent: this.privacy.roundPercentage((distribution.low / total) * 100),
      mediumPercent: this.privacy.roundPercentage(
        (distribution.medium / total) * 100
      ),
      highPercent: this.privacy.roundPercentage(
        (distribution.high / total) * 100
      ),
      criticalPercent: this.privacy.roundPercentage(
        (distribution.critical / total) * 100
      ),
    };
  }

  /**
   * Get department-level metrics (with privacy enforcement)
   */
  async getDepartmentMetrics(): Promise<DepartmentMetrics[]> {
    if (!this.privacy.isDepartmentBreakdownAllowed()) {
      this.log.debug('Department breakdown disabled in privacy config');
      return [];
    }

    // Get departments with student counts
    const departments = await this.prisma.riskProfile.groupBy({
      by: ['department'],
      _count: { id: true },
      _avg: { riskScore: true },
      where: { department: { not: null } },
    });

    const metrics: DepartmentMetrics[] = [];

    for (const dept of departments) {
      if (!dept.department) continue;

      // Get risk distribution for this department
      const deptDistribution = await this.prisma.riskProfile.groupBy({
        by: ['riskLevel'],
        _count: { id: true },
        where: { department: dept.department },
      });

      const distribution: RiskDistribution = {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
        total: dept._count.id,
      };

      for (const entry of deptDistribution) {
        switch (entry.riskLevel) {
          case RiskLevel.LOW:
            distribution.low = entry._count.id;
            break;
          case RiskLevel.MEDIUM:
            distribution.medium = entry._count.id;
            break;
          case RiskLevel.HIGH:
            distribution.high = entry._count.id;
            break;
          case RiskLevel.CRITICAL:
            distribution.critical = entry._count.id;
            break;
        }
      }

      // Get phishing and click stats for department
      const threatStats = await this.prisma.threatLog.aggregate({
        _count: { id: true },
        where: { department: dept.department },
      });

      const clickedCount = await this.prisma.threatLog.count({
        where: {
          department: dept.department,
          userClicked: true,
        },
      });

      const clickRate =
        threatStats._count.id > 0
          ? (clickedCount / threatStats._count.id) * 100
          : 0;

      metrics.push({
        department: dept.department,
        studentCount: dept._count.id,
        averageRiskScore: this.privacy.roundPercentage(
          dept._avg.riskScore ?? 50
        ),
        riskDistribution: distribution,
        phishingCount: threatStats._count.id,
        clickRate: this.privacy.roundPercentage(clickRate),
        isSuppressed: false,
      });
    }

    // Apply privacy suppression
    return this.privacy.suppressDepartmentData(metrics);
  }

  /**
   * Get weekly trend data
   */
  async getWeeklyTrends(weeks: number = 12): Promise<WeeklyTrendPoint[]> {
    this.log.debug({ weeks }, 'Computing weekly trends');

    const trends: WeeklyTrendPoint[] = [];
    const now = new Date();

    for (let i = 0; i < weeks; i++) {
      const weekEnd = new Date(now);
      weekEnd.setDate(weekEnd.getDate() - i * 7);
      
      const weekStart = new Date(weekEnd);
      weekStart.setDate(weekStart.getDate() - 7);

      const { year, week } = this.getISOWeek(weekStart);

      // Get average risk score for the week from snapshots
      const snapshotStats = await this.prisma.weeklySnapshot.aggregate({
        _avg: { riskScore: true },
        _sum: { eventCount: true, phishingCount: true },
        where: { year, weekNumber: week },
      });

      // Get threat counts for the week
      const phishingCount = await this.prisma.threatLog.count({
        where: {
          status: ThreatStatus.SUSPICIOUS,
          createdAt: { gte: weekStart, lt: weekEnd },
        },
      });

      const clickCount = await this.prisma.threatLog.count({
        where: {
          userClicked: true,
          createdAt: { gte: weekStart, lt: weekEnd },
        },
      });

      // Get consent request count
      const consentCount = await this.prisma.consentRequest.count({
        where: {
          createdAt: { gte: weekStart, lt: weekEnd },
        },
      });

      // Get event count
      const eventCount = await this.prisma.riskEvent.count({
        where: {
          createdAt: { gte: weekStart, lt: weekEnd },
        },
      });

      trends.push({
        year,
        week,
        weekStart,
        averageRiskScore: this.privacy.roundPercentage(
          snapshotStats._avg.riskScore ?? 50
        ),
        phishingCount:
          snapshotStats._sum.phishingCount ?? phishingCount,
        clickCount,
        eventCount: snapshotStats._sum.eventCount ?? eventCount,
        consentRequestCount: consentCount,
      });
    }

    return trends.reverse(); // Oldest first
  }

  /**
   * Get most common phishing signals
   */
  async getTopPhishingSignals(limit: number = 10): Promise<PhishingSignalFrequency[]> {
    const threats = await this.prisma.threatLog.findMany({
      where: { status: ThreatStatus.SUSPICIOUS },
      select: { phishingSignals: true },
    });

    const signalCounts = new Map<string, number>();
    const totalThreats = threats.length;

    for (const threat of threats) {
      const signals = threat.phishingSignals as string[];
      if (Array.isArray(signals)) {
        for (const signal of signals) {
          signalCounts.set(signal, (signalCounts.get(signal) || 0) + 1);
        }
      }
    }

    const frequencies: PhishingSignalFrequency[] = [];
    for (const [signal, count] of signalCounts.entries()) {
      frequencies.push({
        signal,
        count,
        percentage: this.privacy.roundPercentage(
          (count / totalThreats) * 100
        ),
      });
    }

    return frequencies
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  /**
   * Get consent analytics summary
   */
  async getConsentAnalytics(): Promise<ConsentAnalytics> {
    const totalRequests = await this.prisma.consentRequest.count();
    
    const statusCounts = await this.prisma.consentRequest.groupBy({
      by: ['status'],
      _count: { id: true },
      _avg: { riskScore: true },
    });

    let approvedCount = 0;
    let deniedCount = 0;
    let expiredRevokedCount = 0;
    let avgApprovedRiskScore = 0;
    let avgDeniedRiskScore = 0;

    for (const entry of statusCounts) {
      switch (entry.status) {
        case ConsentStatus.APPROVED:
          approvedCount = entry._count.id;
          avgApprovedRiskScore = entry._avg.riskScore ?? 0;
          break;
        case ConsentStatus.DENIED:
          deniedCount = entry._count.id;
          avgDeniedRiskScore = entry._avg.riskScore ?? 0;
          break;
        case ConsentStatus.EXPIRED:
        case ConsentStatus.REVOKED:
          expiredRevokedCount += entry._count.id;
          break;
      }
    }

    // Get top requested fields
    const requests = await this.prisma.consentRequest.findMany({
      select: { requestedFields: true },
    });

    const fieldCounts = new Map<string, number>();
    for (const req of requests) {
      const fields = req.requestedFields as string[];
      if (Array.isArray(fields)) {
        for (const field of fields) {
          fieldCounts.set(field, (fieldCounts.get(field) || 0) + 1);
        }
      }
    }

    const topRequestedFields = Array.from(fieldCounts.entries())
      .map(([field, count]) => ({ field, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalRequests,
      approvedCount,
      deniedCount,
      expiredRevokedCount,
      approvalRate: this.privacy.roundPercentage(
        totalRequests > 0 ? (approvedCount / totalRequests) * 100 : 0
      ),
      avgApprovedRiskScore: this.privacy.roundPercentage(avgApprovedRiskScore),
      avgDeniedRiskScore: this.privacy.roundPercentage(avgDeniedRiskScore),
      topRequestedFields,
    };
  }

  /**
   * Get time range for queries
   */
  getTimeRange(days: number): TimeRange {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - days);
    return { start, end, days };
  }

  /**
   * Calculate median of an array
   */
  private calculateMedian(values: number[]): number {
    if (values.length === 0) return 0;
    
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    
    return sorted.length % 2 !== 0
      ? sorted[mid]
      : (sorted[mid - 1] + sorted[mid]) / 2;
  }

  /**
   * Calculate standard deviation
   */
  private calculateStdDev(values: number[]): number {
    if (values.length === 0) return 0;
    
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map((v) => Math.pow(v - mean, 2));
    const variance = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    
    return Math.sqrt(variance);
  }

  /**
   * Get ISO week number
   */
  private getISOWeek(date: Date): { year: number; week: number } {
    const d = new Date(date);
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() + 4 - (d.getDay() || 7));
    
    const yearStart = new Date(d.getFullYear(), 0, 1);
    const week = Math.ceil(
      ((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7
    );
    
    return { year: d.getFullYear(), week };
  }

  /**
   * Calculate statistical summary for a dataset
   */
  calculateStatistics(values: number[]): StatisticalSummary {
    if (values.length === 0) {
      return {
        count: 0,
        sum: 0,
        average: 0,
        median: 0,
        stdDev: 0,
        min: 0,
        max: 0,
      };
    }

    const sorted = [...values].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    const average = sum / sorted.length;

    return {
      count: sorted.length,
      sum,
      average: this.privacy.roundPercentage(average),
      median: this.calculateMedian(sorted),
      stdDev: this.privacy.roundPercentage(this.calculateStdDev(sorted)),
      min: sorted[0],
      max: sorted[sorted.length - 1],
    };
  }
}

// Singleton instance
let aggregationServiceInstance: AggregationService | null = null;

/**
 * Get the aggregation service instance
 */
export function getAggregationService(
  prisma?: PrismaClient,
  privacy?: PrivacyService
): AggregationService {
  if (!aggregationServiceInstance) {
    aggregationServiceInstance = new AggregationService(prisma, privacy);
  }
  return aggregationServiceInstance;
}

/**
 * Reset the aggregation service (for testing)
 */
export function resetAggregationService(): void {
  aggregationServiceInstance = null;
}
