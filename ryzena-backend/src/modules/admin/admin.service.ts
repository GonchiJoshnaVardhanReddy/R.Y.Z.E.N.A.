/**
 * R.Y.Z.E.N.A. - Phase 6: Admin Service
 * Orchestrates analytics flows with privacy enforcement
 */

import { PrismaClient, AdminAction } from '../../generated/prisma/index.js';
import { getDbClient } from '../../database/client.js';
import { logger } from '../../shared/logger.js';
import { getPrivacyService, PrivacyService } from './privacy.service.js';
import { getAggregationService, AggregationService } from './aggregation.service.js';
import { getAnomalyService, AnomalyService } from './anomaly.service.js';
import {
  AdminOverviewResponse,
  RiskDistributionResponse,
  TrendsResponse,
  AnomaliesResponse,
  TrendsQueryParams,
  AnomaliesQueryParams,
  DistributionQueryParams,
  AdminAuditEntry,
  TrendComparison,
  TrendData,
} from './admin.types.js';

/**
 * Admin service for orchestrating analytics operations
 */
export class AdminService {
  private prisma: PrismaClient;
  private privacy: PrivacyService;
  private aggregation: AggregationService;
  private anomaly: AnomalyService;
  private log = logger.child({ module: 'admin-service' });

  constructor(
    prisma?: PrismaClient,
    privacy?: PrivacyService,
    aggregation?: AggregationService,
    anomaly?: AnomalyService
  ) {
    this.prisma = prisma || getDbClient();
    this.privacy = privacy || getPrivacyService();
    this.aggregation = aggregation || getAggregationService();
    this.anomaly = anomaly || getAnomalyService();
    this.log.info('Admin service initialized');
  }

  /**
   * Get university-wide overview metrics
   */
  async getOverview(adminId: string, ipAddress?: string): Promise<AdminOverviewResponse> {
    this.log.info({ adminId }, 'Getting university overview');

    // Audit log
    await this.logAdminAccess({
      adminId,
      action: 'VIEW_OVERVIEW',
      endpoint: '/api/v1/admin/overview',
      ipAddress,
      timestamp: new Date(),
    });

    const overview = await this.aggregation.getUniversityOverview();

    if (!overview) {
      return {
        success: false,
        data: null,
        privacyNotice: 'Insufficient data to meet privacy requirements',
        generatedAt: new Date(),
      };
    }

    // Validate no PII in response
    const validation = this.privacy.validateNoPII(overview);
    if (!validation.isValid) {
      this.log.error({ violations: validation.violations }, 'PII found in overview');
      return {
        success: false,
        data: null,
        privacyNotice: 'Data validation failed',
        generatedAt: new Date(),
      };
    }

    return {
      success: true,
      data: overview,
      generatedAt: new Date(),
    };
  }

  /**
   * Get risk distribution across university and departments
   */
  async getRiskDistribution(
    adminId: string,
    params: DistributionQueryParams = {},
    ipAddress?: string
  ): Promise<RiskDistributionResponse> {
    this.log.info({ adminId, params }, 'Getting risk distribution');

    // Audit log
    await this.logAdminAccess({
      adminId,
      action: 'VIEW_DISTRIBUTION',
      endpoint: '/api/v1/admin/risk-distribution',
      queryParams: params as Record<string, unknown>,
      ipAddress,
      timestamp: new Date(),
    });

    const universityDistribution = await this.aggregation.getRiskDistribution();

    // Check privacy threshold
    if (!this.privacy.canReturnData(universityDistribution.total)) {
      return {
        success: false,
        data: null,
        privacyNotice: `Data suppressed: sample size below ${this.privacy.getKAnonymityThreshold()} threshold`,
        generatedAt: new Date(),
      };
    }

    let departments = undefined;
    if (params.includeDepartments) {
      const deptMetrics = await this.aggregation.getDepartmentMetrics();
      
      // Filter by specific department if requested
      if (params.department) {
        departments = deptMetrics.filter(
          (d) => d.department.toLowerCase() === params.department?.toLowerCase()
        );
      } else {
        departments = deptMetrics;
      }
    }

    return {
      success: true,
      data: {
        university: universityDistribution,
        departments,
      },
      privacyNotice: this.privacy.generatePrivacyNotice({
        dataSize: universityDistribution.total,
        hasSuppressedDepartments: departments?.some((d) => d.isSuppressed),
      }),
      generatedAt: new Date(),
    };
  }

  /**
   * Get weekly trend data
   */
  async getTrends(
    adminId: string,
    params: TrendsQueryParams = {},
    ipAddress?: string
  ): Promise<TrendsResponse> {
    const weeks = params.weeks || 12;
    this.log.info({ adminId, weeks }, 'Getting trend data');

    // Audit log
    await this.logAdminAccess({
      adminId,
      action: 'VIEW_TRENDS',
      endpoint: '/api/v1/admin/trends',
      queryParams: params as Record<string, unknown>,
      ipAddress,
      timestamp: new Date(),
    });

    const weeklyTrends = await this.aggregation.getWeeklyTrends(weeks);

    if (weeklyTrends.length < 2) {
      return {
        success: false,
        data: null,
        privacyNotice: 'Insufficient historical data for trend analysis',
        generatedAt: new Date(),
      };
    }

    // Calculate comparison
    const current = weeklyTrends[weeklyTrends.length - 1];
    const previous = weeklyTrends[weeklyTrends.length - 2];

    const comparison: TrendComparison = {
      current,
      previous,
      changes: {
        riskScoreChange: current.averageRiskScore - previous.averageRiskScore,
        riskScoreChangePercent: this.calculateChangePercent(
          previous.averageRiskScore,
          current.averageRiskScore
        ),
        phishingCountChange: current.phishingCount - previous.phishingCount,
        phishingCountChangePercent: this.calculateChangePercent(
          previous.phishingCount,
          current.phishingCount
        ),
        clickCountChange: current.clickCount - previous.clickCount,
        clickCountChangePercent: this.calculateChangePercent(
          previous.clickCount,
          current.clickCount
        ),
      },
    };

    // Determine overall trend direction
    const avgRiskChange =
      weeklyTrends.length > 4
        ? this.calculateOverallTrend(weeklyTrends.map((t) => t.averageRiskScore))
        : 0;

    let trendDirection: 'improving' | 'stable' | 'declining';
    if (avgRiskChange < -2) {
      trendDirection = 'improving';
    } else if (avgRiskChange > 2) {
      trendDirection = 'declining';
    } else {
      trendDirection = 'stable';
    }

    const trendData: TrendData = {
      weeks: weeklyTrends,
      weekCount: weeklyTrends.length,
      comparison,
      trendDirection,
      meetsPrivacyThreshold: true,
    };

    return {
      success: true,
      data: trendData,
      generatedAt: new Date(),
    };
  }

  /**
   * Get anomaly reports
   */
  async getAnomalies(
    adminId: string,
    params: AnomaliesQueryParams = {},
    ipAddress?: string
  ): Promise<AnomaliesResponse> {
    this.log.info({ adminId, params }, 'Getting anomaly reports');

    // Audit log
    await this.logAdminAccess({
      adminId,
      action: 'VIEW_ANOMALIES',
      endpoint: '/api/v1/admin/anomalies',
      queryParams: params as Record<string, unknown>,
      ipAddress,
      timestamp: new Date(),
    });

    // Run detection to find new anomalies
    await this.anomaly.detectAnomalies();

    // Get stored anomalies
    const anomalies = await this.anomaly.getAnomalyReports({
      severity: params.severity,
      type: params.type,
      unreviewedOnly: params.unreviewedOnly,
      limit: params.limit,
    });

    const counts = await this.anomaly.getAnomalyCounts();

    return {
      success: true,
      data: {
        anomalies,
        totalCount: counts.total,
        unreviewedCount: counts.unreviewed,
      },
      generatedAt: new Date(),
    };
  }

  /**
   * Mark an anomaly as reviewed
   */
  async reviewAnomaly(
    adminId: string,
    anomalyId: string,
    ipAddress?: string
  ): Promise<{ success: boolean }> {
    this.log.info({ adminId, anomalyId }, 'Reviewing anomaly');

    // Audit log
    await this.logAdminAccess({
      adminId,
      action: 'REVIEW_ANOMALY',
      endpoint: '/api/v1/admin/anomalies/review',
      queryParams: { anomalyId },
      ipAddress,
      responseSummary: `Reviewed anomaly ${anomalyId}`,
      timestamp: new Date(),
    });

    await this.anomaly.markAsReviewed(anomalyId, adminId);

    return { success: true };
  }

  /**
   * Get top phishing signals
   */
  async getTopPhishingSignals(adminId: string, limit: number = 10) {
    this.log.info({ adminId, limit }, 'Getting top phishing signals');

    const signals = await this.aggregation.getTopPhishingSignals(limit);
    return signals;
  }

  /**
   * Get consent analytics
   */
  async getConsentAnalytics(adminId: string) {
    this.log.info({ adminId }, 'Getting consent analytics');

    return await this.aggregation.getConsentAnalytics();
  }

  /**
   * Log admin data access for audit trail
   */
  private async logAdminAccess(entry: AdminAuditEntry): Promise<void> {
    try {
      await this.prisma.adminAuditLog.create({
        data: {
          adminId: entry.adminId,
          action: entry.action as AdminAction,
          endpoint: entry.endpoint,
          queryParams: entry.queryParams as object | undefined,
          ipAddress: entry.ipAddress,
          responseSummary: entry.responseSummary,
          createdAt: entry.timestamp,
        },
      });
    } catch (error) {
      this.log.error({ error, entry }, 'Failed to create admin audit log');
    }
  }

  /**
   * Calculate percentage change
   */
  private calculateChangePercent(previous: number, current: number): number {
    if (previous === 0) return current > 0 ? 100 : 0;
    return Math.round(((current - previous) / previous) * 1000) / 10;
  }

  /**
   * Calculate overall trend direction from data points
   */
  private calculateOverallTrend(values: number[]): number {
    if (values.length < 2) return 0;

    // Simple linear regression slope
    const n = values.length;
    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumXX = 0;

    for (let i = 0; i < n; i++) {
      sumX += i;
      sumY += values[i];
      sumXY += i * values[i];
      sumXX += i * i;
    }

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    return slope;
  }

  /**
   * Verify admin role (to be called by middleware)
   */
  async verifyAdminRole(adminId: string): Promise<boolean> {
    // Stub: In production, this would check against an admin table
    // For now, we just verify the ID is not empty
    return adminId !== undefined && adminId.length > 0;
  }
}

// Singleton instance
let adminServiceInstance: AdminService | null = null;

/**
 * Get the admin service instance
 */
export function getAdminService(
  prisma?: PrismaClient,
  privacy?: PrivacyService,
  aggregation?: AggregationService,
  anomaly?: AnomalyService
): AdminService {
  if (!adminServiceInstance) {
    adminServiceInstance = new AdminService(prisma, privacy, aggregation, anomaly);
  }
  return adminServiceInstance;
}

/**
 * Reset the admin service (for testing)
 */
export function resetAdminService(): void {
  adminServiceInstance = null;
}
