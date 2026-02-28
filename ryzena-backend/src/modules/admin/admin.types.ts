/**
 * R.Y.Z.E.N.A. - Phase 6: Admin Analytics Types
 * Type definitions for privacy-preserving analytics layer
 */

// ============================================================================
// CONFIGURATION TYPES
// ============================================================================

/**
 * Privacy configuration for k-anonymity and data protection
 */
export interface PrivacyConfig {
  /** Minimum group size for k-anonymity (default: 5) */
  kAnonymityThreshold: number;
  /** Whether to allow department-level breakdown */
  allowDepartmentBreakdown: boolean;
  /** Maximum precision for percentages */
  percentagePrecision: number;
  /** Fields that are never exposed */
  prohibitedFields: string[];
}

/**
 * Anomaly detection thresholds
 */
export interface AnomalyThresholds {
  /** Percentage increase to trigger phishing spike alert */
  phishingSpikePercent: number;
  /** Percentage drop to trigger risk score drop alert */
  riskScoreDropPercent: number;
  /** Percentage increase for consent approval surge */
  consentApprovalSurgePercent: number;
  /** Percentage increase for click rate alert */
  clickRateIncreasePercent: number;
  /** Standard deviations for statistical anomaly */
  standardDeviationThreshold: number;
}

/**
 * Default privacy configuration
 */
export const DEFAULT_PRIVACY_CONFIG: PrivacyConfig = {
  kAnonymityThreshold: 5,
  allowDepartmentBreakdown: true,
  percentagePrecision: 1,
  prohibitedFields: [
    'studentId',
    'email',
    'name',
    'ssn',
    'phone',
    'address',
    'ipAddress',
  ],
};

/**
 * Default anomaly thresholds
 */
export const DEFAULT_ANOMALY_THRESHOLDS: AnomalyThresholds = {
  phishingSpikePercent: 50,
  riskScoreDropPercent: 20,
  consentApprovalSurgePercent: 100,
  clickRateIncreasePercent: 30,
  standardDeviationThreshold: 2,
};

// ============================================================================
// AGGREGATION TYPES
// ============================================================================

/**
 * Risk level distribution
 */
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Risk distribution counts
 */
export interface RiskDistribution {
  low: number;
  medium: number;
  high: number;
  critical: number;
  total: number;
}

/**
 * Risk distribution with percentages
 */
export interface RiskDistributionWithPercent extends RiskDistribution {
  lowPercent: number;
  mediumPercent: number;
  highPercent: number;
  criticalPercent: number;
}

/**
 * University-level overview metrics
 */
export interface UniversityOverview {
  /** Total number of students tracked */
  totalStudents: number;
  /** Average risk score across all students */
  averageRiskScore: number;
  /** Median risk score */
  medianRiskScore: number;
  /** Standard deviation of risk scores */
  riskScoreStdDev: number;
  /** Risk distribution */
  riskDistribution: RiskDistributionWithPercent;
  /** Total phishing emails detected */
  totalPhishingDetected: number;
  /** Phishing detection rate (detected / total emails) */
  phishingDetectionRate: number;
  /** Average trust score for detected threats */
  averageThreatTrustScore: number;
  /** Active consent grants count */
  activeConsentGrants: number;
  /** Pending consent requests count */
  pendingConsentRequests: number;
  /** Data freshness timestamp */
  dataAsOf: Date;
  /** Whether data meets k-anonymity threshold */
  meetsPrivacyThreshold: boolean;
}

/**
 * Department-level metrics (if k-anonymity allows)
 */
export interface DepartmentMetrics {
  /** Department name (anonymized if needed) */
  department: string;
  /** Number of students (only if >= k threshold) */
  studentCount: number;
  /** Average risk score */
  averageRiskScore: number;
  /** Risk distribution */
  riskDistribution: RiskDistribution;
  /** Phishing emails received */
  phishingCount: number;
  /** Click rate on phishing links */
  clickRate: number;
  /** Whether this department's data is suppressed */
  isSuppressed: boolean;
}

/**
 * Phishing signal frequency
 */
export interface PhishingSignalFrequency {
  /** Signal name */
  signal: string;
  /** Number of occurrences */
  count: number;
  /** Percentage of phishing emails with this signal */
  percentage: number;
}

/**
 * Consent analytics summary
 */
export interface ConsentAnalytics {
  /** Total consent requests */
  totalRequests: number;
  /** Approved requests */
  approvedCount: number;
  /** Denied requests */
  deniedCount: number;
  /** Expired/revoked count */
  expiredRevokedCount: number;
  /** Approval rate */
  approvalRate: number;
  /** Average risk score of approved requests */
  avgApprovedRiskScore: number;
  /** Average risk score of denied requests */
  avgDeniedRiskScore: number;
  /** Most requested fields (anonymized counts) */
  topRequestedFields: { field: string; count: number }[];
}

// ============================================================================
// TREND TYPES
// ============================================================================

/**
 * Weekly trend data point
 */
export interface WeeklyTrendPoint {
  /** Year */
  year: number;
  /** ISO week number */
  week: number;
  /** Week start date */
  weekStart: Date;
  /** Average risk score that week */
  averageRiskScore: number;
  /** Number of phishing emails detected */
  phishingCount: number;
  /** Number of threats clicked */
  clickCount: number;
  /** Number of risk events */
  eventCount: number;
  /** Number of consent requests */
  consentRequestCount: number;
}

/**
 * Trend comparison between two periods
 */
export interface TrendComparison {
  /** Current period metrics */
  current: WeeklyTrendPoint;
  /** Previous period metrics */
  previous: WeeklyTrendPoint;
  /** Changes */
  changes: {
    riskScoreChange: number;
    riskScoreChangePercent: number;
    phishingCountChange: number;
    phishingCountChangePercent: number;
    clickCountChange: number;
    clickCountChangePercent: number;
  };
}

/**
 * Extended trend data with multiple weeks
 */
export interface TrendData {
  /** Weekly data points */
  weeks: WeeklyTrendPoint[];
  /** Number of weeks included */
  weekCount: number;
  /** Comparison with previous period */
  comparison: TrendComparison | null;
  /** Overall trend direction */
  trendDirection: 'improving' | 'stable' | 'declining';
  /** Data meets privacy threshold */
  meetsPrivacyThreshold: boolean;
}

// ============================================================================
// ANOMALY TYPES
// ============================================================================

/**
 * Anomaly types detected by the system
 */
export type AnomalyType =
  | 'PHISHING_SPIKE'
  | 'RISK_SCORE_DROP'
  | 'CONSENT_APPROVAL_SURGE'
  | 'CLICK_RATE_INCREASE'
  | 'DEPARTMENT_RISK_SPIKE';

/**
 * Anomaly severity levels
 */
export type AnomalySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Anomaly report structure
 */
export interface AnomalyReport {
  /** Unique identifier */
  id: string;
  /** Type of anomaly */
  type: AnomalyType;
  /** Severity level */
  severity: AnomalySeverity;
  /** Human-readable description */
  description: string;
  /** Affected scope (university, department name, etc.) */
  scope: string;
  /** Statistical details */
  statistics: AnomalyStatistics;
  /** When the anomaly was detected */
  detectedAt: Date;
  /** Whether it has been reviewed */
  isReviewed: boolean;
  /** Who reviewed it (admin ID, not name) */
  reviewedBy?: string;
  /** When it was reviewed */
  reviewedAt?: Date;
}

/**
 * Statistics for an anomaly
 */
export interface AnomalyStatistics {
  /** Baseline/expected value */
  baseline: number;
  /** Current/observed value */
  current: number;
  /** Percentage change */
  changePercent: number;
  /** Standard deviations from mean */
  standardDeviations?: number;
  /** Time period for comparison */
  comparisonPeriod: string;
  /** Sample size (for k-anonymity) */
  sampleSize: number;
}

/**
 * Input for anomaly detection
 */
export interface AnomalyDetectionInput {
  /** Current week's metrics */
  currentMetrics: WeeklyTrendPoint;
  /** Previous week's metrics */
  previousMetrics: WeeklyTrendPoint;
  /** Historical average (for baseline) */
  historicalAverage: {
    riskScore: number;
    phishingCount: number;
    clickRate: number;
    consentApprovals: number;
  };
  /** Standard deviations */
  standardDeviations: {
    riskScore: number;
    phishingCount: number;
    clickRate: number;
    consentApprovals: number;
  };
}

// ============================================================================
// API RESPONSE TYPES
// ============================================================================

/**
 * Admin overview response
 */
export interface AdminOverviewResponse {
  success: boolean;
  data: UniversityOverview | null;
  privacyNotice?: string;
  generatedAt: Date;
}

/**
 * Risk distribution response
 */
export interface RiskDistributionResponse {
  success: boolean;
  data: {
    university: RiskDistributionWithPercent;
    departments?: DepartmentMetrics[];
  } | null;
  privacyNotice?: string;
  generatedAt: Date;
}

/**
 * Trends response
 */
export interface TrendsResponse {
  success: boolean;
  data: TrendData | null;
  privacyNotice?: string;
  generatedAt: Date;
}

/**
 * Anomalies response
 */
export interface AnomaliesResponse {
  success: boolean;
  data: {
    anomalies: AnomalyReport[];
    totalCount: number;
    unreviewedCount: number;
  } | null;
  generatedAt: Date;
}

// ============================================================================
// QUERY TYPES
// ============================================================================

/**
 * Query parameters for trends endpoint
 */
export interface TrendsQueryParams {
  /** Number of weeks to include (default: 12) */
  weeks?: number;
  /** Include department breakdown */
  includeDepartments?: boolean;
  /** Filter by department */
  department?: string;
}

/**
 * Query parameters for anomalies endpoint
 */
export interface AnomaliesQueryParams {
  /** Filter by severity */
  severity?: AnomalySeverity;
  /** Filter by type */
  type?: AnomalyType;
  /** Only show unreviewed */
  unreviewedOnly?: boolean;
  /** Limit results */
  limit?: number;
}

/**
 * Query parameters for distribution endpoint
 */
export interface DistributionQueryParams {
  /** Include department breakdown */
  includeDepartments?: boolean;
  /** Filter by department */
  department?: string;
}

// ============================================================================
// AUDIT TYPES
// ============================================================================

/**
 * Admin action types for audit logging
 */
export type AdminActionType =
  | 'VIEW_OVERVIEW'
  | 'VIEW_DISTRIBUTION'
  | 'VIEW_TRENDS'
  | 'VIEW_ANOMALIES'
  | 'EXPORT_DATA'
  | 'REVIEW_ANOMALY';

/**
 * Admin audit log entry
 */
export interface AdminAuditEntry {
  /** Admin identifier */
  adminId: string;
  /** Action performed */
  action: AdminActionType;
  /** Endpoint accessed */
  endpoint: string;
  /** Query parameters (sanitized) */
  queryParams?: Record<string, unknown>;
  /** IP address */
  ipAddress?: string;
  /** Response summary (no PII) */
  responseSummary?: string;
  /** Timestamp */
  timestamp: Date;
}

// ============================================================================
// HELPER TYPES
// ============================================================================

/**
 * Result of privacy check
 */
export interface PrivacyCheckResult {
  /** Whether data can be returned */
  isAllowed: boolean;
  /** Reason for suppression (if any) */
  reason?: string;
  /** Sample size */
  sampleSize: number;
  /** Required threshold */
  threshold: number;
}

/**
 * Sanitized data wrapper
 */
export interface SanitizedData<T> {
  /** The sanitized data */
  data: T;
  /** Fields that were removed */
  removedFields: string[];
  /** Whether any suppression occurred */
  wasSuppressed: boolean;
  /** Privacy notice */
  privacyNotice?: string;
}

/**
 * Aggregation time range
 */
export interface TimeRange {
  /** Start date */
  start: Date;
  /** End date */
  end: Date;
  /** Number of days */
  days: number;
}

/**
 * Statistical summary
 */
export interface StatisticalSummary {
  /** Count */
  count: number;
  /** Sum */
  sum: number;
  /** Average */
  average: number;
  /** Median */
  median: number;
  /** Standard deviation */
  stdDev: number;
  /** Minimum */
  min: number;
  /** Maximum */
  max: number;
}
