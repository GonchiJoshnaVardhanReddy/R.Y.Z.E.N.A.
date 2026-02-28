/**
 * R.Y.Z.E.N.A. - Phase 6: Privacy Service
 * Enforces k-anonymity, PII stripping, and data protection
 */

import {
  PrivacyConfig,
  DEFAULT_PRIVACY_CONFIG,
  PrivacyCheckResult,
  SanitizedData,
  DepartmentMetrics,
  RiskDistribution,
} from './admin.types.js';
import { logger } from '../../shared/logger.js';

/**
 * Privacy service for enforcing data protection rules
 */
export class PrivacyService {
  private config: PrivacyConfig;
  private log = logger.child({ module: 'privacy-service' });

  constructor(config: Partial<PrivacyConfig> = {}) {
    this.config = { ...DEFAULT_PRIVACY_CONFIG, ...config };
    this.log.info({ config: this.config }, 'Privacy service initialized');
  }

  /**
   * Get current privacy configuration
   */
  getConfig(): PrivacyConfig {
    return { ...this.config };
  }

  /**
   * Update privacy configuration
   */
  updateConfig(updates: Partial<PrivacyConfig>): void {
    this.config = { ...this.config, ...updates };
    this.log.info({ config: this.config }, 'Privacy config updated');
  }

  /**
   * Check if a group size meets k-anonymity threshold
   */
  checkKAnonymity(groupSize: number): PrivacyCheckResult {
    const isAllowed = groupSize >= this.config.kAnonymityThreshold;
    
    return {
      isAllowed,
      reason: isAllowed 
        ? undefined 
        : `Group size ${groupSize} below k-anonymity threshold of ${this.config.kAnonymityThreshold}`,
      sampleSize: groupSize,
      threshold: this.config.kAnonymityThreshold,
    };
  }

  /**
   * Check if data can be returned based on sample size
   */
  canReturnData(sampleSize: number): boolean {
    return sampleSize >= this.config.kAnonymityThreshold;
  }

  /**
   * Strip prohibited fields from an object
   */
  stripProhibitedFields<T extends Record<string, unknown>>(
    data: T
  ): SanitizedData<Partial<T>> {
    const removedFields: string[] = [];
    const sanitized: Partial<T> = {};

    for (const [key, value] of Object.entries(data)) {
      if (this.isProhibitedField(key)) {
        removedFields.push(key);
      } else if (typeof value === 'object' && value !== null) {
        // Recursively sanitize nested objects
        if (Array.isArray(value)) {
          sanitized[key as keyof T] = value.map((item) =>
            typeof item === 'object' && item !== null
              ? this.stripProhibitedFields(item as Record<string, unknown>).data
              : item
          ) as T[keyof T];
        } else {
          const nested = this.stripProhibitedFields(
            value as Record<string, unknown>
          );
          sanitized[key as keyof T] = nested.data as T[keyof T];
          removedFields.push(...nested.removedFields.map((f) => `${key}.${f}`));
        }
      } else {
        sanitized[key as keyof T] = value as T[keyof T];
      }
    }

    return {
      data: sanitized,
      removedFields,
      wasSuppressed: removedFields.length > 0,
      privacyNotice:
        removedFields.length > 0
          ? 'Some fields were removed to protect privacy'
          : undefined,
    };
  }

  /**
   * Check if a field name is prohibited
   */
  isProhibitedField(fieldName: string): boolean {
    const normalizedField = fieldName.toLowerCase();
    return this.config.prohibitedFields.some(
      (prohibited) =>
        normalizedField === prohibited.toLowerCase() ||
        normalizedField.includes(prohibited.toLowerCase())
    );
  }

  /**
   * Round a percentage to configured precision
   */
  roundPercentage(value: number): number {
    const multiplier = Math.pow(10, this.config.percentagePrecision);
    return Math.round(value * multiplier) / multiplier;
  }

  /**
   * Suppress department data if below k-anonymity threshold
   */
  suppressDepartmentData(
    departments: DepartmentMetrics[]
  ): DepartmentMetrics[] {
    return departments.map((dept) => {
      if (dept.studentCount < this.config.kAnonymityThreshold) {
        return {
          ...dept,
          department: this.anonymizeDepartmentName(dept.department),
          averageRiskScore: 0,
          riskDistribution: this.createEmptyDistribution(),
          phishingCount: 0,
          clickRate: 0,
          isSuppressed: true,
        };
      }
      return { ...dept, isSuppressed: false };
    });
  }

  /**
   * Anonymize a department name for suppressed data
   */
  private anonymizeDepartmentName(name: string): string {
    // Hash the name to create consistent but anonymous identifier
    const hash = this.simpleHash(name);
    return `Department-${hash.substring(0, 4)}`;
  }

  /**
   * Create an empty risk distribution
   */
  private createEmptyDistribution(): RiskDistribution {
    return {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
      total: 0,
    };
  }

  /**
   * Simple hash function for anonymization
   */
  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Validate that response data contains no PII
   */
  validateNoPII<T>(data: T): { isValid: boolean; violations: string[] } {
    const violations: string[] = [];
    const jsonStr = JSON.stringify(data);

    // Check for common PII patterns
    const piiPatterns = [
      { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, type: 'email' },
      { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, type: 'SSN' },
      { pattern: /\b\d{10}\b/g, type: 'phone' },
      { pattern: /"studentId"\s*:\s*"[^"]+"/g, type: 'studentId' },
      { pattern: /"name"\s*:\s*"[^"]+"/g, type: 'name field' },
    ];

    for (const { pattern, type } of piiPatterns) {
      if (pattern.test(jsonStr)) {
        violations.push(`Potential ${type} found in response`);
      }
    }

    if (violations.length > 0) {
      this.log.warn({ violations }, 'PII validation failed');
    }

    return {
      isValid: violations.length === 0,
      violations,
    };
  }

  /**
   * Generate privacy notice for response
   */
  generatePrivacyNotice(
    context: {
      dataSize: number;
      hasSuppressedDepartments?: boolean;
      hasRemovedFields?: boolean;
    }
  ): string | undefined {
    const notices: string[] = [];

    if (context.dataSize < this.config.kAnonymityThreshold) {
      notices.push(
        `Data suppressed: sample size below ${this.config.kAnonymityThreshold} threshold`
      );
    }

    if (context.hasSuppressedDepartments) {
      notices.push(
        'Some department data suppressed to protect privacy'
      );
    }

    if (context.hasRemovedFields) {
      notices.push('Personally identifiable fields removed');
    }

    return notices.length > 0 ? notices.join('. ') : undefined;
  }

  /**
   * Aggregate values with noise for differential privacy (optional enhancement)
   * Note: Basic implementation - can be extended with true differential privacy
   */
  addStatisticalNoise(
    value: number,
    sensitivity: number,
    epsilon: number = 1.0
  ): number {
    // Laplace mechanism for differential privacy
    // This is a stub for future implementation
    // For now, just round to reduce precision
    const scale = sensitivity / epsilon;
    const noise = this.laplaceSample(scale);
    return Math.round(value + noise);
  }

  /**
   * Sample from Laplace distribution
   */
  private laplaceSample(scale: number): number {
    const u = Math.random() - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  /**
   * Check if department breakdown is allowed
   */
  isDepartmentBreakdownAllowed(): boolean {
    return this.config.allowDepartmentBreakdown;
  }

  /**
   * Get the k-anonymity threshold
   */
  getKAnonymityThreshold(): number {
    return this.config.kAnonymityThreshold;
  }
}

// Singleton instance
let privacyServiceInstance: PrivacyService | null = null;

/**
 * Get the privacy service instance
 */
export function getPrivacyService(
  config?: Partial<PrivacyConfig>
): PrivacyService {
  if (!privacyServiceInstance) {
    privacyServiceInstance = new PrivacyService(config);
  }
  return privacyServiceInstance;
}

/**
 * Reset the privacy service (for testing)
 */
export function resetPrivacyService(): void {
  privacyServiceInstance = null;
}
