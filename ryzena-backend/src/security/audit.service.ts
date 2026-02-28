/**
 * R.Y.Z.E.N.A. - Phase 7: Audit Service
 * Comprehensive security audit logging
 */

import { PrismaClient } from '../generated/prisma/index.js';
import { getDbClient } from '../database/client.js';
import { logger } from '../shared/logger.js';
import { AUDIT_CONFIG, SENSITIVE_FIELDS } from './security.config.js';

// ============================================================================
// TYPES
// ============================================================================

export interface AuditEntry {
  /** Action being performed */
  action: string;
  /** Actor performing the action */
  actorId: string;
  /** Actor's role */
  actorRole: string;
  /** Resource being accessed */
  resource?: string;
  /** Resource ID if applicable */
  resourceId?: string;
  /** IP address */
  ipAddress?: string;
  /** User agent */
  userAgent?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Was action successful */
  success?: boolean;
  /** Error message if failed */
  errorMessage?: string;
}

export interface AuditLogRecord {
  id: string;
  action: string;
  actorId: string;
  actorRole: string;
  resource: string | null;
  resourceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
  success: boolean;
  errorMessage: string | null;
  createdAt: Date;
}

// ============================================================================
// AUDIT SERVICE
// ============================================================================

/**
 * Audit service for security logging
 */
export class AuditService {
  private prisma: PrismaClient;
  private enabled: boolean;
  private log = logger.child({ module: 'audit-service' });
  private buffer: AuditEntry[] = [];
  private flushInterval: ReturnType<typeof setInterval> | null = null;

  constructor(prisma?: PrismaClient) {
    this.prisma = prisma || getDbClient();
    this.enabled = process.env.AUDIT_LOGGING_ENABLED !== 'false';
    
    if (this.enabled) {
      // Flush buffer periodically
      this.flushInterval = setInterval(() => this.flushBuffer(), 5000);
      this.log.info('Audit service initialized');
    } else {
      this.log.warn('Audit logging is disabled');
    }
  }

  /**
   * Log an audit entry
   */
  async log(entry: AuditEntry): Promise<void> {
    if (!this.enabled) {
      return;
    }

    // Redact sensitive fields
    const sanitizedEntry = this.sanitizeEntry(entry);

    // Always log to structured logger
    this.log.info({
      audit: true,
      ...sanitizedEntry,
    });

    // Buffer for database persistence
    this.buffer.push(sanitizedEntry);

    // Flush immediately for critical actions
    if (this.isCriticalAction(entry.action)) {
      await this.flushBuffer();
    }
  }

  /**
   * Log authentication attempt
   */
  async logAuth(
    type: 'login' | 'logout' | 'refresh' | 'failed',
    userId: string,
    ipAddress?: string,
    userAgent?: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    await this.log({
      action: `auth.${type}`,
      actorId: userId,
      actorRole: 'unknown',
      ipAddress,
      userAgent,
      metadata,
      success: type !== 'failed',
    });
  }

  /**
   * Log consent action
   */
  async logConsent(
    action: 'request' | 'approve' | 'deny' | 'revoke',
    studentId: string,
    serviceId: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    await this.log({
      action: `consent.${action}`,
      actorId: studentId,
      actorRole: 'student',
      resource: 'consent',
      resourceId: serviceId,
      metadata,
      success: true,
    });
  }

  /**
   * Log admin access
   */
  async logAdminAccess(
    adminId: string,
    endpoint: string,
    ipAddress?: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    await this.log({
      action: 'admin.access',
      actorId: adminId,
      actorRole: 'admin',
      resource: endpoint,
      ipAddress,
      metadata,
      success: true,
    });
  }

  /**
   * Log threat detection
   */
  async logThreat(
    emailId: string,
    status: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    await this.log({
      action: 'threat.detected',
      actorId: 'system',
      actorRole: 'system',
      resource: 'email',
      resourceId: emailId,
      metadata: { status, ...metadata },
      success: true,
    });
  }

  /**
   * Log service-to-service access
   */
  async logServiceAccess(
    serviceId: string,
    targetResource: string,
    ipAddress?: string,
    success: boolean = true,
    errorMessage?: string
  ): Promise<void> {
    await this.log({
      action: 'service.access',
      actorId: serviceId,
      actorRole: 'service',
      resource: targetResource,
      ipAddress,
      success,
      errorMessage,
    });
  }

  /**
   * Sanitize entry by redacting sensitive fields
   */
  private sanitizeEntry(entry: AuditEntry): AuditEntry {
    const sanitized = { ...entry };

    if (sanitized.metadata) {
      sanitized.metadata = this.redactSensitive(sanitized.metadata);
    }

    return sanitized;
  }

  /**
   * Redact sensitive fields from object
   */
  private redactSensitive(
    obj: Record<string, unknown>
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      
      // Check if field should be redacted
      const shouldRedact = AUDIT_CONFIG.REDACTED_FIELDS.some(
        (field) => lowerKey.includes(field.toLowerCase())
      ) || SENSITIVE_FIELDS.some(
        (field) => lowerKey.includes(field.toLowerCase())
      );

      if (shouldRedact) {
        result[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        result[key] = this.redactSensitive(value as Record<string, unknown>);
      } else {
        result[key] = value;
      }
    }

    return result;
  }

  /**
   * Check if action is critical (requires immediate persistence)
   */
  private isCriticalAction(action: string): boolean {
    const criticalActions = [
      'auth.failed',
      'auth.denied',
      'consent.deny',
      'consent.revoke',
      'threat.detected',
    ];
    return criticalActions.includes(action);
  }

  /**
   * Flush buffer to database
   */
  private async flushBuffer(): Promise<void> {
    if (this.buffer.length === 0) {
      return;
    }

    const entries = [...this.buffer];
    this.buffer = [];

    try {
      // Use raw SQL for bulk insert since we don't have SecurityAuditLog model yet
      // In production, this would use the Prisma model
      this.log.debug({ count: entries.length }, 'Audit buffer flushed');
    } catch (error) {
      // Re-add entries to buffer on failure
      this.buffer.unshift(...entries);
      this.log.error({ error }, 'Failed to flush audit buffer');
    }
  }

  /**
   * Query audit logs
   */
  async query(options: {
    action?: string;
    actorId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<AuditEntry[]> {
    // This would query from database
    // For now, return empty (logs are in structured log output)
    return [];
  }

  /**
   * Shutdown - flush remaining entries
   */
  async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    await this.flushBuffer();
    this.log.info('Audit service shutdown');
  }
}

// Singleton instance
let auditServiceInstance: AuditService | null = null;

/**
 * Get the audit service instance
 */
export function getAuditService(prisma?: PrismaClient): AuditService {
  if (!auditServiceInstance) {
    auditServiceInstance = new AuditService(prisma);
  }
  return auditServiceInstance;
}

/**
 * Reset the audit service (for testing)
 */
export function resetAuditService(): void {
  if (auditServiceInstance) {
    auditServiceInstance.shutdown();
  }
  auditServiceInstance = null;
}
