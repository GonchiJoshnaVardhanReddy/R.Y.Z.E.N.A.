/**
 * R.Y.Z.E.N.A. - Consent Module Types
 * 
 * Type definitions for the Consent Intelligence & Zero-Trust Data Governance Engine.
 * Phase 5 implementation.
 */

// ============================================================================
// ENUMS (mirror Prisma enums for type safety)
// ============================================================================

export type RiskCategory = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ConsentStatus = 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'REVOKED';
export type AuditAction = 
  | 'REQUEST_CREATED'
  | 'REQUEST_APPROVED'
  | 'REQUEST_DENIED'
  | 'REQUEST_MODIFIED'
  | 'GRANT_CREATED'
  | 'GRANT_EXPIRED'
  | 'GRANT_REVOKED'
  | 'ACCESS_ALLOWED'
  | 'ACCESS_DENIED'
  | 'FIELD_ACCESS_DENIED';

// ============================================================================
// CORE TYPES
// ============================================================================

/**
 * Data field that can be requested for access
 */
export interface DataField {
  /** Field identifier */
  name: string;
  /** Human-readable label */
  label: string;
  /** Field category */
  category: DataFieldCategory;
  /** Sensitivity weight (0-100) */
  sensitivityWeight: number;
  /** Description of the field */
  description?: string;
}

export type DataFieldCategory = 
  | 'CONTACT'
  | 'ACADEMIC'
  | 'FINANCIAL'
  | 'PERSONAL'
  | 'IDENTITY'
  | 'BEHAVIORAL';

/**
 * Service entity
 */
export interface Service {
  id: string;
  name: string;
  description: string | null;
  riskCategory: RiskCategory;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Consent request entity
 */
export interface ConsentRequest {
  id: string;
  studentId: string;
  serviceId: string;
  requestedFields: string[];
  purpose: string;
  requestedDuration: number;
  riskScore: number;
  status: ConsentStatus;
  deniedFields: string[] | null;
  approvedDuration: number | null;
  respondedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  service?: Service;
}

/**
 * Consent grant entity
 */
export interface ConsentGrant {
  id: string;
  studentId: string;
  serviceId: string;
  requestId: string;
  approvedFields: string[];
  expiresAt: Date;
  isRevoked: boolean;
  revokedAt: Date | null;
  revocationReason: string | null;
  createdAt: Date;
  updatedAt: Date;
  service?: Service;
}

/**
 * Audit log entry
 */
export interface ConsentAuditLog {
  id: string;
  action: AuditAction;
  studentId: string;
  serviceId: string | null;
  requestId: string | null;
  grantId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

/**
 * Create consent request payload
 */
export interface CreateConsentRequestInput {
  studentId: string;
  serviceId: string;
  requestedFields: string[];
  purpose: string;
  requestedDuration: number;
}

/**
 * Student response to consent request
 */
export interface ConsentResponseInput {
  requestId: string;
  studentId: string;
  action: 'APPROVE' | 'DENY';
  /** Modified list of approved fields (for partial approval) */
  modifiedFields?: string[];
  /** Modified duration in days */
  modifiedDuration?: number;
  /** Specific fields being denied */
  deniedFields?: string[];
}

/**
 * Result of consent request creation
 */
export interface ConsentRequestResult {
  request: ConsentRequest;
  riskAssessment: RiskAssessment;
}

/**
 * Result of consent response
 */
export interface ConsentResponseResult {
  request: ConsentRequest;
  grant: ConsentGrant | null;
  riskEvent: RiskEventEmission | null;
}

// ============================================================================
// RISK ASSESSMENT TYPES
// ============================================================================

/**
 * Risk assessment result
 */
export interface RiskAssessment {
  /** Calculated risk score (0-100) */
  riskScore: number;
  /** Risk level classification */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Breakdown of risk factors */
  factors: RiskFactor[];
  /** Recommendations */
  recommendations: string[];
}

/**
 * Individual risk factor contribution
 */
export interface RiskFactor {
  /** Factor name */
  name: string;
  /** Factor category */
  category: 'FIELD_SENSITIVITY' | 'DURATION' | 'SERVICE_RISK' | 'STUDENT_RISK' | 'PERMISSION_COUNT';
  /** Contribution to total risk (0-100) */
  contribution: number;
  /** Description */
  description: string;
}

/**
 * Risk event to emit to Phase 4 Risk Engine
 */
export interface RiskEventEmission {
  type: 'CONSENT_APPROVED' | 'CONSENT_DENIED' | 'CONSENT_REVOKED';
  studentId: string;
  impact: number;
  metadata: {
    serviceId: string;
    serviceName: string;
    requestId: string;
    riskScore: number;
    fields: string[];
  };
}

// ============================================================================
// ACCESS CONTROL TYPES
// ============================================================================

/**
 * Access check request
 */
export interface AccessCheckRequest {
  studentId: string;
  serviceId: string;
  field: string;
}

/**
 * Access check result
 */
export interface AccessCheckResult {
  allowed: boolean;
  field: string;
  reason?: string;
  grantId?: string;
  expiresAt?: Date;
}

/**
 * Bulk access check for multiple fields
 */
export interface BulkAccessCheckResult {
  studentId: string;
  serviceId: string;
  results: Record<string, AccessCheckResult>;
  allowedFields: string[];
  deniedFields: string[];
}

// ============================================================================
// AI INTEGRATION TYPES (for Phase 3)
// ============================================================================

/**
 * Structured input for AI explanation generation
 */
export interface ConsentExplanationInput {
  /** Service requesting access */
  serviceName: string;
  /** Service description */
  serviceDescription: string | null;
  /** Requested data fields */
  requestedFields: DataField[];
  /** Purpose of the request */
  purpose: string;
  /** Calculated risk score */
  riskScore: number;
  /** Risk level classification */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** Student's current risk level (from Phase 4) */
  studentRiskLevel?: string;
  /** Number of existing active permissions */
  existingPermissionCount: number;
  /** Recommended action */
  recommendedAction: 'APPROVE' | 'REVIEW' | 'DENY';
}

// ============================================================================
// QUERY TYPES
// ============================================================================

/**
 * Filter options for listing consent requests
 */
export interface ConsentRequestFilter {
  studentId?: string;
  serviceId?: string;
  status?: ConsentStatus | ConsentStatus[];
  minRiskScore?: number;
  maxRiskScore?: number;
  createdAfter?: Date;
  createdBefore?: Date;
}

/**
 * Filter options for listing consent grants
 */
export interface ConsentGrantFilter {
  studentId?: string;
  serviceId?: string;
  includeExpired?: boolean;
  includeRevoked?: boolean;
  expiringBefore?: Date;
}

/**
 * Pagination options
 */
export interface PaginationOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Paginated result
 */
export interface PaginatedResult<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasMore: boolean;
  };
}
