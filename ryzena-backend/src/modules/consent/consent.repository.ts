/**
 * R.Y.Z.E.N.A. - Consent Repository
 * 
 * Database operations for consent-related entities.
 * Handles all Prisma interactions for the consent module.
 */

import { prisma } from '../../database/client.js';
import { createLogger } from '../../shared/logger.js';
import type {
  Service,
  ConsentRequest,
  ConsentGrant,
  ConsentAuditLog,
  ConsentStatus,
  RiskCategory,
  AuditAction,
  ConsentRequestFilter,
  ConsentGrantFilter,
  PaginationOptions,
  PaginatedResult,
} from './consent.types.js';

const logger = createLogger({ module: 'consent-repository' });

// ============================================================================
// SERVICE OPERATIONS
// ============================================================================

/**
 * Find service by ID
 */
export async function findServiceById(id: string): Promise<Service | null> {
  const service = await prisma.service.findUnique({
    where: { id },
  });
  return service;
}

/**
 * Find service by name
 */
export async function findServiceByName(name: string): Promise<Service | null> {
  const service = await prisma.service.findUnique({
    where: { name },
  });
  return service;
}

/**
 * Create a new service
 */
export async function createService(data: {
  name: string;
  description?: string;
  riskCategory?: RiskCategory;
  apiKeyHash?: string;
}): Promise<Service> {
  const service = await prisma.service.create({
    data: {
      name: data.name,
      description: data.description,
      riskCategory: data.riskCategory ?? 'MEDIUM',
      apiKeyHash: data.apiKeyHash,
    },
  });
  
  logger.info({
    action: 'service_created',
    serviceId: service.id,
    serviceName: service.name,
  });
  
  return service;
}

/**
 * Update service
 */
export async function updateService(
  id: string,
  data: Partial<{
    name: string;
    description: string;
    riskCategory: RiskCategory;
    isActive: boolean;
  }>
): Promise<Service> {
  return prisma.service.update({
    where: { id },
    data,
  });
}

/**
 * List all active services
 */
export async function listActiveServices(): Promise<Service[]> {
  return prisma.service.findMany({
    where: { isActive: true },
    orderBy: { name: 'asc' },
  });
}

// ============================================================================
// CONSENT REQUEST OPERATIONS
// ============================================================================

/**
 * Create consent request
 */
export async function createConsentRequest(data: {
  studentId: string;
  serviceId: string;
  requestedFields: string[];
  purpose: string;
  requestedDuration: number;
  riskScore: number;
}): Promise<ConsentRequest> {
  const request = await prisma.consentRequest.create({
    data: {
      studentId: data.studentId,
      serviceId: data.serviceId,
      requestedFields: data.requestedFields,
      purpose: data.purpose,
      requestedDuration: data.requestedDuration,
      riskScore: data.riskScore,
      status: 'PENDING',
    },
    include: {
      service: true,
    },
  });
  
  logger.info({
    action: 'consent_request_created',
    requestId: request.id,
    studentId: data.studentId,
    serviceId: data.serviceId,
    riskScore: data.riskScore,
  });
  
  return transformConsentRequest(request);
}

/**
 * Find consent request by ID
 */
export async function findConsentRequestById(id: string): Promise<ConsentRequest | null> {
  const request = await prisma.consentRequest.findUnique({
    where: { id },
    include: { service: true },
  });
  return request ? transformConsentRequest(request) : null;
}

/**
 * Update consent request status
 */
export async function updateConsentRequestStatus(
  id: string,
  data: {
    status: ConsentStatus;
    deniedFields?: string[];
    approvedDuration?: number;
    respondedAt?: Date;
  }
): Promise<ConsentRequest> {
  const request = await prisma.consentRequest.update({
    where: { id },
    data: {
      status: data.status,
      deniedFields: data.deniedFields,
      approvedDuration: data.approvedDuration,
      respondedAt: data.respondedAt ?? new Date(),
    },
    include: { service: true },
  });
  
  logger.info({
    action: 'consent_request_updated',
    requestId: id,
    newStatus: data.status,
  });
  
  return transformConsentRequest(request);
}

/**
 * List consent requests with filters
 */
export async function listConsentRequests(
  filter: ConsentRequestFilter = {},
  pagination: PaginationOptions = {}
): Promise<PaginatedResult<ConsentRequest>> {
  const { page = 1, limit = 20, sortBy = 'createdAt', sortOrder = 'desc' } = pagination;
  const skip = (page - 1) * limit;
  
  const where: Record<string, unknown> = {};
  
  if (filter.studentId) where.studentId = filter.studentId;
  if (filter.serviceId) where.serviceId = filter.serviceId;
  if (filter.status) {
    where.status = Array.isArray(filter.status) ? { in: filter.status } : filter.status;
  }
  if (filter.minRiskScore !== undefined || filter.maxRiskScore !== undefined) {
    where.riskScore = {
      ...(filter.minRiskScore !== undefined && { gte: filter.minRiskScore }),
      ...(filter.maxRiskScore !== undefined && { lte: filter.maxRiskScore }),
    };
  }
  if (filter.createdAfter || filter.createdBefore) {
    where.createdAt = {
      ...(filter.createdAfter && { gte: filter.createdAfter }),
      ...(filter.createdBefore && { lte: filter.createdBefore }),
    };
  }
  
  const [requests, total] = await Promise.all([
    prisma.consentRequest.findMany({
      where,
      include: { service: true },
      skip,
      take: limit,
      orderBy: { [sortBy]: sortOrder },
    }),
    prisma.consentRequest.count({ where }),
  ]);
  
  return {
    data: requests.map(transformConsentRequest),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total,
    },
  };
}

/**
 * Count pending requests for a student
 */
export async function countPendingRequests(studentId: string): Promise<number> {
  return prisma.consentRequest.count({
    where: {
      studentId,
      status: 'PENDING',
    },
  });
}

// ============================================================================
// CONSENT GRANT OPERATIONS
// ============================================================================

/**
 * Create consent grant
 */
export async function createConsentGrant(data: {
  studentId: string;
  serviceId: string;
  requestId: string;
  approvedFields: string[];
  expiresAt: Date;
}): Promise<ConsentGrant> {
  const grant = await prisma.consentGrant.create({
    data: {
      studentId: data.studentId,
      serviceId: data.serviceId,
      requestId: data.requestId,
      approvedFields: data.approvedFields,
      expiresAt: data.expiresAt,
    },
    include: { service: true },
  });
  
  logger.info({
    action: 'consent_grant_created',
    grantId: grant.id,
    studentId: data.studentId,
    serviceId: data.serviceId,
    expiresAt: data.expiresAt.toISOString(),
  });
  
  return transformConsentGrant(grant);
}

/**
 * Find consent grant by ID
 */
export async function findConsentGrantById(id: string): Promise<ConsentGrant | null> {
  const grant = await prisma.consentGrant.findUnique({
    where: { id },
    include: { service: true },
  });
  return grant ? transformConsentGrant(grant) : null;
}

/**
 * Find active consent grant for student and service
 */
export async function findActiveGrant(
  studentId: string,
  serviceId: string
): Promise<ConsentGrant | null> {
  const grant = await prisma.consentGrant.findFirst({
    where: {
      studentId,
      serviceId,
      isRevoked: false,
      expiresAt: { gt: new Date() },
    },
    include: { service: true },
    orderBy: { createdAt: 'desc' },
  });
  return grant ? transformConsentGrant(grant) : null;
}

/**
 * Revoke consent grant
 */
export async function revokeConsentGrant(
  id: string,
  reason: string
): Promise<ConsentGrant> {
  const grant = await prisma.consentGrant.update({
    where: { id },
    data: {
      isRevoked: true,
      revokedAt: new Date(),
      revocationReason: reason,
    },
    include: { service: true },
  });
  
  logger.info({
    action: 'consent_grant_revoked',
    grantId: id,
    reason,
  });
  
  return transformConsentGrant(grant);
}

/**
 * List consent grants with filters
 */
export async function listConsentGrants(
  filter: ConsentGrantFilter = {},
  pagination: PaginationOptions = {}
): Promise<PaginatedResult<ConsentGrant>> {
  const { page = 1, limit = 20, sortBy = 'createdAt', sortOrder = 'desc' } = pagination;
  const skip = (page - 1) * limit;
  
  const where: Record<string, unknown> = {};
  
  if (filter.studentId) where.studentId = filter.studentId;
  if (filter.serviceId) where.serviceId = filter.serviceId;
  if (!filter.includeRevoked) where.isRevoked = false;
  if (!filter.includeExpired) where.expiresAt = { gt: new Date() };
  if (filter.expiringBefore) {
    where.expiresAt = { lte: filter.expiringBefore };
    where.isRevoked = false;
  }
  
  const [grants, total] = await Promise.all([
    prisma.consentGrant.findMany({
      where,
      include: { service: true },
      skip,
      take: limit,
      orderBy: { [sortBy]: sortOrder },
    }),
    prisma.consentGrant.count({ where }),
  ]);
  
  return {
    data: grants.map(transformConsentGrant),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total,
    },
  };
}

/**
 * Count active grants for a student
 */
export async function countActiveGrants(studentId: string): Promise<number> {
  return prisma.consentGrant.count({
    where: {
      studentId,
      isRevoked: false,
      expiresAt: { gt: new Date() },
    },
  });
}

/**
 * Find expired grants for cleanup
 */
export async function findExpiredGrants(): Promise<ConsentGrant[]> {
  const grants = await prisma.consentGrant.findMany({
    where: {
      isRevoked: false,
      expiresAt: { lte: new Date() },
    },
    include: { service: true },
  });
  return grants.map(transformConsentGrant);
}

/**
 * Mark grants as expired
 */
export async function markGrantsExpired(ids: string[]): Promise<number> {
  // Update associated requests to EXPIRED status
  await prisma.consentRequest.updateMany({
    where: {
      id: { in: ids },
    },
    data: {
      status: 'EXPIRED',
    },
  });
  
  // We don't delete grants, just mark associated requests as expired
  logger.info({
    action: 'grants_expired',
    count: ids.length,
  });
  
  return ids.length;
}

// ============================================================================
// AUDIT LOG OPERATIONS
// ============================================================================

/**
 * Create audit log entry
 */
export async function createAuditLog(data: {
  action: AuditAction;
  studentId: string;
  serviceId?: string;
  requestId?: string;
  grantId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}): Promise<ConsentAuditLog> {
  const log = await prisma.consentAuditLog.create({
    data: {
      action: data.action,
      studentId: data.studentId,
      serviceId: data.serviceId,
      requestId: data.requestId,
      grantId: data.grantId,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      metadata: data.metadata as object | undefined,
    },
  });
  
  logger.debug({
    action: 'audit_log_created',
    auditAction: data.action,
    studentId: data.studentId,
  });
  
  return transformAuditLog(log);
}

/**
 * List audit logs for a student
 */
export async function listAuditLogs(
  studentId: string,
  options: { limit?: number; actions?: AuditAction[] } = {}
): Promise<ConsentAuditLog[]> {
  const { limit = 100, actions } = options;
  
  const logs = await prisma.consentAuditLog.findMany({
    where: {
      studentId,
      ...(actions && { action: { in: actions } }),
    },
    orderBy: { createdAt: 'desc' },
    take: limit,
  });
  
  return logs.map(transformAuditLog);
}

// ============================================================================
// TRANSFORM HELPERS
// ============================================================================

/* eslint-disable @typescript-eslint/no-explicit-any */
function transformConsentRequest(data: any): ConsentRequest {
  return {
    id: data.id,
    studentId: data.studentId,
    serviceId: data.serviceId,
    requestedFields: data.requestedFields as string[],
    purpose: data.purpose,
    requestedDuration: data.requestedDuration,
    riskScore: data.riskScore,
    status: data.status as ConsentStatus,
    deniedFields: data.deniedFields as string[] | null,
    approvedDuration: data.approvedDuration,
    respondedAt: data.respondedAt,
    createdAt: data.createdAt,
    updatedAt: data.updatedAt,
    service: data.service,
  };
}

function transformConsentGrant(data: any): ConsentGrant {
  return {
    id: data.id,
    studentId: data.studentId,
    serviceId: data.serviceId,
    requestId: data.requestId,
    approvedFields: data.approvedFields as string[],
    expiresAt: data.expiresAt,
    isRevoked: data.isRevoked,
    revokedAt: data.revokedAt,
    revocationReason: data.revocationReason,
    createdAt: data.createdAt,
    updatedAt: data.updatedAt,
    service: data.service,
  };
}

function transformAuditLog(data: any): ConsentAuditLog {
  return {
    id: data.id,
    action: data.action as AuditAction,
    studentId: data.studentId,
    serviceId: data.serviceId,
    requestId: data.requestId,
    grantId: data.grantId,
    ipAddress: data.ipAddress,
    userAgent: data.userAgent,
    metadata: data.metadata as Record<string, unknown> | null,
    createdAt: data.createdAt,
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */
