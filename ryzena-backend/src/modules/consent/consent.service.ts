/**
 * R.Y.Z.E.N.A. - Consent Service
 * 
 * Orchestrates consent management flows including:
 * - Creating consent requests
 * - Processing responses (approve/deny/modify)
 * - Revoking grants
 * - Managing expiration
 */

import { createLogger } from '../../shared/logger.js';
import * as repository from './consent.repository.js';
import * as engine from './consent.engine.js';
import { AppError } from '../../shared/errors.js';
import type {
  ConsentRequest,
  ConsentGrant,
  ConsentAuditLog,
  Service,
  RiskAssessment,
  CreateConsentRequestInput as ConsentRequestInput,
  ConsentResponseInput,
  ConsentStatus,
  RiskEventEmission,
} from './consent.types.js';

const logger = createLogger({ module: 'consent-service' });

// Event queue for Phase 4 Risk Engine integration
const riskEventQueue: RiskEventEmission[] = [];

// ============================================================================
// CONSENT REQUEST FLOW
// ============================================================================

/**
 * Create a new consent request from a service
 */
export async function createConsentRequest(
  input: ConsentRequestInput,
  requestMetadata?: { ipAddress?: string; userAgent?: string }
): Promise<{
  request: ConsentRequest;
  riskAssessment: RiskAssessment;
}> {
  // 1. Validate service exists
  const service = await repository.findServiceById(input.serviceId);
  if (!service || !service.isActive) {
    throw new AppError('Service not found or inactive', 404, 'SERVICE_NOT_FOUND');
  }
  
  // 2. Validate fields
  const fieldValidation = engine.validateFields(input.requestedFields);
  if (!fieldValidation.valid) {
    throw new AppError(
      `Invalid fields: ${fieldValidation.invalidFields.join(', ')}`,
      400,
      'INVALID_FIELDS'
    );
  }
  
  // 3. Validate duration
  if (input.requestedDuration < 1 || input.requestedDuration > 365) {
    throw new AppError(
      'Requested duration must be between 1 and 365 days',
      400,
      'INVALID_DURATION'
    );
  }
  
  // 4. Check for existing pending request
  const existingRequests = await repository.listConsentRequests({
    studentId: input.studentId,
    serviceId: input.serviceId,
    status: 'PENDING',
  });
  
  if (existingRequests.data.length > 0) {
    throw new AppError(
      'A pending request from this service already exists',
      409,
      'DUPLICATE_REQUEST'
    );
  }
  
  // 5. Get existing permission count for risk calculation
  const existingPermissionCount = await repository.countActiveGrants(input.studentId);
  
  // 6. Calculate risk assessment
  // TODO: Get student risk level from Phase 4 Digital Twin
  const studentRiskLevel = undefined;
  
  const riskAssessment = engine.calculateRiskAssessment(
    input.requestedFields,
    input.requestedDuration,
    service.riskCategory,
    existingPermissionCount,
    studentRiskLevel
  );
  
  // 7. Create the request
  const request = await repository.createConsentRequest({
    studentId: input.studentId,
    serviceId: input.serviceId,
    requestedFields: input.requestedFields,
    purpose: input.purpose,
    requestedDuration: input.requestedDuration,
    riskScore: riskAssessment.riskScore,
  });
  
  // 8. Create audit log
  await repository.createAuditLog({
    action: 'REQUEST_CREATED',
    studentId: input.studentId,
    serviceId: input.serviceId,
    requestId: request.id,
    ipAddress: requestMetadata?.ipAddress,
    userAgent: requestMetadata?.userAgent,
    metadata: {
      requestedFields: input.requestedFields,
      riskScore: riskAssessment.riskScore,
    },
  });
  
  logger.info({
    action: 'consent_request_created',
    requestId: request.id,
    studentId: input.studentId,
    serviceId: input.serviceId,
    riskScore: riskAssessment.riskScore,
    riskLevel: riskAssessment.riskLevel,
  });
  
  return { request, riskAssessment };
}

// ============================================================================
// CONSENT RESPONSE FLOW
// ============================================================================

/**
 * Process student response to consent request
 */
export async function respondToConsentRequest(
  input: ConsentResponseInput,
  requestMetadata?: { ipAddress?: string; userAgent?: string }
): Promise<{
  request: ConsentRequest;
  grant: ConsentGrant | null;
  riskEvent: RiskEventEmission | null;
}> {
  // 1. Get and validate request
  const request = await repository.findConsentRequestById(input.requestId);
  if (!request) {
    throw new AppError('Consent request not found', 404, 'REQUEST_NOT_FOUND');
  }
  
  // 2. Validate request is pending
  if (request.status !== 'PENDING') {
    throw new AppError(
      `Request has already been ${request.status.toLowerCase()}`,
      400,
      'REQUEST_ALREADY_PROCESSED'
    );
  }
  
  // 3. Validate student owns the request
  if (request.studentId !== input.studentId) {
    throw new AppError(
      'Unauthorized to respond to this request',
      403,
      'UNAUTHORIZED'
    );
  }
  
  // 4. Get service for risk event
  const service = await repository.findServiceById(request.serviceId);
  if (!service) {
    throw new AppError('Service not found', 404, 'SERVICE_NOT_FOUND');
  }
  
  let updatedRequest: ConsentRequest;
  let grant: ConsentGrant | null = null;
  let riskEvent: RiskEventEmission | null = null;
  
  switch (input.action) {
    case 'APPROVE':
      ({ request: updatedRequest, grant } = await processApproval(
        request,
        input.modifiedFields,
        input.modifiedDuration
      ));
      riskEvent = engine.createRiskEvent('CONSENT_APPROVED', updatedRequest, service);
      break;
      
    case 'DENY':
      updatedRequest = await processDenial(request, input.deniedFields);
      riskEvent = engine.createRiskEvent('CONSENT_DENIED', updatedRequest, service);
      break;
      
    default:
      throw new AppError('Invalid action', 400, 'INVALID_ACTION');
  }
  
  // 5. Create audit log
  await repository.createAuditLog({
    action: input.action === 'APPROVE' ? 'REQUEST_APPROVED' : 'REQUEST_DENIED',
    studentId: input.studentId,
    serviceId: request.serviceId,
    requestId: request.id,
    grantId: grant?.id,
    ipAddress: requestMetadata?.ipAddress,
    userAgent: requestMetadata?.userAgent,
    metadata: {
      action: input.action,
      modifiedFields: input.modifiedFields,
      modifiedDuration: input.modifiedDuration,
    },
  });
  
  // 6. Queue risk event for Phase 4
  if (riskEvent) {
    queueRiskEvent(riskEvent);
  }
  
  logger.info({
    action: 'consent_response_processed',
    requestId: request.id,
    studentId: input.studentId,
    responseAction: input.action,
    grantId: grant?.id,
  });
  
  return { request: updatedRequest, grant, riskEvent };
}

/**
 * Process approval - create grant
 */
async function processApproval(
  request: ConsentRequest,
  modifiedFields?: string[],
  modifiedDuration?: number
): Promise<{ request: ConsentRequest; grant: ConsentGrant }> {
  // Determine final approved fields and duration
  const approvedFields = modifiedFields ?? request.requestedFields;
  const approvedDuration = modifiedDuration ?? request.requestedDuration;
  
  // Calculate expiration date
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + approvedDuration);
  
  // Update request status
  const deniedFields = modifiedFields
    ? request.requestedFields.filter(f => !modifiedFields.includes(f))
    : undefined;
  
  const updatedRequest = await repository.updateConsentRequestStatus(request.id, {
    status: 'APPROVED',
    deniedFields,
    approvedDuration,
    respondedAt: new Date(),
  });
  
  // Create grant
  const grant = await repository.createConsentGrant({
    studentId: request.studentId,
    serviceId: request.serviceId,
    requestId: request.id,
    approvedFields,
    expiresAt,
  });
  
  return { request: updatedRequest, grant };
}

/**
 * Process denial
 */
async function processDenial(
  request: ConsentRequest,
  deniedFields?: string[]
): Promise<ConsentRequest> {
  return repository.updateConsentRequestStatus(request.id, {
    status: 'DENIED',
    deniedFields: deniedFields ?? request.requestedFields,
    respondedAt: new Date(),
  });
}

// ============================================================================
// GRANT MANAGEMENT
// ============================================================================

/**
 * Revoke an active consent grant
 */
export async function revokeGrant(
  grantId: string,
  studentId: string,
  reason: string,
  requestMetadata?: { ipAddress?: string; userAgent?: string }
): Promise<{
  grant: ConsentGrant;
  riskEvent: RiskEventEmission | null;
}> {
  // 1. Get and validate grant
  const grant = await repository.findConsentGrantById(grantId);
  if (!grant) {
    throw new AppError('Grant not found', 404, 'GRANT_NOT_FOUND');
  }
  
  // 2. Validate student owns the grant
  if (grant.studentId !== studentId) {
    throw new AppError('Unauthorized to revoke this grant', 403, 'UNAUTHORIZED');
  }
  
  // 3. Check if already revoked
  if (grant.isRevoked) {
    throw new AppError('Grant is already revoked', 400, 'ALREADY_REVOKED');
  }
  
  // 4. Revoke the grant
  const revokedGrant = await repository.revokeConsentGrant(grantId, reason);
  
  // 5. Get service and request for risk event
  const service = await repository.findServiceById(grant.serviceId);
  const request = await repository.findConsentRequestById(grant.requestId);
  
  let riskEvent: RiskEventEmission | null = null;
  if (service && request) {
    riskEvent = engine.createRiskEvent('CONSENT_REVOKED', request, service);
    queueRiskEvent(riskEvent);
  }
  
  // 6. Create audit log
  await repository.createAuditLog({
    action: 'GRANT_REVOKED',
    studentId,
    serviceId: grant.serviceId,
    grantId,
    ipAddress: requestMetadata?.ipAddress,
    userAgent: requestMetadata?.userAgent,
    metadata: { reason },
  });
  
  logger.info({
    action: 'grant_revoked',
    grantId,
    studentId,
    reason,
  });
  
  return { grant: revokedGrant, riskEvent };
}

// ============================================================================
// QUERY OPERATIONS
// ============================================================================

/**
 * Get active consents for a student
 */
export async function getActiveConsents(
  studentId: string
): Promise<ConsentGrant[]> {
  const result = await repository.listConsentGrants({
    studentId,
    includeRevoked: false,
    includeExpired: false,
  });
  return result.data;
}

/**
 * Get consent history for a student
 */
export async function getConsentHistory(
  studentId: string,
  options?: {
    status?: ConsentStatus | ConsentStatus[];
    page?: number;
    limit?: number;
  }
): Promise<{
  requests: ConsentRequest[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasMore: boolean;
  };
}> {
  const result = await repository.listConsentRequests(
    { studentId, status: options?.status },
    { page: options?.page, limit: options?.limit }
  );
  return {
    requests: result.data,
    pagination: result.pagination,
  };
}

/**
 * Get pending requests for a student
 */
export async function getPendingRequests(
  studentId: string
): Promise<ConsentRequest[]> {
  const result = await repository.listConsentRequests({
    studentId,
    status: 'PENDING',
  });
  return result.data;
}

/**
 * Get consent explanation input for AI
 */
export async function getConsentExplanationInput(requestId: string) {
  const request = await repository.findConsentRequestById(requestId);
  if (!request) {
    throw new AppError('Request not found', 404, 'REQUEST_NOT_FOUND');
  }
  
  const service = await repository.findServiceById(request.serviceId);
  if (!service) {
    throw new AppError('Service not found', 404, 'SERVICE_NOT_FOUND');
  }
  
  const existingPermissionCount = await repository.countActiveGrants(request.studentId);
  
  // Recalculate risk assessment
  const riskAssessment = engine.calculateRiskAssessment(
    request.requestedFields,
    request.requestedDuration,
    service.riskCategory,
    existingPermissionCount
  );
  
  return engine.buildConsentExplanationInput(
    request,
    service,
    riskAssessment,
    existingPermissionCount
  );
}

// ============================================================================
// SERVICE MANAGEMENT
// ============================================================================

/**
 * Register a new service
 */
export async function registerService(data: {
  name: string;
  description?: string;
  riskCategory?: string;
}): Promise<Service> {
  // Check for duplicate name
  const existing = await repository.findServiceByName(data.name);
  if (existing) {
    throw new AppError('Service with this name already exists', 409, 'DUPLICATE_SERVICE');
  }
  
  return repository.createService({
    name: data.name,
    description: data.description,
    riskCategory: (data.riskCategory as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') ?? 'MEDIUM',
  });
}

/**
 * Get service by ID
 */
export async function getService(id: string): Promise<Service | null> {
  return repository.findServiceById(id);
}

/**
 * List all active services
 */
export async function listServices(): Promise<Service[]> {
  return repository.listActiveServices();
}

// ============================================================================
// EXPIRATION MANAGEMENT
// ============================================================================

/**
 * Process expired grants (for background job)
 */
export async function processExpiredGrants(): Promise<{
  processed: number;
  grants: ConsentGrant[];
}> {
  const expiredGrants = await repository.findExpiredGrants();
  
  if (expiredGrants.length === 0) {
    return { processed: 0, grants: [] };
  }
  
  // Create audit logs for each expired grant
  for (const grant of expiredGrants) {
    await repository.createAuditLog({
      action: 'GRANT_EXPIRED',
      studentId: grant.studentId,
      serviceId: grant.serviceId,
      grantId: grant.id,
      metadata: {
        expiredAt: grant.expiresAt.toISOString(),
      },
    });
  }
  
  // Mark associated requests as expired
  await repository.markGrantsExpired(expiredGrants.map(g => g.requestId));
  
  logger.info({
    action: 'expired_grants_processed',
    count: expiredGrants.length,
  });
  
  return { processed: expiredGrants.length, grants: expiredGrants };
}

// ============================================================================
// RISK EVENT QUEUE (Phase 4 Integration)
// ============================================================================

/**
 * Queue a risk event for Phase 4
 */
function queueRiskEvent(event: RiskEventEmission): void {
  riskEventQueue.push(event);
  logger.debug({
    action: 'risk_event_queued',
    type: event.type,
    studentId: event.studentId,
    impact: event.impact,
  });
}

/**
 * Get and clear pending risk events
 */
export function flushRiskEvents(): RiskEventEmission[] {
  const events = [...riskEventQueue];
  riskEventQueue.length = 0;
  return events;
}

/**
 * Get pending risk event count
 */
export function getRiskEventCount(): number {
  return riskEventQueue.length;
}

// ============================================================================
// AUDIT OPERATIONS
// ============================================================================

/**
 * Get audit logs for a student
 */
export async function getAuditLogs(
  studentId: string,
  options?: { limit?: number }
): Promise<ConsentAuditLog[]> {
  return repository.listAuditLogs(studentId, options);
}
