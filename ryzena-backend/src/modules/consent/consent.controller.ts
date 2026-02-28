/**
 * R.Y.Z.E.N.A. - Consent Controller
 * 
 * HTTP handlers for consent management endpoints.
 * Controllers handle HTTP concerns only - all business logic is in the service.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import { createLogger } from '../../shared/logger.js';
import * as consentService from './consent.service.js';
import * as accessGuard from './access.guard.js';
import {
  consentRequestSchema,
  consentResponseSchema,
  revokeGrantSchema,
  registerServiceSchema,
  checkAccessSchema,
} from './consent.validation.js';

const logger = createLogger({ module: 'consent-controller' });

// ============================================================================
// CONSENT REQUEST ENDPOINTS
// ============================================================================

/**
 * POST /api/v1/consent/request
 * Create a new consent request from a service
 */
export async function createConsentRequest(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const startTime = Date.now();
  
  try {
    const body = consentRequestSchema.parse(request.body);
    
    const result = await consentService.createConsentRequest(body, {
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'],
    });
    
    logger.info({
      action: 'consent_request_created',
      requestId: result.request.id,
      studentId: body.studentId,
      serviceId: body.serviceId,
      riskScore: result.riskAssessment.riskScore,
      durationMs: Date.now() - startTime,
    });
    
    reply.status(201).send({
      success: true,
      data: {
        request: result.request,
        riskAssessment: result.riskAssessment,
      },
    });
  } catch (error) {
    handleError(error, reply, 'create_consent_request');
  }
}

/**
 * POST /api/v1/consent/respond
 * Student responds to a consent request (approve/deny)
 */
export async function respondToConsentRequest(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const startTime = Date.now();
  
  try {
    const body = consentResponseSchema.parse(request.body);
    
    const result = await consentService.respondToConsentRequest(body, {
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'],
    });
    
    logger.info({
      action: 'consent_response_processed',
      requestId: body.requestId,
      action_type: body.action,
      grantCreated: result.grant !== null,
      durationMs: Date.now() - startTime,
    });
    
    reply.status(200).send({
      success: true,
      data: {
        request: result.request,
        grant: result.grant,
        riskEventEmitted: result.riskEvent !== null,
      },
    });
  } catch (error) {
    handleError(error, reply, 'respond_to_consent');
  }
}

// ============================================================================
// CONSENT QUERY ENDPOINTS
// ============================================================================

/**
 * GET /api/v1/consent/:studentId
 * List active consents for a student
 */
export async function getActiveConsents(
  request: FastifyRequest<{ Params: { studentId: string } }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { studentId } = request.params;
    
    const grants = await consentService.getActiveConsents(studentId);
    
    reply.status(200).send({
      success: true,
      data: {
        studentId,
        activeConsents: grants,
        count: grants.length,
      },
    });
  } catch (error) {
    handleError(error, reply, 'get_active_consents');
  }
}

/**
 * GET /api/v1/consent/:studentId/history
 * List consent request history for a student
 */
export async function getConsentHistory(
  request: FastifyRequest<{
    Params: { studentId: string };
    Querystring: { page?: string; limit?: string; status?: string };
  }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { studentId } = request.params;
    const { page, limit, status } = request.query;
    
    const result = await consentService.getConsentHistory(studentId, {
      page: page ? parseInt(page, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
      status: status as 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'REVOKED' | undefined,
    });
    
    reply.status(200).send({
      success: true,
      data: {
        studentId,
        requests: result.requests,
        pagination: result.pagination,
      },
    });
  } catch (error) {
    handleError(error, reply, 'get_consent_history');
  }
}

/**
 * GET /api/v1/consent/:studentId/pending
 * List pending consent requests for a student
 */
export async function getPendingRequests(
  request: FastifyRequest<{ Params: { studentId: string } }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { studentId } = request.params;
    
    const requests = await consentService.getPendingRequests(studentId);
    
    reply.status(200).send({
      success: true,
      data: {
        studentId,
        pendingRequests: requests,
        count: requests.length,
      },
    });
  } catch (error) {
    handleError(error, reply, 'get_pending_requests');
  }
}

// ============================================================================
// GRANT MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * POST /api/v1/consent/revoke
 * Revoke an active consent grant
 */
export async function revokeGrant(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    const body = revokeGrantSchema.parse(request.body);
    
    const result = await consentService.revokeGrant(
      body.grantId,
      body.studentId,
      body.reason,
      {
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      }
    );
    
    logger.info({
      action: 'grant_revoked',
      grantId: body.grantId,
      studentId: body.studentId,
    });
    
    reply.status(200).send({
      success: true,
      data: {
        grant: result.grant,
        riskEventEmitted: result.riskEvent !== null,
      },
    });
  } catch (error) {
    handleError(error, reply, 'revoke_grant');
  }
}

// ============================================================================
// ACCESS CHECK ENDPOINTS
// ============================================================================

/**
 * POST /api/v1/consent/check-access
 * Check if a service has access to specific fields
 */
export async function checkAccess(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    const body = checkAccessSchema.parse(request.body);
    
    const result = await accessGuard.checkMultiFieldAccess(
      body.studentId,
      body.serviceId,
      body.fields
    );
    
    reply.status(200).send({
      success: true,
      data: {
        studentId: body.studentId,
        serviceId: body.serviceId,
        allAllowed: result.allAllowed,
        allowedFields: result.allowedFields,
        deniedFields: result.deniedFields,
        results: result.results,
      },
    });
  } catch (error) {
    handleError(error, reply, 'check_access');
  }
}

// ============================================================================
// SERVICE MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * POST /api/v1/consent/services
 * Register a new service
 */
export async function registerService(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    const body = registerServiceSchema.parse(request.body);
    
    const service = await consentService.registerService(body);
    
    logger.info({
      action: 'service_registered',
      serviceId: service.id,
      serviceName: service.name,
    });
    
    reply.status(201).send({
      success: true,
      data: { service },
    });
  } catch (error) {
    handleError(error, reply, 'register_service');
  }
}

/**
 * GET /api/v1/consent/services
 * List all active services
 */
export async function listServices(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    const services = await consentService.listServices();
    
    reply.status(200).send({
      success: true,
      data: {
        services,
        count: services.length,
      },
    });
  } catch (error) {
    handleError(error, reply, 'list_services');
  }
}

/**
 * GET /api/v1/consent/services/:serviceId
 * Get service details
 */
export async function getService(
  request: FastifyRequest<{ Params: { serviceId: string } }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { serviceId } = request.params;
    
    const service = await consentService.getService(serviceId);
    
    if (!service) {
      reply.status(404).send({
        success: false,
        error: {
          code: 'SERVICE_NOT_FOUND',
          message: 'Service not found',
        },
      });
      return;
    }
    
    reply.status(200).send({
      success: true,
      data: { service },
    });
  } catch (error) {
    handleError(error, reply, 'get_service');
  }
}

// ============================================================================
// AI INTEGRATION ENDPOINTS
// ============================================================================

/**
 * GET /api/v1/consent/request/:requestId/explain
 * Get consent explanation input for AI layer
 */
export async function getConsentExplanationInput(
  request: FastifyRequest<{ Params: { requestId: string } }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { requestId } = request.params;
    
    const explanationInput = await consentService.getConsentExplanationInput(requestId);
    
    reply.status(200).send({
      success: true,
      data: { explanationInput },
    });
  } catch (error) {
    handleError(error, reply, 'get_consent_explanation_input');
  }
}

// ============================================================================
// ADMIN ENDPOINTS
// ============================================================================

/**
 * POST /api/v1/consent/admin/process-expired
 * Process expired grants (admin endpoint)
 */
export async function processExpiredGrants(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    const result = await consentService.processExpiredGrants();
    
    logger.info({
      action: 'expired_grants_processed',
      count: result.processed,
    });
    
    reply.status(200).send({
      success: true,
      data: {
        processed: result.processed,
        grants: result.grants,
      },
    });
  } catch (error) {
    handleError(error, reply, 'process_expired_grants');
  }
}

/**
 * GET /api/v1/consent/admin/risk-events
 * Get and flush pending risk events (for Phase 4 integration)
 */
export async function getRiskEvents(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    const events = consentService.flushRiskEvents();
    
    reply.status(200).send({
      success: true,
      data: {
        events,
        count: events.length,
      },
    });
  } catch (error) {
    handleError(error, reply, 'get_risk_events');
  }
}

// ============================================================================
// AUDIT ENDPOINTS
// ============================================================================

/**
 * GET /api/v1/consent/:studentId/audit
 * Get audit logs for a student
 */
export async function getAuditLogs(
  request: FastifyRequest<{
    Params: { studentId: string };
    Querystring: { limit?: string };
  }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { studentId } = request.params;
    const { limit } = request.query;
    
    const logs = await consentService.getAuditLogs(studentId, {
      limit: limit ? parseInt(limit, 10) : undefined,
    });
    
    reply.status(200).send({
      success: true,
      data: {
        studentId,
        auditLogs: logs,
        count: logs.length,
      },
    });
  } catch (error) {
    handleError(error, reply, 'get_audit_logs');
  }
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

interface AppError extends Error {
  statusCode?: number;
  code?: string;
}

function handleError(
  error: unknown,
  reply: FastifyReply,
  action: string
): void {
  const appError = error as AppError;
  
  logger.error({
    action,
    error: appError.message,
    code: appError.code,
    stack: appError.stack,
  });
  
  // Zod validation errors
  if (appError.name === 'ZodError') {
    reply.status(400).send({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid request body',
        details: error,
      },
    });
    return;
  }
  
  // Application errors
  if (appError.statusCode) {
    reply.status(appError.statusCode).send({
      success: false,
      error: {
        code: appError.code ?? 'ERROR',
        message: appError.message,
      },
    });
    return;
  }
  
  // Unknown errors
  reply.status(500).send({
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
    },
  });
}
