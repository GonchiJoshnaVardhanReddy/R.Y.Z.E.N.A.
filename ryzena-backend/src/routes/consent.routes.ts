/**
 * R.Y.Z.E.N.A. - Consent Routes
 * 
 * Route definitions for consent management endpoints.
 */

import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import * as controller from '../modules/consent/consent.controller.js';

/**
 * Register consent routes
 */
export async function consentRoutes(
  fastify: FastifyInstance,
  _options: FastifyPluginOptions
): Promise<void> {
  // ============================================================================
  // CONSENT REQUEST ENDPOINTS
  // ============================================================================
  
  /**
   * POST /api/v1/consent/request
   * Create a new consent request from a service
   */
  fastify.post('/request', {
    schema: {
      body: {
        type: 'object',
        required: ['studentId', 'serviceId', 'requestedFields', 'purpose', 'requestedDuration'],
        properties: {
          studentId: { type: 'string' },
          serviceId: { type: 'string', format: 'uuid' },
          requestedFields: { type: 'array', items: { type: 'string' } },
          purpose: { type: 'string' },
          requestedDuration: { type: 'number' },
        },
      },
    },
    handler: controller.createConsentRequest,
  });
  
  /**
   * POST /api/v1/consent/respond
   * Student responds to a consent request
   */
  fastify.post('/respond', {
    schema: {
      body: {
        type: 'object',
        required: ['requestId', 'studentId', 'action'],
        properties: {
          requestId: { type: 'string', format: 'uuid' },
          studentId: { type: 'string' },
          action: { type: 'string', enum: ['APPROVE', 'DENY'] },
          modifiedFields: { type: 'array', items: { type: 'string' } },
          modifiedDuration: { type: 'number' },
          deniedFields: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    handler: controller.respondToConsentRequest,
  });
  
  // ============================================================================
  // CONSENT QUERY ENDPOINTS
  // ============================================================================
  
  /**
   * GET /api/v1/consent/:studentId
   * List active consents for a student
   */
  fastify.get('/:studentId', {
    schema: {
      params: {
        type: 'object',
        required: ['studentId'],
        properties: {
          studentId: { type: 'string' },
        },
      },
    },
    handler: controller.getActiveConsents,
  });
  
  /**
   * GET /api/v1/consent/:studentId/history
   * List consent request history for a student
   */
  fastify.get('/:studentId/history', {
    schema: {
      params: {
        type: 'object',
        required: ['studentId'],
        properties: {
          studentId: { type: 'string' },
        },
      },
      querystring: {
        type: 'object',
        properties: {
          page: { type: 'string' },
          limit: { type: 'string' },
          status: { type: 'string', enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED'] },
        },
      },
    },
    handler: controller.getConsentHistory,
  });
  
  /**
   * GET /api/v1/consent/:studentId/pending
   * List pending consent requests for a student
   */
  fastify.get('/:studentId/pending', {
    schema: {
      params: {
        type: 'object',
        required: ['studentId'],
        properties: {
          studentId: { type: 'string' },
        },
      },
    },
    handler: controller.getPendingRequests,
  });
  
  /**
   * GET /api/v1/consent/:studentId/audit
   * Get audit logs for a student
   */
  fastify.get('/:studentId/audit', {
    schema: {
      params: {
        type: 'object',
        required: ['studentId'],
        properties: {
          studentId: { type: 'string' },
        },
      },
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'string' },
        },
      },
    },
    handler: controller.getAuditLogs,
  });
  
  // ============================================================================
  // GRANT MANAGEMENT ENDPOINTS
  // ============================================================================
  
  /**
   * POST /api/v1/consent/revoke
   * Revoke an active consent grant
   */
  fastify.post('/revoke', {
    schema: {
      body: {
        type: 'object',
        required: ['grantId', 'studentId', 'reason'],
        properties: {
          grantId: { type: 'string', format: 'uuid' },
          studentId: { type: 'string' },
          reason: { type: 'string' },
        },
      },
    },
    handler: controller.revokeGrant,
  });
  
  // ============================================================================
  // ACCESS CHECK ENDPOINTS
  // ============================================================================
  
  /**
   * POST /api/v1/consent/check-access
   * Check if a service has access to specific fields
   */
  fastify.post('/check-access', {
    schema: {
      body: {
        type: 'object',
        required: ['studentId', 'serviceId', 'fields'],
        properties: {
          studentId: { type: 'string' },
          serviceId: { type: 'string', format: 'uuid' },
          fields: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    handler: controller.checkAccess,
  });
  
  // ============================================================================
  // SERVICE MANAGEMENT ENDPOINTS
  // ============================================================================
  
  /**
   * POST /api/v1/consent/services
   * Register a new service
   */
  fastify.post('/services', {
    schema: {
      body: {
        type: 'object',
        required: ['name'],
        properties: {
          name: { type: 'string' },
          description: { type: 'string' },
          riskCategory: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
        },
      },
    },
    handler: controller.registerService,
  });
  
  /**
   * GET /api/v1/consent/services
   * List all active services
   */
  fastify.get('/services', controller.listServices);
  
  /**
   * GET /api/v1/consent/services/:serviceId
   * Get service details
   */
  fastify.get('/services/:serviceId', {
    schema: {
      params: {
        type: 'object',
        required: ['serviceId'],
        properties: {
          serviceId: { type: 'string', format: 'uuid' },
        },
      },
    },
    handler: controller.getService,
  });
  
  // ============================================================================
  // AI INTEGRATION ENDPOINTS
  // ============================================================================
  
  /**
   * GET /api/v1/consent/request/:requestId/explain
   * Get consent explanation input for AI layer
   */
  fastify.get('/request/:requestId/explain', {
    schema: {
      params: {
        type: 'object',
        required: ['requestId'],
        properties: {
          requestId: { type: 'string', format: 'uuid' },
        },
      },
    },
    handler: controller.getConsentExplanationInput,
  });
  
  // ============================================================================
  // ADMIN ENDPOINTS
  // ============================================================================
  
  /**
   * POST /api/v1/consent/admin/process-expired
   * Process expired grants (admin endpoint)
   */
  fastify.post('/admin/process-expired', controller.processExpiredGrants);
  
  /**
   * GET /api/v1/consent/admin/risk-events
   * Get and flush pending risk events
   */
  fastify.get('/admin/risk-events', controller.getRiskEvents);
}
