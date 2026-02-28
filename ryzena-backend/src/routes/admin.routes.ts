/**
 * R.Y.Z.E.N.A. - Phase 6: Admin Routes
 * Fastify route definitions for admin analytics endpoints
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  getOverviewHandler,
  getRiskDistributionHandler,
  getTrendsHandler,
  getAnomaliesHandler,
  reviewAnomalyHandler,
  getTopPhishingSignalsHandler,
  getConsentAnalyticsHandler,
} from '../modules/admin/admin.controller.js';

/**
 * Admin role verification middleware
 */
async function adminAuthHook(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  // Check for admin authorization
  const authHeader = request.headers.authorization;
  const adminHeader = request.headers['x-admin-id'];

  // In production, this would verify JWT token and admin role
  // For now, we just check that some form of auth is provided
  if (!authHeader && !adminHeader) {
    reply.status(401).send({
      success: false,
      error: 'Unauthorized',
      message: 'Admin authentication required',
    });
    return;
  }

  // Stub: Verify admin role
  // In production: decode JWT, check role claim
}

/**
 * Register admin analytics routes
 */
export async function adminRoutes(fastify: FastifyInstance): Promise<void> {
  // Apply admin auth hook to all routes in this plugin
  fastify.addHook('preHandler', adminAuthHook);

  // GET /api/v1/admin/overview
  // Returns aggregated university-level metrics
  fastify.get(
    '/overview',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'object', nullable: true },
              privacyNotice: { type: 'string', nullable: true },
              generatedAt: { type: 'string' },
            },
          },
        },
      },
    },
    getOverviewHandler
  );

  // GET /api/v1/admin/risk-distribution
  // Returns percentage distribution of LOW / MEDIUM / HIGH risk levels
  fastify.get(
    '/risk-distribution',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            includeDepartments: { type: 'boolean', default: false },
            department: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'object', nullable: true },
              privacyNotice: { type: 'string', nullable: true },
              generatedAt: { type: 'string' },
            },
          },
        },
      },
    },
    getRiskDistributionHandler
  );

  // GET /api/v1/admin/trends
  // Returns week-over-week institutional trend data
  fastify.get(
    '/trends',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            weeks: { type: 'integer', minimum: 1, maximum: 52, default: 12 },
            includeDepartments: { type: 'boolean', default: false },
            department: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'object', nullable: true },
              privacyNotice: { type: 'string', nullable: true },
              generatedAt: { type: 'string' },
            },
          },
        },
      },
    },
    getTrendsHandler
  );

  // GET /api/v1/admin/anomalies
  // Returns anomaly reports
  fastify.get(
    '/anomalies',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            severity: {
              type: 'string',
              enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            },
            type: {
              type: 'string',
              enum: [
                'PHISHING_SPIKE',
                'RISK_SCORE_DROP',
                'CONSENT_APPROVAL_SURGE',
                'CLICK_RATE_INCREASE',
                'DEPARTMENT_RISK_SPIKE',
              ],
            },
            unreviewedOnly: { type: 'boolean', default: false },
            limit: { type: 'integer', minimum: 1, maximum: 100, default: 50 },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'object', nullable: true },
              generatedAt: { type: 'string' },
            },
          },
        },
      },
    },
    getAnomaliesHandler
  );

  // POST /api/v1/admin/anomalies/review
  // Mark an anomaly as reviewed
  fastify.post(
    '/anomalies/review',
    {
      schema: {
        body: {
          type: 'object',
          required: ['anomalyId'],
          properties: {
            anomalyId: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
            },
          },
        },
      },
    },
    reviewAnomalyHandler
  );

  // GET /api/v1/admin/phishing-signals
  // Returns top phishing signals
  fastify.get(
    '/phishing-signals',
    {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            limit: { type: 'integer', minimum: 1, maximum: 50, default: 10 },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'array' },
              generatedAt: { type: 'string' },
            },
          },
        },
      },
    },
    getTopPhishingSignalsHandler
  );

  // GET /api/v1/admin/consent-analytics
  // Returns consent analytics summary
  fastify.get(
    '/consent-analytics',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'object' },
              generatedAt: { type: 'string' },
            },
          },
        },
      },
    },
    getConsentAnalyticsHandler
  );
}

export default adminRoutes;
