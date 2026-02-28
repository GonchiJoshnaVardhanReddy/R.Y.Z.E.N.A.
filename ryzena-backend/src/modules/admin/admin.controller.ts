/**
 * R.Y.Z.E.N.A. - Phase 6: Admin Controller
 * HTTP handlers for admin analytics endpoints
 */

import { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { logger } from '../../shared/logger.js';
import { getAdminService, AdminService } from './admin.service.js';
import {
  TrendsQueryParams,
  AnomaliesQueryParams,
  DistributionQueryParams,
  AnomalySeverity,
  AnomalyType,
} from './admin.types.js';

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const trendsQuerySchema = z.object({
  weeks: z.coerce.number().min(1).max(52).optional().default(12),
  includeDepartments: z.coerce.boolean().optional().default(false),
  department: z.string().optional(),
});

const distributionQuerySchema = z.object({
  includeDepartments: z.coerce.boolean().optional().default(false),
  department: z.string().optional(),
});

const anomaliesQuerySchema = z.object({
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  type: z.enum([
    'PHISHING_SPIKE',
    'RISK_SCORE_DROP',
    'CONSENT_APPROVAL_SURGE',
    'CLICK_RATE_INCREASE',
    'DEPARTMENT_RISK_SPIKE',
  ]).optional(),
  unreviewedOnly: z.coerce.boolean().optional().default(false),
  limit: z.coerce.number().min(1).max(100).optional().default(50),
});

const reviewAnomalySchema = z.object({
  anomalyId: z.string().min(1),
});

// ============================================================================
// CONTROLLER CLASS
// ============================================================================

/**
 * Admin controller for handling HTTP requests
 */
export class AdminController {
  private service: AdminService;
  private log = logger.child({ module: 'admin-controller' });

  constructor(service?: AdminService) {
    this.service = service || getAdminService();
  }

  /**
   * GET /api/v1/admin/overview
   * Returns aggregated university-level metrics
   */
  async getOverview(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);
    const ipAddress = request.ip;

    this.log.info({ adminId }, 'Overview request');

    const result = await this.service.getOverview(adminId, ipAddress);

    if (!result.success) {
      reply.status(200).send({
        success: false,
        data: null,
        privacyNotice: result.privacyNotice,
        generatedAt: result.generatedAt,
      });
      return;
    }

    reply.status(200).send(result);
  }

  /**
   * GET /api/v1/admin/risk-distribution
   * Returns percentage distribution of risk levels
   */
  async getRiskDistribution(
    request: FastifyRequest<{ Querystring: DistributionQueryParams }>,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);
    const ipAddress = request.ip;

    // Validate query params
    const parseResult = distributionQuerySchema.safeParse(request.query);
    if (!parseResult.success) {
      reply.status(400).send({
        success: false,
        error: 'Invalid query parameters',
        details: parseResult.error.issues,
      });
      return;
    }

    const params = parseResult.data;
    this.log.info({ adminId, params }, 'Risk distribution request');

    const result = await this.service.getRiskDistribution(
      adminId,
      params,
      ipAddress
    );

    reply.status(200).send(result);
  }

  /**
   * GET /api/v1/admin/trends
   * Returns week-over-week institutional trend data
   */
  async getTrends(
    request: FastifyRequest<{ Querystring: TrendsQueryParams }>,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);
    const ipAddress = request.ip;

    // Validate query params
    const parseResult = trendsQuerySchema.safeParse(request.query);
    if (!parseResult.success) {
      reply.status(400).send({
        success: false,
        error: 'Invalid query parameters',
        details: parseResult.error.issues,
      });
      return;
    }

    const params = parseResult.data;
    this.log.info({ adminId, params }, 'Trends request');

    const result = await this.service.getTrends(adminId, params, ipAddress);

    reply.status(200).send(result);
  }

  /**
   * GET /api/v1/admin/anomalies
   * Returns anomaly reports
   */
  async getAnomalies(
    request: FastifyRequest<{ Querystring: AnomaliesQueryParams }>,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);
    const ipAddress = request.ip;

    // Validate query params
    const parseResult = anomaliesQuerySchema.safeParse(request.query);
    if (!parseResult.success) {
      reply.status(400).send({
        success: false,
        error: 'Invalid query parameters',
        details: parseResult.error.issues,
      });
      return;
    }

    const params = parseResult.data as AnomaliesQueryParams;
    this.log.info({ adminId, params }, 'Anomalies request');

    const result = await this.service.getAnomalies(adminId, params, ipAddress);

    reply.status(200).send(result);
  }

  /**
   * POST /api/v1/admin/anomalies/review
   * Mark an anomaly as reviewed
   */
  async reviewAnomaly(
    request: FastifyRequest<{ Body: { anomalyId: string } }>,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);
    const ipAddress = request.ip;

    // Validate body
    const parseResult = reviewAnomalySchema.safeParse(request.body);
    if (!parseResult.success) {
      reply.status(400).send({
        success: false,
        error: 'Invalid request body',
        details: parseResult.error.issues,
      });
      return;
    }

    const { anomalyId } = parseResult.data;
    this.log.info({ adminId, anomalyId }, 'Review anomaly request');

    const result = await this.service.reviewAnomaly(
      adminId,
      anomalyId,
      ipAddress
    );

    reply.status(200).send(result);
  }

  /**
   * GET /api/v1/admin/phishing-signals
   * Returns top phishing signals
   */
  async getTopPhishingSignals(
    request: FastifyRequest<{ Querystring: { limit?: number } }>,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);
    const limit = request.query.limit || 10;

    this.log.info({ adminId, limit }, 'Top phishing signals request');

    const signals = await this.service.getTopPhishingSignals(adminId, limit);

    reply.status(200).send({
      success: true,
      data: signals,
      generatedAt: new Date(),
    });
  }

  /**
   * GET /api/v1/admin/consent-analytics
   * Returns consent analytics summary
   */
  async getConsentAnalytics(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    const adminId = this.extractAdminId(request);

    this.log.info({ adminId }, 'Consent analytics request');

    const analytics = await this.service.getConsentAnalytics(adminId);

    reply.status(200).send({
      success: true,
      data: analytics,
      generatedAt: new Date(),
    });
  }

  /**
   * Extract admin ID from request (auth header or default)
   */
  private extractAdminId(request: FastifyRequest): string {
    // In production, this would come from JWT or session
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      // Stub: Extract from token
      return 'admin-user';
    }

    // Use custom header for testing
    const adminHeader = request.headers['x-admin-id'];
    if (typeof adminHeader === 'string') {
      return adminHeader;
    }

    return 'anonymous-admin';
  }
}

// Singleton instance
let controllerInstance: AdminController | null = null;

/**
 * Get the admin controller instance
 */
export function getAdminController(service?: AdminService): AdminController {
  if (!controllerInstance) {
    controllerInstance = new AdminController(service);
  }
  return controllerInstance;
}

/**
 * Reset the controller (for testing)
 */
export function resetAdminController(): void {
  controllerInstance = null;
}

// ============================================================================
// ROUTE HANDLERS (for direct export)
// ============================================================================

const controller = new AdminController();

export const getOverviewHandler = controller.getOverview.bind(controller);
export const getRiskDistributionHandler = controller.getRiskDistribution.bind(controller);
export const getTrendsHandler = controller.getTrends.bind(controller);
export const getAnomaliesHandler = controller.getAnomalies.bind(controller);
export const reviewAnomalyHandler = controller.reviewAnomaly.bind(controller);
export const getTopPhishingSignalsHandler = controller.getTopPhishingSignals.bind(controller);
export const getConsentAnalyticsHandler = controller.getConsentAnalytics.bind(controller);
