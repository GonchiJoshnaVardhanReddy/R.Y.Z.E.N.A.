/**
 * R.Y.Z.E.N.A. - Resilient Youth Zero-Trust Engine for Networked Awareness
 * Phase 7: Security Hardening and Production Readiness
 * 
 * Main application entry point.
 * Configures Fastify server with security middleware and routes.
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { config } from './shared/config.js';
import { logger } from './shared/logger.js';
import { isRyzenaError } from './shared/errors.js';
import { emailRoutes } from './routes/email.routes.js';
import { aiRoutes } from './routes/ai.routes.js';
import { consentRoutes } from './routes/consent.routes.js';
import { adminRoutes } from './routes/admin.routes.js';
import { initializeRAG } from './modules/rag/rag.service.js';
import { connectDatabase, disconnectDatabase, checkDatabaseHealth } from './database/client.js';
import { getAuditService } from './security/audit.service.js';

/**
 * Create and configure Fastify application
 */
async function buildApp() {
  const app = Fastify({
    logger: false, // We use our own pino logger
    trustProxy: true,
    requestIdHeader: 'x-request-id',
    requestIdLogLabel: 'requestId',
  });

  // Register security plugins
  
  // CORS configuration
  await app.register(cors, {
    origin: config.server.env === 'production' 
      ? false // Disable in production, configure as needed
      : true, // Allow all in development
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    credentials: true,
  });

  // Security headers
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
      },
    },
    crossOriginEmbedderPolicy: false,
  });

  // Rate limiting
  await app.register(rateLimit, {
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.windowMs,
    errorResponseBuilder: (_request, context) => ({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Rate limit exceeded. Try again in ${Math.ceil(context.ttl / 1000)} seconds.`,
      },
      meta: {
        timestamp: new Date().toISOString(),
        retryAfter: Math.ceil(context.ttl / 1000),
      },
    }),
  });

  // Request logging hook
  app.addHook('onRequest', async (request) => {
    logger.debug({
      action: 'request_received',
      method: request.method,
      url: request.url,
      ip: request.ip,
      requestId: request.id,
    });
  });

  // Response logging hook
  app.addHook('onResponse', async (request, reply) => {
    logger.info({
      action: 'request_completed',
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime: reply.elapsedTime,
      requestId: request.id,
    });
  });

  // Global error handler
  app.setErrorHandler((error: Error, request, reply) => {
    logger.error({
      action: 'unhandled_error',
      method: request.method,
      url: request.url,
      error: error.message,
      stack: error.stack,
      requestId: request.id,
    });

    if (isRyzenaError(error)) {
      return reply.status(error.statusCode).send({
        success: false,
        error: {
          code: error.code,
          message: error.message,
        },
        meta: {
          timestamp: new Date().toISOString(),
          requestId: request.id,
        },
      });
    }

    // Fastify validation error
    if ('validation' in error && error.validation) {
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request validation failed',
          details: error.validation as unknown,
        },
        meta: {
          timestamp: new Date().toISOString(),
          requestId: request.id,
        },
      });
    }

    // Generic error
    return reply.status(500).send({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: config.server.env === 'production' 
          ? 'An unexpected error occurred' 
          : (error as Error).message,
      },
      meta: {
        timestamp: new Date().toISOString(),
        requestId: request.id,
      },
    });
  });

  // Not found handler
  app.setNotFoundHandler((request, reply) => {
    return reply.status(404).send({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: `Route ${request.method} ${request.url} not found`,
      },
      meta: {
        timestamp: new Date().toISOString(),
        requestId: request.id,
      },
    });
  });

  // Register routes
  
  // Root health check
  app.get('/', async (_request, reply) => {
    return reply.send({
      service: 'R.Y.Z.E.N.A.',
      name: 'Resilient Youth Zero-Trust Engine for Networked Awareness',
      version: '7.0.0',
      phase: 'Phase 7: Security Hardening and Production Readiness',
      status: 'operational',
      capabilities: [
        'Email Security Analysis',
        'Phishing Detection',
        'AI-Powered Explanations',
        'Educational Content Generation',
        'Consent Intelligence',
        'Zero-Trust Data Governance',
        'Field-Level Access Control',
        'Privacy-Preserving Analytics',
        'Anomaly Detection',
        'JWT Authentication',
        'Role-Based Access Control',
        'Rate Limiting',
        'Audit Logging',
        'Data Encryption',
      ],
      timestamp: new Date().toISOString(),
    });
  });

  // API v1 health check
  app.get('/api/v1/health', async (_request, reply) => {
    const dbHealthy = await checkDatabaseHealth();
    return reply.send({
      status: dbHealthy ? 'healthy' : 'degraded',
      service: 'ryzena-threat-engine',
      version: '7.0.0',
      environment: config.server.env,
      ollamaEnabled: config.ollama.enabled,
      databaseConnected: dbHealthy,
      securityHardened: true,
      timestamp: new Date().toISOString(),
    });
  });

  // Email routes
  await app.register(emailRoutes, { prefix: '/api/v1/email' });
  
  // AI routes
  await app.register(aiRoutes, { prefix: '/api/v1/ai' });
  
  // Consent routes (Phase 5)
  await app.register(consentRoutes, { prefix: '/api/v1/consent' });
  
  // Admin routes (Phase 6)
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });

  return app;
}

/**
 * Start the server
 */
async function start() {
  try {
    // Connect to database
    await connectDatabase();
    
    const app = await buildApp();
    
    // Initialize RAG system in background
    initializeRAG().catch(err => {
      logger.warn({
        action: 'rag_init_background_failed',
        error: err instanceof Error ? err.message : String(err),
      });
    });

    await app.listen({
      port: config.server.port,
      host: config.server.host,
    });

    logger.info({
      action: 'server_started',
      message: `R.Y.Z.E.N.A. Phase 7 server running`,
      host: config.server.host,
      port: config.server.port,
      environment: config.server.env,
      ollamaEnabled: config.ollama.enabled,
      securityFeatures: [
        'JWT Authentication',
        'RBAC',
        'Rate Limiting',
        'Audit Logging',
        'Encryption',
        'Security Headers',
      ],
      endpoints: [
        `http://${config.server.host}:${config.server.port}/`,
        `http://${config.server.host}:${config.server.port}/api/v1/health`,
        `http://${config.server.host}:${config.server.port}/api/v1/email/webhook`,
        `http://${config.server.host}:${config.server.port}/api/v1/ai/explain`,
        `http://${config.server.host}:${config.server.port}/api/v1/consent/request`,
        `http://${config.server.host}:${config.server.port}/api/v1/admin/overview`,
        `http://${config.server.host}:${config.server.port}/api/v1/admin/trends`,
        `http://${config.server.host}:${config.server.port}/api/v1/admin/anomalies`,
      ],
    });

    // Graceful shutdown
    const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
    
    for (const signal of signals) {
      process.on(signal, async () => {
        logger.info({ action: 'shutdown_initiated', signal });
        
        try {
          // Shutdown audit service
          const auditService = getAuditService();
          await auditService.shutdown();
          
          await app.close();
          await disconnectDatabase();
          logger.info({ action: 'shutdown_complete' });
          process.exit(0);
        } catch (error) {
          logger.error({ 
            action: 'shutdown_error', 
            error: error instanceof Error ? error.message : String(error) 
          });
          process.exit(1);
        }
      });
    }
  } catch (error) {
    logger.fatal({
      action: 'startup_failed',
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }
}

// Export for testing
export { buildApp };

// Start server
start();
