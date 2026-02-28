/**
 * R.Y.Z.E.N.A. - Phase 7: Input Validation Middleware
 * Centralized request validation and sanitization
 */

import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify';
import { ZodSchema, ZodError } from 'zod';
import { logger } from '../shared/logger.js';
import { REQUEST_LIMITS } from './security.config.js';

// ============================================================================
// TYPES
// ============================================================================

interface ValidationOptions {
  /** Max body size in bytes */
  maxBodySize?: number;
  /** Request timeout in ms */
  timeout?: number;
  /** Allowed content types */
  allowedContentTypes?: string[];
  /** Strip unknown fields */
  stripUnknown?: boolean;
}

// ============================================================================
// CONTENT TYPE VALIDATION
// ============================================================================

const ALLOWED_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
];

/**
 * Validate content type
 */
function isValidContentType(contentType: string | undefined): boolean {
  if (!contentType) {
    return true; // GET requests may not have content type
  }
  return ALLOWED_CONTENT_TYPES.some((allowed) =>
    contentType.toLowerCase().startsWith(allowed)
  );
}

// ============================================================================
// INPUT SANITIZATION
// ============================================================================

/**
 * Sanitize string input
 */
export function sanitizeString(input: string): string {
  return input
    // Remove null bytes
    .replace(/\0/g, '')
    // Normalize whitespace
    .replace(/[\r\n]+/g, '\n')
    // Trim excessive whitespace
    .trim();
}

/**
 * Check for common injection patterns
 */
export function hasInjectionPattern(input: string): boolean {
  const patterns = [
    // SQL injection
    /(\b(union|select|insert|update|delete|drop|truncate)\b)/i,
    // NoSQL injection
    /(\$where|\$gt|\$lt|\$ne|\$regex)/i,
    // Command injection
    /([;&|`$]|(\|\|)|(&&))/,
    // Path traversal
    /(\.\.\/|\.\.\\)/,
  ];

  return patterns.some((pattern) => pattern.test(input));
}

/**
 * Deep sanitize object
 */
export function sanitizeObject(obj: unknown): unknown {
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      // Skip prototype pollution attempts
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      result[sanitizeString(key)] = sanitizeObject(value);
    }
    return result;
  }
  return obj;
}

// ============================================================================
// VALIDATION MIDDLEWARE
// ============================================================================

/**
 * Create Zod validation middleware
 */
export function validateBody<T>(schema: ZodSchema<T>) {
  return async function (request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const parsed = schema.parse(request.body);
      // Replace body with parsed/validated data
      request.body = parsed;
    } catch (error) {
      if (error instanceof ZodError) {
        reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request body',
            details: error.errors.map((e) => ({
              path: e.path.join('.'),
              message: e.message,
            })),
          },
          timestamp: new Date().toISOString(),
        });
        return;
      }
      throw error;
    }
  };
}

/**
 * Create query params validation middleware
 */
export function validateQuery<T>(schema: ZodSchema<T>) {
  return async function (request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const parsed = schema.parse(request.query);
      request.query = parsed as typeof request.query;
    } catch (error) {
      if (error instanceof ZodError) {
        reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid query parameters',
            details: error.errors.map((e) => ({
              path: e.path.join('.'),
              message: e.message,
            })),
          },
          timestamp: new Date().toISOString(),
        });
        return;
      }
      throw error;
    }
  };
}

/**
 * Create params validation middleware
 */
export function validateParams<T>(schema: ZodSchema<T>) {
  return async function (request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const parsed = schema.parse(request.params);
      request.params = parsed as typeof request.params;
    } catch (error) {
      if (error instanceof ZodError) {
        reply.status(400).send({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid path parameters',
            details: error.errors.map((e) => ({
              path: e.path.join('.'),
              message: e.message,
            })),
          },
          timestamp: new Date().toISOString(),
        });
        return;
      }
      throw error;
    }
  };
}

// ============================================================================
// GLOBAL VALIDATION MIDDLEWARE
// ============================================================================

const log = logger.child({ module: 'validation-middleware' });

/**
 * Global validation middleware
 */
export async function globalValidationMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  // Check content type for POST/PUT/PATCH
  if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
    const contentType = request.headers['content-type'];
    if (contentType && !isValidContentType(contentType)) {
      log.warn({
        ip: request.ip,
        contentType,
        url: request.url,
      }, 'Invalid content type');

      reply.status(415).send({
        success: false,
        error: {
          code: 'UNSUPPORTED_MEDIA_TYPE',
          message: 'Invalid content type',
        },
        timestamp: new Date().toISOString(),
      });
      return;
    }
  }

  // Check body size
  const contentLength = parseInt(request.headers['content-length'] || '0', 10);
  if (contentLength > REQUEST_LIMITS.MAX_BODY_SIZE) {
    log.warn({
      ip: request.ip,
      contentLength,
      maxAllowed: REQUEST_LIMITS.MAX_BODY_SIZE,
    }, 'Request body too large');

    reply.status(413).send({
      success: false,
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message: `Request body exceeds maximum size of ${REQUEST_LIMITS.MAX_BODY_SIZE} bytes`,
      },
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // Sanitize body
  if (request.body && typeof request.body === 'object') {
    request.body = sanitizeObject(request.body);
  }

  // Check for injection patterns in strings
  const bodyStr = JSON.stringify(request.body || {});
  if (hasInjectionPattern(bodyStr)) {
    log.warn({
      ip: request.ip,
      url: request.url,
    }, 'Potential injection detected');

    // Don't block, but flag for monitoring
    request.headers['x-security-flag'] = 'injection-pattern';
  }
}

// ============================================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================================

/**
 * Add security headers
 */
export async function securityHeadersMiddleware(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  // Prevent MIME type sniffing
  reply.header('X-Content-Type-Options', 'nosniff');

  // XSS protection
  reply.header('X-XSS-Protection', '1; mode=block');

  // Frame protection
  reply.header('X-Frame-Options', 'DENY');

  // HSTS (only in production)
  if (process.env.NODE_ENV === 'production') {
    reply.header(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains'
    );
  }

  // Content Security Policy
  reply.header(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'none'; style-src 'none'"
  );

  // Referrer policy
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions policy
  reply.header(
    'Permissions-Policy',
    'geolocation=(), camera=(), microphone=()'
  );

  // Remove server header
  reply.removeHeader('server');
}

// ============================================================================
// PLUGIN REGISTRATION
// ============================================================================

/**
 * Register validation plugin
 */
export async function registerValidationPlugin(
  fastify: FastifyInstance
): Promise<void> {
  // Add global validation
  fastify.addHook('preHandler', globalValidationMiddleware);

  // Add security headers to all responses
  fastify.addHook('onSend', async (request, reply) => {
    await securityHeadersMiddleware(request, reply);
  });

  // Set body size limit
  fastify.register(async (instance) => {
    instance.setBodyLimit(REQUEST_LIMITS.MAX_BODY_SIZE);
  });

  log.info('Validation plugin registered');
}
