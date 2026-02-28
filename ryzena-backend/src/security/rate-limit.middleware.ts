/**
 * R.Y.Z.E.N.A. - Phase 7: Advanced Rate Limiting
 * Multi-tier rate limiting with per-user and per-IP controls
 */

import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify';
import { logger } from '../shared/logger.js';
import { RATE_LIMIT_CONFIG } from './security.config.js';
import { getAuditService } from './audit.service.js';

// ============================================================================
// TYPES
// ============================================================================

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimitConfig {
  max: number;
  windowMs: number;
}

type RateLimitStore = Map<string, RateLimitEntry>;

// ============================================================================
// RATE LIMIT STORES
// ============================================================================

const stores: Map<string, RateLimitStore> = new Map();

/**
 * Get or create rate limit store
 */
function getStore(name: string): RateLimitStore {
  if (!stores.has(name)) {
    stores.set(name, new Map());
  }
  return stores.get(name)!;
}

/**
 * Clean expired entries
 */
function cleanExpiredEntries(): void {
  const now = Date.now();
  for (const store of stores.values()) {
    for (const [key, entry] of store.entries()) {
      if (entry.resetAt <= now) {
        store.delete(key);
      }
    }
  }
}

// Clean up every minute
setInterval(cleanExpiredEntries, 60000);

// ============================================================================
// RATE LIMIT LOGIC
// ============================================================================

/**
 * Check rate limit for a key
 */
function checkRateLimit(
  store: RateLimitStore,
  key: string,
  config: RateLimitConfig
): { allowed: boolean; remaining: number; resetAt: number; retryAfter?: number } {
  const now = Date.now();
  let entry = store.get(key);

  // Reset if window expired
  if (!entry || entry.resetAt <= now) {
    entry = {
      count: 0,
      resetAt: now + config.windowMs,
    };
    store.set(key, entry);
  }

  // Check limit
  if (entry.count >= config.max) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return {
      allowed: false,
      remaining: 0,
      resetAt: entry.resetAt,
      retryAfter,
    };
  }

  // Increment and allow
  entry.count++;
  return {
    allowed: true,
    remaining: config.max - entry.count,
    resetAt: entry.resetAt,
  };
}

/**
 * Get rate limit key for request
 */
function getRateLimitKey(request: FastifyRequest, type: 'ip' | 'user' | 'combined'): string {
  const ip = request.ip || 'unknown';
  const userId = request.user?.id || 'anonymous';

  switch (type) {
    case 'ip':
      return `ip:${ip}`;
    case 'user':
      return `user:${userId}`;
    case 'combined':
      return `combined:${ip}:${userId}`;
    default:
      return `ip:${ip}`;
  }
}

// ============================================================================
// MIDDLEWARE FACTORY
// ============================================================================

/**
 * Create rate limit middleware
 */
export function createRateLimiter(
  storeName: string,
  config: RateLimitConfig,
  keyType: 'ip' | 'user' | 'combined' = 'ip'
) {
  const store = getStore(storeName);
  const log = logger.child({ module: 'rate-limit', store: storeName });

  return async function rateLimitMiddleware(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    // Skip if rate limiting disabled
    if (process.env.RATE_LIMIT_ENABLED === 'false') {
      return;
    }

    const key = getRateLimitKey(request, keyType);
    const result = checkRateLimit(store, key, config);

    // Set rate limit headers
    reply.header('X-RateLimit-Limit', config.max);
    reply.header('X-RateLimit-Remaining', result.remaining);
    reply.header('X-RateLimit-Reset', Math.ceil(result.resetAt / 1000));

    if (!result.allowed) {
      log.warn({
        key,
        ip: request.ip,
        userId: request.user?.id,
        url: request.url,
      }, 'Rate limit exceeded');

      // Audit rate limit violation
      try {
        const audit = getAuditService();
        await audit.log({
          action: 'ratelimit.exceeded',
          actorId: request.user?.id || 'anonymous',
          actorRole: request.user?.role || 'unknown',
          resource: request.url,
          ipAddress: request.ip,
          metadata: {
            store: storeName,
            limit: config.max,
            windowMs: config.windowMs,
          },
        });
      } catch {
        // Continue even if audit fails
      }

      reply.header('Retry-After', result.retryAfter);
      reply.status(429).send({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: `Too many requests. Try again in ${result.retryAfter} seconds.`,
        },
        retryAfter: result.retryAfter,
        timestamp: new Date().toISOString(),
      });
    }
  };
}

// ============================================================================
// PREDEFINED RATE LIMITERS
// ============================================================================

/**
 * Global rate limiter (per IP)
 */
export const globalRateLimiter = createRateLimiter(
  'global',
  RATE_LIMIT_CONFIG.GLOBAL,
  'ip'
);

/**
 * Auth endpoint rate limiter
 */
export const authRateLimiter = createRateLimiter(
  'auth',
  RATE_LIMIT_CONFIG.AUTH,
  'ip'
);

/**
 * AI endpoint rate limiter (per user)
 */
export const aiRateLimiter = createRateLimiter(
  'ai',
  RATE_LIMIT_CONFIG.AI,
  'combined'
);

/**
 * Consent endpoint rate limiter
 */
export const consentRateLimiter = createRateLimiter(
  'consent',
  RATE_LIMIT_CONFIG.CONSENT,
  'combined'
);

/**
 * Admin endpoint rate limiter
 */
export const adminRateLimiter = createRateLimiter(
  'admin',
  RATE_LIMIT_CONFIG.ADMIN,
  'combined'
);

/**
 * Email webhook rate limiter
 */
export const emailRateLimiter = createRateLimiter(
  'email',
  RATE_LIMIT_CONFIG.EMAIL,
  'ip'
);

// ============================================================================
// FASTIFY PLUGIN
// ============================================================================

/**
 * Register rate limiting plugin
 */
export async function registerRateLimitPlugin(fastify: FastifyInstance): Promise<void> {
  // Apply global rate limit to all routes
  fastify.addHook('preHandler', globalRateLimiter);

  // Apply endpoint-specific rate limits
  fastify.addHook('preHandler', async (request, reply) => {
    const url = request.url;

    if (url.startsWith('/api/v1/auth')) {
      await authRateLimiter(request, reply);
    } else if (url.startsWith('/api/v1/ai')) {
      await aiRateLimiter(request, reply);
    } else if (url.startsWith('/api/v1/consent')) {
      await consentRateLimiter(request, reply);
    } else if (url.startsWith('/api/v1/admin')) {
      await adminRateLimiter(request, reply);
    } else if (url.startsWith('/api/v1/email')) {
      await emailRateLimiter(request, reply);
    }
  });

  logger.info('Rate limiting plugin registered');
}

// ============================================================================
// UTILITIES
// ============================================================================

/**
 * Reset rate limit for a specific key (admin function)
 */
export function resetRateLimit(storeName: string, key: string): boolean {
  const store = stores.get(storeName);
  if (store) {
    return store.delete(key);
  }
  return false;
}

/**
 * Get current rate limit status
 */
export function getRateLimitStatus(
  storeName: string,
  key: string,
  config: RateLimitConfig
): { count: number; max: number; remaining: number; resetAt: number | null } {
  const store = stores.get(storeName);
  const entry = store?.get(key);
  const now = Date.now();

  if (!entry || entry.resetAt <= now) {
    return {
      count: 0,
      max: config.max,
      remaining: config.max,
      resetAt: null,
    };
  }

  return {
    count: entry.count,
    max: config.max,
    remaining: Math.max(0, config.max - entry.count),
    resetAt: entry.resetAt,
  };
}
