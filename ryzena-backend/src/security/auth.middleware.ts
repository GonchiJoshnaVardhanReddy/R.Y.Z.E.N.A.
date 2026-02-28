/**
 * R.Y.Z.E.N.A. - Phase 7: Authentication Middleware
 * JWT-based authentication with refresh token flow
 */

import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify';
import jwt from 'jsonwebtoken';
import { logger } from '../shared/logger.js';
import {
  JWT_CONFIG,
  JwtPayload,
  JwtPayloadSchema,
  PUBLIC_ENDPOINTS,
  UserRole,
  ROLE_PERMISSIONS,
} from './security.config.js';
import { getEncryptionService } from './encryption.service.js';
import { getAuditService } from './audit.service.js';

// ============================================================================
// TYPES
// ============================================================================

export interface AuthenticatedUser {
  id: string;
  role: UserRole;
  permissions: string[];
  tokenId?: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
    isAuthenticated: boolean;
  }
}

// ============================================================================
// TOKEN GENERATION
// ============================================================================

/**
 * Generate access token
 */
export function generateAccessToken(
  userId: string,
  role: UserRole,
  additionalClaims?: Record<string, unknown>
): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET not configured');
  }

  const permissions = ROLE_PERMISSIONS[role] || [];
  const tokenId = getEncryptionService().generateToken(16);

  const payload: Omit<JwtPayload, 'iat' | 'exp'> = {
    sub: userId,
    role,
    permissions,
    iss: JWT_CONFIG.ISSUER,
    aud: JWT_CONFIG.AUDIENCE,
    jti: tokenId,
    ...additionalClaims,
  };

  return jwt.sign(payload, secret, {
    expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
    algorithm: JWT_CONFIG.ALGORITHM,
  });
}

/**
 * Generate refresh token
 */
export function generateRefreshToken(
  userId: string,
  role: UserRole
): string {
  const secret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_REFRESH_SECRET not configured');
  }

  const tokenId = getEncryptionService().generateToken(16);

  const payload = {
    sub: userId,
    role,
    type: 'refresh',
    jti: tokenId,
    iss: JWT_CONFIG.ISSUER,
    aud: JWT_CONFIG.AUDIENCE,
  };

  return jwt.sign(payload, secret, {
    expiresIn: JWT_CONFIG.REFRESH_TOKEN_EXPIRY,
    algorithm: JWT_CONFIG.ALGORITHM,
  });
}

/**
 * Generate token pair
 */
export function generateTokenPair(
  userId: string,
  role: UserRole
): { accessToken: string; refreshToken: string; expiresIn: string } {
  return {
    accessToken: generateAccessToken(userId, role),
    refreshToken: generateRefreshToken(userId, role),
    expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY,
  };
}

// ============================================================================
// TOKEN VALIDATION
// ============================================================================

/**
 * Verify and decode access token
 */
export function verifyAccessToken(token: string): JwtPayload | null {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    logger.error('JWT_SECRET not configured');
    return null;
  }

  try {
    const decoded = jwt.verify(token, secret, {
      issuer: JWT_CONFIG.ISSUER,
      audience: JWT_CONFIG.AUDIENCE,
      algorithms: [JWT_CONFIG.ALGORITHM],
      clockTolerance: JWT_CONFIG.CLOCK_TOLERANCE,
    });

    const result = JwtPayloadSchema.safeParse(decoded);
    if (!result.success) {
      logger.warn({ errors: result.error.issues }, 'Invalid token payload');
      return null;
    }

    return result.data;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.debug('Token expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      logger.warn({ error: error.message }, 'Invalid token');
    } else {
      logger.error({ error }, 'Token verification failed');
    }
    return null;
  }
}

/**
 * Verify refresh token
 */
export function verifyRefreshToken(token: string): JwtPayload | null {
  const secret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
  if (!secret) {
    logger.error('JWT_REFRESH_SECRET not configured');
    return null;
  }

  try {
    const decoded = jwt.verify(token, secret, {
      issuer: JWT_CONFIG.ISSUER,
      audience: JWT_CONFIG.AUDIENCE,
      algorithms: [JWT_CONFIG.ALGORITHM],
    });

    if (typeof decoded === 'object' && decoded !== null) {
      return decoded as JwtPayload;
    }
    return null;
  } catch (error) {
    logger.warn({ error }, 'Refresh token verification failed');
    return null;
  }
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

/**
 * Extract token from request
 */
function extractToken(request: FastifyRequest): string | null {
  // Check Authorization header
  const authHeader = request.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Check X-API-Key header (for service-to-service)
  const apiKey = request.headers['x-api-key'];
  if (typeof apiKey === 'string') {
    return apiKey;
  }

  return null;
}

/**
 * Check if endpoint is public
 */
function isPublicEndpoint(url: string): boolean {
  const path = url.split('?')[0]; // Remove query string
  return PUBLIC_ENDPOINTS.some((endpoint) => {
    if (endpoint.endsWith('*')) {
      return path.startsWith(endpoint.slice(0, -1));
    }
    return path === endpoint;
  });
}

/**
 * Authentication middleware
 */
export async function authMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const log = logger.child({ module: 'auth-middleware' });
  
  // Initialize auth state
  request.isAuthenticated = false;
  request.user = undefined;

  // Skip auth for public endpoints
  if (isPublicEndpoint(request.url)) {
    return;
  }

  // Check if auth is required (configurable)
  const adminRequiresAuth = process.env.ADMIN_REQUIRES_AUTH !== 'false';
  if (!adminRequiresAuth && request.url.startsWith('/api/v1/admin')) {
    // Development mode: allow admin access without auth
    request.isAuthenticated = true;
    request.user = {
      id: 'dev-admin',
      role: UserRole.ADMIN,
      permissions: ROLE_PERMISSIONS[UserRole.ADMIN],
    };
    return;
  }

  // Extract token
  const token = extractToken(request);
  if (!token) {
    log.debug({ url: request.url }, 'No token provided');
    reply.status(401).send({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      },
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // Verify token
  const payload = verifyAccessToken(token);
  if (!payload) {
    // Audit failed auth attempt
    try {
      const audit = getAuditService();
      await audit.log({
        action: 'auth.failed',
        actorId: 'unknown',
        actorRole: 'unknown',
        resource: request.url,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
        metadata: { reason: 'invalid_token' },
      });
    } catch {
      // Continue even if audit fails
    }

    reply.status(401).send({
      success: false,
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid or expired token',
      },
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // Set authenticated user
  request.isAuthenticated = true;
  request.user = {
    id: payload.sub,
    role: payload.role,
    permissions: payload.permissions,
    tokenId: payload.jti,
  };

  log.debug({
    userId: payload.sub,
    role: payload.role,
    url: request.url,
  }, 'User authenticated');
}

/**
 * Require authentication decorator
 */
export function requireAuth(
  _target: unknown,
  _propertyKey: string,
  descriptor: PropertyDescriptor
): PropertyDescriptor {
  const originalMethod = descriptor.value;

  descriptor.value = async function (
    request: FastifyRequest,
    reply: FastifyReply,
    ...args: unknown[]
  ) {
    if (!request.isAuthenticated) {
      return reply.status(401).send({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
        },
        timestamp: new Date().toISOString(),
      });
    }
    return originalMethod.call(this, request, reply, ...args);
  };

  return descriptor;
}

// ============================================================================
// FASTIFY PLUGIN
// ============================================================================

/**
 * Register authentication plugin
 */
export async function registerAuthPlugin(fastify: FastifyInstance): Promise<void> {
  // Add auth middleware to all routes
  fastify.addHook('preHandler', authMiddleware);

  // Add decorators
  fastify.decorateRequest('user', null);
  fastify.decorateRequest('isAuthenticated', false);

  logger.info('Authentication plugin registered');
}
