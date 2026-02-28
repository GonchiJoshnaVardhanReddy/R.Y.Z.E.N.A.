/**
 * R.Y.Z.E.N.A. - Phase 7: Role-Based Access Control Middleware
 * RBAC enforcement with permission checking
 */

import { FastifyRequest, FastifyReply } from 'fastify';
import { logger } from '../shared/logger.js';
import {
  UserRole,
  Permission,
  ROLE_HIERARCHY,
  ROLE_PERMISSIONS,
} from './security.config.js';
import { getAuditService } from './audit.service.js';

// ============================================================================
// TYPES
// ============================================================================

interface RoleCheckOptions {
  /** Required role(s) - user must have at least one */
  roles?: UserRole[];
  /** Required permission(s) - user must have at least one */
  permissions?: Permission[];
  /** Require all specified permissions (default: false - any permission) */
  requireAll?: boolean;
  /** Allow higher roles to access (default: true) */
  allowHierarchy?: boolean;
}

// ============================================================================
// ROLE CHECKING FUNCTIONS
// ============================================================================

/**
 * Check if user has required role
 */
export function hasRole(userRole: UserRole, requiredRole: UserRole): boolean {
  return userRole === requiredRole;
}

/**
 * Check if user role meets hierarchy requirement
 */
export function hasRoleHierarchy(userRole: UserRole, requiredRole: UserRole): boolean {
  const userLevel = ROLE_HIERARCHY[userRole] || 0;
  const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;
  return userLevel >= requiredLevel;
}

/**
 * Check if user has required permission
 */
export function hasPermission(
  userPermissions: string[],
  requiredPermission: Permission
): boolean {
  return userPermissions.includes(requiredPermission) ||
         userPermissions.includes(Permission.SYSTEM_ALL);
}

/**
 * Check if user has any of the required permissions
 */
export function hasAnyPermission(
  userPermissions: string[],
  requiredPermissions: Permission[]
): boolean {
  if (userPermissions.includes(Permission.SYSTEM_ALL)) {
    return true;
  }
  return requiredPermissions.some((p) => userPermissions.includes(p));
}

/**
 * Check if user has all required permissions
 */
export function hasAllPermissions(
  userPermissions: string[],
  requiredPermissions: Permission[]
): boolean {
  if (userPermissions.includes(Permission.SYSTEM_ALL)) {
    return true;
  }
  return requiredPermissions.every((p) => userPermissions.includes(p));
}

// ============================================================================
// MIDDLEWARE FACTORY
// ============================================================================

/**
 * Create role check middleware
 */
export function requireRole(options: RoleCheckOptions) {
  const log = logger.child({ module: 'role-middleware' });
  
  return async function roleMiddleware(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    // Check authentication first
    if (!request.isAuthenticated || !request.user) {
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

    const { user } = request;
    const {
      roles = [],
      permissions = [],
      requireAll = false,
      allowHierarchy = true,
    } = options;

    let authorized = false;

    // Check roles
    if (roles.length > 0) {
      for (const requiredRole of roles) {
        if (allowHierarchy) {
          if (hasRoleHierarchy(user.role, requiredRole)) {
            authorized = true;
            break;
          }
        } else {
          if (hasRole(user.role, requiredRole)) {
            authorized = true;
            break;
          }
        }
      }
    }

    // Check permissions if roles didn't match
    if (!authorized && permissions.length > 0) {
      if (requireAll) {
        authorized = hasAllPermissions(user.permissions, permissions);
      } else {
        authorized = hasAnyPermission(user.permissions, permissions);
      }
    }

    // If no roles or permissions specified, just require authentication
    if (roles.length === 0 && permissions.length === 0) {
      authorized = true;
    }

    if (!authorized) {
      log.warn({
        userId: user.id,
        userRole: user.role,
        requiredRoles: roles,
        requiredPermissions: permissions,
        url: request.url,
      }, 'Access denied');

      // Audit the denial
      try {
        const audit = getAuditService();
        await audit.log({
          action: 'auth.denied',
          actorId: user.id,
          actorRole: user.role,
          resource: request.url,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'],
          metadata: {
            requiredRoles: roles,
            requiredPermissions: permissions,
          },
        });
      } catch {
        // Continue even if audit fails
      }

      reply.status(403).send({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Insufficient permissions',
        },
        timestamp: new Date().toISOString(),
      });
      return;
    }

    log.debug({
      userId: user.id,
      role: user.role,
      url: request.url,
    }, 'Access granted');
  };
}

// ============================================================================
// PREDEFINED MIDDLEWARE
// ============================================================================

/**
 * Require admin role
 */
export const requireAdmin = requireRole({
  roles: [UserRole.ADMIN, UserRole.SYSTEM],
});

/**
 * Require student role
 */
export const requireStudent = requireRole({
  roles: [UserRole.STUDENT],
  allowHierarchy: true,
});

/**
 * Require service role
 */
export const requireService = requireRole({
  roles: [UserRole.SERVICE, UserRole.SYSTEM],
});

/**
 * Require system role
 */
export const requireSystem = requireRole({
  roles: [UserRole.SYSTEM],
  allowHierarchy: false,
});

/**
 * Require admin analytics permission
 */
export const requireAdminAnalytics = requireRole({
  permissions: [Permission.ADMIN_ANALYTICS],
});

/**
 * Require email scan permission
 */
export const requireEmailScan = requireRole({
  permissions: [Permission.SERVICE_EMAIL_SCAN],
});

/**
 * Require AI explanation permission
 */
export const requireAIAccess = requireRole({
  permissions: [Permission.SERVICE_AI_EXPLAIN],
});

/**
 * Require consent permission
 */
export const requireConsentAccess = requireRole({
  permissions: [Permission.STUDENT_CONSENT],
});

// ============================================================================
// ROUTE-LEVEL GUARDS
// ============================================================================

/**
 * Check if user can access student data
 */
export function canAccessStudentData(
  userRole: UserRole,
  userId: string,
  targetStudentId: string
): boolean {
  // System and admin can access all
  if (userRole === UserRole.SYSTEM || userRole === UserRole.ADMIN) {
    return true;
  }
  // Students can only access their own data
  if (userRole === UserRole.STUDENT) {
    return userId === targetStudentId;
  }
  // Services need explicit permission (checked separately)
  return false;
}

/**
 * Middleware to check student data access
 */
export function requireStudentDataAccess(studentIdParam: string = 'studentId') {
  return async function (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> {
    if (!request.user) {
      reply.status(401).send({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        timestamp: new Date().toISOString(),
      });
      return;
    }

    const params = request.params as Record<string, string>;
    const targetStudentId = params[studentIdParam];

    if (!targetStudentId) {
      return; // No student ID to check
    }

    if (!canAccessStudentData(request.user.role, request.user.id, targetStudentId)) {
      reply.status(403).send({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Cannot access other student data' },
        timestamp: new Date().toISOString(),
      });
    }
  };
}
