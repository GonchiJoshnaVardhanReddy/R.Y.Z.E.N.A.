/**
 * R.Y.Z.E.N.A. - Access Guard
 * 
 * Enforces field-level access control for consent grants.
 * Validates service access to student data based on active grants.
 */

import { createLogger } from '../../shared/logger.js';
import * as repository from './consent.repository.js';
import type { AccessCheckResult, ConsentGrant } from './consent.types.js';

const logger = createLogger({ module: 'access-guard' });

// ============================================================================
// ACCESS CHECKING
// ============================================================================

/**
 * Check if a service has access to a specific field for a student
 */
export async function checkAccess(
  studentId: string,
  serviceId: string,
  field: string
): Promise<boolean> {
  const result = await checkFieldAccess(studentId, serviceId, field);
  return result.allowed;
}

/**
 * Check access with detailed result
 */
export async function checkFieldAccess(
  studentId: string,
  serviceId: string,
  field: string
): Promise<AccessCheckResult> {
  const grant = await repository.findActiveGrant(studentId, serviceId);
  
  if (!grant) {
    logger.warn({
      action: 'access_denied',
      reason: 'no_active_grant',
      studentId,
      serviceId,
      field,
    });
    
    return {
      allowed: false,
      reason: 'No active consent grant found',
      field,
    };
  }
  
  // Check if grant is expired
  if (isGrantExpired(grant)) {
    logger.warn({
      action: 'access_denied',
      reason: 'grant_expired',
      studentId,
      serviceId,
      field,
      grantId: grant.id,
      expiresAt: grant.expiresAt.toISOString(),
    });
    
    return {
      allowed: false,
      reason: 'Consent grant has expired',
      field,
      grantId: grant.id,
    };
  }
  
  // Check if grant is revoked
  if (grant.isRevoked) {
    logger.warn({
      action: 'access_denied',
      reason: 'grant_revoked',
      studentId,
      serviceId,
      field,
      grantId: grant.id,
    });
    
    return {
      allowed: false,
      reason: 'Consent grant has been revoked',
      field,
      grantId: grant.id,
    };
  }
  
  // Check if field is in approved fields
  if (!grant.approvedFields.includes(field)) {
    logger.warn({
      action: 'access_denied',
      reason: 'field_not_approved',
      studentId,
      serviceId,
      field,
      grantId: grant.id,
      approvedFields: grant.approvedFields,
    });
    
    return {
      allowed: false,
      reason: `Field '${field}' is not included in approved fields`,
      field,
      grantId: grant.id,
    };
  }
  
  // Access granted
  logger.info({
    action: 'access_granted',
    studentId,
    serviceId,
    field,
    grantId: grant.id,
  });
  
  return {
    allowed: true,
    field,
    grantId: grant.id,
    expiresAt: grant.expiresAt,
  };
}

/**
 * Check access to multiple fields at once
 */
export async function checkMultiFieldAccess(
  studentId: string,
  serviceId: string,
  fields: string[]
): Promise<{
  allAllowed: boolean;
  results: AccessCheckResult[];
  allowedFields: string[];
  deniedFields: string[];
}> {
  const grant = await repository.findActiveGrant(studentId, serviceId);
  
  if (!grant) {
    return {
      allAllowed: false,
      results: fields.map(field => ({
        allowed: false,
        reason: 'No active consent grant found',
        field,
      })),
      allowedFields: [],
      deniedFields: fields,
    };
  }
  
  const results: AccessCheckResult[] = [];
  const allowedFields: string[] = [];
  const deniedFields: string[] = [];
  
  // Check base grant validity
  const baseError = getGrantValidityError(grant);
  
  for (const field of fields) {
    if (baseError) {
      results.push({
        allowed: false,
        reason: baseError,
        field,
        grantId: grant.id,
      });
      deniedFields.push(field);
    } else if (grant.approvedFields.includes(field)) {
      results.push({
        allowed: true,
        field,
        grantId: grant.id,
        expiresAt: grant.expiresAt,
      });
      allowedFields.push(field);
    } else {
      results.push({
        allowed: false,
        reason: `Field '${field}' is not included in approved fields`,
        field,
        grantId: grant.id,
      });
      deniedFields.push(field);
    }
  }
  
  logger.info({
    action: 'multi_field_access_check',
    studentId,
    serviceId,
    requestedFields: fields.length,
    allowedCount: allowedFields.length,
    deniedCount: deniedFields.length,
  });
  
  return {
    allAllowed: deniedFields.length === 0,
    results,
    allowedFields,
    deniedFields,
  };
}

/**
 * Get all accessible fields for a service
 */
export async function getAccessibleFields(
  studentId: string,
  serviceId: string
): Promise<string[]> {
  const grant = await repository.findActiveGrant(studentId, serviceId);
  
  if (!grant || isGrantExpired(grant) || grant.isRevoked) {
    return [];
  }
  
  return grant.approvedFields;
}

/**
 * Validate service has any active grant for student
 */
export async function hasActiveGrant(
  studentId: string,
  serviceId: string
): Promise<boolean> {
  const grant = await repository.findActiveGrant(studentId, serviceId);
  return grant !== null && !isGrantExpired(grant) && !grant.isRevoked;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Check if grant has expired
 */
function isGrantExpired(grant: ConsentGrant): boolean {
  return new Date() > grant.expiresAt;
}

/**
 * Get error message if grant is invalid, or null if valid
 */
function getGrantValidityError(grant: ConsentGrant): string | null {
  if (isGrantExpired(grant)) {
    return 'Consent grant has expired';
  }
  if (grant.isRevoked) {
    return 'Consent grant has been revoked';
  }
  return null;
}

// ============================================================================
// GRANT INFORMATION
// ============================================================================

/**
 * Get grant details for a student and service
 */
export async function getGrantInfo(
  studentId: string,
  serviceId: string
): Promise<{
  hasGrant: boolean;
  grant: ConsentGrant | null;
  isValid: boolean;
  remainingTime: number | null;
} | null> {
  const grant = await repository.findActiveGrant(studentId, serviceId);
  
  if (!grant) {
    return {
      hasGrant: false,
      grant: null,
      isValid: false,
      remainingTime: null,
    };
  }
  
  const isValid = !isGrantExpired(grant) && !grant.isRevoked;
  const remainingTime = isValid
    ? Math.max(0, grant.expiresAt.getTime() - Date.now())
    : null;
  
  return {
    hasGrant: true,
    grant,
    isValid,
    remainingTime,
  };
}
