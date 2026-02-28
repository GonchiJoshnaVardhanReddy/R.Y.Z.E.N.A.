/**
 * R.Y.Z.E.N.A. - Consent Validation Schemas
 * 
 * Zod schemas for validating consent-related API requests.
 */

import { z } from 'zod';

// ============================================================================
// CONSENT REQUEST SCHEMAS
// ============================================================================

/**
 * Schema for creating a consent request
 */
export const consentRequestSchema = z.object({
  studentId: z
    .string()
    .min(1, 'Student ID is required')
    .max(100, 'Student ID too long'),
  serviceId: z
    .string()
    .uuid('Invalid service ID format'),
  requestedFields: z
    .array(z.string().min(1))
    .min(1, 'At least one field must be requested')
    .max(50, 'Too many fields requested'),
  purpose: z
    .string()
    .min(10, 'Purpose must be at least 10 characters')
    .max(1000, 'Purpose too long'),
  requestedDuration: z
    .number()
    .int('Duration must be an integer')
    .min(1, 'Duration must be at least 1 day')
    .max(365, 'Duration cannot exceed 365 days'),
});

export type ConsentRequestInput = z.infer<typeof consentRequestSchema>;

// ============================================================================
// CONSENT RESPONSE SCHEMAS
// ============================================================================

/**
 * Schema for responding to a consent request
 */
export const consentResponseSchema = z.object({
  requestId: z
    .string()
    .uuid('Invalid request ID format'),
  studentId: z
    .string()
    .min(1, 'Student ID is required')
    .max(100, 'Student ID too long'),
  action: z
    .enum(['APPROVE', 'DENY'], {
      errorMap: () => ({ message: 'Action must be APPROVE or DENY' }),
    }),
  modifiedFields: z
    .array(z.string().min(1))
    .optional()
    .describe('Modified list of approved fields (for partial approval)'),
  modifiedDuration: z
    .number()
    .int()
    .min(1)
    .max(365)
    .optional()
    .describe('Modified approval duration in days'),
  deniedFields: z
    .array(z.string().min(1))
    .optional()
    .describe('Specific fields being denied'),
});

export type ConsentResponseInput = z.infer<typeof consentResponseSchema>;

// ============================================================================
// GRANT MANAGEMENT SCHEMAS
// ============================================================================

/**
 * Schema for revoking a consent grant
 */
export const revokeGrantSchema = z.object({
  grantId: z
    .string()
    .uuid('Invalid grant ID format'),
  studentId: z
    .string()
    .min(1, 'Student ID is required')
    .max(100, 'Student ID too long'),
  reason: z
    .string()
    .min(5, 'Reason must be at least 5 characters')
    .max(500, 'Reason too long'),
});

export type RevokeGrantInput = z.infer<typeof revokeGrantSchema>;

// ============================================================================
// ACCESS CHECK SCHEMAS
// ============================================================================

/**
 * Schema for checking field access
 */
export const checkAccessSchema = z.object({
  studentId: z
    .string()
    .min(1, 'Student ID is required')
    .max(100, 'Student ID too long'),
  serviceId: z
    .string()
    .uuid('Invalid service ID format'),
  fields: z
    .array(z.string().min(1))
    .min(1, 'At least one field must be specified')
    .max(50, 'Too many fields specified'),
});

export type CheckAccessInput = z.infer<typeof checkAccessSchema>;

// ============================================================================
// SERVICE MANAGEMENT SCHEMAS
// ============================================================================

/**
 * Schema for registering a service
 */
export const registerServiceSchema = z.object({
  name: z
    .string()
    .min(2, 'Service name must be at least 2 characters')
    .max(100, 'Service name too long')
    .regex(/^[a-zA-Z0-9\s\-_]+$/, 'Service name contains invalid characters'),
  description: z
    .string()
    .max(1000, 'Description too long')
    .optional(),
  riskCategory: z
    .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    .optional()
    .default('MEDIUM'),
});

export type RegisterServiceInput = z.infer<typeof registerServiceSchema>;

// ============================================================================
// QUERY PARAMETER SCHEMAS
// ============================================================================

/**
 * Schema for pagination query parameters
 */
export const paginationSchema = z.object({
  page: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().int().min(1))
    .optional()
    .default('1'),
  limit: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().int().min(1).max(100))
    .optional()
    .default('20'),
});

/**
 * Schema for consent history query parameters
 */
export const consentHistoryQuerySchema = z.object({
  page: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .optional(),
  limit: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .optional(),
  status: z
    .enum(['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED'])
    .optional(),
});

// ============================================================================
// STUDENT ID PARAMETER SCHEMA
// ============================================================================

/**
 * Schema for student ID path parameter
 */
export const studentIdParamSchema = z.object({
  studentId: z
    .string()
    .min(1, 'Student ID is required')
    .max(100, 'Student ID too long'),
});

/**
 * Schema for service ID path parameter
 */
export const serviceIdParamSchema = z.object({
  serviceId: z
    .string()
    .uuid('Invalid service ID format'),
});

/**
 * Schema for request ID path parameter
 */
export const requestIdParamSchema = z.object({
  requestId: z
    .string()
    .uuid('Invalid request ID format'),
});

/**
 * Schema for grant ID path parameter
 */
export const grantIdParamSchema = z.object({
  grantId: z
    .string()
    .uuid('Invalid grant ID format'),
});
