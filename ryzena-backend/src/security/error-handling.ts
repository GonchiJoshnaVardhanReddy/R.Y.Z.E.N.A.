/**
 * R.Y.Z.E.N.A. - Phase 7: Standardized Error Handling
 * Production-ready error responses and logging
 */

import { FastifyError, FastifyReply, FastifyRequest, FastifyInstance } from 'fastify';
import { logger } from '../shared/logger.js';
import { ZodError } from 'zod';

// ============================================================================
// TYPES
// ============================================================================

export interface StandardError {
  code: string;
  message: string;
  details?: unknown;
}

export interface StandardErrorResponse {
  success: false;
  error: StandardError;
  timestamp: string;
  requestId?: string;
}

// ============================================================================
// ERROR CODES
// ============================================================================

export const ErrorCodes = {
  // Authentication
  UNAUTHORIZED: 'UNAUTHORIZED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  FORBIDDEN: 'FORBIDDEN',

  // Validation
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  MISSING_FIELD: 'MISSING_FIELD',

  // Rate limiting
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',

  // Resource
  NOT_FOUND: 'NOT_FOUND',
  ALREADY_EXISTS: 'ALREADY_EXISTS',
  CONFLICT: 'CONFLICT',

  // Server
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  TIMEOUT: 'TIMEOUT',

  // External services
  AI_SERVICE_ERROR: 'AI_SERVICE_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',

  // Business logic
  CONSENT_REQUIRED: 'CONSENT_REQUIRED',
  ACCESS_DENIED: 'ACCESS_DENIED',
  EXPIRED: 'EXPIRED',
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

// ============================================================================
// CUSTOM ERROR CLASS
// ============================================================================

/**
 * Application error with code and details
 */
export class AppError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: unknown;
  public readonly isOperational: boolean;

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 500,
    details?: unknown
  ) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true;

    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Create from error code
   */
  static fromCode(code: ErrorCode, details?: unknown): AppError {
    const mapping = ERROR_CODE_MAPPING[code];
    return new AppError(
      code,
      mapping?.message || 'An error occurred',
      mapping?.statusCode || 500,
      details
    );
  }
}

// ============================================================================
// ERROR CODE MAPPING
// ============================================================================

const ERROR_CODE_MAPPING: Record<string, { message: string; statusCode: number }> = {
  [ErrorCodes.UNAUTHORIZED]: {
    message: 'Authentication required',
    statusCode: 401,
  },
  [ErrorCodes.INVALID_TOKEN]: {
    message: 'Invalid authentication token',
    statusCode: 401,
  },
  [ErrorCodes.TOKEN_EXPIRED]: {
    message: 'Authentication token has expired',
    statusCode: 401,
  },
  [ErrorCodes.FORBIDDEN]: {
    message: 'Access denied',
    statusCode: 403,
  },
  [ErrorCodes.VALIDATION_ERROR]: {
    message: 'Invalid request data',
    statusCode: 400,
  },
  [ErrorCodes.INVALID_INPUT]: {
    message: 'Invalid input provided',
    statusCode: 400,
  },
  [ErrorCodes.MISSING_FIELD]: {
    message: 'Required field is missing',
    statusCode: 400,
  },
  [ErrorCodes.RATE_LIMIT_EXCEEDED]: {
    message: 'Too many requests',
    statusCode: 429,
  },
  [ErrorCodes.NOT_FOUND]: {
    message: 'Resource not found',
    statusCode: 404,
  },
  [ErrorCodes.ALREADY_EXISTS]: {
    message: 'Resource already exists',
    statusCode: 409,
  },
  [ErrorCodes.CONFLICT]: {
    message: 'Request conflicts with current state',
    statusCode: 409,
  },
  [ErrorCodes.INTERNAL_ERROR]: {
    message: 'An internal error occurred',
    statusCode: 500,
  },
  [ErrorCodes.SERVICE_UNAVAILABLE]: {
    message: 'Service temporarily unavailable',
    statusCode: 503,
  },
  [ErrorCodes.TIMEOUT]: {
    message: 'Request timed out',
    statusCode: 504,
  },
  [ErrorCodes.AI_SERVICE_ERROR]: {
    message: 'AI service error',
    statusCode: 503,
  },
  [ErrorCodes.DATABASE_ERROR]: {
    message: 'Database error',
    statusCode: 500,
  },
  [ErrorCodes.CONSENT_REQUIRED]: {
    message: 'Consent required for this action',
    statusCode: 403,
  },
  [ErrorCodes.ACCESS_DENIED]: {
    message: 'Access to requested resource denied',
    statusCode: 403,
  },
  [ErrorCodes.EXPIRED]: {
    message: 'Resource has expired',
    statusCode: 410,
  },
};

// ============================================================================
// ERROR RESPONSE BUILDER
// ============================================================================

const log = logger.child({ module: 'error-handler' });

/**
 * Build standardized error response
 */
export function buildErrorResponse(
  error: Error | AppError | FastifyError | ZodError,
  requestId?: string
): StandardErrorResponse {
  let code = ErrorCodes.INTERNAL_ERROR;
  let message = 'An unexpected error occurred';
  let details: unknown = undefined;
  let statusCode = 500;

  if (error instanceof AppError) {
    code = error.code;
    message = error.message;
    details = error.details;
    statusCode = error.statusCode;
  } else if (error instanceof ZodError) {
    code = ErrorCodes.VALIDATION_ERROR;
    message = 'Validation failed';
    details = error.errors.map((e) => ({
      path: e.path.join('.'),
      message: e.message,
    }));
    statusCode = 400;
  } else if ('statusCode' in error && typeof error.statusCode === 'number') {
    statusCode = error.statusCode;
    message = error.message;
    
    // Map HTTP status to error code
    if (statusCode === 404) code = ErrorCodes.NOT_FOUND;
    else if (statusCode === 401) code = ErrorCodes.UNAUTHORIZED;
    else if (statusCode === 403) code = ErrorCodes.FORBIDDEN;
    else if (statusCode === 400) code = ErrorCodes.INVALID_INPUT;
    else if (statusCode === 429) code = ErrorCodes.RATE_LIMIT_EXCEEDED;
  }

  // Never expose internal details in production
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction && statusCode >= 500) {
    message = ERROR_CODE_MAPPING[code]?.message || 'An error occurred';
    details = undefined;
  }

  return {
    success: false,
    error: {
      code,
      message,
      ...(details && { details }),
    },
    timestamp: new Date().toISOString(),
    ...(requestId && { requestId }),
  };
}

// ============================================================================
// GLOBAL ERROR HANDLER
// ============================================================================

/**
 * Global error handler for Fastify
 */
export function globalErrorHandler(
  error: FastifyError | Error,
  request: FastifyRequest,
  reply: FastifyReply
): void {
  const requestId = request.headers['x-request-id'] as string | undefined;

  // Log error
  const logData = {
    requestId,
    url: request.url,
    method: request.method,
    ip: request.ip,
    userId: request.user?.id,
    errorName: error.name,
    errorMessage: error.message,
    stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined,
  };

  // Determine if operational error
  const isOperational = error instanceof AppError ? error.isOperational : false;
  
  if (isOperational) {
    log.warn(logData, 'Operational error');
  } else {
    log.error(logData, 'Unexpected error');
  }

  // Build response
  const response = buildErrorResponse(error, requestId);

  // Determine status code
  let statusCode = 500;
  if (error instanceof AppError) {
    statusCode = error.statusCode;
  } else if ('statusCode' in error && typeof error.statusCode === 'number') {
    statusCode = error.statusCode;
  }

  reply.status(statusCode).send(response);
}

// ============================================================================
// PLUGIN REGISTRATION
// ============================================================================

/**
 * Register error handling plugin
 */
export async function registerErrorHandlingPlugin(
  fastify: FastifyInstance
): Promise<void> {
  // Set error handler
  fastify.setErrorHandler(globalErrorHandler);

  // Handle not found
  fastify.setNotFoundHandler((request, reply) => {
    log.debug({
      url: request.url,
      method: request.method,
      ip: request.ip,
    }, 'Route not found');

    reply.status(404).send({
      success: false,
      error: {
        code: ErrorCodes.NOT_FOUND,
        message: `Route ${request.method} ${request.url} not found`,
      },
      timestamp: new Date().toISOString(),
    });
  });

  log.info('Error handling plugin registered');
}

// ============================================================================
// ERROR FACTORY FUNCTIONS
// ============================================================================

/**
 * Create unauthorized error
 */
export function unauthorized(message?: string): AppError {
  return new AppError(
    ErrorCodes.UNAUTHORIZED,
    message || 'Authentication required',
    401
  );
}

/**
 * Create forbidden error
 */
export function forbidden(message?: string): AppError {
  return new AppError(
    ErrorCodes.FORBIDDEN,
    message || 'Access denied',
    403
  );
}

/**
 * Create not found error
 */
export function notFound(resource?: string): AppError {
  return new AppError(
    ErrorCodes.NOT_FOUND,
    resource ? `${resource} not found` : 'Resource not found',
    404
  );
}

/**
 * Create validation error
 */
export function validationError(details: unknown): AppError {
  return new AppError(
    ErrorCodes.VALIDATION_ERROR,
    'Validation failed',
    400,
    details
  );
}

/**
 * Create internal error
 */
export function internalError(message?: string): AppError {
  return new AppError(
    ErrorCodes.INTERNAL_ERROR,
    message || 'An internal error occurred',
    500
  );
}
