/**
 * R.Y.Z.E.N.A. - Custom Error Classes
 * 
 * Centralized error handling with typed error classes.
 * All errors include error codes for consistent API responses.
 */

/**
 * Base error class for R.Y.Z.E.N.A. application errors
 */
export class RyzenaError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;
  public readonly timestamp: string;

  constructor(
    message: string,
    code: string,
    statusCode: number = 500,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'RyzenaError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Serialize error for API response
   */
  toJSON(): Record<string, unknown> {
    return {
      error: {
        name: this.name,
        code: this.code,
        message: this.message,
        statusCode: this.statusCode,
        timestamp: this.timestamp,
        ...(this.details && { details: this.details }),
      },
    };
  }
}

/**
 * Validation error for invalid input data
 */
export class ValidationError extends RyzenaError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'VALIDATION_ERROR', 400, details);
    this.name = 'ValidationError';
  }
}

/**
 * Email parsing error
 */
export class EmailParsingError extends RyzenaError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'EMAIL_PARSING_ERROR', 422, details);
    this.name = 'EmailParsingError';
  }
}

/**
 * Threat analysis error
 */
export class ThreatAnalysisError extends RyzenaError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'THREAT_ANALYSIS_ERROR', 500, details);
    this.name = 'ThreatAnalysisError';
  }
}

/**
 * Configuration error
 */
export class ConfigurationError extends RyzenaError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'CONFIGURATION_ERROR', 500, details);
    this.name = 'ConfigurationError';
  }
}

/**
 * Rate limit exceeded error
 */
export class RateLimitError extends RyzenaError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 'RATE_LIMIT_EXCEEDED', 429);
    this.name = 'RateLimitError';
  }
}

/**
 * External service error (for future integrations)
 */
export class ExternalServiceError extends RyzenaError {
  constructor(
    serviceName: string,
    message: string,
    details?: Record<string, unknown>
  ) {
    super(`${serviceName}: ${message}`, 'EXTERNAL_SERVICE_ERROR', 502, details);
    this.name = 'ExternalServiceError';
  }
}

/**
 * Type guard to check if an error is a RyzenaError
 */
export function isRyzenaError(error: unknown): error is RyzenaError {
  return error instanceof RyzenaError;
}

/**
 * Format unknown error for logging
 */
export function formatError(error: unknown): Record<string, unknown> {
  if (isRyzenaError(error)) {
    return error.toJSON();
  }
  
  if (error instanceof Error) {
    return {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
    };
  }
  
  return {
    error: {
      message: String(error),
    },
  };
}

export default {
  RyzenaError,
  ValidationError,
  EmailParsingError,
  ThreatAnalysisError,
  ConfigurationError,
  RateLimitError,
  ExternalServiceError,
  isRyzenaError,
  formatError,
};
