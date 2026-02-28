/**
 * R.Y.Z.E.N.A. - Email Controller
 * 
 * HTTP request handler for email webhook endpoint.
 * Controllers handle HTTP concerns only - no business logic.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import { createLogger } from '../../shared/logger.js';
import { isRyzenaError } from '../../shared/errors.js';
import { safeValidateEmailWebhook, formatZodErrors } from '../../shared/validation.js';
import { processEmail } from './email.service.js';
import type { RawEmailInput, EmailProcessingResult } from './email.types.js';

const logger = createLogger({ module: 'email-controller' });

/**
 * Webhook request body type
 */
interface WebhookRequestBody {
  sender: string;
  recipient: string;
  subject: string;
  body_html: string;
  body_text: string;
  attachments: Array<{
    filename: string;
    content_type?: string;
    size?: number;
    content_id?: string;
    content?: string;
  }>;
  headers: Record<string, unknown>;
  timestamp?: string;
}

/**
 * API response structure
 */
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  meta?: {
    requestId: string;
    timestamp: string;
    processingTimeMs?: number;
  };
}

/**
 * Generate request ID for tracing
 */
function generateRequestId(): string {
  return `req_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Handle email webhook POST request
 * POST /api/v1/email/webhook
 */
export async function handleWebhook(
  request: FastifyRequest<{ Body: WebhookRequestBody }>,
  reply: FastifyReply
): Promise<ApiResponse<EmailProcessingResult>> {
  const requestId = generateRequestId();
  const startTime = Date.now();
  
  logger.info({
    action: 'webhook_received',
    requestId,
    ip: request.ip,
    userAgent: request.headers['user-agent'],
  });
  
  try {
    // Validate request body
    const validationResult = safeValidateEmailWebhook(request.body);
    
    if (!validationResult.success) {
      const formattedErrors = formatZodErrors(validationResult.error);
      
      logger.warn({
        action: 'validation_failed',
        requestId,
        errors: formattedErrors,
      });
      
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request body',
          details: formattedErrors,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
        },
      };
      
      return reply.status(400).send(errorResponse);
    }
    
    // Convert to internal format
    const rawEmail: RawEmailInput = {
      sender: validationResult.data.sender,
      recipient: validationResult.data.recipient,
      subject: validationResult.data.subject,
      body_html: validationResult.data.body_html,
      body_text: validationResult.data.body_text,
      attachments: validationResult.data.attachments,
      headers: validationResult.data.headers,
      timestamp: validationResult.data.timestamp,
    };
    
    // Process email through threat detection pipeline
    const result = await processEmail(rawEmail);
    
    const processingTimeMs = Date.now() - startTime;
    
    logger.info({
      action: 'webhook_processed',
      requestId,
      emailId: result.emailId,
      status: result.status,
      trustScore: result.trustScore,
      processingTimeMs,
    });
    
    const response: ApiResponse<EmailProcessingResult> = {
      success: true,
      data: result,
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        processingTimeMs,
      },
    };
    
    return reply.status(200).send(response);
  } catch (error) {
    const processingTimeMs = Date.now() - startTime;
    
    logger.error({
      action: 'webhook_error',
      requestId,
      error: error instanceof Error ? error.message : String(error),
      processingTimeMs,
    });
    
    if (isRyzenaError(error)) {
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: error.code,
          message: error.message,
          details: error.details,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          processingTimeMs,
        },
      };
      
      return reply.status(error.statusCode).send(errorResponse);
    }
    
    // Unknown error
    const errorResponse: ApiResponse<never> = {
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        processingTimeMs,
      },
    };
    
    return reply.status(500).send(errorResponse);
  }
}

/**
 * Health check endpoint handler
 * GET /api/v1/email/health
 */
export async function handleHealthCheck(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const response = {
    status: 'healthy',
    service: 'ryzena-email-service',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
  };
  
  return reply.status(200).send(response);
}

export default {
  handleWebhook,
  handleHealthCheck,
};
