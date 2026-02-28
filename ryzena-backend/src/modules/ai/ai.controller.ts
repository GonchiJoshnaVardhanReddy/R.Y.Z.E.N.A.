/**
 * R.Y.Z.E.N.A. - AI Controller
 * 
 * HTTP request handler for AI explanation endpoints.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import { createLogger } from '../../shared/logger.js';
import { isRyzenaError } from '../../shared/errors.js';
import { generateExplanation, checkAIHealth } from './ai.service.js';
import { getRAGHealth } from '../rag/rag.service.js';
import type { SecurityAnalysisResult } from '../threat/threat.types.js';
import type { AIExplanationResult, AIExplanationOptions } from './ai.types.js';
import { z } from 'zod';

const logger = createLogger({ module: 'ai-controller' });

/**
 * Request validation schema for AI explanation
 */
const AIExplanationRequestSchema = z.object({
  securityAnalysisResult: z.object({
    emailId: z.string(),
    status: z.enum(['SAFE', 'SUSPICIOUS']),
    trustScore: z.number().min(0).max(100),
    phishingSignals: z.array(z.string()),
    phishingProbability: z.number().min(0).max(1),
    urlFindings: z.array(z.object({
      url: z.string(),
      riskLevel: z.enum(['low', 'medium', 'high']),
      reason: z.string(),
    })),
    malwareFindings: z.object({
      hasRisk: z.boolean(),
      flaggedFiles: z.array(z.string()),
      findings: z.array(z.any()).optional(),
    }),
    sanitizedBody: z.string(),
    originalBody: z.string(),
    securityFlag: z.boolean(),
    analyzedAt: z.string(),
    actionsTaken: z.array(z.string()),
  }),
  options: z.object({
    model: z.string().optional(),
    includeQuiz: z.boolean().optional(),
    verbosity: z.enum(['brief', 'standard', 'detailed']).optional(),
    language: z.string().optional(),
  }).optional(),
});

type AIExplanationRequestBody = z.infer<typeof AIExplanationRequestSchema>;

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
 * Generate request ID
 */
function generateRequestId(): string {
  return `ai_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Handle AI explanation request
 * POST /api/v1/ai/explain
 */
export async function handleExplain(
  request: FastifyRequest<{ Body: AIExplanationRequestBody }>,
  reply: FastifyReply
): Promise<ApiResponse<AIExplanationResult>> {
  const requestId = generateRequestId();
  const startTime = Date.now();
  
  logger.info({
    action: 'ai_explain_request',
    requestId,
    ip: request.ip,
  });
  
  try {
    // Validate request
    const validationResult = AIExplanationRequestSchema.safeParse(request.body);
    
    if (!validationResult.success) {
      const errors = validationResult.error.flatten();
      
      logger.warn({
        action: 'validation_failed',
        requestId,
        errors,
      });
      
      return reply.status(400).send({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request body',
          details: errors,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
        },
      });
    }
    
    const { securityAnalysisResult, options } = validationResult.data;
    
    // Generate explanation
    const result = await generateExplanation({
      securityAnalysisResult: securityAnalysisResult as SecurityAnalysisResult,
      options: options as AIExplanationOptions,
    });
    
    const processingTimeMs = Date.now() - startTime;
    
    logger.info({
      action: 'ai_explain_complete',
      requestId,
      emailId: result.emailId,
      confidence: result.confidence,
      processingTimeMs,
    });
    
    return reply.status(200).send({
      success: true,
      data: result,
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        processingTimeMs,
      },
    });
  } catch (error) {
    const processingTimeMs = Date.now() - startTime;
    
    logger.error({
      action: 'ai_explain_error',
      requestId,
      error: error instanceof Error ? error.message : String(error),
      processingTimeMs,
    });
    
    if (isRyzenaError(error)) {
      return reply.status(error.statusCode).send({
        success: false,
        error: {
          code: error.code,
          message: error.message,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          processingTimeMs,
        },
      });
    }
    
    return reply.status(500).send({
      success: false,
      error: {
        code: 'AI_SERVICE_ERROR',
        message: 'Failed to generate AI explanation',
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        processingTimeMs,
      },
    });
  }
}

/**
 * Handle AI health check
 * GET /api/v1/ai/health
 */
export async function handleAIHealth(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const aiHealth = await checkAIHealth();
  const ragHealth = getRAGHealth();
  
  const status = aiHealth.available && ragHealth.initialized ? 'healthy' : 'degraded';
  
  return reply.status(status === 'healthy' ? 200 : 503).send({
    status,
    service: 'ryzena-ai-service',
    version: '3.0.0',
    timestamp: new Date().toISOString(),
    components: {
      ollama: {
        status: aiHealth.ollamaStatus,
        model: aiHealth.model,
        modelAvailable: aiHealth.modelAvailable,
      },
      rag: {
        initialized: ragHealth.initialized,
        documentCount: ragHealth.documentCount,
      },
    },
  });
}

export default {
  handleExplain,
  handleAIHealth,
};
