/**
 * R.Y.Z.E.N.A. - AI Routes
 * 
 * API route definitions for AI explanation endpoints.
 */

import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { handleExplain, handleAIHealth } from '../modules/ai/ai.controller.js';

/**
 * AI routes plugin
 */
export async function aiRoutes(
  fastify: FastifyInstance,
  _opts: FastifyPluginOptions
): Promise<void> {
  /**
   * POST /explain
   * Generate AI explanation for security analysis result
   */
  fastify.post('/explain', {
    schema: {
      description: 'Generate AI-powered explanation for email security analysis',
      tags: ['ai'],
      body: {
        type: 'object',
        required: ['securityAnalysisResult'],
        properties: {
          securityAnalysisResult: {
            type: 'object',
            required: ['emailId', 'status', 'trustScore'],
            properties: {
              emailId: { type: 'string' },
              status: { type: 'string', enum: ['SAFE', 'SUSPICIOUS'] },
              trustScore: { type: 'number', minimum: 0, maximum: 100 },
              phishingSignals: { type: 'array', items: { type: 'string' } },
              phishingProbability: { type: 'number', minimum: 0, maximum: 1 },
              urlFindings: { type: 'array' },
              malwareFindings: { type: 'object' },
              sanitizedBody: { type: 'string' },
              originalBody: { type: 'string' },
              securityFlag: { type: 'boolean' },
              analyzedAt: { type: 'string' },
              actionsTaken: { type: 'array', items: { type: 'string' } },
            },
          },
          options: {
            type: 'object',
            properties: {
              model: { type: 'string' },
              includeQuiz: { type: 'boolean', default: true },
              verbosity: { type: 'string', enum: ['brief', 'standard', 'detailed'], default: 'standard' },
              language: { type: 'string', default: 'en' },
            },
          },
        },
      },
      response: {
        200: {
          description: 'Successful AI explanation',
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                emailId: { type: 'string' },
                explanation: { type: 'string' },
                suspiciousHighlights: { type: 'array', items: { type: 'string' } },
                educationalBreakdown: { type: 'array', items: { type: 'string' } },
                quiz: {
                  type: 'object',
                  properties: {
                    question: { type: 'string' },
                    options: { type: 'array', items: { type: 'string' } },
                    correctIndex: { type: 'number' },
                    explanation: { type: 'string' },
                  },
                },
                confidence: { type: 'number' },
                metadata: { type: 'object' },
              },
            },
            meta: { type: 'object' },
          },
        },
        400: {
          description: 'Validation error',
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'object' },
            meta: { type: 'object' },
          },
        },
        500: {
          description: 'Internal server error',
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'object' },
            meta: { type: 'object' },
          },
        },
      },
    },
  }, handleExplain);

  /**
   * GET /health
   * AI service health check
   */
  fastify.get('/health', {
    schema: {
      description: 'AI service health check including Ollama and RAG status',
      tags: ['health'],
      response: {
        200: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            service: { type: 'string' },
            version: { type: 'string' },
            timestamp: { type: 'string' },
            components: {
              type: 'object',
              properties: {
                ollama: { type: 'object' },
                rag: { type: 'object' },
              },
            },
          },
        },
      },
    },
  }, handleAIHealth);
}

export default aiRoutes;
