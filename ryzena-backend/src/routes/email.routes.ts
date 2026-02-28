/**
 * R.Y.Z.E.N.A. - Email Routes
 * 
 * API route definitions for email endpoints.
 */

import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import { handleWebhook, handleHealthCheck } from '../modules/email/email.controller.js';

/**
 * Email routes plugin
 */
export async function emailRoutes(
  fastify: FastifyInstance,
  _opts: FastifyPluginOptions
): Promise<void> {
  /**
   * POST /webhook
   * Receives email payloads from university email gateway
   */
  fastify.post('/webhook', {
    schema: {
      description: 'Process email through R.Y.Z.E.N.A. threat detection pipeline',
      tags: ['email'],
      body: {
        type: 'object',
        required: ['sender', 'recipient', 'subject'],
        properties: {
          sender: { type: 'string', format: 'email' },
          recipient: { type: 'string', format: 'email' },
          subject: { type: 'string', minLength: 1, maxLength: 1000 },
          body_html: { type: 'string', default: '' },
          body_text: { type: 'string', default: '' },
          attachments: {
            type: 'array',
            items: {
              type: 'object',
              required: ['filename'],
              properties: {
                filename: { type: 'string' },
                content_type: { type: 'string' },
                size: { type: 'number' },
                content_id: { type: 'string' },
                content: { type: 'string' },
              },
            },
            default: [],
          },
          headers: { type: 'object', default: {} },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      response: {
        200: {
          description: 'Successful security analysis',
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                emailId: { type: 'string' },
                status: { type: 'string', enum: ['SAFE', 'SUSPICIOUS'] },
                trustScore: { type: 'number' },
                processingTimeMs: { type: 'number' },
                analysis: { type: 'object' },
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
  }, handleWebhook);

  /**
   * GET /health
   * Health check endpoint
   */
  fastify.get('/health', {
    schema: {
      description: 'Email service health check',
      tags: ['health'],
      response: {
        200: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            service: { type: 'string' },
            version: { type: 'string' },
            timestamp: { type: 'string' },
          },
        },
      },
    },
  }, handleHealthCheck);
}

export default emailRoutes;
