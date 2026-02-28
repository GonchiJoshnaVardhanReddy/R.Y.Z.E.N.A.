/**
 * R.Y.Z.E.N.A. - Validation Schemas
 * 
 * Zod schemas for request validation.
 * All API inputs are validated before processing.
 */

import { z } from 'zod';

/**
 * Attachment schema for email attachments
 */
export const AttachmentSchema = z.object({
  filename: z.string().min(1, 'Filename is required'),
  content_type: z.string().optional(),
  size: z.number().int().positive().optional(),
  content_id: z.string().optional(),
  content: z.string().optional(), // Base64 encoded content
});

/**
 * Email webhook request schema
 */
export const EmailWebhookSchema = z.object({
  sender: z.string().email('Invalid sender email address'),
  recipient: z.string().email('Invalid recipient email address'),
  subject: z.string().min(1, 'Subject is required').max(1000, 'Subject too long'),
  body_html: z.string().default(''),
  body_text: z.string().default(''),
  attachments: z.array(AttachmentSchema).default([]),
  headers: z.record(z.string(), z.unknown()).default({}),
  timestamp: z.string().datetime({ message: 'Invalid timestamp format' }).optional(),
});

/**
 * Type inference for email webhook request
 */
export type EmailWebhookRequest = z.infer<typeof EmailWebhookSchema>;

/**
 * Type inference for attachment
 */
export type AttachmentInput = z.infer<typeof AttachmentSchema>;

/**
 * Validate email webhook request
 * @param data - Raw request data
 * @returns Validated data or throws ValidationError
 */
export function validateEmailWebhook(data: unknown): EmailWebhookRequest {
  return EmailWebhookSchema.parse(data);
}

/**
 * Safe validation that returns result object instead of throwing
 */
export function safeValidateEmailWebhook(data: unknown): z.SafeParseReturnType<unknown, EmailWebhookRequest> {
  return EmailWebhookSchema.safeParse(data);
}

/**
 * Format Zod validation errors for API response
 */
export function formatZodErrors(error: z.ZodError): Record<string, string[]> {
  const formattedErrors: Record<string, string[]> = {};
  
  for (const issue of error.issues) {
    const path = issue.path.join('.') || 'root';
    if (!formattedErrors[path]) {
      formattedErrors[path] = [];
    }
    formattedErrors[path].push(issue.message);
  }
  
  return formattedErrors;
}

export default {
  EmailWebhookSchema,
  AttachmentSchema,
  validateEmailWebhook,
  safeValidateEmailWebhook,
  formatZodErrors,
};
