/**
 * R.Y.Z.E.N.A. - Phase 7: Environment Validation
 * Strict environment variable validation using Zod
 */

import { z } from 'zod';
import { logger } from '../shared/logger.js';

// ============================================================================
// ENVIRONMENT SCHEMAS
// ============================================================================

/**
 * Base environment schema (required in all environments)
 */
const baseEnvSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().min(1).max(65535).default(3001),
  HOST: z.string().default('0.0.0.0'),
  
  // Database
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  
  // Security
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters').optional(),
  ENCRYPTION_KEY: z.string().length(64, 'ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)').optional(),
  
  // Rate limiting
  RATE_LIMIT_ENABLED: z.coerce.boolean().default(true),
  RATE_LIMIT_MAX: z.coerce.number().min(1).default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().min(1000).default(60000),
  
  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  LOG_PRETTY: z.coerce.boolean().default(false),
  
  // Ollama
  OLLAMA_ENABLED: z.coerce.boolean().default(true),
  OLLAMA_BASE_URL: z.string().url().default('http://localhost:11434'),
  OLLAMA_MODEL: z.string().default('llama3.2'),
  OLLAMA_TIMEOUT: z.coerce.number().min(1000).default(120000),
  OLLAMA_TEMPERATURE: z.coerce.number().min(0).max(2).default(0.3),
  OLLAMA_MAX_TOKENS: z.coerce.number().min(1).max(8192).default(2048),
  
  // CORS
  CORS_ORIGINS: z.string().default(''),
  
  // Feature flags
  AUDIT_LOGGING_ENABLED: z.coerce.boolean().default(true),
  ADMIN_REQUIRES_AUTH: z.coerce.boolean().default(true),
});

/**
 * Production-specific requirements
 */
const productionEnvSchema = baseEnvSchema.extend({
  JWT_SECRET: z.string().min(64, 'JWT_SECRET must be at least 64 characters in production'),
  JWT_REFRESH_SECRET: z.string().min(64, 'JWT_REFRESH_SECRET is required in production'),
  ENCRYPTION_KEY: z.string().length(64, 'ENCRYPTION_KEY is required in production'),
  CORS_ORIGINS: z.string().min(1, 'CORS_ORIGINS must be configured in production'),
  DATABASE_URL: z.string().includes('ssl=true', { message: 'Database SSL must be enabled in production' }).or(
    z.string().includes('sslmode=require')
  ),
});

/**
 * Development-specific defaults
 */
const developmentEnvSchema = baseEnvSchema.extend({
  JWT_SECRET: z.string().min(32).default('dev-secret-key-minimum-32-characters-long'),
  JWT_REFRESH_SECRET: z.string().min(32).optional(),
  ENCRYPTION_KEY: z.string().length(64).optional(),
});

// ============================================================================
// ENVIRONMENT TYPE
// ============================================================================

export type Environment = z.infer<typeof baseEnvSchema>;

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/**
 * Get the appropriate schema based on NODE_ENV
 */
function getEnvSchema(): z.ZodType<Environment> {
  const nodeEnv = process.env.NODE_ENV || 'development';
  
  switch (nodeEnv) {
    case 'production':
      return productionEnvSchema;
    case 'test':
      return baseEnvSchema;
    case 'development':
    default:
      return developmentEnvSchema;
  }
}

/**
 * Validate environment variables
 * Throws on failure - application should not start with invalid config
 */
export function validateEnvironment(): Environment {
  const schema = getEnvSchema();
  
  const result = schema.safeParse(process.env);
  
  if (!result.success) {
    const errors = result.error.issues.map((issue) => ({
      path: issue.path.join('.'),
      message: issue.message,
    }));
    
    // Log errors before failing
    console.error('❌ Environment validation failed:');
    for (const error of errors) {
      console.error(`  - ${error.path}: ${error.message}`);
    }
    
    throw new Error(
      `Environment validation failed:\n${errors.map((e) => `  ${e.path}: ${e.message}`).join('\n')}`
    );
  }
  
  return result.data;
}

/**
 * Check if running in production
 */
export function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

/**
 * Check if running in development
 */
export function isDevelopment(): boolean {
  return process.env.NODE_ENV === 'development' || !process.env.NODE_ENV;
}

/**
 * Check if running in test
 */
export function isTest(): boolean {
  return process.env.NODE_ENV === 'test';
}

/**
 * Get validated environment with logging
 */
export function getValidatedEnv(): Environment {
  try {
    const env = validateEnvironment();
    
    // Log sanitized config (no secrets)
    logger.info({
      action: 'environment_validated',
      nodeEnv: env.NODE_ENV,
      port: env.PORT,
      ollamaEnabled: env.OLLAMA_ENABLED,
      rateLimitEnabled: env.RATE_LIMIT_ENABLED,
      auditEnabled: env.AUDIT_LOGGING_ENABLED,
    });
    
    return env;
  } catch (error) {
    logger.fatal({
      action: 'environment_validation_failed',
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

// ============================================================================
// REQUIRED ENVIRONMENT CHECKLIST
// ============================================================================

export const REQUIRED_ENV_VARS = {
  always: [
    'DATABASE_URL',
    'JWT_SECRET',
  ],
  production: [
    'DATABASE_URL',
    'JWT_SECRET',
    'JWT_REFRESH_SECRET',
    'ENCRYPTION_KEY',
    'CORS_ORIGINS',
  ],
};

/**
 * Print environment checklist for deployment
 */
export function printEnvChecklist(): void {
  console.log('\n📋 R.Y.Z.E.N.A. Environment Checklist\n');
  console.log('Required variables:');
  for (const varName of REQUIRED_ENV_VARS.always) {
    const isSet = !!process.env[varName];
    console.log(`  ${isSet ? '✅' : '❌'} ${varName}`);
  }
  
  if (isProduction()) {
    console.log('\nProduction-specific:');
    for (const varName of REQUIRED_ENV_VARS.production) {
      if (!REQUIRED_ENV_VARS.always.includes(varName)) {
        const isSet = !!process.env[varName];
        console.log(`  ${isSet ? '✅' : '❌'} ${varName}`);
      }
    }
  }
  console.log('');
}

// ============================================================================
// SECURE DEFAULTS
// ============================================================================

/**
 * Generate secure random string for development
 * NOT for production use
 */
export function generateDevSecret(length: number = 64): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
