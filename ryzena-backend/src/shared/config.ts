/**
 * R.Y.Z.E.N.A. - Centralized Configuration
 * 
 * Environment-based configuration with type-safe defaults.
 * All configuration values are loaded from environment variables.
 */

import 'dotenv/config';

export interface RyzenaConfig {
  /** Server configuration */
  server: {
    port: number;
    host: string;
    env: 'development' | 'production' | 'test';
  };
  
  /** Logging configuration */
  logging: {
    level: string;
  };
  
  /** Rate limiting configuration */
  rateLimit: {
    max: number;
    windowMs: number;
  };
  
  /** Security thresholds for threat detection */
  thresholds: {
    phishing: number;
    urlHighRisk: number;
  };
  
  /** AI service configuration (Phase 3) */
  aiService: {
    url: string;
    enabled: boolean;
  };
}

/**
 * Parse environment variable as number with fallback
 */
function parseEnvNumber(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? fallback : parsed;
}

/**
 * Parse environment variable as boolean
 */
function parseEnvBoolean(value: string | undefined, fallback: boolean): boolean {
  if (!value) return fallback;
  return value.toLowerCase() === 'true';
}

/**
 * Validate NODE_ENV value
 */
function parseNodeEnv(value: string | undefined): 'development' | 'production' | 'test' {
  const validEnvs = ['development', 'production', 'test'] as const;
  if (value && validEnvs.includes(value as typeof validEnvs[number])) {
    return value as typeof validEnvs[number];
  }
  return 'development';
}

/**
 * Global application configuration
 */
export const config: RyzenaConfig = {
  server: {
    port: parseEnvNumber(process.env.PORT, 3001),
    host: process.env.HOST || '0.0.0.0',
    env: parseNodeEnv(process.env.NODE_ENV),
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
  },
  rateLimit: {
    max: parseEnvNumber(process.env.RATE_LIMIT_MAX, 100),
    windowMs: parseEnvNumber(process.env.RATE_LIMIT_WINDOW_MS, 60000),
  },
  thresholds: {
    phishing: parseFloat(process.env.PHISHING_THRESHOLD || '0.7'),
    urlHighRisk: parseFloat(process.env.URL_HIGH_RISK_THRESHOLD || '0.8'),
  },
  aiService: {
    url: process.env.AI_SERVICE_URL || 'http://localhost:11434',
    enabled: parseEnvBoolean(process.env.AI_SERVICE_ENABLED, false),
  },
};

export default config;
