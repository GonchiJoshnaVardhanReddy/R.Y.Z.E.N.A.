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
  
  /** Ollama LLM configuration */
  ollama: {
    baseUrl: string;
    model: string;
    embeddingModel: string;
    timeout: number;
    temperature: number;
    maxTokens: number;
    enabled: boolean;
  };
  
  /** RAG configuration */
  rag: {
    knowledgePath: string;
    vectorStorePath: string;
    chunkSize: number;
    chunkOverlap: number;
    topK: number;
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
 * Parse environment variable as float with fallback
 */
function parseEnvFloat(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = parseFloat(value);
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
    phishing: parseEnvFloat(process.env.PHISHING_THRESHOLD, 0.7),
    urlHighRisk: parseEnvFloat(process.env.URL_HIGH_RISK_THRESHOLD, 0.8),
  },
  ollama: {
    baseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
    model: process.env.OLLAMA_MODEL || 'llama3.2',
    embeddingModel: process.env.OLLAMA_EMBEDDING_MODEL || 'nomic-embed-text',
    timeout: parseEnvNumber(process.env.OLLAMA_TIMEOUT, 120000),
    temperature: parseEnvFloat(process.env.OLLAMA_TEMPERATURE, 0.3),
    maxTokens: parseEnvNumber(process.env.OLLAMA_MAX_TOKENS, 2048),
    enabled: parseEnvBoolean(process.env.OLLAMA_ENABLED, true),
  },
  rag: {
    knowledgePath: process.env.RAG_KNOWLEDGE_PATH || './knowledge',
    vectorStorePath: process.env.RAG_VECTOR_STORE_PATH || './data/vectors',
    chunkSize: parseEnvNumber(process.env.RAG_CHUNK_SIZE, 500),
    chunkOverlap: parseEnvNumber(process.env.RAG_CHUNK_OVERLAP, 50),
    topK: parseEnvNumber(process.env.RAG_TOP_K, 3),
  },
};

export default config;
