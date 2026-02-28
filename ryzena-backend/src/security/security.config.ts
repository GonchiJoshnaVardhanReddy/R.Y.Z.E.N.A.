/**
 * R.Y.Z.E.N.A. - Phase 7: Security Configuration
 * Centralized security constants and configuration
 */

import { z } from 'zod';

// ============================================================================
// SECURITY CONSTANTS
// ============================================================================

/**
 * User roles in the system
 */
export const UserRole = {
  ADMIN: 'admin',
  STUDENT: 'student',
  SERVICE: 'service',
  SYSTEM: 'system',
} as const;

export type UserRole = (typeof UserRole)[keyof typeof UserRole];

/**
 * Role hierarchy for access control
 */
export const ROLE_HIERARCHY: Record<UserRole, number> = {
  [UserRole.SYSTEM]: 100,
  [UserRole.ADMIN]: 80,
  [UserRole.SERVICE]: 60,
  [UserRole.STUDENT]: 40,
};

/**
 * Permission definitions
 */
export const Permission = {
  // Admin permissions
  ADMIN_READ: 'admin:read',
  ADMIN_WRITE: 'admin:write',
  ADMIN_ANALYTICS: 'admin:analytics',
  
  // Student permissions
  STUDENT_READ: 'student:read',
  STUDENT_WRITE: 'student:write',
  STUDENT_CONSENT: 'student:consent',
  
  // Service permissions
  SERVICE_EMAIL_SCAN: 'service:email_scan',
  SERVICE_AI_EXPLAIN: 'service:ai_explain',
  SERVICE_DATA_ACCESS: 'service:data_access',
  
  // System permissions
  SYSTEM_ALL: 'system:all',
} as const;

export type Permission = (typeof Permission)[keyof typeof Permission];

/**
 * Role to permission mapping
 */
export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  [UserRole.SYSTEM]: Object.values(Permission),
  [UserRole.ADMIN]: [
    Permission.ADMIN_READ,
    Permission.ADMIN_WRITE,
    Permission.ADMIN_ANALYTICS,
    Permission.STUDENT_READ,
  ],
  [UserRole.SERVICE]: [
    Permission.SERVICE_EMAIL_SCAN,
    Permission.SERVICE_AI_EXPLAIN,
    Permission.SERVICE_DATA_ACCESS,
  ],
  [UserRole.STUDENT]: [
    Permission.STUDENT_READ,
    Permission.STUDENT_WRITE,
    Permission.STUDENT_CONSENT,
  ],
};

// ============================================================================
// JWT CONFIGURATION
// ============================================================================

export const JWT_CONFIG = {
  /** Access token expiration (15 minutes) */
  ACCESS_TOKEN_EXPIRY: '15m',
  /** Refresh token expiration (7 days) */
  REFRESH_TOKEN_EXPIRY: '7d',
  /** Token issuer */
  ISSUER: 'ryzena-security-engine',
  /** Token audience */
  AUDIENCE: 'ryzena-api',
  /** Algorithm */
  ALGORITHM: 'HS256' as const,
  /** Clock tolerance in seconds */
  CLOCK_TOLERANCE: 30,
};

/**
 * JWT payload schema
 */
export const JwtPayloadSchema = z.object({
  sub: z.string(),
  role: z.enum([UserRole.ADMIN, UserRole.STUDENT, UserRole.SERVICE, UserRole.SYSTEM]),
  permissions: z.array(z.string()),
  iss: z.string(),
  aud: z.string(),
  iat: z.number(),
  exp: z.number(),
  jti: z.string().optional(),
});

export type JwtPayload = z.infer<typeof JwtPayloadSchema>;

// ============================================================================
// RATE LIMITING CONFIGURATION
// ============================================================================

export const RATE_LIMIT_CONFIG = {
  /** Global rate limit per IP */
  GLOBAL: {
    max: 100,
    windowMs: 60 * 1000, // 1 minute
  },
  /** Auth endpoints */
  AUTH: {
    max: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
  },
  /** AI explanation endpoint */
  AI: {
    max: 10,
    windowMs: 60 * 1000, // 1 minute
  },
  /** Consent endpoints */
  CONSENT: {
    max: 30,
    windowMs: 60 * 1000, // 1 minute
  },
  /** Admin endpoints */
  ADMIN: {
    max: 50,
    windowMs: 60 * 1000, // 1 minute
  },
  /** Email webhook */
  EMAIL: {
    max: 100,
    windowMs: 60 * 1000, // 1 minute
  },
};

// ============================================================================
// REQUEST LIMITS
// ============================================================================

export const REQUEST_LIMITS = {
  /** Maximum request body size (1MB) */
  MAX_BODY_SIZE: 1024 * 1024,
  /** Maximum URL length */
  MAX_URL_LENGTH: 2048,
  /** Maximum header size (8KB) */
  MAX_HEADER_SIZE: 8 * 1024,
  /** Request timeout (30 seconds) */
  REQUEST_TIMEOUT_MS: 30 * 1000,
  /** AI request timeout (120 seconds) */
  AI_REQUEST_TIMEOUT_MS: 120 * 1000,
  /** Maximum array items in request */
  MAX_ARRAY_ITEMS: 100,
  /** Maximum string field length */
  MAX_STRING_LENGTH: 10000,
};

// ============================================================================
// SECURITY HEADERS
// ============================================================================

export const SECURITY_HEADERS = {
  /** Content Security Policy */
  CSP: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  },
  /** Permissions Policy */
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
  },
};

// ============================================================================
// ENCRYPTION CONFIGURATION
// ============================================================================

export const ENCRYPTION_CONFIG = {
  /** Password hashing rounds */
  BCRYPT_ROUNDS: 12,
  /** AES encryption mode */
  AES_MODE: 'aes-256-gcm' as const,
  /** IV length */
  IV_LENGTH: 16,
  /** Auth tag length */
  AUTH_TAG_LENGTH: 16,
  /** Salt length */
  SALT_LENGTH: 32,
};

// ============================================================================
// AUDIT CONFIGURATION
// ============================================================================

export const AUDIT_CONFIG = {
  /** Actions to audit */
  AUDITED_ACTIONS: [
    'auth.login',
    'auth.logout',
    'auth.refresh',
    'auth.failed',
    'consent.request',
    'consent.approve',
    'consent.deny',
    'consent.revoke',
    'admin.access',
    'admin.analytics',
    'service.access',
    'risk.update',
    'threat.detected',
  ],
  /** Fields to redact from logs */
  REDACTED_FIELDS: [
    'password',
    'token',
    'secret',
    'apiKey',
    'authorization',
    'cookie',
    'ssn',
    'creditCard',
  ],
  /** Maximum log retention (days) */
  LOG_RETENTION_DAYS: 90,
};

// ============================================================================
// SENSITIVE FIELDS
// ============================================================================

export const SENSITIVE_FIELDS = [
  'password',
  'passwordHash',
  'token',
  'refreshToken',
  'accessToken',
  'apiKey',
  'secret',
  'ssn',
  'creditCard',
  'cvv',
];

// ============================================================================
// PUBLIC ENDPOINTS (no auth required)
// ============================================================================

export const PUBLIC_ENDPOINTS = [
  '/',
  '/api/v1/health',
  '/api/v1/auth/login',
  '/api/v1/auth/refresh',
];

// ============================================================================
// CORS CONFIGURATION
// ============================================================================

export const CORS_CONFIG = {
  /** Allowed origins (configured via env) */
  origins: [] as string[],
  /** Allowed methods */
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  /** Allowed headers */
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Request-ID',
    'X-API-Key',
  ],
  /** Exposed headers */
  exposedHeaders: [
    'X-Request-ID',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
  ],
  /** Credentials */
  credentials: true,
  /** Max age (24 hours) */
  maxAge: 86400,
};

// ============================================================================
// DATABASE SECURITY
// ============================================================================

export const DATABASE_CONFIG = {
  /** Connection pool size */
  POOL_SIZE: 10,
  /** Connection timeout (ms) */
  CONNECTION_TIMEOUT_MS: 5000,
  /** Query timeout (ms) */
  QUERY_TIMEOUT_MS: 30000,
  /** Idle timeout (ms) */
  IDLE_TIMEOUT_MS: 10000,
};

// ============================================================================
// OLLAMA SECURITY
// ============================================================================

export const OLLAMA_SECURITY = {
  /** Allowed models */
  ALLOWED_MODELS: ['llama3.2', 'llama3.1', 'mistral', 'nomic-embed-text'],
  /** Maximum prompt length */
  MAX_PROMPT_LENGTH: 32000,
  /** Maximum response tokens */
  MAX_RESPONSE_TOKENS: 4096,
  /** Request timeout (ms) */
  REQUEST_TIMEOUT_MS: 120000,
};
