/**
 * R.Y.Z.E.N.A. - MCP Context Types
 * 
 * Type definitions for the Model Context Protocol layer.
 */

/**
 * Complete MCP context bundle for LLM
 */
export interface MCPContextBundle {
  /** Version of the context schema */
  schemaVersion: string;
  /** Timestamp when context was generated */
  generatedAt: string;
  /** Email context */
  email: MCPEmailContext;
  /** Security analysis context */
  security: MCPSecurityContext;
  /** User context */
  user: MCPUserContext;
  /** System context */
  system: MCPSystemContext;
}

/**
 * Email-specific context
 */
export interface MCPEmailContext {
  id: string;
  sender: {
    address: string;
    domain: string;
    displayName?: string;
  };
  recipient: {
    address: string;
    domain: string;
  };
  subject: string;
  bodyPreview: string;
  bodyLength: number;
  urls: {
    count: number;
    domains: string[];
  };
  attachments: {
    count: number;
    types: string[];
    names: string[];
  };
  headers: {
    replyTo?: string;
    returnPath?: string;
    hasAuthFailures: boolean;
  };
  receivedAt: string;
}

/**
 * Security analysis context
 */
export interface MCPSecurityContext {
  verdict: 'SAFE' | 'SUSPICIOUS';
  trustScore: number;
  phishing: {
    probability: number;
    signals: string[];
    signalCount: number;
  };
  urls: {
    scanned: number;
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
    findings: MCPURLFinding[];
  };
  malware: {
    detected: boolean;
    flaggedFiles: string[];
    risks: string[];
  };
  actions: string[];
}

/**
 * URL finding in MCP format
 */
export interface MCPURLFinding {
  url: string;
  domain: string;
  riskLevel: 'low' | 'medium' | 'high';
  reasons: string[];
}

/**
 * User context (stub for future)
 */
export interface MCPUserContext {
  type: 'student' | 'faculty' | 'staff' | 'unknown';
  department?: string;
  experienceLevel: 'novice' | 'intermediate' | 'expert';
  preferredLanguage: string;
  accessLevel: 'standard' | 'elevated';
}

/**
 * System context
 */
export interface MCPSystemContext {
  serviceName: string;
  version: string;
  environment: string;
  capabilities: string[];
  constraints: string[];
}

/**
 * Context access permissions
 */
export interface MCPContextPermissions {
  canAccessFullEmail: boolean;
  canAccessUserProfile: boolean;
  canAccessHistoricalData: boolean;
  canAccessSensitiveFields: boolean;
}

/**
 * Context request options
 */
export interface MCPContextOptions {
  /** Include full email body */
  includeFullBody?: boolean;
  /** Include URL details */
  includeUrlDetails?: boolean;
  /** Include attachment content */
  includeAttachmentDetails?: boolean;
  /** Permissions for context access */
  permissions?: MCPContextPermissions;
}
