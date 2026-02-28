/**
 * R.Y.Z.E.N.A. - AI Module Types
 * 
 * Type definitions for the AI Intelligence Layer.
 */

import type { SecurityAnalysisResult } from '../threat/threat.types.js';

/**
 * Quiz question with multiple choice answers
 */
export interface QuizQuestion {
  /** The quiz question text */
  question: string;
  /** Multiple choice options */
  options: string[];
  /** Index of the correct answer (0-based) */
  correctIndex: number;
  /** Explanation of why this is correct */
  explanation?: string;
}

/**
 * AI-generated explanation result
 */
export interface AIExplanationResult {
  /** Email identifier from the analysis */
  emailId: string;
  /** Human-readable explanation of the threat */
  explanation: string;
  /** Key suspicious signals highlighted */
  suspiciousHighlights: string[];
  /** Educational breakdown for students */
  educationalBreakdown: string[];
  /** Quiz question for learning */
  quiz: QuizQuestion;
  /** Confidence score of the AI analysis */
  confidence: number;
  /** Processing metadata */
  metadata: AIProcessingMetadata;
}

/**
 * AI processing metadata
 */
export interface AIProcessingMetadata {
  /** Model used for generation */
  model: string;
  /** Total processing time in milliseconds */
  processingTimeMs: number;
  /** Number of RAG documents retrieved */
  ragDocumentsUsed: number;
  /** Token count (if available) */
  tokenCount?: number;
  /** Timestamp of analysis */
  analyzedAt: string;
}

/**
 * RAG retrieved document
 */
export interface RAGDocument {
  /** Document content */
  content: string;
  /** Relevance score */
  score: number;
  /** Source file or reference */
  source: string;
  /** Document metadata */
  metadata?: Record<string, unknown>;
}

/**
 * RAG query result
 */
export interface RAGQueryResult {
  /** Retrieved documents */
  documents: RAGDocument[];
  /** Query that was used */
  query: string;
  /** Processing time */
  processingTimeMs: number;
}

/**
 * MCP Context for LLM
 */
export interface MCPContext {
  /** Email summary */
  emailSummary: EmailSummaryContext;
  /** Threat signals */
  threatSignals: ThreatSignalsContext;
  /** URL analysis */
  urlAnalysis: URLAnalysisContext;
  /** Attachment analysis */
  attachmentAnalysis: AttachmentAnalysisContext;
  /** User profile (stub) */
  userProfile: UserProfileContext;
}

/**
 * Email summary context
 */
export interface EmailSummaryContext {
  emailId: string;
  sender: string;
  senderDomain: string;
  recipient: string;
  subject: string;
  bodyPreview: string;
  urlCount: number;
  attachmentCount: number;
  timestamp: string;
}

/**
 * Threat signals context
 */
export interface ThreatSignalsContext {
  overallStatus: 'SAFE' | 'SUSPICIOUS';
  trustScore: number;
  phishingProbability: number;
  phishingSignals: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * URL analysis context
 */
export interface URLAnalysisContext {
  totalUrls: number;
  highRiskUrls: number;
  mediumRiskUrls: number;
  findings: Array<{
    url: string;
    riskLevel: string;
    reason: string;
  }>;
}

/**
 * Attachment analysis context
 */
export interface AttachmentAnalysisContext {
  totalAttachments: number;
  flaggedAttachments: number;
  flaggedFiles: string[];
  risks: string[];
}

/**
 * User profile context (stub for future implementation)
 */
export interface UserProfileContext {
  userType: 'student' | 'faculty' | 'staff' | 'unknown';
  department?: string;
  riskTolerance: 'low' | 'medium' | 'high';
  previousIncidents: number;
}

/**
 * Prompt template for AI explanation
 */
export interface PromptTemplate {
  systemPrompt: string;
  userPrompt: string;
  maxTokens: number;
  temperature: number;
}

/**
 * AI service request
 */
export interface AIExplanationRequest {
  securityAnalysisResult: SecurityAnalysisResult;
  options?: AIExplanationOptions;
}

/**
 * AI explanation options
 */
export interface AIExplanationOptions {
  /** Override model */
  model?: string;
  /** Include quiz */
  includeQuiz?: boolean;
  /** Verbosity level */
  verbosity?: 'brief' | 'standard' | 'detailed';
  /** Language for explanation */
  language?: string;
}

/**
 * Knowledge document for RAG
 */
export interface KnowledgeDocument {
  id: string;
  title: string;
  content: string;
  category: 'phishing_patterns' | 'scam_templates' | 'university_policy' | 'historical_examples';
  tags: string[];
  source?: string;
  createdAt: string;
}

/**
 * Vector store document
 */
export interface VectorDocument {
  id: string;
  content: string;
  embedding?: number[];
  metadata: {
    source: string;
    category: string;
    chunkIndex: number;
    totalChunks: number;
  };
}

/**
 * LLM raw response parsing result
 */
export interface ParsedLLMResponse {
  explanation: string;
  highlights: string[];
  educationalPoints: string[];
  quiz: {
    question: string;
    options: string[];
    correctIndex: number;
    explanation?: string;
  } | null;
  confidence: number;
  parseSuccess: boolean;
  rawResponse?: string;
}
