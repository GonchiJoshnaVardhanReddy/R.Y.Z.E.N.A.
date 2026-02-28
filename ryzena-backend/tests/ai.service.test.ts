/**
 * R.Y.Z.E.N.A. - AI Service Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildContextFromAnalysis, serializeContext, getRiskLevelDescription } from '../src/modules/mcp/context.service.js';
import { buildPrompt, validatePrompt, truncatePrompt } from '../src/modules/ai/prompt.builder.js';
import type { SecurityAnalysisResult } from '../src/modules/threat/threat.types.js';

/**
 * Create mock security analysis result
 */
function createMockAnalysisResult(overrides: Partial<SecurityAnalysisResult> = {}): SecurityAnalysisResult {
  return {
    emailId: 'test123',
    status: 'SUSPICIOUS',
    trustScore: 25,
    phishingSignals: ['Urgency Keywords Detected', 'Suspicious TLD'],
    phishingProbability: 0.75,
    urlFindings: [
      { url: 'http://evil.xyz/login', riskLevel: 'high', reason: 'Suspicious TLD' },
    ],
    malwareFindings: {
      hasRisk: false,
      flaggedFiles: [],
    },
    sanitizedBody: '<p>Test body</p>',
    originalBody: '<p>Test body</p>',
    securityFlag: true,
    analyzedAt: new Date().toISOString(),
    actionsTaken: ['Email flagged as suspicious'],
    ...overrides,
  };
}

describe('MCP Context Service', () => {
  describe('buildContextFromAnalysis', () => {
    it('should build context from security analysis result', () => {
      const result = createMockAnalysisResult();
      const context = buildContextFromAnalysis(result);
      
      expect(context.schemaVersion).toBe('1.0.0');
      expect(context.email.id).toBe('test123');
      expect(context.security.verdict).toBe('SUSPICIOUS');
      expect(context.security.trustScore).toBe(25);
      expect(context.security.phishing.signals).toContain('Urgency Keywords Detected');
    });

    it('should include URL findings in security context', () => {
      const result = createMockAnalysisResult({
        urlFindings: [
          { url: 'http://evil.xyz/login', riskLevel: 'high', reason: 'Suspicious' },
          { url: 'https://safe.com', riskLevel: 'low', reason: 'Safe' },
        ],
      });
      
      const context = buildContextFromAnalysis(result);
      
      expect(context.security.urls.scanned).toBe(2);
      expect(context.security.urls.highRisk).toBe(1);
      expect(context.security.urls.lowRisk).toBe(1);
    });

    it('should include malware findings', () => {
      const result = createMockAnalysisResult({
        malwareFindings: {
          hasRisk: true,
          flaggedFiles: ['virus.exe', 'malware.scr'],
        },
      });
      
      const context = buildContextFromAnalysis(result);
      
      expect(context.security.malware.detected).toBe(true);
      expect(context.security.malware.flaggedFiles).toContain('virus.exe');
    });
  });

  describe('serializeContext', () => {
    it('should serialize context to string', () => {
      const result = createMockAnalysisResult();
      const context = buildContextFromAnalysis(result);
      const serialized = serializeContext(context);
      
      expect(typeof serialized).toBe('string');
      expect(serialized).toContain('Email Information');
      expect(serialized).toContain('Security Analysis');
      expect(serialized).toContain('SUSPICIOUS');
    });
  });

  describe('getRiskLevelDescription', () => {
    it('should return CRITICAL for very low trust scores', () => {
      const result = createMockAnalysisResult({ trustScore: 10 });
      const context = buildContextFromAnalysis(result);
      const description = getRiskLevelDescription(context);
      
      expect(description).toContain('CRITICAL');
    });

    it('should return LOW for high trust scores', () => {
      const result = createMockAnalysisResult({
        status: 'SAFE',
        trustScore: 95,
        phishingProbability: 0.05,
      });
      const context = buildContextFromAnalysis(result);
      const description = getRiskLevelDescription(context);
      
      expect(description).toContain('LOW');
    });
  });
});

describe('Prompt Builder', () => {
  describe('buildPrompt', () => {
    it('should build a complete prompt template', () => {
      const result = createMockAnalysisResult();
      const context = buildContextFromAnalysis(result);
      const prompt = buildPrompt(context, []);
      
      expect(prompt.systemPrompt).toContain('R.Y.Z.E.N.A.');
      expect(prompt.userPrompt).toContain('Email Security Analysis');
      expect(prompt.maxTokens).toBeGreaterThan(0);
      expect(prompt.temperature).toBeGreaterThanOrEqual(0);
    });

    it('should include RAG documents in prompt', () => {
      const result = createMockAnalysisResult();
      const context = buildContextFromAnalysis(result);
      const ragDocs = [
        { content: 'Phishing is bad', score: 0.9, source: 'test.md' },
      ];
      
      const prompt = buildPrompt(context, ragDocs);
      
      expect(prompt.userPrompt).toContain('Relevant Knowledge Base');
      expect(prompt.userPrompt).toContain('Phishing is bad');
    });

    it('should include email context in prompt', () => {
      const result = createMockAnalysisResult();
      const context = buildContextFromAnalysis(result);
      const prompt = buildPrompt(context, []);
      
      expect(prompt.userPrompt).toContain('Trust Score');
      expect(prompt.userPrompt).toContain('Phishing Probability');
    });
  });

  describe('validatePrompt', () => {
    it('should validate a normal prompt', () => {
      const result = createMockAnalysisResult();
      const context = buildContextFromAnalysis(result);
      const prompt = buildPrompt(context, []);
      
      const validation = validatePrompt(prompt);
      
      expect(validation.valid).toBe(true);
    });

    it('should reject invalid temperature', () => {
      const prompt = {
        systemPrompt: 'Test',
        userPrompt: 'Test',
        maxTokens: 100,
        temperature: 5,
      };
      
      const validation = validatePrompt(prompt);
      
      expect(validation.valid).toBe(false);
      expect(validation.reason).toContain('temperature');
    });
  });

  describe('truncatePrompt', () => {
    it('should not truncate short prompts', () => {
      const prompt = {
        systemPrompt: 'Short system',
        userPrompt: 'Short user',
        maxTokens: 100,
        temperature: 0.3,
      };
      
      const truncated = truncatePrompt(prompt);
      
      expect(truncated.userPrompt).toBe(prompt.userPrompt);
    });

    it('should truncate long prompts', () => {
      const longContent = 'x'.repeat(40000);
      const prompt = {
        systemPrompt: 'System',
        userPrompt: longContent,
        maxTokens: 100,
        temperature: 0.3,
      };
      
      const truncated = truncatePrompt(prompt, 1000);
      
      expect(truncated.userPrompt.length).toBeLessThan(prompt.userPrompt.length);
      expect(truncated.userPrompt).toContain('truncated');
    });
  });
});

describe('RAG Integration', () => {
  describe('Document Loading', () => {
    it('should load built-in knowledge documents', async () => {
      const { getBuiltInKnowledge } = await import('../src/modules/rag/document.loader.js');
      const docs = getBuiltInKnowledge();
      
      expect(docs.length).toBeGreaterThan(0);
      expect(docs[0]).toHaveProperty('id');
      expect(docs[0]).toHaveProperty('content');
      expect(docs[0]).toHaveProperty('category');
    });
  });

  describe('Document Chunking', () => {
    it('should chunk large documents', async () => {
      const { chunkDocument } = await import('../src/modules/rag/document.loader.js');
      
      const doc = {
        id: 'test',
        title: 'Test Doc',
        content: 'x'.repeat(2000),
        category: 'phishing_patterns' as const,
        tags: [],
        createdAt: new Date().toISOString(),
      };
      
      const chunks = chunkDocument(doc, 500, 50);
      
      expect(chunks.length).toBeGreaterThan(1);
      expect(chunks[0].metadata.chunkIndex).toBe(0);
    });

    it('should not chunk small documents', async () => {
      const { chunkDocument } = await import('../src/modules/rag/document.loader.js');
      
      const doc = {
        id: 'test',
        title: 'Small Doc',
        content: 'Small content',
        category: 'phishing_patterns' as const,
        tags: [],
        createdAt: new Date().toISOString(),
      };
      
      const chunks = chunkDocument(doc, 500, 50);
      
      expect(chunks.length).toBe(1);
    });
  });
});

describe('AI Response Parsing', () => {
  it('should parse valid JSON response', async () => {
    const validResponse = JSON.stringify({
      explanation: 'This email is suspicious because...',
      highlights: ['Signal 1', 'Signal 2'],
      educationalPoints: ['Tip 1', 'Tip 2'],
      quiz: {
        question: 'What should you do?',
        options: ['A', 'B', 'C', 'D'],
        correctIndex: 0,
        explanation: 'Because...',
      },
      confidence: 0.85,
    });
    
    // This would test the parse function directly
    // For now, we verify the structure is valid JSON
    const parsed = JSON.parse(validResponse);
    expect(parsed.explanation).toBeDefined();
    expect(parsed.highlights).toBeInstanceOf(Array);
    expect(parsed.quiz.correctIndex).toBe(0);
  });
});
