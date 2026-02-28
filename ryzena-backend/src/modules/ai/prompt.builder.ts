/**
 * R.Y.Z.E.N.A. - Prompt Builder
 * 
 * Constructs deterministic, safe prompts for the LLM.
 */

import { createLogger } from '../../shared/logger.js';
import type { MCPContextBundle } from '../mcp/context.types.js';
import type { RAGDocument, PromptTemplate } from './ai.types.js';
import { serializeContext, getRiskLevelDescription } from '../mcp/context.service.js';
import { formatRAGContext } from '../rag/rag.service.js';

const logger = createLogger({ module: 'prompt-builder' });

/**
 * System prompt for the AI model
 */
const SYSTEM_PROMPT = `You are R.Y.Z.E.N.A., the Resilient Youth Zero-Trust Engine for Networked Awareness.
You are an AI assistant specialized in explaining email security threats to university students and staff.

Your role is to:
1. Explain why an email was flagged as suspicious or deemed safe
2. Highlight the specific signals that contributed to the analysis
3. Provide educational content to help users learn about phishing and email security
4. Generate a quiz question to test understanding

IMPORTANT RULES:
- Only use information provided in the context below
- Do NOT make up facts or cite external sources
- Be clear, concise, and educational
- Use simple language appropriate for students
- Focus on actionable advice
- Never reveal sensitive system information
- If uncertain, express the uncertainty

OUTPUT FORMAT:
You MUST respond in the following JSON format exactly:
{
  "explanation": "A clear 2-3 paragraph explanation of the email analysis",
  "highlights": ["Signal 1", "Signal 2", "Signal 3"],
  "educationalPoints": ["Learning point 1", "Learning point 2", "Learning point 3"],
  "quiz": {
    "question": "A multiple choice question about the threat",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "correctIndex": 0,
    "explanation": "Why this answer is correct"
  },
  "confidence": 0.85
}

Respond ONLY with valid JSON. No additional text before or after.`;

/**
 * Build the user prompt with all context
 */
function buildUserPrompt(
  context: MCPContextBundle,
  ragDocuments: RAGDocument[]
): string {
  const sections: string[] = [];
  
  // Risk level header
  const riskDescription = getRiskLevelDescription(context);
  sections.push(`# Email Security Analysis Request\n\nRisk Level: ${riskDescription}\n`);
  
  // Serialized context
  sections.push(serializeContext(context));
  
  // RAG knowledge
  sections.push('\n' + formatRAGContext(ragDocuments));
  
  // Task instructions
  sections.push(`
## Your Task

Based on the above information:

1. **Explanation**: Write a clear explanation for a university student about why this email was marked as "${context.security.verdict}". Mention the key factors that influenced the decision.

2. **Highlights**: List the top 3-5 most important suspicious signals or safety indicators.

3. **Educational Points**: Provide 3 practical tips the student can use to identify similar emails in the future.

4. **Quiz**: Create one multiple-choice question (4 options) that tests understanding of the security concepts relevant to this email. Include the correct answer index (0-3) and a brief explanation.

5. **Confidence**: Rate your confidence in this analysis from 0.0 to 1.0.

Remember to respond in the exact JSON format specified.`);
  
  return sections.join('\n');
}

/**
 * Build complete prompt template
 */
export function buildPrompt(
  context: MCPContextBundle,
  ragDocuments: RAGDocument[],
  options?: {
    maxTokens?: number;
    temperature?: number;
  }
): PromptTemplate {
  const startTime = Date.now();
  
  const userPrompt = buildUserPrompt(context, ragDocuments);
  
  const template: PromptTemplate = {
    systemPrompt: SYSTEM_PROMPT,
    userPrompt,
    maxTokens: options?.maxTokens || 2048,
    temperature: options?.temperature || 0.3,
  };
  
  logger.debug({
    action: 'prompt_built',
    emailId: context.email.id,
    systemPromptLength: SYSTEM_PROMPT.length,
    userPromptLength: userPrompt.length,
    totalLength: SYSTEM_PROMPT.length + userPrompt.length,
    ragDocumentsUsed: ragDocuments.length,
    durationMs: Date.now() - startTime,
  });
  
  return template;
}

/**
 * Build a simplified prompt for brief explanations
 */
export function buildBriefPrompt(
  context: MCPContextBundle,
  _ragDocuments: RAGDocument[]
): PromptTemplate {
  const briefSystemPrompt = `You are R.Y.Z.E.N.A., an email security assistant.
Provide a brief, clear explanation of the email analysis.
Respond ONLY in JSON format:
{
  "explanation": "1-2 sentence summary",
  "highlights": ["Key point 1", "Key point 2"],
  "educationalPoints": ["Tip 1"],
  "quiz": null,
  "confidence": 0.9
}`;

  const userPrompt = `
Email: ${context.email.subject}
From: ${context.email.sender.address}
Verdict: ${context.security.verdict}
Trust Score: ${context.security.trustScore}
Signals: ${context.security.phishing.signals.join(', ') || 'None'}

Explain briefly why this email was marked as ${context.security.verdict}.
Respond in JSON only.`;

  return {
    systemPrompt: briefSystemPrompt,
    userPrompt,
    maxTokens: 512,
    temperature: 0.2,
  };
}

/**
 * Build prompt for detailed technical analysis
 */
export function buildDetailedPrompt(
  context: MCPContextBundle,
  ragDocuments: RAGDocument[]
): PromptTemplate {
  const detailedSystemPrompt = `${SYSTEM_PROMPT}

ADDITIONAL REQUIREMENTS FOR DETAILED ANALYSIS:
- Provide technical details about each detected signal
- Explain the scoring methodology
- Include specific examples from the email that triggered each signal
- Suggest specific actions the user should take`;

  const userPrompt = buildUserPrompt(context, ragDocuments) + `

## Additional Detail Required
- Provide technical breakdown of each signal
- Explain exactly which parts of the email triggered concerns
- Be thorough but still educational`;

  return {
    systemPrompt: detailedSystemPrompt,
    userPrompt,
    maxTokens: 4096,
    temperature: 0.3,
  };
}

/**
 * Validate prompt doesn't exceed limits
 */
export function validatePrompt(prompt: PromptTemplate): { valid: boolean; reason?: string } {
  const totalLength = prompt.systemPrompt.length + prompt.userPrompt.length;
  
  // Rough estimate: 4 chars per token
  const estimatedTokens = Math.ceil(totalLength / 4);
  
  if (estimatedTokens > 8000) {
    return {
      valid: false,
      reason: `Prompt too long: ~${estimatedTokens} tokens (max 8000)`,
    };
  }
  
  if (prompt.temperature < 0 || prompt.temperature > 2) {
    return {
      valid: false,
      reason: `Invalid temperature: ${prompt.temperature} (must be 0-2)`,
    };
  }
  
  return { valid: true };
}

/**
 * Truncate prompt to fit within limits
 */
export function truncatePrompt(
  prompt: PromptTemplate,
  maxChars: number = 30000
): PromptTemplate {
  const totalLength = prompt.systemPrompt.length + prompt.userPrompt.length;
  
  if (totalLength <= maxChars) {
    return prompt;
  }
  
  // Truncate user prompt (keep system prompt intact)
  const availableForUser = maxChars - prompt.systemPrompt.length - 100;
  const truncatedUserPrompt = prompt.userPrompt.substring(0, availableForUser) +
    '\n\n[Content truncated for length. Provide analysis based on available information.]';
  
  logger.warn({
    action: 'prompt_truncated',
    originalLength: totalLength,
    truncatedLength: prompt.systemPrompt.length + truncatedUserPrompt.length,
  });
  
  return {
    ...prompt,
    userPrompt: truncatedUserPrompt,
  };
}

export default {
  buildPrompt,
  buildBriefPrompt,
  buildDetailedPrompt,
  validatePrompt,
  truncatePrompt,
  SYSTEM_PROMPT,
};
