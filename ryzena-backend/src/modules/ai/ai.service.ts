/**
 * R.Y.Z.E.N.A. - AI Service
 * 
 * Orchestrates the AI explanation pipeline.
 * Coordinates context, RAG, prompts, and LLM calls.
 */

import { createLogger } from '../../shared/logger.js';
import { config } from '../../shared/config.js';
import { ollamaClient } from '../../shared/ollama.client.js';
import { buildContextFromAnalysis } from '../mcp/context.service.js';
import { retrieveKnowledge } from '../rag/rag.service.js';
import { buildPrompt, buildBriefPrompt, buildDetailedPrompt, validatePrompt, truncatePrompt } from './prompt.builder.js';
import type { SecurityAnalysisResult } from '../threat/threat.types.js';
import type {
  AIExplanationResult,
  AIExplanationRequest,
  ParsedLLMResponse,
  QuizQuestion,
} from './ai.types.js';

const logger = createLogger({ module: 'ai-service' });

/**
 * Default quiz for fallback
 */
const DEFAULT_QUIZ: QuizQuestion = {
  question: 'What is the best action when you receive a suspicious email?',
  options: [
    'Click on links to verify if they are real',
    'Forward it to all your contacts as a warning',
    'Report it to IT security and delete it',
    'Reply asking if it is legitimate',
  ],
  correctIndex: 2,
  explanation: 'Always report suspicious emails to IT security and delete them. Never click links or reply to potential phishing attempts.',
};

/**
 * Parse LLM response into structured format
 */
function parseLLMResponse(rawResponse: string): ParsedLLMResponse {
  try {
    // Try to extract JSON from the response
    const jsonMatch = rawResponse.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('No JSON found in response');
    }
    
    const parsed = JSON.parse(jsonMatch[0]);
    
    // Validate required fields
    if (!parsed.explanation || typeof parsed.explanation !== 'string') {
      throw new Error('Missing or invalid explanation field');
    }
    
    return {
      explanation: parsed.explanation,
      highlights: Array.isArray(parsed.highlights) ? parsed.highlights : [],
      educationalPoints: Array.isArray(parsed.educationalPoints) ? parsed.educationalPoints : [],
      quiz: parsed.quiz && typeof parsed.quiz === 'object' ? {
        question: parsed.quiz.question || DEFAULT_QUIZ.question,
        options: Array.isArray(parsed.quiz.options) ? parsed.quiz.options : DEFAULT_QUIZ.options,
        correctIndex: typeof parsed.quiz.correctIndex === 'number' ? parsed.quiz.correctIndex : 0,
        explanation: parsed.quiz.explanation,
      } : null,
      confidence: typeof parsed.confidence === 'number' ? Math.min(1, Math.max(0, parsed.confidence)) : 0.7,
      parseSuccess: true,
    };
  } catch (error) {
    logger.warn({
      action: 'llm_parse_failed',
      error: error instanceof Error ? error.message : String(error),
      responsePreview: rawResponse.substring(0, 200),
    });
    
    // Return fallback with raw response as explanation
    return {
      explanation: rawResponse.substring(0, 1000) || 'Unable to generate explanation.',
      highlights: [],
      educationalPoints: [],
      quiz: null,
      confidence: 0.5,
      parseSuccess: false,
      rawResponse,
    };
  }
}

/**
 * Generate fallback explanation without LLM
 */
function generateFallbackExplanation(result: SecurityAnalysisResult): AIExplanationResult {
  const isSuspicious = result.status === 'SUSPICIOUS';
  
  let explanation: string;
  if (isSuspicious) {
    explanation = `This email has been flagged as suspicious with a trust score of ${result.trustScore}/100. `;
    if (result.phishingSignals.length > 0) {
      explanation += `The following concerning patterns were detected: ${result.phishingSignals.join(', ')}. `;
    }
    if (result.urlFindings.some(f => f.riskLevel === 'high')) {
      explanation += 'The email contains links that appear to be potentially malicious. ';
    }
    if (result.malwareFindings.hasRisk) {
      explanation += `Suspicious attachments were detected: ${result.malwareFindings.flaggedFiles.join(', ')}. `;
    }
    explanation += 'Please do not click any links or download attachments from this email.';
  } else {
    explanation = `This email appears to be safe with a trust score of ${result.trustScore}/100. `;
    explanation += 'No significant phishing indicators or malicious content were detected. ';
    explanation += 'However, always remain cautious with unexpected emails.';
  }
  
  const highlights = isSuspicious ? result.phishingSignals.slice(0, 5) : ['No significant threats detected'];
  
  const educationalPoints = isSuspicious ? [
    'Always verify the sender\'s email address carefully',
    'Be cautious of emails creating urgency or pressure',
    'Never click links without hovering to check the destination first',
  ] : [
    'Continue to verify senders of unexpected emails',
    'Keep your email security awareness up to date',
    'Report any emails that seem suspicious to IT security',
  ];
  
  return {
    emailId: result.emailId,
    explanation,
    suspiciousHighlights: highlights,
    educationalBreakdown: educationalPoints,
    quiz: DEFAULT_QUIZ,
    confidence: 0.6,
    metadata: {
      model: 'fallback',
      processingTimeMs: 0,
      ragDocumentsUsed: 0,
      analyzedAt: new Date().toISOString(),
    },
  };
}

/**
 * Generate AI explanation for security analysis
 */
export async function generateExplanation(
  request: AIExplanationRequest
): Promise<AIExplanationResult> {
  const startTime = Date.now();
  const { securityAnalysisResult, options = {} } = request;
  
  logger.info({
    action: 'ai_explanation_start',
    emailId: securityAnalysisResult.emailId,
    status: securityAnalysisResult.status,
    verbosity: options.verbosity || 'standard',
  });
  
  // Check if Ollama is enabled
  if (!config.ollama.enabled) {
    logger.info({
      action: 'ollama_disabled',
      message: 'Returning fallback explanation',
    });
    return generateFallbackExplanation(securityAnalysisResult);
  }
  
  try {
    // Step 1: Build MCP context
    const context = buildContextFromAnalysis(securityAnalysisResult);
    
    // Step 2: Retrieve relevant knowledge via RAG
    const ragResult = await retrieveKnowledge(securityAnalysisResult);
    
    // Step 3: Build prompt
    let prompt;
    switch (options.verbosity) {
      case 'brief':
        prompt = buildBriefPrompt(context, ragResult.documents);
        break;
      case 'detailed':
        prompt = buildDetailedPrompt(context, ragResult.documents);
        break;
      default:
        prompt = buildPrompt(context, ragResult.documents);
    }
    
    // Validate and truncate if needed
    const validation = validatePrompt(prompt);
    if (!validation.valid) {
      logger.warn({
        action: 'prompt_validation_failed',
        reason: validation.reason,
      });
      prompt = truncatePrompt(prompt);
    }
    
    // Step 4: Call Ollama
    const model = options.model || config.ollama.model;
    
    logger.debug({
      action: 'calling_ollama',
      model,
      promptLength: prompt.systemPrompt.length + prompt.userPrompt.length,
    });
    
    const ollamaResponse = await ollamaClient.chat([
      { role: 'system', content: prompt.systemPrompt },
      { role: 'user', content: prompt.userPrompt },
    ], {
      model,
      options: {
        temperature: prompt.temperature,
        num_predict: prompt.maxTokens,
      },
    });
    
    // Step 5: Parse response
    const parsedResponse = parseLLMResponse(ollamaResponse.message.content);
    
    const processingTimeMs = Date.now() - startTime;
    
    // Build result
    const result: AIExplanationResult = {
      emailId: securityAnalysisResult.emailId,
      explanation: parsedResponse.explanation,
      suspiciousHighlights: parsedResponse.highlights.length > 0 
        ? parsedResponse.highlights 
        : securityAnalysisResult.phishingSignals.slice(0, 5),
      educationalBreakdown: parsedResponse.educationalPoints.length > 0
        ? parsedResponse.educationalPoints
        : ['Stay vigilant about email security', 'Verify senders before responding'],
      quiz: parsedResponse.quiz || DEFAULT_QUIZ,
      confidence: parsedResponse.confidence,
      metadata: {
        model,
        processingTimeMs,
        ragDocumentsUsed: ragResult.documents.length,
        tokenCount: ollamaResponse.eval_count,
        analyzedAt: new Date().toISOString(),
      },
    };
    
    logger.info({
      action: 'ai_explanation_complete',
      emailId: result.emailId,
      confidence: result.confidence,
      parseSuccess: parsedResponse.parseSuccess,
      processingTimeMs,
    });
    
    return result;
  } catch (error) {
    logger.error({
      action: 'ai_explanation_failed',
      emailId: securityAnalysisResult.emailId,
      error: error instanceof Error ? error.message : String(error),
    });
    
    // Return fallback on error
    const fallback = generateFallbackExplanation(securityAnalysisResult);
    fallback.metadata.processingTimeMs = Date.now() - startTime;
    return fallback;
  }
}

/**
 * Check if AI service is available
 */
export async function checkAIHealth(): Promise<{
  available: boolean;
  ollamaStatus: string;
  model: string;
  modelAvailable: boolean;
}> {
  const model = config.ollama.model;
  
  if (!config.ollama.enabled) {
    return {
      available: false,
      ollamaStatus: 'disabled',
      model,
      modelAvailable: false,
    };
  }
  
  try {
    const ollamaAvailable = await ollamaClient.isAvailable();
    if (!ollamaAvailable) {
      return {
        available: false,
        ollamaStatus: 'unreachable',
        model,
        modelAvailable: false,
      };
    }
    
    const modelAvailable = await ollamaClient.isModelAvailable(model);
    
    return {
      available: modelAvailable,
      ollamaStatus: 'connected',
      model,
      modelAvailable,
    };
  } catch (error) {
    return {
      available: false,
      ollamaStatus: 'error',
      model,
      modelAvailable: false,
    };
  }
}

export default {
  generateExplanation,
  checkAIHealth,
  generateFallbackExplanation,
};
