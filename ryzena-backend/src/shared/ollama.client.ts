/**
 * R.Y.Z.E.N.A. - Ollama HTTP Client
 * 
 * Handles communication with local Ollama LLM runtime.
 * Provides retry logic, timeout handling, and response parsing.
 */

import { createLogger } from './logger.js';
import { config } from './config.js';
import { ExternalServiceError } from './errors.js';

const logger = createLogger({ module: 'ollama-client' });

/**
 * Ollama chat message format
 */
export interface OllamaMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

/**
 * Ollama generation request
 */
export interface OllamaGenerateRequest {
  model: string;
  prompt: string;
  system?: string;
  stream?: boolean;
  options?: OllamaOptions;
}

/**
 * Ollama chat request
 */
export interface OllamaChatRequest {
  model: string;
  messages: OllamaMessage[];
  stream?: boolean;
  options?: OllamaOptions;
}

/**
 * Ollama model options
 */
export interface OllamaOptions {
  temperature?: number;
  num_predict?: number;
  top_p?: number;
  top_k?: number;
  repeat_penalty?: number;
  seed?: number;
}

/**
 * Ollama generation response
 */
export interface OllamaGenerateResponse {
  model: string;
  created_at: string;
  response: string;
  done: boolean;
  done_reason?: string;
  total_duration?: number;
  load_duration?: number;
  prompt_eval_count?: number;
  eval_count?: number;
  eval_duration?: number;
}

/**
 * Ollama chat response
 */
export interface OllamaChatResponse {
  model: string;
  created_at: string;
  message: OllamaMessage;
  done: boolean;
  done_reason?: string;
  total_duration?: number;
  eval_count?: number;
  eval_duration?: number;
}

/**
 * Ollama model info
 */
export interface OllamaModelInfo {
  name: string;
  modified_at: string;
  size: number;
  digest: string;
}

/**
 * Retry configuration
 */
interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 10000,
};

/**
 * Sleep utility
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculate exponential backoff delay
 */
function getBackoffDelay(attempt: number, config: RetryConfig): number {
  const delay = config.baseDelayMs * Math.pow(2, attempt);
  return Math.min(delay, config.maxDelayMs);
}

/**
 * Ollama HTTP Client class
 */
export class OllamaClient {
  private baseUrl: string;
  private model: string;
  private timeout: number;
  private defaultOptions: OllamaOptions;

  constructor(options?: {
    baseUrl?: string;
    model?: string;
    timeout?: number;
    defaultOptions?: OllamaOptions;
  }) {
    this.baseUrl = options?.baseUrl || config.ollama.baseUrl;
    this.model = options?.model || config.ollama.model;
    this.timeout = options?.timeout || config.ollama.timeout;
    this.defaultOptions = options?.defaultOptions || {
      temperature: config.ollama.temperature,
      num_predict: config.ollama.maxTokens,
    };
  }

  /**
   * Make HTTP request to Ollama with timeout
   */
  private async request<T>(
    endpoint: string,
    method: 'GET' | 'POST',
    body?: unknown
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Ollama API error: ${response.status} - ${errorText}`);
      }

      return await response.json() as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Make request with retry logic
   */
  private async requestWithRetry<T>(
    endpoint: string,
    method: 'GET' | 'POST',
    body?: unknown,
    retryConfig: RetryConfig = DEFAULT_RETRY_CONFIG
  ): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retryConfig.maxRetries; attempt++) {
      try {
        return await this.request<T>(endpoint, method, body);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        const isAborted = lastError.name === 'AbortError';
        const isNetworkError = lastError.message.includes('fetch failed') ||
                               lastError.message.includes('ECONNREFUSED');

        if (attempt < retryConfig.maxRetries && (isAborted || isNetworkError)) {
          const delay = getBackoffDelay(attempt, retryConfig);
          logger.warn({
            action: 'ollama_retry',
            attempt: attempt + 1,
            maxRetries: retryConfig.maxRetries,
            delayMs: delay,
            error: lastError.message,
          });
          await sleep(delay);
        } else {
          break;
        }
      }
    }

    logger.error({
      action: 'ollama_request_failed',
      endpoint,
      error: lastError?.message,
    });

    throw new ExternalServiceError('Ollama', lastError?.message || 'Request failed');
  }

  /**
   * Generate text completion
   */
  async generate(
    prompt: string,
    options?: {
      system?: string;
      model?: string;
      options?: OllamaOptions;
    }
  ): Promise<OllamaGenerateResponse> {
    const startTime = Date.now();
    
    const request: OllamaGenerateRequest = {
      model: options?.model || this.model,
      prompt,
      system: options?.system,
      stream: false,
      options: {
        ...this.defaultOptions,
        ...options?.options,
      },
    };

    logger.info({
      action: 'ollama_generate_start',
      model: request.model,
      promptLength: prompt.length,
    });

    const response = await this.requestWithRetry<OllamaGenerateResponse>(
      '/api/generate',
      'POST',
      request
    );

    const duration = Date.now() - startTime;

    logger.info({
      action: 'ollama_generate_complete',
      model: response.model,
      responseLength: response.response.length,
      evalCount: response.eval_count,
      durationMs: duration,
    });

    return response;
  }

  /**
   * Chat completion with message history
   */
  async chat(
    messages: OllamaMessage[],
    options?: {
      model?: string;
      options?: OllamaOptions;
    }
  ): Promise<OllamaChatResponse> {
    const startTime = Date.now();

    const request: OllamaChatRequest = {
      model: options?.model || this.model,
      messages,
      stream: false,
      options: {
        ...this.defaultOptions,
        ...options?.options,
      },
    };

    logger.info({
      action: 'ollama_chat_start',
      model: request.model,
      messageCount: messages.length,
    });

    const response = await this.requestWithRetry<OllamaChatResponse>(
      '/api/chat',
      'POST',
      request
    );

    const duration = Date.now() - startTime;

    logger.info({
      action: 'ollama_chat_complete',
      model: response.model,
      responseLength: response.message.content.length,
      evalCount: response.eval_count,
      durationMs: duration,
    });

    return response;
  }

  /**
   * List available models
   */
  async listModels(): Promise<OllamaModelInfo[]> {
    const response = await this.requestWithRetry<{ models: OllamaModelInfo[] }>(
      '/api/tags',
      'GET'
    );
    return response.models;
  }

  /**
   * Check if Ollama is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.request('/api/tags', 'GET');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if specific model is available
   */
  async isModelAvailable(modelName?: string): Promise<boolean> {
    try {
      const models = await this.listModels();
      const targetModel = modelName || this.model;
      return models.some(m => m.name === targetModel || m.name.startsWith(targetModel));
    } catch {
      return false;
    }
  }
}

/**
 * Default Ollama client instance
 */
export const ollamaClient = new OllamaClient();

export default OllamaClient;
