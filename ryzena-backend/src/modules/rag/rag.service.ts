/**
 * R.Y.Z.E.N.A. - RAG Service
 * 
 * Retrieval-Augmented Generation service for fetching relevant knowledge.
 */

import { createLogger } from '../../shared/logger.js';
import { config } from '../../shared/config.js';
import { vectorStore } from './vector.store.js';
import type { SecurityAnalysisResult } from '../threat/threat.types.js';
import type { RAGDocument, RAGQueryResult } from '../ai/ai.types.js';

const logger = createLogger({ module: 'rag-service' });

/**
 * Extract search queries from security analysis
 */
function extractQueries(result: SecurityAnalysisResult): string[] {
  const queries: string[] = [];
  
  // Query based on phishing signals
  if (result.phishingSignals.length > 0) {
    queries.push(`phishing signals: ${result.phishingSignals.join(', ')}`);
  }
  
  // Query based on status
  if (result.status === 'SUSPICIOUS') {
    queries.push('suspicious email characteristics how to identify phishing');
  }
  
  // Query based on URL findings
  const highRiskUrls = result.urlFindings.filter(f => f.riskLevel === 'high');
  if (highRiskUrls.length > 0) {
    queries.push('suspicious URLs malicious links phishing websites');
  }
  
  // Query based on malware findings
  if (result.malwareFindings.hasRisk) {
    queries.push('malicious attachments email malware executable files');
  }
  
  // Add general query if no specific signals
  if (queries.length === 0) {
    queries.push('email security best practices safe email handling');
  }
  
  return queries;
}

/**
 * Deduplicate documents by content similarity
 */
function deduplicateDocuments(docs: RAGDocument[]): RAGDocument[] {
  const seen = new Set<string>();
  const unique: RAGDocument[] = [];
  
  for (const doc of docs) {
    // Use first 100 chars as key for deduplication
    const key = doc.content.substring(0, 100).toLowerCase().replace(/\s+/g, ' ');
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(doc);
    }
  }
  
  return unique;
}

/**
 * Retrieve relevant documents for security analysis
 */
export async function retrieveKnowledge(
  result: SecurityAnalysisResult,
  options?: { topK?: number }
): Promise<RAGQueryResult> {
  const startTime = Date.now();
  const topK = options?.topK || config.rag.topK;
  
  try {
    // Ensure vector store is initialized
    if (!vectorStore.isInitialized()) {
      logger.info({ action: 'initializing_vector_store' });
      await vectorStore.initialize();
    }
    
    // Extract queries from analysis
    const queries = extractQueries(result);
    
    logger.debug({
      action: 'rag_queries_generated',
      emailId: result.emailId,
      queryCount: queries.length,
      queries,
    });
    
    // Retrieve documents for each query
    const allDocuments: RAGDocument[] = [];
    
    for (const query of queries) {
      const docs = await vectorStore.search(query, topK);
      allDocuments.push(...docs);
    }
    
    // Deduplicate and sort by score
    const uniqueDocs = deduplicateDocuments(allDocuments);
    uniqueDocs.sort((a, b) => b.score - a.score);
    
    // Take top K overall
    const finalDocs = uniqueDocs.slice(0, topK);
    
    const processingTimeMs = Date.now() - startTime;
    
    logger.info({
      action: 'rag_retrieval_complete',
      emailId: result.emailId,
      documentsRetrieved: finalDocs.length,
      topScore: finalDocs[0]?.score || 0,
      processingTimeMs,
    });
    
    return {
      documents: finalDocs,
      query: queries.join(' | '),
      processingTimeMs,
    };
  } catch (error) {
    logger.error({
      action: 'rag_retrieval_failed',
      emailId: result.emailId,
      error: error instanceof Error ? error.message : String(error),
    });
    
    // Return empty result on error
    return {
      documents: [],
      query: '',
      processingTimeMs: Date.now() - startTime,
    };
  }
}

/**
 * Format RAG documents for prompt injection
 */
export function formatRAGContext(documents: RAGDocument[]): string {
  if (documents.length === 0) {
    return 'No relevant knowledge base documents found.';
  }
  
  const sections: string[] = [
    '## Relevant Knowledge Base Information\n',
  ];
  
  for (let i = 0; i < documents.length; i++) {
    const doc = documents[i];
    const relevance = (doc.score * 100).toFixed(0);
    
    sections.push(`### Reference ${i + 1} (${relevance}% relevance)`);
    sections.push(`Source: ${doc.source}`);
    sections.push(doc.content);
    sections.push('');
  }
  
  return sections.join('\n');
}

/**
 * Get targeted knowledge for specific phishing signals
 */
export async function getSignalKnowledge(signals: string[]): Promise<RAGDocument[]> {
  if (signals.length === 0) {
    return [];
  }
  
  const query = signals.join(' ');
  return vectorStore.search(query, 2);
}

/**
 * Initialize RAG service
 */
export async function initializeRAG(): Promise<void> {
  const startTime = Date.now();
  logger.info({ action: 'rag_init_start' });
  
  await vectorStore.initialize();
  
  logger.info({
    action: 'rag_initialized',
    documentCount: vectorStore.getDocumentCount(),
    durationMs: Date.now() - startTime,
  });
}

/**
 * Check RAG service health
 */
export function getRAGHealth(): { initialized: boolean; documentCount: number } {
  return {
    initialized: vectorStore.isInitialized(),
    documentCount: vectorStore.getDocumentCount(),
  };
}

export default {
  retrieveKnowledge,
  formatRAGContext,
  getSignalKnowledge,
  initializeRAG,
  getRAGHealth,
};
