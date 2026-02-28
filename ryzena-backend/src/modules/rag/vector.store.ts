/**
 * R.Y.Z.E.N.A. - Vector Store
 * 
 * Simple in-memory vector store for RAG.
 * Uses cosine similarity for document retrieval.
 */

import { createLogger } from '../../shared/logger.js';
import { config } from '../../shared/config.js';
import { loadDocuments, chunkDocument } from './document.loader.js';
import type { KnowledgeDocument, RAGDocument } from '../ai/ai.types.js';

const logger = createLogger({ module: 'vector-store' });

/**
 * Vector document with embedding
 */
interface StoredDocument {
  id: string;
  content: string;
  embedding: number[];
  metadata: {
    source: string;
    category: string;
    title: string;
    chunkIndex: number;
    totalChunks: number;
  };
}

/**
 * Simple in-memory vector store
 */
class VectorStore {
  private documents: StoredDocument[] = [];
  private initialized = false;
  private initializationPromise: Promise<void> | null = null;

  /**
   * Check if store is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get document count
   */
  getDocumentCount(): number {
    return this.documents.length;
  }

  /**
   * Generate embedding using Ollama
   */
  private async generateEmbedding(text: string): Promise<number[]> {
    try {
      const response = await fetch(`${config.ollama.baseUrl}/api/embeddings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: config.ollama.embeddingModel,
          prompt: text,
        }),
      });

      if (!response.ok) {
        throw new Error(`Embedding generation failed: ${response.status}`);
      }

      const data = await response.json() as { embedding: number[] };
      return data.embedding;
    } catch (error) {
      logger.warn({
        action: 'embedding_failed',
        error: error instanceof Error ? error.message : String(error),
        message: 'Using fallback TF-IDF style embedding',
      });
      return this.generateFallbackEmbedding(text);
    }
  }

  /**
   * Generate simple TF-IDF style embedding as fallback
   */
  private generateFallbackEmbedding(text: string): number[] {
    const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2);
    const wordFreq = new Map<string, number>();
    
    for (const word of words) {
      wordFreq.set(word, (wordFreq.get(word) || 0) + 1);
    }
    
    // Security-relevant keywords to track
    const keywords = [
      'phishing', 'scam', 'urgent', 'verify', 'account', 'password',
      'click', 'link', 'attachment', 'suspicious', 'malware', 'virus',
      'credential', 'login', 'secure', 'bank', 'payment', 'invoice',
      'warning', 'alert', 'confirm', 'update', 'expire', 'suspend',
      'immediately', 'action', 'required', 'lottery', 'prize', 'winner',
      'exe', 'macro', 'script', 'download', 'install', 'fraud',
    ];
    
    // Create embedding vector
    const embedding: number[] = [];
    
    // Keyword presence features
    for (const keyword of keywords) {
      embedding.push(wordFreq.get(keyword) || 0);
    }
    
    // Text statistics
    embedding.push(words.length / 100); // Normalized word count
    embedding.push(wordFreq.size / 50); // Vocabulary size
    embedding.push(text.split(/[.!?]/).length / 10); // Sentence count
    
    // Normalize the embedding
    const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    if (magnitude > 0) {
      for (let i = 0; i < embedding.length; i++) {
        embedding[i] /= magnitude;
      }
    }
    
    return embedding;
  }

  /**
   * Calculate cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) {
      // Pad shorter vector with zeros
      const maxLen = Math.max(a.length, b.length);
      while (a.length < maxLen) a.push(0);
      while (b.length < maxLen) b.push(0);
    }
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
    return magnitude === 0 ? 0 : dotProduct / magnitude;
  }

  /**
   * Initialize the vector store with documents
   */
  async initialize(documents?: KnowledgeDocument[]): Promise<void> {
    if (this.initialized) {
      return;
    }

    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    this.initializationPromise = this._initialize(documents);
    return this.initializationPromise;
  }

  private async _initialize(documents?: KnowledgeDocument[]): Promise<void> {
    const startTime = Date.now();
    logger.info({ action: 'vector_store_init_start' });

    try {
      const docs = documents || loadDocuments();
      const chunks: Array<{ content: string; metadata: Record<string, unknown> }> = [];

      // Chunk all documents
      for (const doc of docs) {
        const docChunks = chunkDocument(doc);
        chunks.push(...docChunks);
      }

      logger.info({
        action: 'documents_chunked',
        documentCount: docs.length,
        chunkCount: chunks.length,
      });

      // Generate embeddings for all chunks
      for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        const embedding = await this.generateEmbedding(chunk.content);

        this.documents.push({
          id: `chunk_${i}`,
          content: chunk.content,
          embedding,
          metadata: chunk.metadata as StoredDocument['metadata'],
        });

        if ((i + 1) % 10 === 0) {
          logger.debug({
            action: 'embedding_progress',
            processed: i + 1,
            total: chunks.length,
          });
        }
      }

      this.initialized = true;
      
      logger.info({
        action: 'vector_store_initialized',
        documentCount: this.documents.length,
        durationMs: Date.now() - startTime,
      });
    } catch (error) {
      logger.error({
        action: 'vector_store_init_failed',
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Search for similar documents
   */
  async search(query: string, topK: number = config.rag.topK): Promise<RAGDocument[]> {
    if (!this.initialized) {
      await this.initialize();
    }

    const startTime = Date.now();
    const queryEmbedding = await this.generateEmbedding(query);

    // Calculate similarities
    const scored = this.documents.map(doc => ({
      doc,
      score: this.cosineSimilarity(queryEmbedding, doc.embedding),
    }));

    // Sort by similarity and take top K
    scored.sort((a, b) => b.score - a.score);
    const topDocs = scored.slice(0, topK);

    const results: RAGDocument[] = topDocs.map(({ doc, score }) => ({
      content: doc.content,
      score,
      source: doc.metadata.source,
      metadata: {
        category: doc.metadata.category,
        title: doc.metadata.title,
        chunkIndex: doc.metadata.chunkIndex,
      },
    }));

    logger.debug({
      action: 'vector_search',
      query: query.substring(0, 100),
      resultsCount: results.length,
      topScore: results[0]?.score || 0,
      durationMs: Date.now() - startTime,
    });

    return results;
  }

  /**
   * Add a new document to the store
   */
  async addDocument(doc: KnowledgeDocument): Promise<void> {
    const chunks = chunkDocument(doc);
    
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const embedding = await this.generateEmbedding(chunk.content);
      
      this.documents.push({
        id: `${doc.id}_chunk_${i}`,
        content: chunk.content,
        embedding,
        metadata: chunk.metadata as StoredDocument['metadata'],
      });
    }

    logger.info({
      action: 'document_added',
      docId: doc.id,
      chunksAdded: chunks.length,
    });
  }

  /**
   * Clear all documents
   */
  clear(): void {
    this.documents = [];
    this.initialized = false;
    this.initializationPromise = null;
    logger.info({ action: 'vector_store_cleared' });
  }
}

/**
 * Singleton vector store instance
 */
export const vectorStore = new VectorStore();

export default VectorStore;
