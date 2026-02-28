/**
 * R.Y.Z.E.N.A. - Document Loader
 * 
 * Loads and processes knowledge base documents for RAG.
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, extname, basename } from 'path';
import { createLogger } from '../../shared/logger.js';
import { config } from '../../shared/config.js';
import type { KnowledgeDocument } from '../ai/ai.types.js';

const logger = createLogger({ module: 'document-loader' });

/**
 * Document category mapping based on filename patterns
 */
const CATEGORY_PATTERNS: Record<string, RegExp> = {
  phishing_patterns: /phishing|scam-pattern|attack-pattern/i,
  scam_templates: /template|example|sample/i,
  university_policy: /policy|guideline|procedure/i,
  historical_examples: /historical|case|incident/i,
};

/**
 * Supported file extensions
 */
const SUPPORTED_EXTENSIONS = ['.txt', '.md', '.json'];

/**
 * Determine document category from filename
 */
function determineCategory(filename: string): KnowledgeDocument['category'] {
  for (const [category, pattern] of Object.entries(CATEGORY_PATTERNS)) {
    if (pattern.test(filename)) {
      return category as KnowledgeDocument['category'];
    }
  }
  return 'phishing_patterns'; // Default category
}

/**
 * Extract tags from content
 */
function extractTags(content: string): string[] {
  const tags = new Set<string>();
  
  // Common phishing-related keywords
  const keywords = [
    'phishing', 'spam', 'malware', 'ransomware', 'spear-phishing',
    'whaling', 'vishing', 'smishing', 'social-engineering',
    'credential-harvesting', 'impersonation', 'spoofing',
    'urgency', 'suspicious', 'scam', 'fraud',
  ];
  
  const lowerContent = content.toLowerCase();
  for (const keyword of keywords) {
    if (lowerContent.includes(keyword)) {
      tags.add(keyword);
    }
  }
  
  return Array.from(tags);
}

/**
 * Load a single document from file
 */
function loadDocument(filePath: string): KnowledgeDocument | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const filename = basename(filePath);
    const ext = extname(filePath).toLowerCase();
    
    let parsedContent = content;
    let title = filename.replace(ext, '');
    
    // Handle JSON documents
    if (ext === '.json') {
      try {
        const jsonDoc = JSON.parse(content);
        parsedContent = jsonDoc.content || JSON.stringify(jsonDoc, null, 2);
        title = jsonDoc.title || title;
      } catch {
        // Use raw content if JSON parsing fails
      }
    }
    
    // Handle Markdown - extract title from first heading
    if (ext === '.md') {
      const titleMatch = content.match(/^#\s+(.+)$/m);
      if (titleMatch) {
        title = titleMatch[1];
      }
    }
    
    const doc: KnowledgeDocument = {
      id: `doc_${Buffer.from(filePath).toString('base64').substring(0, 16)}`,
      title,
      content: parsedContent,
      category: determineCategory(filename),
      tags: extractTags(parsedContent),
      source: filePath,
      createdAt: new Date().toISOString(),
    };
    
    logger.debug({
      action: 'document_loaded',
      path: filePath,
      title: doc.title,
      category: doc.category,
      contentLength: doc.content.length,
      tags: doc.tags,
    });
    
    return doc;
  } catch (error) {
    logger.error({
      action: 'document_load_failed',
      path: filePath,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/**
 * Load all documents from knowledge directory
 */
export function loadDocuments(knowledgePath?: string): KnowledgeDocument[] {
  const dirPath = knowledgePath || config.rag.knowledgePath;
  const documents: KnowledgeDocument[] = [];
  
  if (!existsSync(dirPath)) {
    logger.warn({
      action: 'knowledge_dir_missing',
      path: dirPath,
      message: 'Knowledge directory does not exist, using built-in knowledge',
    });
    return getBuiltInKnowledge();
  }
  
  try {
    const files = readdirSync(dirPath);
    
    for (const file of files) {
      const ext = extname(file).toLowerCase();
      if (!SUPPORTED_EXTENSIONS.includes(ext)) {
        continue;
      }
      
      const filePath = join(dirPath, file);
      const doc = loadDocument(filePath);
      if (doc) {
        documents.push(doc);
      }
    }
    
    logger.info({
      action: 'documents_loaded',
      path: dirPath,
      totalDocuments: documents.length,
      categories: [...new Set(documents.map(d => d.category))],
    });
    
    // Add built-in knowledge
    const builtIn = getBuiltInKnowledge();
    documents.push(...builtIn);
    
    return documents;
  } catch (error) {
    logger.error({
      action: 'documents_load_failed',
      path: dirPath,
      error: error instanceof Error ? error.message : String(error),
    });
    return getBuiltInKnowledge();
  }
}

/**
 * Get built-in knowledge base
 */
export function getBuiltInKnowledge(): KnowledgeDocument[] {
  return [
    {
      id: 'builtin_phishing_patterns',
      title: 'Common Phishing Patterns',
      content: `# Common Phishing Patterns

## Urgency Tactics
Phishing emails often create artificial urgency to pressure recipients into acting quickly without thinking. Common phrases include:
- "Your account will be suspended"
- "Immediate action required"
- "Limited time offer"
- "Verify within 24 hours"

## Credential Harvesting
Attackers try to steal login credentials by:
- Creating fake login pages that mimic legitimate sites
- Asking users to "verify" or "confirm" their password
- Claiming there was "suspicious activity" requiring re-authentication

## Domain Spoofing
Attackers use domains that look similar to legitimate ones:
- paypa1.com instead of paypal.com
- amaz0n.com instead of amazon.com
- micr0soft.com instead of microsoft.com
- Adding extra words: paypal-security.com, amazon-support.com

## Generic Greetings
Legitimate companies typically know your name. Phishing emails often use:
- "Dear Customer"
- "Dear User"
- "Dear Account Holder"
- "Dear Sir/Madam"

## Suspicious Attachments
Be wary of unexpected attachments, especially:
- Executable files (.exe, .scr, .bat)
- Files with double extensions (document.pdf.exe)
- Macro-enabled Office documents (.docm, .xlsm)
- Password-protected archives`,
      category: 'phishing_patterns',
      tags: ['phishing', 'urgency', 'credential-harvesting', 'spoofing'],
      createdAt: new Date().toISOString(),
    },
    {
      id: 'builtin_scam_templates',
      title: 'Common Scam Email Templates',
      content: `# Common Scam Email Templates

## Nigerian Prince / Advance Fee Fraud
Claims you've inherited money or won a lottery, but need to pay fees to receive it. Red flags:
- Unexpected windfall from unknown source
- Request for upfront payment
- Poor grammar and spelling

## Tech Support Scam
Claims your computer is infected and offers "help". Signs:
- Unsolicited contact about computer problems
- Request to install remote access software
- Pressure to pay for unnecessary services

## CEO/Executive Impersonation
Pretends to be a company executive requesting urgent wire transfer. Indicators:
- Unusual request from "boss"
- Emphasis on secrecy and urgency
- Request to bypass normal procedures

## Invoice Scam
Fake invoices for services never ordered. Watch for:
- Unknown vendor names
- Vague service descriptions
- Pressure to pay quickly

## Account Suspension Scam
Claims your account (bank, email, social media) will be closed. Features:
- Threat of account closure
- Link to fake login page
- Request to "verify" credentials`,
      category: 'scam_templates',
      tags: ['scam', 'fraud', 'impersonation', 'social-engineering'],
      createdAt: new Date().toISOString(),
    },
    {
      id: 'builtin_university_policy',
      title: 'University Email Security Guidelines',
      content: `# University Email Security Guidelines

## Official Communication Policy
The university will NEVER:
- Ask for your password via email
- Request sensitive information through unverified links
- Threaten immediate account suspension
- Send unsolicited attachments from unknown sources

## Reporting Suspicious Emails
If you receive a suspicious email:
1. Do NOT click any links
2. Do NOT download attachments
3. Do NOT reply to the sender
4. Forward to security@university.edu
5. Delete the email

## Verification Steps
Before acting on any email:
1. Verify sender's email address carefully
2. Look for spelling/grammar errors
3. Hover over links to see actual URLs
4. Contact the supposed sender through official channels
5. When in doubt, ask IT security

## Protected Information
Never share via email:
- University login credentials
- Social Security numbers
- Financial account information
- Personal identification documents
- Research data without encryption`,
      category: 'university_policy',
      tags: ['policy', 'guideline', 'security', 'university'],
      createdAt: new Date().toISOString(),
    },
    {
      id: 'builtin_url_analysis',
      title: 'URL Analysis Guide',
      content: `# URL Analysis Guide

## Suspicious URL Indicators
- IP addresses instead of domain names (http://192.168.1.1/login)
- Misspelled domains (micr0soft.com, amaz0n.com)
- Excessive subdomains (secure.login.verify.bank.evil.com)
- Unusual TLDs (.xyz, .top, .click, .work)
- URL shorteners hiding destination (bit.ly, tinyurl)

## Safe URL Practices
- Hover over links before clicking to preview destination
- Check for HTTPS (though phishing sites can have HTTPS too)
- Verify domain matches expected organization
- Type URLs directly instead of clicking links
- Use bookmarks for frequently visited sites

## URL Red Flags
- URLs with login/password/account in path
- Very long URLs with encoded characters
- URLs that don't match the claimed organization
- Redirects through multiple domains
- Mixed protocols (HTTP on a banking site)`,
      category: 'phishing_patterns',
      tags: ['url', 'suspicious', 'analysis', 'security'],
      createdAt: new Date().toISOString(),
    },
    {
      id: 'builtin_attachment_safety',
      title: 'Email Attachment Safety',
      content: `# Email Attachment Safety

## High-Risk File Types
These file types can execute malicious code:
- .exe, .scr, .com, .bat, .cmd (Windows executables)
- .js, .vbs, .ps1 (Script files)
- .docm, .xlsm, .pptm (Macro-enabled Office files)
- .jar (Java executables)
- .iso, .img (Disk images)

## Double Extension Trick
Attackers hide true file types:
- document.pdf.exe (appears as PDF, is actually executable)
- image.jpg.scr (appears as image, is screensaver malware)
- report.doc.js (appears as Word doc, is JavaScript)

## Safe Attachment Handling
1. Never open unexpected attachments
2. Verify with sender through separate communication
3. Scan attachments with antivirus before opening
4. Open suspicious Office docs in Protected View
5. Disable macros unless absolutely necessary

## Warning Signs
- Unsolicited attachments from unknown senders
- Generic messages like "Please see attached"
- Pressure to open quickly
- Password-protected archives (to evade scanning)`,
      category: 'phishing_patterns',
      tags: ['attachment', 'malware', 'executable', 'safety'],
      createdAt: new Date().toISOString(),
    },
  ];
}

/**
 * Chunk document into smaller pieces for embedding
 */
export function chunkDocument(
  doc: KnowledgeDocument,
  chunkSize: number = config.rag.chunkSize,
  overlap: number = config.rag.chunkOverlap
): Array<{ content: string; metadata: Record<string, unknown> }> {
  const chunks: Array<{ content: string; metadata: Record<string, unknown> }> = [];
  const content = doc.content;
  
  if (content.length <= chunkSize) {
    chunks.push({
      content,
      metadata: {
        source: doc.source || doc.id,
        category: doc.category,
        title: doc.title,
        chunkIndex: 0,
        totalChunks: 1,
      },
    });
    return chunks;
  }
  
  let start = 0;
  let chunkIndex = 0;
  
  while (start < content.length) {
    let end = start + chunkSize;
    
    // Try to break at a sentence or paragraph boundary
    if (end < content.length) {
      const breakPoints = ['\n\n', '\n', '. ', '! ', '? '];
      for (const bp of breakPoints) {
        const breakIndex = content.lastIndexOf(bp, end);
        if (breakIndex > start + chunkSize / 2) {
          end = breakIndex + bp.length;
          break;
        }
      }
    }
    
    const chunk = content.slice(start, end).trim();
    if (chunk.length > 0) {
      chunks.push({
        content: chunk,
        metadata: {
          source: doc.source || doc.id,
          category: doc.category,
          title: doc.title,
          chunkIndex,
          totalChunks: -1, // Will be updated after
        },
      });
      chunkIndex++;
    }
    
    start = end - overlap;
    if (start >= content.length - overlap) break;
  }
  
  // Update total chunks count
  for (const chunk of chunks) {
    chunk.metadata.totalChunks = chunks.length;
  }
  
  return chunks;
}

export default {
  loadDocuments,
  loadDocument,
  getBuiltInKnowledge,
  chunkDocument,
};
