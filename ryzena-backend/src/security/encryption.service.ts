/**
 * R.Y.Z.E.N.A. - Phase 7: Encryption Service
 * Secure encryption utilities for data protection
 */

import crypto from 'crypto';
import { logger } from '../shared/logger.js';
import { ENCRYPTION_CONFIG } from './security.config.js';

// ============================================================================
// TYPES
// ============================================================================

interface EncryptedData {
  /** Encrypted content (base64) */
  encrypted: string;
  /** Initialization vector (base64) */
  iv: string;
  /** Authentication tag (base64) */
  authTag: string;
  /** Algorithm used */
  algorithm: string;
}

interface HashResult {
  /** Hashed value */
  hash: string;
  /** Salt used (base64) */
  salt: string;
}

// ============================================================================
// ENCRYPTION SERVICE
// ============================================================================

/**
 * Encryption service for data protection
 */
export class EncryptionService {
  private encryptionKey: Buffer | null = null;
  private log = logger.child({ module: 'encryption-service' });

  constructor() {
    this.initializeKey();
  }

  /**
   * Initialize encryption key from environment
   */
  private initializeKey(): void {
    const keyHex = process.env.ENCRYPTION_KEY;
    
    if (keyHex) {
      if (keyHex.length !== 64) {
        this.log.warn('ENCRYPTION_KEY must be 64 hex characters (32 bytes)');
        return;
      }
      this.encryptionKey = Buffer.from(keyHex, 'hex');
      this.log.info('Encryption key initialized');
    } else {
      this.log.warn('ENCRYPTION_KEY not set - field encryption disabled');
    }
  }

  /**
   * Check if encryption is available
   */
  isAvailable(): boolean {
    return this.encryptionKey !== null;
  }

  /**
   * Encrypt data using AES-256-GCM
   */
  encrypt(plaintext: string): EncryptedData | null {
    if (!this.encryptionKey) {
      this.log.warn('Encryption attempted but key not available');
      return null;
    }

    try {
      const iv = crypto.randomBytes(ENCRYPTION_CONFIG.IV_LENGTH);
      const cipher = crypto.createCipheriv(
        ENCRYPTION_CONFIG.AES_MODE,
        this.encryptionKey,
        iv
      );

      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      const authTag = cipher.getAuthTag();

      return {
        encrypted,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        algorithm: ENCRYPTION_CONFIG.AES_MODE,
      };
    } catch (error) {
      this.log.error({ error }, 'Encryption failed');
      return null;
    }
  }

  /**
   * Decrypt data
   */
  decrypt(data: EncryptedData): string | null {
    if (!this.encryptionKey) {
      this.log.warn('Decryption attempted but key not available');
      return null;
    }

    try {
      const iv = Buffer.from(data.iv, 'base64');
      const authTag = Buffer.from(data.authTag, 'base64');
      const encrypted = data.encrypted;

      const decipher = crypto.createDecipheriv(
        ENCRYPTION_CONFIG.AES_MODE,
        this.encryptionKey,
        iv
      );
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encrypted, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      this.log.error({ error }, 'Decryption failed');
      return null;
    }
  }

  /**
   * Hash a value with salt (for passwords, tokens)
   */
  async hashWithSalt(value: string): Promise<HashResult> {
    const salt = crypto.randomBytes(ENCRYPTION_CONFIG.SALT_LENGTH);
    
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        value,
        salt,
        100000, // iterations
        64, // key length
        'sha512',
        (err, derivedKey) => {
          if (err) {
            reject(err);
            return;
          }
          resolve({
            hash: derivedKey.toString('hex'),
            salt: salt.toString('hex'),
          });
        }
      );
    });
  }

  /**
   * Verify a hashed value
   */
  async verifyHash(value: string, hash: string, saltHex: string): Promise<boolean> {
    const salt = Buffer.from(saltHex, 'hex');
    
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        value,
        salt,
        100000,
        64,
        'sha512',
        (err, derivedKey) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(crypto.timingSafeEqual(
            Buffer.from(hash, 'hex'),
            derivedKey
          ));
        }
      );
    });
  }

  /**
   * Generate a secure random token
   */
  generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate a secure API key
   */
  generateApiKey(): string {
    const prefix = 'ryz_';
    const randomPart = crypto.randomBytes(24).toString('base64url');
    return `${prefix}${randomPart}`;
  }

  /**
   * Hash an API key for storage
   */
  hashApiKey(apiKey: string): string {
    return crypto
      .createHash('sha256')
      .update(apiKey)
      .digest('hex');
  }

  /**
   * Create a deterministic hash (for IDs, deduplication)
   */
  deterministicHash(data: string): string {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Mask sensitive data for logging
   */
  maskSensitive(value: string, visibleChars: number = 4): string {
    if (value.length <= visibleChars * 2) {
      return '*'.repeat(value.length);
    }
    const start = value.substring(0, visibleChars);
    const end = value.substring(value.length - visibleChars);
    const masked = '*'.repeat(Math.min(value.length - visibleChars * 2, 8));
    return `${start}${masked}${end}`;
  }

  /**
   * Encrypt sensitive fields in an object
   */
  encryptFields<T extends Record<string, unknown>>(
    obj: T,
    fields: string[]
  ): T {
    if (!this.isAvailable()) {
      return obj;
    }

    const result = { ...obj };
    
    for (const field of fields) {
      if (field in result && typeof result[field] === 'string') {
        const encrypted = this.encrypt(result[field] as string);
        if (encrypted) {
          (result as Record<string, unknown>)[`${field}_encrypted`] = encrypted;
          delete result[field];
        }
      }
    }

    return result;
  }

  /**
   * Decrypt sensitive fields in an object
   */
  decryptFields<T extends Record<string, unknown>>(
    obj: T,
    fields: string[]
  ): T {
    if (!this.isAvailable()) {
      return obj;
    }

    const result = { ...obj };

    for (const field of fields) {
      const encryptedField = `${field}_encrypted`;
      if (encryptedField in result) {
        const encrypted = result[encryptedField] as EncryptedData;
        const decrypted = this.decrypt(encrypted);
        if (decrypted) {
          (result as Record<string, unknown>)[field] = decrypted;
          delete result[encryptedField];
        }
      }
    }

    return result;
  }
}

// Singleton instance
let encryptionServiceInstance: EncryptionService | null = null;

/**
 * Get the encryption service instance
 */
export function getEncryptionService(): EncryptionService {
  if (!encryptionServiceInstance) {
    encryptionServiceInstance = new EncryptionService();
  }
  return encryptionServiceInstance;
}

/**
 * Reset the encryption service (for testing)
 */
export function resetEncryptionService(): void {
  encryptionServiceInstance = null;
}
