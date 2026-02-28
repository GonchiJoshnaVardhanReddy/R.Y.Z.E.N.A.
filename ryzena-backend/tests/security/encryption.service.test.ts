/**
 * R.Y.Z.E.N.A. - Phase 7: Encryption Service Tests
 * Tests for data encryption and hashing
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EncryptionService, getEncryptionService, resetEncryptionService } from '../../src/security/encryption.service.js';

// Set up test environment with encryption key
const TEST_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

describe('Encryption Service', () => {
  beforeEach(() => {
    // Set encryption key in environment
    process.env.ENCRYPTION_KEY = TEST_KEY;
    resetEncryptionService();
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt text correctly', () => {
      const service = getEncryptionService();
      const plaintext = 'Hello, World!';
      const encrypted = service.encrypt(plaintext);
      expect(encrypted).not.toBeNull();
      const decrypted = service.decrypt(encrypted!);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const service = getEncryptionService();
      const plaintext = 'Test message';
      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);
      expect(encrypted1?.encrypted).not.toBe(encrypted2?.encrypted);
    });

    it('should handle empty string', () => {
      const service = getEncryptionService();
      const plaintext = '';
      const encrypted = service.encrypt(plaintext);
      expect(encrypted).not.toBeNull();
      const decrypted = service.decrypt(encrypted!);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle special characters', () => {
      const service = getEncryptionService();
      const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?/~`';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted!);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle unicode characters', () => {
      const service = getEncryptionService();
      const plaintext = 'Unicode: 你好世界 مرحبا العالم 🔒🔐';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted!);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle long strings', () => {
      const service = getEncryptionService();
      const plaintext = 'A'.repeat(10000);
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted!);
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('generateToken', () => {
    it('should generate token of specified length', () => {
      const service = getEncryptionService();
      const token = service.generateToken(32);
      expect(token).toHaveLength(64); // 32 bytes = 64 hex chars
    });

    it('should generate unique tokens', () => {
      const service = getEncryptionService();
      const token1 = service.generateToken(32);
      const token2 = service.generateToken(32);
      expect(token1).not.toBe(token2);
    });

    it('should use default length', () => {
      const service = getEncryptionService();
      const token = service.generateToken();
      expect(token.length).toBeGreaterThan(0);
    });
  });

  describe('generateApiKey', () => {
    it('should generate API key with prefix', () => {
      const service = getEncryptionService();
      const apiKey = service.generateApiKey();
      expect(apiKey).toMatch(/^ryz_[A-Za-z0-9_-]+$/);
    });

    it('should generate unique API keys', () => {
      const service = getEncryptionService();
      const key1 = service.generateApiKey();
      const key2 = service.generateApiKey();
      expect(key1).not.toBe(key2);
    });
  });

  describe('hashWithSalt (password hashing)', () => {
    it('should hash value with salt', async () => {
      const service = getEncryptionService();
      const password = 'SecurePassword123!';
      const result = await service.hashWithSalt(password);
      expect(result.hash).toBeDefined();
      expect(result.salt).toBeDefined();
      expect(result.hash).not.toBe(password);
    });

    it('should produce different hashes for same password', async () => {
      const service = getEncryptionService();
      const password = 'TestPassword123!';
      const hash1 = await service.hashWithSalt(password);
      const hash2 = await service.hashWithSalt(password);
      expect(hash1.hash).not.toBe(hash2.hash); // Different salts
    });
  });

  describe('verifyHash', () => {
    it('should verify correct password', async () => {
      const service = getEncryptionService();
      const password = 'CorrectPassword123!';
      const result = await service.hashWithSalt(password);
      const isValid = await service.verifyHash(password, result.hash, result.salt);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const service = getEncryptionService();
      const password = 'CorrectPassword123!';
      const result = await service.hashWithSalt(password);
      const isValid = await service.verifyHash('WrongPassword', result.hash, result.salt);
      expect(isValid).toBe(false);
    });
  });

  describe('deterministicHash', () => {
    it('should create deterministic hash', () => {
      const service = getEncryptionService();
      const data = 'test data';
      const hash1 = service.deterministicHash(data);
      const hash2 = service.deterministicHash(data);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different data', () => {
      const service = getEncryptionService();
      const hash1 = service.deterministicHash('data1');
      const hash2 = service.deterministicHash('data2');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('maskSensitive', () => {
    it('should mask middle of long strings', () => {
      const service = getEncryptionService();
      const value = 'secret-api-key-12345';
      const masked = service.maskSensitive(value, 4);
      expect(masked).toMatch(/^secr\*+2345$/);
    });

    it('should mask entire short strings', () => {
      const service = getEncryptionService();
      const value = 'abc';
      const masked = service.maskSensitive(value, 4);
      expect(masked).toBe('***');
    });
  });
});

describe('Key Validation', () => {
  beforeEach(() => {
    resetEncryptionService();
  });

  it('should handle invalid key length gracefully', () => {
    process.env.ENCRYPTION_KEY = 'short';
    const service = getEncryptionService();
    expect(service.isAvailable()).toBe(false);
  });

  it('should work with valid 64-char hex key', () => {
    process.env.ENCRYPTION_KEY = TEST_KEY;
    const service = getEncryptionService();
    expect(service.isAvailable()).toBe(true);
  });

  it('should return null when encrypting without key', () => {
    delete process.env.ENCRYPTION_KEY;
    const service = getEncryptionService();
    const result = service.encrypt('test');
    expect(result).toBeNull();
  });
});

describe('Security Properties', () => {
  beforeEach(() => {
    process.env.ENCRYPTION_KEY = TEST_KEY;
    resetEncryptionService();
  });

  it('encrypted data should be different from plaintext', () => {
    const service = getEncryptionService();
    const plaintext = 'secret data';
    const encrypted = service.encrypt(plaintext);
    expect(encrypted?.encrypted).not.toBe(plaintext);
  });

  it('should include IV and authTag in encrypted output', () => {
    const service = getEncryptionService();
    const encrypted = service.encrypt('test');
    expect(encrypted).not.toBeNull();
    expect(encrypted?.iv).toBeDefined();
    expect(encrypted?.authTag).toBeDefined();
    expect(encrypted?.algorithm).toBe('aes-256-gcm');
  });

  it('tampered data should fail decryption', () => {
    const service = getEncryptionService();
    const encrypted = service.encrypt('secret');
    expect(encrypted).not.toBeNull();
    // Tamper with authTag
    encrypted!.authTag = 'tampered' + encrypted!.authTag.slice(8);
    const result = service.decrypt(encrypted!);
    expect(result).toBeNull();
  });
});
