/**
 * R.Y.Z.E.N.A. - Phase 7: Authentication Tests
 * Tests for JWT authentication and token handling
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import jwt from 'jsonwebtoken';
import { UserRole, Permission, ROLE_PERMISSIONS } from '../../src/security/security.config.js';

// Test secrets
const TEST_JWT_SECRET = 'test_access_secret_64_chars_minimum_for_security_testing_purposes';
const TEST_REFRESH_SECRET = 'test_refresh_secret_64_chars_minimum_for_security_testing_purposes';

// Mock environment before importing auth module
process.env.JWT_SECRET = TEST_JWT_SECRET;
process.env.JWT_REFRESH_SECRET = TEST_REFRESH_SECRET;
process.env.ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Mock audit service
vi.mock('../../src/security/audit.service.js', () => ({
  getAuditService: () => ({
    log: vi.fn(),
    logAuth: vi.fn(),
  }),
}));

// Import after mocking
import {
  generateAccessToken,
  generateRefreshToken,
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
} from '../../src/security/auth.middleware.js';

describe('Auth Middleware', () => {
  const testUserId = 'user-123';
  const testRole = UserRole.STUDENT;

  beforeEach(() => {
    process.env.JWT_SECRET = TEST_JWT_SECRET;
    process.env.JWT_REFRESH_SECRET = TEST_REFRESH_SECRET;
  });

  describe('generateAccessToken', () => {
    it('should generate a valid JWT token', () => {
      const token = generateAccessToken(testUserId, testRole);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    it('should include user data in token payload', () => {
      const token = generateAccessToken(testUserId, testRole);
      const decoded = jwt.decode(token) as any;
      expect(decoded.sub).toBe(testUserId);
      expect(decoded.role).toBe(testRole);
    });

    it('should include permissions in token', () => {
      const token = generateAccessToken(testUserId, testRole);
      const decoded = jwt.decode(token) as any;
      expect(decoded.permissions).toBeDefined();
      expect(Array.isArray(decoded.permissions)).toBe(true);
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate a valid refresh token', () => {
      const token = generateRefreshToken(testUserId, testRole);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
    });

    it('should have refresh token type', () => {
      const token = generateRefreshToken(testUserId, testRole);
      const decoded = jwt.decode(token) as any;
      expect(decoded.type).toBe('refresh');
    });
  });

  describe('generateTokenPair', () => {
    it('should return both access and refresh tokens', () => {
      const tokens = generateTokenPair(testUserId, testRole);
      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(tokens.expiresIn).toBeDefined();
    });

    it('should generate different tokens', () => {
      const tokens = generateTokenPair(testUserId, testRole);
      expect(tokens.accessToken).not.toBe(tokens.refreshToken);
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify valid access token', () => {
      const token = generateAccessToken(testUserId, testRole);
      const result = verifyAccessToken(token);
      expect(result).not.toBeNull();
      expect(result?.sub).toBe(testUserId);
    });

    it('should reject invalid token', () => {
      const result = verifyAccessToken('invalid.token.here');
      expect(result).toBeNull();
    });

    it('should reject expired token', () => {
      const expiredToken = jwt.sign(
        { sub: testUserId, role: testRole, permissions: [], iss: 'ryzena', aud: 'ryzena-api' },
        TEST_JWT_SECRET,
        { expiresIn: '-1h' }
      );
      const result = verifyAccessToken(expiredToken);
      expect(result).toBeNull();
    });

    it('should reject tampered token', () => {
      const token = generateAccessToken(testUserId, testRole);
      const tampered = token.slice(0, -10) + 'tampered00';
      const result = verifyAccessToken(tampered);
      expect(result).toBeNull();
    });
  });

  describe('verifyRefreshToken', () => {
    it('should verify valid refresh token', () => {
      const token = generateRefreshToken(testUserId, testRole);
      const result = verifyRefreshToken(token);
      expect(result).not.toBeNull();
    });
  });
});

describe('Token Security', () => {
  it('should include issuer and audience', () => {
    const token = generateAccessToken('user-1', UserRole.STUDENT);
    const decoded = jwt.decode(token) as any;
    expect(decoded.iss).toBeDefined();
    expect(decoded.aud).toBeDefined();
  });

  it('should handle admin role correctly', () => {
    const token = generateAccessToken('admin-1', UserRole.ADMIN);
    const decoded = jwt.decode(token) as any;
    expect(decoded.role).toBe(UserRole.ADMIN);
  });

  it('should handle system role correctly', () => {
    const token = generateAccessToken('system', UserRole.SYSTEM);
    const result = verifyAccessToken(token);
    expect(result).not.toBeNull();
    expect(result?.role).toBe(UserRole.SYSTEM);
  });

  it('should include role-based permissions', () => {
    const token = generateAccessToken('student-1', UserRole.STUDENT);
    const decoded = jwt.decode(token) as any;
    const expectedPermissions = ROLE_PERMISSIONS[UserRole.STUDENT];
    expect(decoded.permissions).toEqual(expectedPermissions);
  });
});
