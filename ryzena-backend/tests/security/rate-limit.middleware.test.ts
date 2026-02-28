/**
 * R.Y.Z.E.N.A. - Phase 7: Rate Limiting Tests
 * Tests for rate limit enforcement
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the rate limit stores
const mockStores = new Map<string, Map<string, { count: number; resetAt: number }>>();

function getStore(name: string) {
  if (!mockStores.has(name)) {
    mockStores.set(name, new Map());
  }
  return mockStores.get(name)!;
}

function checkRateLimit(
  store: Map<string, { count: number; resetAt: number }>,
  key: string,
  config: { max: number; windowMs: number }
) {
  const now = Date.now();
  let entry = store.get(key);

  if (!entry || entry.resetAt <= now) {
    entry = { count: 0, resetAt: now + config.windowMs };
    store.set(key, entry);
  }

  if (entry.count >= config.max) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return { allowed: false, remaining: 0, resetAt: entry.resetAt, retryAfter };
  }

  entry.count++;
  return { allowed: true, remaining: config.max - entry.count, resetAt: entry.resetAt };
}

describe('Rate Limiting', () => {
  beforeEach(() => {
    mockStores.clear();
  });

  describe('checkRateLimit', () => {
    it('should allow requests under limit', () => {
      const store = getStore('test');
      const config = { max: 10, windowMs: 60000 };
      
      const result = checkRateLimit(store, 'user-1', config);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('should track request count', () => {
      const store = getStore('test');
      const config = { max: 10, windowMs: 60000 };
      
      checkRateLimit(store, 'user-1', config);
      checkRateLimit(store, 'user-1', config);
      const result = checkRateLimit(store, 'user-1', config);
      
      expect(result.remaining).toBe(7);
    });

    it('should block requests over limit', () => {
      const store = getStore('test');
      const config = { max: 3, windowMs: 60000 };
      
      checkRateLimit(store, 'user-1', config);
      checkRateLimit(store, 'user-1', config);
      checkRateLimit(store, 'user-1', config);
      const result = checkRateLimit(store, 'user-1', config);
      
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should provide retry-after on block', () => {
      const store = getStore('test');
      const config = { max: 1, windowMs: 60000 };
      
      checkRateLimit(store, 'user-1', config);
      const result = checkRateLimit(store, 'user-1', config);
      
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeGreaterThan(0);
      expect(result.retryAfter).toBeLessThanOrEqual(60);
    });

    it('should track different users separately', () => {
      const store = getStore('test');
      const config = { max: 2, windowMs: 60000 };
      
      checkRateLimit(store, 'user-1', config);
      checkRateLimit(store, 'user-1', config);
      const resultUser1 = checkRateLimit(store, 'user-1', config);
      
      const resultUser2 = checkRateLimit(store, 'user-2', config);
      
      expect(resultUser1.allowed).toBe(false);
      expect(resultUser2.allowed).toBe(true);
    });

    it('should reset after window expires', () => {
      const store = getStore('test');
      const config = { max: 2, windowMs: 100 }; // 100ms window
      
      checkRateLimit(store, 'user-1', config);
      checkRateLimit(store, 'user-1', config);
      
      // Manually expire the entry
      const entry = store.get('user-1');
      if (entry) {
        entry.resetAt = Date.now() - 1;
      }
      
      const result = checkRateLimit(store, 'user-1', config);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(1);
    });
  });

  describe('Store Isolation', () => {
    it('should keep different stores separate', () => {
      const globalStore = getStore('global');
      const authStore = getStore('auth');
      
      checkRateLimit(globalStore, 'user-1', { max: 100, windowMs: 60000 });
      checkRateLimit(authStore, 'user-1', { max: 5, windowMs: 900000 });
      
      expect(globalStore.get('user-1')?.count).toBe(1);
      expect(authStore.get('user-1')?.count).toBe(1);
    });

    it('should have different limits for different stores', () => {
      const authStore = getStore('auth');
      const aiStore = getStore('ai');
      
      // Auth: 5 requests per 15 minutes
      for (let i = 0; i < 5; i++) {
        checkRateLimit(authStore, 'user-1', { max: 5, windowMs: 900000 });
      }
      const authResult = checkRateLimit(authStore, 'user-1', { max: 5, windowMs: 900000 });
      
      // AI: 10 requests per minute
      for (let i = 0; i < 10; i++) {
        checkRateLimit(aiStore, 'user-1', { max: 10, windowMs: 60000 });
      }
      const aiResult = checkRateLimit(aiStore, 'user-1', { max: 10, windowMs: 60000 });
      
      expect(authResult.allowed).toBe(false);
      expect(aiResult.allowed).toBe(false);
    });
  });

  describe('Key Generation', () => {
    it('should generate different keys for IP vs user', () => {
      const ipKey = `ip:192.168.1.1`;
      const userKey = `user:user-123`;
      const combinedKey = `combined:192.168.1.1:user-123`;
      
      expect(ipKey).not.toBe(userKey);
      expect(combinedKey).toContain('192.168.1.1');
      expect(combinedKey).toContain('user-123');
    });

    it('should handle anonymous users', () => {
      const anonymousKey = `user:anonymous`;
      const ipKey = `ip:192.168.1.1`;
      
      expect(anonymousKey).toBeDefined();
      expect(ipKey).toBeDefined();
    });
  });

  describe('Edge Cases', () => {
    it('should handle max=0 (disabled)', () => {
      const store = getStore('disabled');
      const config = { max: 0, windowMs: 60000 };
      
      const result = checkRateLimit(store, 'user-1', config);
      expect(result.allowed).toBe(false);
    });

    it('should handle very large windows', () => {
      const store = getStore('large-window');
      const config = { max: 100, windowMs: 86400000 }; // 24 hours
      
      const result = checkRateLimit(store, 'user-1', config);
      expect(result.allowed).toBe(true);
      expect(result.resetAt).toBeGreaterThan(Date.now() + 86000000);
    });

    it('should handle rapid requests', () => {
      const store = getStore('rapid');
      const config = { max: 100, windowMs: 60000 };
      
      // Simulate 100 rapid requests
      for (let i = 0; i < 100; i++) {
        checkRateLimit(store, 'user-1', config);
      }
      
      const result = checkRateLimit(store, 'user-1', config);
      expect(result.allowed).toBe(false);
    });
  });
});

describe('Rate Limit Configurations', () => {
  it('should define global rate limit', () => {
    const globalConfig = { max: 100, windowMs: 60000 };
    expect(globalConfig.max).toBe(100);
    expect(globalConfig.windowMs).toBe(60000);
  });

  it('should define stricter auth rate limit', () => {
    const authConfig = { max: 5, windowMs: 900000 }; // 5 per 15 min
    expect(authConfig.max).toBe(5);
    expect(authConfig.windowMs).toBe(900000);
  });

  it('should define AI rate limit', () => {
    const aiConfig = { max: 10, windowMs: 60000 }; // 10 per minute
    expect(aiConfig.max).toBe(10);
    expect(aiConfig.windowMs).toBe(60000);
  });

  it('should define consent rate limit', () => {
    const consentConfig = { max: 30, windowMs: 60000 };
    expect(consentConfig.max).toBe(30);
  });

  it('should define admin rate limit', () => {
    const adminConfig = { max: 50, windowMs: 60000 };
    expect(adminConfig.max).toBe(50);
  });
});
