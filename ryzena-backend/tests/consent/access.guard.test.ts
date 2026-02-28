/**
 * R.Y.Z.E.N.A. - Access Guard Tests
 * 
 * Unit tests for field-level access control.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ConsentGrant } from '../../src/modules/consent/consent.types.js';

// Mock the repository module
vi.mock('../../src/modules/consent/consent.repository.js', () => ({
  findActiveGrant: vi.fn(),
}));

import * as accessGuard from '../../src/modules/consent/access.guard.js';
import * as repository from '../../src/modules/consent/consent.repository.js';

const mockRepository = vi.mocked(repository);

describe('Access Guard', () => {
  const validGrant: ConsentGrant = {
    id: 'grant-1',
    studentId: 'student-1',
    serviceId: 'service-1',
    requestId: 'request-1',
    approvedFields: ['email', 'gpa', 'full_name'],
    expiresAt: new Date(Date.now() + 86400000), // Tomorrow
    isRevoked: false,
    revokedAt: null,
    revocationReason: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  
  beforeEach(() => {
    vi.clearAllMocks();
  });
  
  describe('checkAccess', () => {
    it('should return true for approved field with active grant', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.checkAccess('student-1', 'service-1', 'email');
      
      expect(result).toBe(true);
      expect(mockRepository.findActiveGrant).toHaveBeenCalledWith('student-1', 'service-1');
    });
    
    it('should return false when no grant exists', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(null);
      
      const result = await accessGuard.checkAccess('student-1', 'service-1', 'email');
      
      expect(result).toBe(false);
    });
    
    it('should return false for unapproved field', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.checkAccess('student-1', 'service-1', 'ssn');
      
      expect(result).toBe(false);
    });
  });
  
  describe('checkFieldAccess', () => {
    it('should return detailed result for approved access', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.checkFieldAccess('student-1', 'service-1', 'email');
      
      expect(result.allowed).toBe(true);
      expect(result.field).toBe('email');
      expect(result.grantId).toBe('grant-1');
      expect(result.expiresAt).toBeDefined();
    });
    
    it('should return reason when no grant exists', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(null);
      
      const result = await accessGuard.checkFieldAccess('student-1', 'service-1', 'email');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('No active consent grant');
    });
    
    it('should return reason for expired grant', async () => {
      const expiredGrant = {
        ...validGrant,
        expiresAt: new Date(Date.now() - 86400000), // Yesterday
      };
      mockRepository.findActiveGrant.mockResolvedValue(expiredGrant);
      
      const result = await accessGuard.checkFieldAccess('student-1', 'service-1', 'email');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('expired');
    });
    
    it('should return reason for revoked grant', async () => {
      const revokedGrant = {
        ...validGrant,
        isRevoked: true,
        revokedAt: new Date(),
        revocationReason: 'User requested revocation',
      };
      mockRepository.findActiveGrant.mockResolvedValue(revokedGrant);
      
      const result = await accessGuard.checkFieldAccess('student-1', 'service-1', 'email');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('revoked');
    });
    
    it('should return reason for unapproved field', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.checkFieldAccess('student-1', 'service-1', 'ssn');
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('not included in approved fields');
      expect(result.grantId).toBe('grant-1');
    });
  });
  
  describe('checkMultiFieldAccess', () => {
    it('should check multiple fields at once', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.checkMultiFieldAccess(
        'student-1',
        'service-1',
        ['email', 'gpa', 'ssn']
      );
      
      expect(result.allAllowed).toBe(false);
      expect(result.allowedFields).toEqual(['email', 'gpa']);
      expect(result.deniedFields).toEqual(['ssn']);
      expect(result.results).toHaveLength(3);
    });
    
    it('should return all allowed for approved fields', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.checkMultiFieldAccess(
        'student-1',
        'service-1',
        ['email', 'gpa']
      );
      
      expect(result.allAllowed).toBe(true);
      expect(result.allowedFields).toEqual(['email', 'gpa']);
      expect(result.deniedFields).toEqual([]);
    });
    
    it('should return all denied when no grant exists', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(null);
      
      const result = await accessGuard.checkMultiFieldAccess(
        'student-1',
        'service-1',
        ['email', 'gpa']
      );
      
      expect(result.allAllowed).toBe(false);
      expect(result.allowedFields).toEqual([]);
      expect(result.deniedFields).toEqual(['email', 'gpa']);
    });
    
    it('should handle expired grant for all fields', async () => {
      const expiredGrant = {
        ...validGrant,
        expiresAt: new Date(Date.now() - 86400000),
      };
      mockRepository.findActiveGrant.mockResolvedValue(expiredGrant);
      
      const result = await accessGuard.checkMultiFieldAccess(
        'student-1',
        'service-1',
        ['email', 'gpa']
      );
      
      expect(result.allAllowed).toBe(false);
      expect(result.deniedFields).toEqual(['email', 'gpa']);
      for (const r of result.results) {
        expect(r.reason).toContain('expired');
      }
    });
  });
  
  describe('getAccessibleFields', () => {
    it('should return approved fields for valid grant', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const fields = await accessGuard.getAccessibleFields('student-1', 'service-1');
      
      expect(fields).toEqual(['email', 'gpa', 'full_name']);
    });
    
    it('should return empty array when no grant exists', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(null);
      
      const fields = await accessGuard.getAccessibleFields('student-1', 'service-1');
      
      expect(fields).toEqual([]);
    });
    
    it('should return empty array for expired grant', async () => {
      const expiredGrant = {
        ...validGrant,
        expiresAt: new Date(Date.now() - 86400000),
      };
      mockRepository.findActiveGrant.mockResolvedValue(expiredGrant);
      
      const fields = await accessGuard.getAccessibleFields('student-1', 'service-1');
      
      expect(fields).toEqual([]);
    });
    
    it('should return empty array for revoked grant', async () => {
      const revokedGrant = {
        ...validGrant,
        isRevoked: true,
      };
      mockRepository.findActiveGrant.mockResolvedValue(revokedGrant);
      
      const fields = await accessGuard.getAccessibleFields('student-1', 'service-1');
      
      expect(fields).toEqual([]);
    });
  });
  
  describe('hasActiveGrant', () => {
    it('should return true for valid grant', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.hasActiveGrant('student-1', 'service-1');
      
      expect(result).toBe(true);
    });
    
    it('should return false when no grant exists', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(null);
      
      const result = await accessGuard.hasActiveGrant('student-1', 'service-1');
      
      expect(result).toBe(false);
    });
    
    it('should return false for expired grant', async () => {
      const expiredGrant = {
        ...validGrant,
        expiresAt: new Date(Date.now() - 86400000),
      };
      mockRepository.findActiveGrant.mockResolvedValue(expiredGrant);
      
      const result = await accessGuard.hasActiveGrant('student-1', 'service-1');
      
      expect(result).toBe(false);
    });
    
    it('should return false for revoked grant', async () => {
      const revokedGrant = {
        ...validGrant,
        isRevoked: true,
      };
      mockRepository.findActiveGrant.mockResolvedValue(revokedGrant);
      
      const result = await accessGuard.hasActiveGrant('student-1', 'service-1');
      
      expect(result).toBe(false);
    });
  });
  
  describe('getGrantInfo', () => {
    it('should return grant info for valid grant', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(validGrant);
      
      const result = await accessGuard.getGrantInfo('student-1', 'service-1');
      
      expect(result).toBeDefined();
      expect(result!.hasGrant).toBe(true);
      expect(result!.isValid).toBe(true);
      expect(result!.grant).toBe(validGrant);
      expect(result!.remainingTime).toBeGreaterThan(0);
    });
    
    it('should return no grant info when grant not found', async () => {
      mockRepository.findActiveGrant.mockResolvedValue(null);
      
      const result = await accessGuard.getGrantInfo('student-1', 'service-1');
      
      expect(result).toBeDefined();
      expect(result!.hasGrant).toBe(false);
      expect(result!.isValid).toBe(false);
      expect(result!.grant).toBeNull();
      expect(result!.remainingTime).toBeNull();
    });
    
    it('should return invalid for expired grant', async () => {
      const expiredGrant = {
        ...validGrant,
        expiresAt: new Date(Date.now() - 86400000),
      };
      mockRepository.findActiveGrant.mockResolvedValue(expiredGrant);
      
      const result = await accessGuard.getGrantInfo('student-1', 'service-1');
      
      expect(result).toBeDefined();
      expect(result!.hasGrant).toBe(true);
      expect(result!.isValid).toBe(false);
      expect(result!.remainingTime).toBeNull();
    });
  });
});
