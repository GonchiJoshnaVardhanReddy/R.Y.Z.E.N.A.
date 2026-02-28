/**
 * R.Y.Z.E.N.A. - Consent Validation Tests
 * 
 * Unit tests for Zod validation schemas.
 */

import { describe, it, expect } from 'vitest';
import {
  consentRequestSchema,
  consentResponseSchema,
  revokeGrantSchema,
  checkAccessSchema,
  registerServiceSchema,
} from '../../src/modules/consent/consent.validation.js';

describe('Consent Validation', () => {
  describe('consentRequestSchema', () => {
    it('should validate valid consent request', () => {
      const validRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        requestedFields: ['email', 'gpa'],
        purpose: 'Academic advising and course recommendations',
        requestedDuration: 30,
      };
      
      const result = consentRequestSchema.safeParse(validRequest);
      expect(result.success).toBe(true);
    });
    
    it('should reject empty student ID', () => {
      const invalidRequest = {
        studentId: '',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        requestedFields: ['email'],
        purpose: 'Valid purpose here',
        requestedDuration: 30,
      };
      
      const result = consentRequestSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject invalid service ID format', () => {
      const invalidRequest = {
        studentId: 'student-123',
        serviceId: 'not-a-uuid',
        requestedFields: ['email'],
        purpose: 'Valid purpose here',
        requestedDuration: 30,
      };
      
      const result = consentRequestSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject empty requested fields', () => {
      const invalidRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        requestedFields: [],
        purpose: 'Valid purpose here',
        requestedDuration: 30,
      };
      
      const result = consentRequestSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject too short purpose', () => {
      const invalidRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        requestedFields: ['email'],
        purpose: 'Short',
        requestedDuration: 30,
      };
      
      const result = consentRequestSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject duration less than 1 day', () => {
      const invalidRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        requestedFields: ['email'],
        purpose: 'Valid purpose here',
        requestedDuration: 0,
      };
      
      const result = consentRequestSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject duration more than 365 days', () => {
      const invalidRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        requestedFields: ['email'],
        purpose: 'Valid purpose here',
        requestedDuration: 400,
      };
      
      const result = consentRequestSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
  });
  
  describe('consentResponseSchema', () => {
    it('should validate approval response', () => {
      const validResponse = {
        requestId: '550e8400-e29b-41d4-a716-446655440000',
        studentId: 'student-123',
        action: 'APPROVE',
      };
      
      const result = consentResponseSchema.safeParse(validResponse);
      expect(result.success).toBe(true);
    });
    
    it('should validate denial response', () => {
      const validResponse = {
        requestId: '550e8400-e29b-41d4-a716-446655440000',
        studentId: 'student-123',
        action: 'DENY',
      };
      
      const result = consentResponseSchema.safeParse(validResponse);
      expect(result.success).toBe(true);
    });
    
    it('should validate response with modified fields', () => {
      const validResponse = {
        requestId: '550e8400-e29b-41d4-a716-446655440000',
        studentId: 'student-123',
        action: 'APPROVE',
        modifiedFields: ['email'],
        modifiedDuration: 7,
      };
      
      const result = consentResponseSchema.safeParse(validResponse);
      expect(result.success).toBe(true);
    });
    
    it('should reject invalid action', () => {
      const invalidResponse = {
        requestId: '550e8400-e29b-41d4-a716-446655440000',
        studentId: 'student-123',
        action: 'INVALID',
      };
      
      const result = consentResponseSchema.safeParse(invalidResponse);
      expect(result.success).toBe(false);
    });
    
    it('should reject invalid request ID', () => {
      const invalidResponse = {
        requestId: 'not-a-uuid',
        studentId: 'student-123',
        action: 'APPROVE',
      };
      
      const result = consentResponseSchema.safeParse(invalidResponse);
      expect(result.success).toBe(false);
    });
  });
  
  describe('revokeGrantSchema', () => {
    it('should validate valid revocation request', () => {
      const validRequest = {
        grantId: '550e8400-e29b-41d4-a716-446655440000',
        studentId: 'student-123',
        reason: 'No longer needed',
      };
      
      const result = revokeGrantSchema.safeParse(validRequest);
      expect(result.success).toBe(true);
    });
    
    it('should reject too short reason', () => {
      const invalidRequest = {
        grantId: '550e8400-e29b-41d4-a716-446655440000',
        studentId: 'student-123',
        reason: 'No',
      };
      
      const result = revokeGrantSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject invalid grant ID', () => {
      const invalidRequest = {
        grantId: 'not-a-uuid',
        studentId: 'student-123',
        reason: 'Valid reason here',
      };
      
      const result = revokeGrantSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
  });
  
  describe('checkAccessSchema', () => {
    it('should validate valid access check', () => {
      const validRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        fields: ['email', 'gpa'],
      };
      
      const result = checkAccessSchema.safeParse(validRequest);
      expect(result.success).toBe(true);
    });
    
    it('should reject empty fields array', () => {
      const invalidRequest = {
        studentId: 'student-123',
        serviceId: '550e8400-e29b-41d4-a716-446655440000',
        fields: [],
      };
      
      const result = checkAccessSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
  });
  
  describe('registerServiceSchema', () => {
    it('should validate valid service registration', () => {
      const validRequest = {
        name: 'Academic Services',
        description: 'Provides academic support services',
        riskCategory: 'LOW',
      };
      
      const result = registerServiceSchema.safeParse(validRequest);
      expect(result.success).toBe(true);
    });
    
    it('should validate service with only name', () => {
      const validRequest = {
        name: 'Simple Service',
      };
      
      const result = registerServiceSchema.safeParse(validRequest);
      expect(result.success).toBe(true);
    });
    
    it('should reject too short name', () => {
      const invalidRequest = {
        name: 'A',
      };
      
      const result = registerServiceSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject invalid characters in name', () => {
      const invalidRequest = {
        name: 'Service@Name!',
      };
      
      const result = registerServiceSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should reject invalid risk category', () => {
      const invalidRequest = {
        name: 'Valid Service',
        riskCategory: 'INVALID',
      };
      
      const result = registerServiceSchema.safeParse(invalidRequest);
      expect(result.success).toBe(false);
    });
    
    it('should accept all valid risk categories', () => {
      const categories = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      
      for (const category of categories) {
        const request = {
          name: 'Test Service',
          riskCategory: category,
        };
        
        const result = registerServiceSchema.safeParse(request);
        expect(result.success).toBe(true);
      }
    });
  });
});
