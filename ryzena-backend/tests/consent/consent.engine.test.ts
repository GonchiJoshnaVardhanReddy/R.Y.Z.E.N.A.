/**
 * R.Y.Z.E.N.A. - Consent Engine Tests
 * 
 * Unit tests for consent risk scoring and calculation.
 */

import { describe, it, expect } from 'vitest';
import {
  calculateRiskAssessment,
  createRiskEvent,
  buildConsentExplanationInput,
  validateFields,
  canAutoApprove,
} from '../../src/modules/consent/consent.engine.js';
import type { ConsentRequest, Service } from '../../src/modules/consent/consent.types.js';

describe('Consent Engine', () => {
  describe('calculateRiskAssessment', () => {
    it('should return low risk for minimal data request', () => {
      const result = calculateRiskAssessment(
        ['email'],              // Low sensitivity field
        7,                      // Short duration
        'LOW',                  // Low risk service
        0                       // No existing permissions
      );
      
      expect(result.riskScore).toBeLessThanOrEqual(25);
      expect(result.riskLevel).toBe('LOW');
      expect(result.factors).toHaveLength(4);
      expect(result.recommendations.length).toBeGreaterThan(0);
    });
    
    it('should return high risk for sensitive data request', () => {
      const result = calculateRiskAssessment(
        ['ssn', 'financial_aid', 'payment_history'], // High sensitivity fields
        180,                                         // Long duration
        'HIGH',                                      // High risk service
        10                                           // Many existing permissions
      );
      
      expect(result.riskScore).toBeGreaterThan(50);
      expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
    });
    
    it('should include field sensitivity in factors', () => {
      const result = calculateRiskAssessment(
        ['gpa', 'transcript', 'grades'],
        30,
        'MEDIUM',
        0
      );
      
      const fieldFactor = result.factors.find(f => f.category === 'FIELD_SENSITIVITY');
      expect(fieldFactor).toBeDefined();
      expect(fieldFactor!.contribution).toBeGreaterThan(0);
    });
    
    it('should include duration in factors', () => {
      const result = calculateRiskAssessment(
        ['email'],
        90,
        'LOW',
        0
      );
      
      const durationFactor = result.factors.find(f => f.category === 'DURATION');
      expect(durationFactor).toBeDefined();
      expect(durationFactor!.description).toContain('Quarterly');
    });
    
    it('should apply service risk multiplier', () => {
      const lowRiskResult = calculateRiskAssessment(['gpa'], 30, 'LOW', 0);
      const highRiskResult = calculateRiskAssessment(['gpa'], 30, 'HIGH', 0);
      
      expect(highRiskResult.riskScore).toBeGreaterThan(lowRiskResult.riskScore);
    });
    
    it('should apply permission count multiplier', () => {
      const fewPermissions = calculateRiskAssessment(['gpa'], 30, 'MEDIUM', 2);
      const manyPermissions = calculateRiskAssessment(['gpa'], 30, 'MEDIUM', 15);
      
      expect(manyPermissions.riskScore).toBeGreaterThan(fewPermissions.riskScore);
    });
    
    it('should include student risk level when provided', () => {
      const result = calculateRiskAssessment(
        ['email'],
        7,
        'LOW',
        0,
        'HIGH'
      );
      
      const studentFactor = result.factors.find(f => f.category === 'STUDENT_RISK');
      expect(studentFactor).toBeDefined();
      expect(studentFactor!.description).toContain('HIGH');
    });
    
    it('should clamp risk score to 0-100', () => {
      const result = calculateRiskAssessment(
        ['ssn', 'passport', 'financial_aid', 'payment_history', 'account_balance'],
        365,
        'CRITICAL',
        25,
        'CRITICAL'
      );
      
      expect(result.riskScore).toBeLessThanOrEqual(100);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
    });
    
    it('should generate appropriate recommendations for high risk', () => {
      const result = calculateRiskAssessment(
        ['ssn', 'financial_aid'],
        90,
        'HIGH',
        5
      );
      
      expect(result.recommendations).toContainEqual(
        expect.stringContaining('highly sensitive')
      );
    });
    
    it('should recommend duration reduction for long access periods', () => {
      const result = calculateRiskAssessment(
        ['email'],
        60,
        'LOW',
        0
      );
      
      expect(result.recommendations).toContainEqual(
        expect.stringContaining('reducing access duration')
      );
    });
  });
  
  describe('createRiskEvent', () => {
    const mockRequest: ConsentRequest = {
      id: 'request-1',
      studentId: 'student-1',
      serviceId: 'service-1',
      requestedFields: ['gpa', 'transcript'],
      purpose: 'Academic review',
      requestedDuration: 30,
      riskScore: 60,
      status: 'PENDING',
      deniedFields: null,
      approvedDuration: null,
      respondedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    const mockService: Service = {
      id: 'service-1',
      name: 'Academic Services',
      description: 'Academic services department',
      riskCategory: 'MEDIUM',
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    it('should create negative impact event for high-risk approval', () => {
      const highRiskRequest = { ...mockRequest, riskScore: 80 };
      const event = createRiskEvent('CONSENT_APPROVED', highRiskRequest, mockService);
      
      expect(event.type).toBe('CONSENT_APPROVED');
      expect(event.impact).toBeLessThan(0);
      expect(event.studentId).toBe('student-1');
    });
    
    it('should create positive impact event for high-risk denial', () => {
      const highRiskRequest = { ...mockRequest, riskScore: 80 };
      const event = createRiskEvent('CONSENT_DENIED', highRiskRequest, mockService);
      
      expect(event.type).toBe('CONSENT_DENIED');
      expect(event.impact).toBeGreaterThan(0);
    });
    
    it('should create neutral impact for low-risk approval', () => {
      const lowRiskRequest = { ...mockRequest, riskScore: 20 };
      const event = createRiskEvent('CONSENT_APPROVED', lowRiskRequest, mockService);
      
      expect(event.impact).toBe(0);
    });
    
    it('should create positive impact for revocation', () => {
      const event = createRiskEvent('CONSENT_REVOKED', mockRequest, mockService);
      
      expect(event.type).toBe('CONSENT_REVOKED');
      expect(event.impact).toBeGreaterThan(0);
    });
    
    it('should include metadata with service and request info', () => {
      const event = createRiskEvent('CONSENT_APPROVED', mockRequest, mockService);
      
      expect(event.metadata.serviceId).toBe('service-1');
      expect(event.metadata.serviceName).toBe('Academic Services');
      expect(event.metadata.requestId).toBe('request-1');
      expect(event.metadata.riskScore).toBe(60);
      expect(event.metadata.fields).toEqual(['gpa', 'transcript']);
    });
  });
  
  describe('buildConsentExplanationInput', () => {
    const mockRequest: ConsentRequest = {
      id: 'request-1',
      studentId: 'student-1',
      serviceId: 'service-1',
      requestedFields: ['email', 'gpa'],
      purpose: 'Send academic updates',
      requestedDuration: 30,
      riskScore: 35,
      status: 'PENDING',
      deniedFields: null,
      approvedDuration: null,
      respondedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    const mockService: Service = {
      id: 'service-1',
      name: 'Academic Portal',
      description: 'Student academic information portal',
      riskCategory: 'LOW',
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    const mockRiskAssessment = {
      riskScore: 35,
      riskLevel: 'MEDIUM' as const,
      factors: [],
      recommendations: [],
    };
    
    it('should build explanation input with all fields', () => {
      const input = buildConsentExplanationInput(
        mockRequest,
        mockService,
        mockRiskAssessment,
        5
      );
      
      expect(input.serviceName).toBe('Academic Portal');
      expect(input.serviceDescription).toBe('Student academic information portal');
      expect(input.purpose).toBe('Send academic updates');
      expect(input.riskScore).toBe(35);
      expect(input.riskLevel).toBe('MEDIUM');
      expect(input.existingPermissionCount).toBe(5);
    });
    
    it('should include field definitions', () => {
      const input = buildConsentExplanationInput(
        mockRequest,
        mockService,
        mockRiskAssessment,
        0
      );
      
      expect(input.requestedFields).toHaveLength(2);
      expect(input.requestedFields[0]).toHaveProperty('name');
      expect(input.requestedFields[0]).toHaveProperty('sensitivityWeight');
    });
    
    it('should recommend APPROVE for low risk', () => {
      const lowRiskAssessment = { ...mockRiskAssessment, riskScore: 20 };
      const input = buildConsentExplanationInput(
        mockRequest,
        mockService,
        lowRiskAssessment,
        0
      );
      
      expect(input.recommendedAction).toBe('APPROVE');
    });
    
    it('should recommend REVIEW for medium risk', () => {
      const mediumRiskAssessment = { ...mockRiskAssessment, riskScore: 50 };
      const input = buildConsentExplanationInput(
        mockRequest,
        mockService,
        mediumRiskAssessment,
        0
      );
      
      expect(input.recommendedAction).toBe('REVIEW');
    });
    
    it('should recommend DENY for high risk', () => {
      const highRiskAssessment = { ...mockRiskAssessment, riskScore: 80 };
      const input = buildConsentExplanationInput(
        mockRequest,
        mockService,
        highRiskAssessment,
        0
      );
      
      expect(input.recommendedAction).toBe('DENY');
    });
    
    it('should include student risk level when provided', () => {
      const input = buildConsentExplanationInput(
        mockRequest,
        mockService,
        mockRiskAssessment,
        0,
        'HIGH'
      );
      
      expect(input.studentRiskLevel).toBe('HIGH');
    });
  });
  
  describe('validateFields', () => {
    it('should validate all known fields', () => {
      const result = validateFields(['email', 'gpa', 'transcript']);
      
      expect(result.valid).toBe(true);
      expect(result.validFields).toEqual(['email', 'gpa', 'transcript']);
      expect(result.invalidFields).toEqual([]);
    });
    
    it('should detect invalid fields', () => {
      const result = validateFields(['email', 'invalid_field', 'unknown']);
      
      expect(result.valid).toBe(false);
      expect(result.validFields).toEqual(['email']);
      expect(result.invalidFields).toEqual(['invalid_field', 'unknown']);
    });
    
    it('should handle empty array', () => {
      const result = validateFields([]);
      
      expect(result.valid).toBe(true);
      expect(result.validFields).toEqual([]);
      expect(result.invalidFields).toEqual([]);
    });
  });
  
  describe('canAutoApprove', () => {
    it('should allow auto-approve for low risk, short duration', () => {
      const result = canAutoApprove(20, 7, ['email', 'full_name']);
      expect(result).toBe(true);
    });
    
    it('should deny auto-approve for high risk score', () => {
      const result = canAutoApprove(50, 7, ['email']);
      expect(result).toBe(false);
    });
    
    it('should deny auto-approve for long duration', () => {
      const result = canAutoApprove(20, 14, ['email']);
      expect(result).toBe(false);
    });
    
    it('should deny auto-approve for sensitive fields', () => {
      const result = canAutoApprove(20, 7, ['ssn']);
      expect(result).toBe(false);
    });
    
    it('should deny auto-approve for financial fields', () => {
      const result = canAutoApprove(20, 7, ['email', 'financial_aid']);
      expect(result).toBe(false);
    });
  });
});
