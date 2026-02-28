/**
 * R.Y.Z.E.N.A. - Consent Policy Tests
 * 
 * Unit tests for consent policy configuration and utility functions.
 */

import { describe, it, expect } from 'vitest';
import {
  DATA_FIELDS,
  DURATION_MULTIPLIERS,
  SERVICE_RISK_WEIGHTS,
  RISK_LEVEL_THRESHOLDS,
  getDurationMultiplier,
  getPermissionCountMultiplier,
  getRiskLevel,
  getFieldDefinition,
  getFieldDefinitions,
  calculateFieldSensitivity,
  hasHighSensitivityField,
  getAllFieldNames,
  validateFieldNames,
  HIGH_SENSITIVITY_FIELDS,
} from '../../src/modules/consent/consent.policy.js';

describe('Consent Policy', () => {
  describe('DATA_FIELDS', () => {
    it('should define all required field categories', () => {
      const categories = new Set(
        Object.values(DATA_FIELDS).map(f => f.category)
      );
      
      expect(categories).toContain('CONTACT');
      expect(categories).toContain('ACADEMIC');
      expect(categories).toContain('FINANCIAL');
      expect(categories).toContain('PERSONAL');
      expect(categories).toContain('IDENTITY');
      expect(categories).toContain('BEHAVIORAL');
    });
    
    it('should have valid sensitivity weights (0-100)', () => {
      for (const field of Object.values(DATA_FIELDS)) {
        expect(field.sensitivityWeight).toBeGreaterThanOrEqual(0);
        expect(field.sensitivityWeight).toBeLessThanOrEqual(100);
      }
    });
    
    it('should have SSN as highest sensitivity', () => {
      const maxWeight = Math.max(
        ...Object.values(DATA_FIELDS).map(f => f.sensitivityWeight)
      );
      
      expect(DATA_FIELDS.ssn.sensitivityWeight).toBe(maxWeight);
    });
    
    it('should have email as low sensitivity', () => {
      expect(DATA_FIELDS.email.sensitivityWeight).toBeLessThanOrEqual(10);
    });
  });
  
  describe('DURATION_MULTIPLIERS', () => {
    it('should have increasing multipliers for longer durations', () => {
      for (let i = 1; i < DURATION_MULTIPLIERS.length; i++) {
        expect(DURATION_MULTIPLIERS[i].multiplier)
          .toBeGreaterThanOrEqual(DURATION_MULTIPLIERS[i - 1].multiplier);
      }
    });
    
    it('should start at 0.8x for one-time access', () => {
      expect(DURATION_MULTIPLIERS[0].multiplier).toBe(0.8);
      expect(DURATION_MULTIPLIERS[0].maxDays).toBe(1);
    });
    
    it('should have 2.0x for extended access', () => {
      const last = DURATION_MULTIPLIERS[DURATION_MULTIPLIERS.length - 1];
      expect(last.multiplier).toBe(2.0);
      expect(last.maxDays).toBe(Infinity);
    });
  });
  
  describe('getDurationMultiplier', () => {
    it('should return 0.8x for 1 day', () => {
      const result = getDurationMultiplier(1);
      expect(result.multiplier).toBe(0.8);
      expect(result.label).toContain('One-time');
    });
    
    it('should return 1.0x for 7 days', () => {
      const result = getDurationMultiplier(7);
      expect(result.multiplier).toBe(1.0);
      expect(result.label).toContain('Short-term');
    });
    
    it('should return 1.2x for 30 days', () => {
      const result = getDurationMultiplier(30);
      expect(result.multiplier).toBe(1.2);
      expect(result.label).toContain('Medium-term');
    });
    
    it('should return 1.4x for 90 days', () => {
      const result = getDurationMultiplier(90);
      expect(result.multiplier).toBe(1.4);
      expect(result.label).toContain('Quarterly');
    });
    
    it('should return 1.8x for 365 days', () => {
      const result = getDurationMultiplier(365);
      expect(result.multiplier).toBe(1.8);
      expect(result.label).toContain('Annual');
    });
    
    it('should return 2.0x for over 365 days', () => {
      const result = getDurationMultiplier(500);
      expect(result.multiplier).toBe(2.0);
      expect(result.label).toContain('Extended');
    });
  });
  
  describe('SERVICE_RISK_WEIGHTS', () => {
    it('should have all risk categories defined', () => {
      expect(SERVICE_RISK_WEIGHTS.LOW).toBeDefined();
      expect(SERVICE_RISK_WEIGHTS.MEDIUM).toBeDefined();
      expect(SERVICE_RISK_WEIGHTS.HIGH).toBeDefined();
      expect(SERVICE_RISK_WEIGHTS.CRITICAL).toBeDefined();
    });
    
    it('should have increasing weights for higher risk', () => {
      expect(SERVICE_RISK_WEIGHTS.LOW).toBe(1.0);
      expect(SERVICE_RISK_WEIGHTS.MEDIUM).toBeGreaterThan(SERVICE_RISK_WEIGHTS.LOW);
      expect(SERVICE_RISK_WEIGHTS.HIGH).toBeGreaterThan(SERVICE_RISK_WEIGHTS.MEDIUM);
      expect(SERVICE_RISK_WEIGHTS.CRITICAL).toBeGreaterThan(SERVICE_RISK_WEIGHTS.HIGH);
    });
  });
  
  describe('getPermissionCountMultiplier', () => {
    it('should return 1.0 for few permissions', () => {
      expect(getPermissionCountMultiplier(0)).toBe(1.0);
      expect(getPermissionCountMultiplier(3)).toBe(1.0);
    });
    
    it('should increase for more permissions', () => {
      expect(getPermissionCountMultiplier(5)).toBeGreaterThan(1.0);
      expect(getPermissionCountMultiplier(10)).toBeGreaterThan(getPermissionCountMultiplier(5));
    });
    
    it('should cap at maximum multiplier', () => {
      expect(getPermissionCountMultiplier(100)).toBe(1.5);
    });
  });
  
  describe('getRiskLevel', () => {
    it('should return LOW for scores <= 25', () => {
      expect(getRiskLevel(0)).toBe('LOW');
      expect(getRiskLevel(15)).toBe('LOW');
      expect(getRiskLevel(25)).toBe('LOW');
    });
    
    it('should return MEDIUM for scores 26-50', () => {
      expect(getRiskLevel(26)).toBe('MEDIUM');
      expect(getRiskLevel(40)).toBe('MEDIUM');
      expect(getRiskLevel(50)).toBe('MEDIUM');
    });
    
    it('should return HIGH for scores 51-75', () => {
      expect(getRiskLevel(51)).toBe('HIGH');
      expect(getRiskLevel(65)).toBe('HIGH');
      expect(getRiskLevel(75)).toBe('HIGH');
    });
    
    it('should return CRITICAL for scores > 75', () => {
      expect(getRiskLevel(76)).toBe('CRITICAL');
      expect(getRiskLevel(90)).toBe('CRITICAL');
      expect(getRiskLevel(100)).toBe('CRITICAL');
    });
    
    it('should match threshold constants', () => {
      expect(getRiskLevel(RISK_LEVEL_THRESHOLDS.LOW)).toBe('LOW');
      expect(getRiskLevel(RISK_LEVEL_THRESHOLDS.MEDIUM)).toBe('MEDIUM');
      expect(getRiskLevel(RISK_LEVEL_THRESHOLDS.HIGH)).toBe('HIGH');
    });
  });
  
  describe('getFieldDefinition', () => {
    it('should return field definition for valid field', () => {
      const field = getFieldDefinition('email');
      
      expect(field).toBeDefined();
      expect(field!.name).toBe('email');
      expect(field!.label).toBe('Email Address');
      expect(field!.category).toBe('CONTACT');
    });
    
    it('should return undefined for invalid field', () => {
      const field = getFieldDefinition('nonexistent');
      expect(field).toBeUndefined();
    });
  });
  
  describe('getFieldDefinitions', () => {
    it('should return definitions for multiple fields', () => {
      const fields = getFieldDefinitions(['email', 'gpa', 'transcript']);
      
      expect(fields).toHaveLength(3);
      expect(fields.map(f => f.name)).toEqual(['email', 'gpa', 'transcript']);
    });
    
    it('should filter out invalid fields', () => {
      const fields = getFieldDefinitions(['email', 'invalid', 'gpa']);
      
      expect(fields).toHaveLength(2);
      expect(fields.map(f => f.name)).toEqual(['email', 'gpa']);
    });
    
    it('should return empty array for all invalid fields', () => {
      const fields = getFieldDefinitions(['invalid1', 'invalid2']);
      expect(fields).toHaveLength(0);
    });
  });
  
  describe('calculateFieldSensitivity', () => {
    it('should sum sensitivity weights', () => {
      const total = calculateFieldSensitivity(['email', 'gpa']);
      
      expect(total).toBe(
        DATA_FIELDS.email.sensitivityWeight + DATA_FIELDS.gpa.sensitivityWeight
      );
    });
    
    it('should return 0 for empty array', () => {
      expect(calculateFieldSensitivity([])).toBe(0);
    });
    
    it('should ignore invalid fields', () => {
      const total = calculateFieldSensitivity(['email', 'invalid']);
      expect(total).toBe(DATA_FIELDS.email.sensitivityWeight);
    });
    
    it('should calculate high total for sensitive fields', () => {
      const total = calculateFieldSensitivity(['ssn', 'passport', 'financial_aid']);
      expect(total).toBeGreaterThan(100);
    });
  });
  
  describe('hasHighSensitivityField', () => {
    it('should return true for SSN', () => {
      expect(hasHighSensitivityField(['email', 'ssn'])).toBe(true);
    });
    
    it('should return true for passport', () => {
      expect(hasHighSensitivityField(['passport'])).toBe(true);
    });
    
    it('should return true for financial fields', () => {
      expect(hasHighSensitivityField(['financial_aid'])).toBe(true);
      expect(hasHighSensitivityField(['payment_history'])).toBe(true);
      expect(hasHighSensitivityField(['account_balance'])).toBe(true);
    });
    
    it('should return false for low sensitivity fields', () => {
      expect(hasHighSensitivityField(['email', 'full_name', 'major'])).toBe(false);
    });
    
    it('should return false for empty array', () => {
      expect(hasHighSensitivityField([])).toBe(false);
    });
  });
  
  describe('getAllFieldNames', () => {
    it('should return all field names', () => {
      const names = getAllFieldNames();
      
      expect(names).toContain('email');
      expect(names).toContain('gpa');
      expect(names).toContain('ssn');
      expect(names).toContain('financial_aid');
      expect(names.length).toBe(Object.keys(DATA_FIELDS).length);
    });
  });
  
  describe('validateFieldNames', () => {
    it('should validate all fields as valid', () => {
      const result = validateFieldNames(['email', 'gpa', 'transcript']);
      
      expect(result.valid).toBe(true);
      expect(result.invalid).toHaveLength(0);
    });
    
    it('should detect invalid fields', () => {
      const result = validateFieldNames(['email', 'unknown_field']);
      
      expect(result.valid).toBe(false);
      expect(result.invalid).toContain('unknown_field');
    });
    
    it('should handle empty array', () => {
      const result = validateFieldNames([]);
      
      expect(result.valid).toBe(true);
      expect(result.invalid).toHaveLength(0);
    });
  });
  
  describe('HIGH_SENSITIVITY_FIELDS', () => {
    it('should include SSN', () => {
      expect(HIGH_SENSITIVITY_FIELDS).toContain('ssn');
    });
    
    it('should include passport', () => {
      expect(HIGH_SENSITIVITY_FIELDS).toContain('passport');
    });
    
    it('should include financial fields', () => {
      expect(HIGH_SENSITIVITY_FIELDS).toContain('financial_aid');
      expect(HIGH_SENSITIVITY_FIELDS).toContain('payment_history');
      expect(HIGH_SENSITIVITY_FIELDS).toContain('account_balance');
    });
    
    it('should not include low sensitivity fields', () => {
      expect(HIGH_SENSITIVITY_FIELDS).not.toContain('email');
      expect(HIGH_SENSITIVITY_FIELDS).not.toContain('full_name');
    });
  });
});
