/**
 * R.Y.Z.E.N.A. - Consent Policy Configuration
 * 
 * Defines field sensitivity weights, duration multipliers, and governance rules.
 * All weights are configurable and stored centrally.
 */

import type { DataField, DataFieldCategory, RiskCategory } from './consent.types.js';

// ============================================================================
// FIELD SENSITIVITY CONFIGURATION
// ============================================================================

/**
 * Default sensitivity weights for data field categories
 * Weight range: 0-100 (higher = more sensitive)
 */
export const DEFAULT_CATEGORY_WEIGHTS: Record<DataFieldCategory, number> = {
  CONTACT: 5,      // Email, phone, address
  ACADEMIC: 12,    // GPA, courses, transcript
  FINANCIAL: 25,   // Financial aid, payment info
  PERSONAL: 8,     // Name, date of birth
  IDENTITY: 20,    // Student ID, SSN
  BEHAVIORAL: 15,  // Login history, usage patterns
};

/**
 * Pre-defined data fields with sensitivity weights
 */
export const DATA_FIELDS: Record<string, DataField> = {
  // Contact Information
  email: {
    name: 'email',
    label: 'Email Address',
    category: 'CONTACT',
    sensitivityWeight: 5,
    description: 'Student email address',
  },
  phone: {
    name: 'phone',
    label: 'Phone Number',
    category: 'CONTACT',
    sensitivityWeight: 5,
    description: 'Student phone number',
  },
  address: {
    name: 'address',
    label: 'Physical Address',
    category: 'CONTACT',
    sensitivityWeight: 8,
    description: 'Student physical address',
  },
  
  // Academic Information
  gpa: {
    name: 'gpa',
    label: 'Grade Point Average',
    category: 'ACADEMIC',
    sensitivityWeight: 10,
    description: 'Current GPA',
  },
  transcript: {
    name: 'transcript',
    label: 'Academic Transcript',
    category: 'ACADEMIC',
    sensitivityWeight: 15,
    description: 'Full academic transcript',
  },
  courses: {
    name: 'courses',
    label: 'Course Enrollment',
    category: 'ACADEMIC',
    sensitivityWeight: 8,
    description: 'Current course enrollment',
  },
  major: {
    name: 'major',
    label: 'Major/Program',
    category: 'ACADEMIC',
    sensitivityWeight: 5,
    description: 'Academic major or program',
  },
  grades: {
    name: 'grades',
    label: 'Course Grades',
    category: 'ACADEMIC',
    sensitivityWeight: 12,
    description: 'Individual course grades',
  },
  
  // Financial Information
  financial_aid: {
    name: 'financial_aid',
    label: 'Financial Aid Status',
    category: 'FINANCIAL',
    sensitivityWeight: 20,
    description: 'Financial aid information',
  },
  payment_history: {
    name: 'payment_history',
    label: 'Payment History',
    category: 'FINANCIAL',
    sensitivityWeight: 25,
    description: 'Tuition payment history',
  },
  scholarship: {
    name: 'scholarship',
    label: 'Scholarship Information',
    category: 'FINANCIAL',
    sensitivityWeight: 18,
    description: 'Scholarship awards and status',
  },
  account_balance: {
    name: 'account_balance',
    label: 'Account Balance',
    category: 'FINANCIAL',
    sensitivityWeight: 22,
    description: 'Current account balance',
  },
  
  // Personal Information
  full_name: {
    name: 'full_name',
    label: 'Full Name',
    category: 'PERSONAL',
    sensitivityWeight: 3,
    description: 'Student full legal name',
  },
  date_of_birth: {
    name: 'date_of_birth',
    label: 'Date of Birth',
    category: 'PERSONAL',
    sensitivityWeight: 10,
    description: 'Student date of birth',
  },
  emergency_contact: {
    name: 'emergency_contact',
    label: 'Emergency Contact',
    category: 'PERSONAL',
    sensitivityWeight: 12,
    description: 'Emergency contact information',
  },
  
  // Identity Information
  student_id: {
    name: 'student_id',
    label: 'Student ID',
    category: 'IDENTITY',
    sensitivityWeight: 15,
    description: 'University student ID number',
  },
  ssn: {
    name: 'ssn',
    label: 'Social Security Number',
    category: 'IDENTITY',
    sensitivityWeight: 50,
    description: 'Social Security Number (highly sensitive)',
  },
  passport: {
    name: 'passport',
    label: 'Passport Information',
    category: 'IDENTITY',
    sensitivityWeight: 45,
    description: 'Passport number and details',
  },
  
  // Behavioral Information
  login_history: {
    name: 'login_history',
    label: 'Login History',
    category: 'BEHAVIORAL',
    sensitivityWeight: 10,
    description: 'System login history',
  },
  library_usage: {
    name: 'library_usage',
    label: 'Library Usage',
    category: 'BEHAVIORAL',
    sensitivityWeight: 5,
    description: 'Library access and borrowing history',
  },
  campus_access: {
    name: 'campus_access',
    label: 'Campus Access Logs',
    category: 'BEHAVIORAL',
    sensitivityWeight: 15,
    description: 'Physical campus access records',
  },
};

// ============================================================================
// DURATION MULTIPLIERS
// ============================================================================

/**
 * Duration multipliers based on access duration
 * Longer access = higher risk
 */
export interface DurationMultiplier {
  maxDays: number;
  multiplier: number;
  label: string;
}

export const DURATION_MULTIPLIERS: DurationMultiplier[] = [
  { maxDays: 1, multiplier: 0.8, label: 'One-time (1 day)' },
  { maxDays: 7, multiplier: 1.0, label: 'Short-term (≤7 days)' },
  { maxDays: 30, multiplier: 1.2, label: 'Medium-term (≤30 days)' },
  { maxDays: 90, multiplier: 1.4, label: 'Quarterly (≤90 days)' },
  { maxDays: 180, multiplier: 1.6, label: 'Semester (≤180 days)' },
  { maxDays: 365, multiplier: 1.8, label: 'Annual (≤365 days)' },
  { maxDays: Infinity, multiplier: 2.0, label: 'Extended (>365 days)' },
];

/**
 * Get duration multiplier for a given number of days
 */
export function getDurationMultiplier(days: number): DurationMultiplier {
  for (const tier of DURATION_MULTIPLIERS) {
    if (days <= tier.maxDays) {
      return tier;
    }
  }
  return DURATION_MULTIPLIERS[DURATION_MULTIPLIERS.length - 1];
}

// ============================================================================
// SERVICE RISK WEIGHTS
// ============================================================================

/**
 * Risk weights based on service risk category
 */
export const SERVICE_RISK_WEIGHTS: Record<RiskCategory, number> = {
  LOW: 1.0,
  MEDIUM: 1.3,
  HIGH: 1.6,
  CRITICAL: 2.0,
};

// ============================================================================
// PERMISSION COUNT IMPACT
// ============================================================================

/**
 * Impact multiplier based on existing active permissions
 * More active permissions = higher cumulative risk
 */
export interface PermissionCountImpact {
  maxCount: number;
  multiplier: number;
}

export const PERMISSION_COUNT_IMPACTS: PermissionCountImpact[] = [
  { maxCount: 3, multiplier: 1.0 },
  { maxCount: 5, multiplier: 1.1 },
  { maxCount: 10, multiplier: 1.2 },
  { maxCount: 20, multiplier: 1.4 },
  { maxCount: Infinity, multiplier: 1.5 },
];

/**
 * Get permission count multiplier
 */
export function getPermissionCountMultiplier(count: number): number {
  for (const tier of PERMISSION_COUNT_IMPACTS) {
    if (count <= tier.maxCount) {
      return tier.multiplier;
    }
  }
  return PERMISSION_COUNT_IMPACTS[PERMISSION_COUNT_IMPACTS.length - 1].multiplier;
}

// ============================================================================
// RISK LEVEL THRESHOLDS
// ============================================================================

/**
 * Risk level classification thresholds
 */
export const RISK_LEVEL_THRESHOLDS = {
  LOW: 25,
  MEDIUM: 50,
  HIGH: 75,
  // Anything above HIGH is CRITICAL
};

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (score <= RISK_LEVEL_THRESHOLDS.LOW) return 'LOW';
  if (score <= RISK_LEVEL_THRESHOLDS.MEDIUM) return 'MEDIUM';
  if (score <= RISK_LEVEL_THRESHOLDS.HIGH) return 'HIGH';
  return 'CRITICAL';
}

// ============================================================================
// POLICY RULES
// ============================================================================

/**
 * Fields that require additional verification
 */
export const HIGH_SENSITIVITY_FIELDS = ['ssn', 'passport', 'financial_aid', 'payment_history', 'account_balance'];

/**
 * Maximum duration allowed without manual review (in days)
 */
export const MAX_AUTO_APPROVE_DURATION = 30;

/**
 * Maximum risk score for auto-approval
 */
export const MAX_AUTO_APPROVE_RISK_SCORE = 40;

/**
 * Risk event weights for Phase 4 integration
 */
export const RISK_EVENT_WEIGHTS = {
  /** Negative impact when approving high-risk requests */
  HIGH_RISK_APPROVAL: -15,
  /** Positive impact when denying high-risk requests */
  HIGH_RISK_DENIAL: 10,
  /** Moderate negative impact for medium-risk approvals */
  MEDIUM_RISK_APPROVAL: -5,
  /** Small positive impact for cautious behavior */
  LOW_RISK_DENIAL: 2,
  /** Base multiplier for repeated risky approvals */
  REPEAT_RISKY_APPROVAL_MULTIPLIER: 1.5,
};

// ============================================================================
// FIELD UTILITY FUNCTIONS
// ============================================================================

/**
 * Get field definition by name
 */
export function getFieldDefinition(fieldName: string): DataField | undefined {
  return DATA_FIELDS[fieldName];
}

/**
 * Get field definitions for multiple field names
 */
export function getFieldDefinitions(fieldNames: string[]): DataField[] {
  return fieldNames
    .map(name => DATA_FIELDS[name])
    .filter((field): field is DataField => field !== undefined);
}

/**
 * Calculate total sensitivity weight for fields
 */
export function calculateFieldSensitivity(fieldNames: string[]): number {
  return fieldNames.reduce((total, name) => {
    const field = DATA_FIELDS[name];
    return total + (field?.sensitivityWeight ?? 0);
  }, 0);
}

/**
 * Check if any field is high sensitivity
 */
export function hasHighSensitivityField(fieldNames: string[]): boolean {
  return fieldNames.some(name => HIGH_SENSITIVITY_FIELDS.includes(name));
}

/**
 * Get all available field names
 */
export function getAllFieldNames(): string[] {
  return Object.keys(DATA_FIELDS);
}

/**
 * Validate field names
 */
export function validateFieldNames(fieldNames: string[]): { valid: boolean; invalid: string[] } {
  const invalid = fieldNames.filter(name => !DATA_FIELDS[name]);
  return {
    valid: invalid.length === 0,
    invalid,
  };
}
