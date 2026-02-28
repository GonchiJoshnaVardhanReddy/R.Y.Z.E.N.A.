/**
 * R.Y.Z.E.N.A. - Consent Risk Engine
 * 
 * Evaluates risk for consent requests using deterministic scoring.
 * Calculates risk based on field sensitivity, duration, service risk,
 * student risk profile, and existing permissions.
 */

import { createLogger } from '../../shared/logger.js';
import {
  DATA_FIELDS,
  getDurationMultiplier,
  SERVICE_RISK_WEIGHTS,
  getPermissionCountMultiplier,
  getRiskLevel,
  calculateFieldSensitivity,
  hasHighSensitivityField,
  getFieldDefinitions,
  RISK_EVENT_WEIGHTS,
} from './consent.policy.js';
import type {
  RiskAssessment,
  RiskFactor,
  RiskEventEmission,
  ConsentRequest,
  Service,
  RiskCategory,
} from './consent.types.js';

const logger = createLogger({ module: 'consent-engine' });

// ============================================================================
// RISK CALCULATION
// ============================================================================

/**
 * Calculate comprehensive risk assessment for a consent request
 */
export function calculateRiskAssessment(
  requestedFields: string[],
  requestedDuration: number,
  serviceRiskCategory: RiskCategory,
  existingPermissionCount: number,
  studentRiskLevel?: string
): RiskAssessment {
  const startTime = Date.now();
  const factors: RiskFactor[] = [];
  
  // 1. Field Sensitivity Score (0-50 base contribution)
  const fieldSensitivity = calculateFieldSensitivity(requestedFields);
  const fieldContribution = Math.min(50, fieldSensitivity);
  factors.push({
    name: 'Field Sensitivity',
    category: 'FIELD_SENSITIVITY',
    contribution: fieldContribution,
    description: `${requestedFields.length} fields requested with total sensitivity weight of ${fieldSensitivity}`,
  });
  
  // 2. Duration Multiplier
  const durationInfo = getDurationMultiplier(requestedDuration);
  const durationContribution = Math.round((durationInfo.multiplier - 0.8) * 25); // 0-30 range
  factors.push({
    name: 'Access Duration',
    category: 'DURATION',
    contribution: durationContribution,
    description: `${durationInfo.label} - ${requestedDuration} days (multiplier: ${durationInfo.multiplier}x)`,
  });
  
  // 3. Service Risk Category
  const serviceMultiplier = SERVICE_RISK_WEIGHTS[serviceRiskCategory];
  const serviceContribution = Math.round((serviceMultiplier - 1) * 20); // 0-20 range
  factors.push({
    name: 'Service Risk Category',
    category: 'SERVICE_RISK',
    contribution: serviceContribution,
    description: `Service is ${serviceRiskCategory} risk (multiplier: ${serviceMultiplier}x)`,
  });
  
  // 4. Existing Permission Count
  const permissionMultiplier = getPermissionCountMultiplier(existingPermissionCount);
  const permissionContribution = Math.round((permissionMultiplier - 1) * 15); // 0-7.5 range
  factors.push({
    name: 'Active Permissions',
    category: 'PERMISSION_COUNT',
    contribution: permissionContribution,
    description: `${existingPermissionCount} existing active permissions (multiplier: ${permissionMultiplier}x)`,
  });
  
  // 5. Student Risk Level (from Phase 4 Digital Twin)
  let studentContribution = 0;
  if (studentRiskLevel) {
    const studentRiskWeights: Record<string, number> = {
      LOW: 0,
      MEDIUM: 5,
      HIGH: 10,
      CRITICAL: 15,
    };
    studentContribution = studentRiskWeights[studentRiskLevel] ?? 0;
    factors.push({
      name: 'Student Risk Profile',
      category: 'STUDENT_RISK',
      contribution: studentContribution,
      description: `Student risk level is ${studentRiskLevel}`,
    });
  }
  
  // Calculate base score
  let baseScore = fieldContribution + durationContribution + serviceContribution + 
                  permissionContribution + studentContribution;
  
  // Apply multipliers
  const totalMultiplier = durationInfo.multiplier * serviceMultiplier * permissionMultiplier;
  const adjustedScore = Math.round(baseScore * (totalMultiplier > 1 ? 1 + (totalMultiplier - 1) * 0.3 : 1));
  
  // Clamp to 0-100
  const finalScore = Math.max(0, Math.min(100, adjustedScore));
  const riskLevel = getRiskLevel(finalScore);
  
  // Generate recommendations
  const recommendations = generateRecommendations(
    requestedFields,
    requestedDuration,
    finalScore,
    riskLevel,
    serviceRiskCategory
  );
  
  const durationMs = Date.now() - startTime;
  logger.info({
    action: 'risk_assessment_complete',
    riskScore: finalScore,
    riskLevel,
    factorCount: factors.length,
    durationMs,
  });
  
  return {
    riskScore: finalScore,
    riskLevel,
    factors,
    recommendations,
  };
}

/**
 * Generate recommendations based on risk assessment
 */
function generateRecommendations(
  requestedFields: string[],
  requestedDuration: number,
  riskScore: number,
  riskLevel: string,
  serviceRiskCategory: RiskCategory
): string[] {
  const recommendations: string[] = [];
  
  // High sensitivity field warnings
  if (hasHighSensitivityField(requestedFields)) {
    recommendations.push('This request includes highly sensitive data fields. Review carefully before approving.');
  }
  
  // Duration recommendations
  if (requestedDuration > 30) {
    recommendations.push(`Consider reducing access duration from ${requestedDuration} days to 30 days or less.`);
  }
  
  // Risk level specific recommendations
  if (riskLevel === 'CRITICAL') {
    recommendations.push('CRITICAL RISK: Strongly consider denying this request or requesting additional justification.');
  } else if (riskLevel === 'HIGH') {
    recommendations.push('HIGH RISK: Review the necessity of each requested field before approval.');
  }
  
  // Service risk warnings
  if (serviceRiskCategory === 'HIGH' || serviceRiskCategory === 'CRITICAL') {
    recommendations.push(`The requesting service is categorized as ${serviceRiskCategory} risk.`);
  }
  
  // Field-specific recommendations
  const fieldDefs = getFieldDefinitions(requestedFields);
  const financialFields = fieldDefs.filter(f => f.category === 'FINANCIAL');
  if (financialFields.length > 0) {
    recommendations.push('Financial information requested. Verify the service genuinely requires this data.');
  }
  
  const identityFields = fieldDefs.filter(f => f.category === 'IDENTITY');
  if (identityFields.length > 0) {
    recommendations.push('Identity documents requested. This may be required for verification purposes only.');
  }
  
  // General approval recommendation
  if (riskScore <= 25) {
    recommendations.push('This is a low-risk request and can typically be safely approved.');
  }
  
  return recommendations;
}

// ============================================================================
// RISK EVENT EMISSION (for Phase 4 Integration)
// ============================================================================

/**
 * Create risk event emission for Phase 4 Risk Engine
 */
export function createRiskEvent(
  type: 'CONSENT_APPROVED' | 'CONSENT_DENIED' | 'CONSENT_REVOKED',
  request: ConsentRequest,
  service: Service
): RiskEventEmission {
  let impact: number;
  
  const riskLevel = getRiskLevel(request.riskScore);
  
  switch (type) {
    case 'CONSENT_APPROVED':
      if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
        impact = RISK_EVENT_WEIGHTS.HIGH_RISK_APPROVAL;
      } else if (riskLevel === 'MEDIUM') {
        impact = RISK_EVENT_WEIGHTS.MEDIUM_RISK_APPROVAL;
      } else {
        impact = 0; // Low risk approvals don't affect score
      }
      break;
      
    case 'CONSENT_DENIED':
      if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
        impact = RISK_EVENT_WEIGHTS.HIGH_RISK_DENIAL;
      } else {
        impact = RISK_EVENT_WEIGHTS.LOW_RISK_DENIAL;
      }
      break;
      
    case 'CONSENT_REVOKED':
      // Revoking is generally positive for security
      impact = 5;
      break;
      
    default:
      impact = 0;
  }
  
  logger.info({
    action: 'risk_event_created',
    type,
    studentId: request.studentId,
    impact,
    riskScore: request.riskScore,
  });
  
  return {
    type,
    studentId: request.studentId,
    impact,
    metadata: {
      serviceId: service.id,
      serviceName: service.name,
      requestId: request.id,
      riskScore: request.riskScore,
      fields: request.requestedFields,
    },
  };
}

// ============================================================================
// CONSENT EXPLANATION INPUT (for Phase 3 AI Integration)
// ============================================================================

/**
 * Build structured input for AI explanation generation
 */
export function buildConsentExplanationInput(
  request: ConsentRequest,
  service: Service,
  riskAssessment: RiskAssessment,
  existingPermissionCount: number,
  studentRiskLevel?: string
) {
  const fieldDefinitions = getFieldDefinitions(request.requestedFields);
  
  // Determine recommended action
  let recommendedAction: 'APPROVE' | 'REVIEW' | 'DENY';
  if (riskAssessment.riskScore >= 75) {
    recommendedAction = 'DENY';
  } else if (riskAssessment.riskScore >= 40) {
    recommendedAction = 'REVIEW';
  } else {
    recommendedAction = 'APPROVE';
  }
  
  return {
    serviceName: service.name,
    serviceDescription: service.description,
    requestedFields: fieldDefinitions.map(f => ({
      name: f.name,
      label: f.label,
      category: f.category,
      sensitivityWeight: f.sensitivityWeight,
      description: f.description,
    })),
    purpose: request.purpose,
    riskScore: riskAssessment.riskScore,
    riskLevel: riskAssessment.riskLevel,
    studentRiskLevel,
    existingPermissionCount,
    recommendedAction,
  };
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Validate requested fields
 */
export function validateFields(fieldNames: string[]): {
  valid: boolean;
  validFields: string[];
  invalidFields: string[];
} {
  const validFields: string[] = [];
  const invalidFields: string[] = [];
  
  for (const name of fieldNames) {
    if (DATA_FIELDS[name]) {
      validFields.push(name);
    } else {
      invalidFields.push(name);
    }
  }
  
  return {
    valid: invalidFields.length === 0,
    validFields,
    invalidFields,
  };
}

/**
 * Check if request should be auto-approved
 * (Low risk + short duration + no high-sensitivity fields)
 */
export function canAutoApprove(
  riskScore: number,
  requestedDuration: number,
  requestedFields: string[]
): boolean {
  const MAX_AUTO_APPROVE_RISK = 30;
  const MAX_AUTO_APPROVE_DURATION = 7;
  
  if (riskScore > MAX_AUTO_APPROVE_RISK) return false;
  if (requestedDuration > MAX_AUTO_APPROVE_DURATION) return false;
  if (hasHighSensitivityField(requestedFields)) return false;
  
  return true;
}
