/**
 * R.Y.Z.E.N.A. - Phase 7: Role Middleware Tests
 * Tests for RBAC enforcement
 */

import { describe, it, expect } from 'vitest';
import {
  hasRole,
  hasRoleHierarchy,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  canAccessStudentData,
} from '../../src/security/role.middleware.js';
import { UserRole, Permission, ROLE_HIERARCHY } from '../../src/security/security.config.js';

describe('Role Middleware', () => {
  describe('hasRole', () => {
    it('should return true for matching role', () => {
      expect(hasRole(UserRole.ADMIN, UserRole.ADMIN)).toBe(true);
      expect(hasRole(UserRole.STUDENT, UserRole.STUDENT)).toBe(true);
    });

    it('should return false for non-matching role', () => {
      expect(hasRole(UserRole.STUDENT, UserRole.ADMIN)).toBe(false);
      expect(hasRole(UserRole.SERVICE, UserRole.STUDENT)).toBe(false);
    });
  });

  describe('hasRoleHierarchy', () => {
    it('should allow SYSTEM role to access everything', () => {
      expect(hasRoleHierarchy(UserRole.SYSTEM, UserRole.ADMIN)).toBe(true);
      expect(hasRoleHierarchy(UserRole.SYSTEM, UserRole.STUDENT)).toBe(true);
      expect(hasRoleHierarchy(UserRole.SYSTEM, UserRole.SERVICE)).toBe(true);
    });

    it('should allow ADMIN role to access student level', () => {
      expect(hasRoleHierarchy(UserRole.ADMIN, UserRole.STUDENT)).toBe(true);
    });

    it('should not allow STUDENT to access ADMIN level', () => {
      expect(hasRoleHierarchy(UserRole.STUDENT, UserRole.ADMIN)).toBe(false);
    });

    it('should not allow SERVICE to access ADMIN level', () => {
      expect(hasRoleHierarchy(UserRole.SERVICE, UserRole.ADMIN)).toBe(false);
    });

    it('should verify role hierarchy order', () => {
      expect(ROLE_HIERARCHY[UserRole.SYSTEM]).toBeGreaterThan(ROLE_HIERARCHY[UserRole.ADMIN]);
      expect(ROLE_HIERARCHY[UserRole.ADMIN]).toBeGreaterThan(ROLE_HIERARCHY[UserRole.STUDENT]);
    });
  });

  describe('hasPermission', () => {
    it('should return true when user has permission', () => {
      const permissions = [Permission.STUDENT_DASHBOARD, Permission.STUDENT_CONSENT];
      expect(hasPermission(permissions, Permission.STUDENT_DASHBOARD)).toBe(true);
    });

    it('should return false when user lacks permission', () => {
      const permissions = [Permission.STUDENT_DASHBOARD];
      expect(hasPermission(permissions, Permission.ADMIN_ANALYTICS)).toBe(false);
    });

    it('should grant all permissions with SYSTEM_ALL', () => {
      const permissions = [Permission.SYSTEM_ALL];
      expect(hasPermission(permissions, Permission.ADMIN_ANALYTICS)).toBe(true);
      expect(hasPermission(permissions, Permission.STUDENT_DASHBOARD)).toBe(true);
      expect(hasPermission(permissions, Permission.SERVICE_EMAIL_SCAN)).toBe(true);
    });
  });

  describe('hasAnyPermission', () => {
    it('should return true if user has any of the required permissions', () => {
      const userPermissions = [Permission.STUDENT_DASHBOARD];
      const required = [Permission.ADMIN_ANALYTICS, Permission.STUDENT_DASHBOARD];
      expect(hasAnyPermission(userPermissions, required)).toBe(true);
    });

    it('should return false if user has none of the required permissions', () => {
      const userPermissions = [Permission.STUDENT_DASHBOARD];
      const required = [Permission.ADMIN_ANALYTICS, Permission.ADMIN_USERS];
      expect(hasAnyPermission(userPermissions, required)).toBe(false);
    });

    it('should return true with SYSTEM_ALL for any permissions', () => {
      const userPermissions = [Permission.SYSTEM_ALL];
      const required = [Permission.ADMIN_ANALYTICS, Permission.SERVICE_AI_EXPLAIN];
      expect(hasAnyPermission(userPermissions, required)).toBe(true);
    });
  });

  describe('hasAllPermissions', () => {
    it('should return true if user has all required permissions', () => {
      const userPermissions = [Permission.STUDENT_DASHBOARD, Permission.STUDENT_CONSENT];
      const required = [Permission.STUDENT_DASHBOARD, Permission.STUDENT_CONSENT];
      expect(hasAllPermissions(userPermissions, required)).toBe(true);
    });

    it('should return false if user is missing any permission', () => {
      const userPermissions = [Permission.STUDENT_DASHBOARD];
      const required = [Permission.STUDENT_DASHBOARD, Permission.STUDENT_CONSENT];
      expect(hasAllPermissions(userPermissions, required)).toBe(false);
    });

    it('should return true with SYSTEM_ALL for all permissions', () => {
      const userPermissions = [Permission.SYSTEM_ALL];
      const required = [Permission.ADMIN_ANALYTICS, Permission.SERVICE_AI_EXPLAIN, Permission.STUDENT_DASHBOARD];
      expect(hasAllPermissions(userPermissions, required)).toBe(true);
    });
  });

  describe('canAccessStudentData', () => {
    it('should allow SYSTEM to access any student data', () => {
      expect(canAccessStudentData(UserRole.SYSTEM, 'admin-1', 'student-123')).toBe(true);
    });

    it('should allow ADMIN to access any student data', () => {
      expect(canAccessStudentData(UserRole.ADMIN, 'admin-1', 'student-123')).toBe(true);
    });

    it('should allow students to access their own data', () => {
      expect(canAccessStudentData(UserRole.STUDENT, 'student-123', 'student-123')).toBe(true);
    });

    it('should NOT allow students to access other student data', () => {
      expect(canAccessStudentData(UserRole.STUDENT, 'student-123', 'student-456')).toBe(false);
    });

    it('should NOT allow SERVICE role to access student data directly', () => {
      expect(canAccessStudentData(UserRole.SERVICE, 'service-1', 'student-123')).toBe(false);
    });
  });
});

describe('Permission Definitions', () => {
  it('should have student permissions defined', () => {
    expect(Permission.STUDENT_DASHBOARD).toBeDefined();
    expect(Permission.STUDENT_CONSENT).toBeDefined();
    expect(Permission.STUDENT_RISK).toBeDefined();
  });

  it('should have admin permissions defined', () => {
    expect(Permission.ADMIN_ANALYTICS).toBeDefined();
    expect(Permission.ADMIN_USERS).toBeDefined();
    expect(Permission.ADMIN_CONFIG).toBeDefined();
  });

  it('should have service permissions defined', () => {
    expect(Permission.SERVICE_EMAIL_SCAN).toBeDefined();
    expect(Permission.SERVICE_AI_EXPLAIN).toBeDefined();
    expect(Permission.SERVICE_DATA_ACCESS).toBeDefined();
  });

  it('should have system permission defined', () => {
    expect(Permission.SYSTEM_ALL).toBeDefined();
  });
});

describe('Role Escalation Prevention', () => {
  it('should not allow role escalation through hierarchy bypass', () => {
    // Student cannot pretend to be admin
    expect(hasRoleHierarchy(UserRole.STUDENT, UserRole.ADMIN)).toBe(false);
  });

  it('should not grant permissions outside role', () => {
    const studentPermissions = [Permission.STUDENT_DASHBOARD, Permission.STUDENT_CONSENT];
    expect(hasPermission(studentPermissions, Permission.ADMIN_ANALYTICS)).toBe(false);
  });

  it('should not allow SERVICE to elevate to ADMIN', () => {
    expect(hasRoleHierarchy(UserRole.SERVICE, UserRole.ADMIN)).toBe(false);
  });
});
