/**
 * RBAC (Role-Based Access Control) Configuration
 * Defines which pages/features each role can access
 */

export type UserRole = 'admin' | 'operator' | 'analyst' | 'user'

export interface RolePermissions {
  // Dashboard & Main
  dashboard: boolean

  // WAF Rules Management
  rules_view: boolean
  rules_create: boolean
  rules_edit: boolean
  rules_delete: boolean

  // Event Logs
  logs_view: boolean
  logs_export: boolean
  logs_delete: boolean

  // IP Management
  blocklist_view: boolean
  blocklist_add: boolean
  blocklist_remove: boolean
  whitelist_view: boolean
  whitelist_add: boolean
  whitelist_remove: boolean

  // False Positives
  false_positives_view: boolean
  false_positives_report: boolean
  false_positives_resolve: boolean
  false_positives_delete: boolean

  // Threat Management (Stats page)
  threats_block: boolean
  threats_unblock: boolean

  // Admin Functions
  users_view: boolean
  users_create: boolean
  users_edit: boolean
  users_delete: boolean
  users_change_role: boolean

  // Access Control (Settings for others)
  access_control: boolean
  settings: boolean
}

/**
 * Permission matrix for each role
 * Each role has a set of permissions that determine what they can do
 */
export const ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  admin: {
    // Admins have full access to everything
    dashboard: true,
    rules_view: true,
    rules_create: true,
    rules_edit: true,
    rules_delete: true,
    logs_view: true,
    logs_export: true,
    logs_delete: true,
    blocklist_view: true,
    blocklist_add: true,
    blocklist_remove: true,
    whitelist_view: true,
    whitelist_add: true,
    whitelist_remove: true,
    false_positives_view: true,
    false_positives_report: true,
    false_positives_resolve: true,
    false_positives_delete: true,
    threats_block: true,
    threats_unblock: true,
    users_view: true,
    users_create: true,
    users_edit: true,
    users_delete: true,
    users_change_role: true,
    access_control: true,
    settings: true,
  },

  operator: {
    // Operators: can block/unblock threats, create/modify rules, manage access control, view logs, view users (no create/edit/delete)
    dashboard: true,
    rules_view: true,
    rules_create: true,
    rules_edit: true,
    rules_delete: false,
    logs_view: true,
    logs_export: true,
    logs_delete: false,
    blocklist_view: true,
    blocklist_add: true,
    blocklist_remove: true,
    whitelist_view: true,
    whitelist_add: true,
    whitelist_remove: true,
    false_positives_view: true,
    false_positives_report: true,
    false_positives_resolve: false,
    false_positives_delete: false,
    threats_block: true,
    threats_unblock: true,
    users_view: true,
    users_create: false,
    users_edit: false,
    users_delete: false,
    users_change_role: false,
    access_control: true,
    settings: false,
  },

  analyst: {
    // Analysts: can view dashboard and logs (READ-ONLY, no actions)
    dashboard: true,
    rules_view: false,
    rules_create: false,
    rules_edit: false,
    rules_delete: false,
    logs_view: true,      // ✓ Can view logs
    logs_export: false,   // ✗ Cannot export
    logs_delete: false,   // ✗ Cannot delete
    blocklist_view: false,
    blocklist_add: false,
    blocklist_remove: false,
    whitelist_view: false,
    whitelist_add: false,
    whitelist_remove: false,
    false_positives_view: false,
    false_positives_report: false,  // ✗ Cannot report FP
    false_positives_resolve: false,
    false_positives_delete: false,
    threats_block: false,           // ✗ Cannot block
    threats_unblock: false,         // ✗ Cannot unblock
    users_view: false,              // ✗ Cannot see Users menu
    users_create: false,
    users_edit: false,
    users_delete: false,
    users_change_role: false,
    access_control: false,
    settings: false,
  },

  user: {
    // Regular users have minimal permissions
    dashboard: true,
    rules_view: false,
    rules_create: false,
    rules_edit: false,
    rules_delete: false,
    logs_view: false,
    logs_export: false,
    logs_delete: false,
    blocklist_view: false,
    blocklist_add: false,
    blocklist_remove: false,
    whitelist_view: false,
    whitelist_add: false,
    whitelist_remove: false,
    false_positives_view: false,
    false_positives_report: false,
    false_positives_resolve: false,
    false_positives_delete: false,
    threats_block: false,
    threats_unblock: false,
    users_view: false,
    users_create: false,
    users_edit: false,
    users_delete: false,
    users_change_role: false,
    access_control: false,
    settings: false,
  },
}

/**
 * Get permissions for a specific role
 */
export function getPermissionsForRole(role: UserRole): RolePermissions {
  return ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.user
}

/**
 * Check if a role has a specific permission
 */
export function hasPermission(role: UserRole, permission: keyof RolePermissions): boolean {
  const permissions = getPermissionsForRole(role)
  return permissions[permission] === true
}
