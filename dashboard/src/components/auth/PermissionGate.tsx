import React from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { hasPermission, UserRole, RolePermissions } from '@/types/rbac'

interface PermissionGateProps {
  children: React.ReactNode
  permission: keyof RolePermissions
  fallback?: React.ReactNode
}

/**
 * PermissionGate component that conditionally renders children based on user permissions
 * Used to hide/show UI elements without navigating away
 *
 * Example:
 * <PermissionGate permission="users_delete">
 *   <button onClick={deleteUser}>Delete User</button>
 * </PermissionGate>
 */
const PermissionGate: React.FC<PermissionGateProps> = ({ children, permission, fallback = null }) => {
  const { user } = useAuth()

  if (!user) {
    return <>{fallback}</>
  }

  const hasAccess = hasPermission(user.role as UserRole, permission)

  return <>{hasAccess ? children : fallback}</>
}

export default PermissionGate
