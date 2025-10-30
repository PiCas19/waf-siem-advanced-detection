import React from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import { hasPermission, UserRole, RolePermissions } from '@/types/rbac'

interface ProtectedRouteProps {
  children: React.ReactNode
  requiredPermission?: keyof RolePermissions
}

/**
 * ProtectedRoute component that checks:
 * 1. User is authenticated
 * 2. User has the required permission (if specified)
 */
const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, requiredPermission }) => {
  const { user, isLoading } = useAuth()

  // Still loading auth state
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-gray-300">Loading...</div>
      </div>
    )
  }

  // Not authenticated
  if (!user) {
    return <Navigate to="/login" replace />
  }

  // Check permission if required
  if (requiredPermission) {
    const hasAccess = hasPermission(user.role as UserRole, requiredPermission)
    if (!hasAccess) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-900">
          <div className="bg-gray-800 p-8 rounded-lg shadow-lg border border-gray-700 max-w-md">
            <h1 className="text-2xl font-bold text-white mb-4">Access Denied</h1>
            <p className="text-gray-300 mb-6">You don't have permission to access this page.</p>
            <a href="/dashboard" className="text-blue-400 hover:text-blue-300">
              Return to Dashboard
            </a>
          </div>
        </div>
      )
    }
  }

  return <>{children}</>
}

export default ProtectedRoute
