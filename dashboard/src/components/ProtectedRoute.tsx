import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import { hasPermission, UserRole, RolePermissions } from '@/types/rbac'

interface ProtectedRouteProps {
  children: React.ReactNode
  requiredPermission?: keyof RolePermissions
  allowTwoFASetup?: boolean
}

/**
 * ProtectedRoute component that checks:
 * 1. User is authenticated
 * 2. User must complete 2FA setup if required
 * 3. User has the required permission (if specified)
 */
const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, requiredPermission, allowTwoFASetup = false }) => {
  const { user, isLoading, requiresTwoFASetup } = useAuth()
  const location = useLocation()

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

  // If 2FA setup is required, redirect to setup page (unless already on setup page or page allows it)
  if (requiresTwoFASetup && !allowTwoFASetup && location.pathname !== '/setup-2fa') {
    return <Navigate to="/setup-2fa" replace />
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
