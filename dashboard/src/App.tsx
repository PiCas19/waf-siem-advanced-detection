import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from '@/contexts/AuthContext'
import { ToastProvider, useToast } from '@/contexts/SnackbarContext'
import ProtectedRoute from '@/components/ProtectedRoute'
import Login from '@/components/auth/Login'
import SetPassword from '@/components/auth/SetPassword'
import ForcedTwoFASetup from '@/components/auth/ForcedTwoFASetup'
import Dashboard from '@/components/Dashboard'
import Settings from '@/components/auth/Settings'
import Profile from '@/components/auth/Profile'
import Users from '@/components/admin/Users'
import Snackbar from '@/components/common/Snackbar'

function SnackbarContainer() {
  const { toasts, removeToast } = useToast()

  return (
    <div className="fixed bottom-4 left-4 z-9999 space-y-2 max-w-sm pointer-events-none">
      {toasts.map(snackbar => (
        <div key={snackbar.id} className="pointer-events-auto">
          <Snackbar message={snackbar} onClose={removeToast} />
        </div>
      ))}
    </div>
  )
}

function AppContent() {
  return (
    <>
      <SnackbarContainer />
      <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/set-password" element={<SetPassword />} />

          {/* Protected routes - 2FA Setup (required after first login) */}
          <Route
            path="/setup-2fa"
            element={
              <ProtectedRoute>
                <ForcedTwoFASetup />
              </ProtectedRoute>
            }
          />

          {/* Protected routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />

          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />

          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            }
          />

          <Route
            path="/admin/users"
            element={
              <ProtectedRoute>
                <Users />
              </ProtectedRoute>
            }
          />

          {/* Redirect root to login or dashboard based on auth status */}
          <Route path="/" element={<Navigate to="/login" replace />} />

          {/* 404 fallback */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
    </>
  )
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <ToastProvider>
          <AppContent />
        </ToastProvider>
      </AuthProvider>
    </Router>
  )
}

export default App
