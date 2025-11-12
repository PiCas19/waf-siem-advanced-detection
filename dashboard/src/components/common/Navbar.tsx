import { Link } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import { hasPermission, UserRole } from '@/types/rbac'
import AvatarMenu from './AvatarMenu'

export default function Navbar() {
  const { user } = useAuth()

  return (
    <nav className="bg-gray-800 border-b border-gray-700 px-4 py-3">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <div className="flex items-center gap-4">
          <Link to="/" className="text-xl font-bold">WAF Dashboard</Link>
          {user?.role && hasPermission(user.role as UserRole, 'logs_view') && (
            <Link to="/logs" className="text-sm text-gray-300 hover:text-white">Logs</Link>
          )}
          {user?.role && hasPermission(user.role as UserRole, 'users_view') && (
            <Link to="/admin/users" className="text-sm text-gray-300 hover:text-white">Users</Link>
          )}
        </div>
        <div>
          {user ? <AvatarMenu /> : <Link to="/login" className="text-sm">Login</Link>}
        </div>
      </div>
    </nav>
  )
}