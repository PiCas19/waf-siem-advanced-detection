import { Link } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import AvatarMenu from './AvatarMenu'

export default function Navbar() {
  const { user } = useAuth()

  return (
    <nav className="bg-gray-800 border-b border-gray-700 px-4 py-3">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <Link to="/" className="text-xl font-bold">WAF Dashboard</Link>
        <div>
          {user ? <AvatarMenu /> : <Link to="/login" className="text-sm">Login</Link>}
        </div>
      </div>
    </nav>
  )
}