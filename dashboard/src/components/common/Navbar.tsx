import { Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

export default function Navbar() {
  const { logout } = useAuth();

  return (
    <nav className="bg-gray-800 border-b border-gray-700 px-4 py-3">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <Link to="/" className="text-xl font-bold">WAF Dashboard</Link>
        <button onClick={logout} className="text-sm hover:text-red-400">
          Logout
        </button>
      </div>
    </nav>
  );
}