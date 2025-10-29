import React from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'

const Profile: React.FC = () => {
  const { user } = useAuth()
  const navigate = useNavigate()

  const seed = user?.email || user?.name || 'guest'
  const avatarUrl = `https://api.dicebear.com/9.x/identicon/svg?seed=${encodeURIComponent(seed)}`

  // Simple permissions mapping (API may expose a richer structure)
  const permissions = user?.role === 'admin' ? ['manage:all'] : ['read:logs', 'view:stats']

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-3xl mx-auto px-4 py-8">
        <button onClick={() => navigate(-1)} className="mb-4 flex items-center gap-2 text-gray-300 hover:text-white">
          <ArrowLeft size={16} /> Back
        </button>

        <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
          <div className="flex items-center gap-6">
            <img src={avatarUrl} alt="avatar" className="w-20 h-20 rounded-full border border-gray-600" />
            <div>
              <h2 className="text-2xl font-bold">{user?.name || 'Unknown'}</h2>
              <p className="text-sm text-gray-400">{user?.email}</p>
              <p className="mt-2 text-sm">Role: <span className="text-gray-200 font-medium">{user?.role || 'user'}</span></p>
            </div>
          </div>

          <div className="mt-6">
            <h3 className="text-lg font-semibold">Permissions</h3>
            <ul className="mt-2 list-disc list-inside text-gray-300">
              {permissions.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Profile
