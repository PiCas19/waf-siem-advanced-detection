import React, { useState, useRef, useEffect } from 'react'
import { User, useAuth } from '@/contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import { User as UserIcon, Settings, LogOut } from 'lucide-react'

const AvatarMenu: React.FC = () => {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [])

  const seed = user?.email || user?.name || 'guest'
  const avatarUrl = `https://avatars.dicebear.com/api/identicon/${encodeURIComponent(seed)}.svg`

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded focus:outline-none"
        aria-haspopup="true"
        aria-expanded={open}
      >
        <img src={avatarUrl} alt="avatar" className="w-8 h-8 rounded-full border border-gray-600" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-700 rounded shadow-lg z-50">
          <button
            onClick={() => { setOpen(false); navigate('/profile') }}
            className="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-gray-700"
          >
            <UserIcon size={16} />
            <span>Profile</span>
          </button>

          <button
            onClick={() => { setOpen(false); navigate('/settings') }}
            className="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-gray-700"
          >
            <Settings size={16} />
            <span>Settings</span>
          </button>

          <div className="border-t border-gray-700" />

          <button
            onClick={handleLogout}
            className="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-gray-700 text-red-400"
          >
            <LogOut size={16} />
            <span>Logout</span>
          </button>
        </div>
      )}
    </div>
  )
}

export default AvatarMenu
