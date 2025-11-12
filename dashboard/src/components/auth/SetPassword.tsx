import React, { useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { Eye, EyeOff } from 'lucide-react'
import axios from 'axios'

const SetPassword: React.FC = () => {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const navigate = useNavigate()

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!token) return setError('Missing token')
    if (password.length < 8) return setError('Password too short')
    if (password !== confirm) return setError('Passwords do not match')
    try {
      await axios.post('/api/auth/set-password', { token, new_password: password })
      setSuccess('Password set. Redirecting to setup...')
      // Mark that user needs to complete 2FA setup on first login
      localStorage.setItem('needsTwoFASetup', 'true')
      // Redirect to setup page after password activation
      setTimeout(() => navigate('/setup'), 1500)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md">
        <h1 className="text-2xl font-bold text-white mb-4">Set your password</h1>
        {error && <div className="bg-red-500/20 border border-red-500 text-red-300 px-4 py-3 rounded mb-3">{error}</div>}
        {success && <div className="bg-green-500/20 border border-green-500 text-green-300 px-4 py-3 rounded mb-3">{success}</div>}
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-sm text-gray-300 mb-1">New password</label>
            <div className="relative">
              <input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type={showPassword ? 'text' : 'password'}
                className="w-full px-3 py-2 bg-gray-700 text-white rounded"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition"
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-sm text-gray-300 mb-1">Confirm password</label>
            <div className="relative">
              <input
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                type={showConfirm ? 'text' : 'password'}
                className="w-full px-3 py-2 bg-gray-700 text-white rounded"
              />
              <button
                type="button"
                onClick={() => setShowConfirm(!showConfirm)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition"
              >
                {showConfirm ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>
          <button className="w-full bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-white font-medium transition">Set password</button>
        </form>
      </div>
    </div>
  )
}

export default SetPassword
