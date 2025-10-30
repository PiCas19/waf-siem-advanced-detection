import React, { useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

const SetPassword: React.FC = () => {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
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
      setSuccess('Password set. You can now log in')
      setTimeout(() => navigate('/login'), 1500)
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
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" className="w-full px-3 py-2 bg-gray-700 text-white rounded" />
          </div>
          <div>
            <label className="block text-sm text-gray-300 mb-1">Confirm password</label>
            <input value={confirm} onChange={(e) => setConfirm(e.target.value)} type="password" className="w-full px-3 py-2 bg-gray-700 text-white rounded" />
          </div>
          <button className="bg-blue-600 px-4 py-2 rounded text-white">Set password</button>
        </form>
      </div>
    </div>
  )
}

export default SetPassword
