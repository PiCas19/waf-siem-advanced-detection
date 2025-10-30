import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'

const Settings: React.FC = () => {
  const navigate = useNavigate()

  // Change password state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmNewPassword, setConfirmNewPassword] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwLoading, setPwLoading] = useState(false)
  const [pwSuccess, setPwSuccess] = useState('')

  const changePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setPwError('')
    setPwSuccess('')
    if (!currentPassword || !newPassword || !confirmNewPassword) {
      setPwError('Please fill all password fields')
      return
    }
    if (newPassword !== confirmNewPassword) {
      setPwError('New passwords do not match')
      return
    }
    setPwLoading(true)
    try {
      const token = localStorage.getItem('authToken')
      const resp = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err?.error || 'Change password failed')
      }
      setPwSuccess('Password updated successfully')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmNewPassword('')
    } catch (e: any) {
      setPwError(e?.message || 'Error updating password')
    } finally {
      setPwLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-3xl mx-auto px-4 py-8">
        <button onClick={() => navigate(-1)} className="mb-4 flex items-center gap-2 text-gray-300 hover:text-white">← Back</button>
        <h2 className="text-2xl font-bold mb-6 text-white">Account Settings</h2>

        <section className="bg-gray-800 p-6 rounded-lg border border-gray-700 mb-8">
          <h3 className="text-lg font-semibold text-white mb-4">Two-Factor Authentication (2FA)</h3>
          <p className="text-gray-300 mb-4">
            Status: <span className="text-green-400 font-semibold">Required & Enabled</span>
          </p>
          <p className="text-gray-400 text-sm">
            Two-factor authentication is required for all accounts to ensure maximum security. It was set up when you first logged in.
          </p>
        </section>

        <section className="bg-gray-800 p-6 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">Change Password</h3>
          <form onSubmit={changePassword} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
              <input
                type="password"
                value={confirmNewPassword}
                onChange={(e) => setConfirmNewPassword(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>
            {pwError && (
              <div className="bg-red-500/20 border border-red-500 text-red-300 px-4 py-3 rounded text-sm">{pwError}</div>
            )}
            {pwSuccess && (
              <div className="bg-green-500/20 border border-green-500 text-green-300 px-4 py-3 rounded text-sm">{pwSuccess}</div>
            )}
            <button
              type="submit"
              disabled={pwLoading}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium px-4 py-2 rounded"
            >
              {pwLoading ? 'Updating…' : 'Change Password'}
            </button>
          </form>
        </section>
      </div>
    </div>
  )
}

export default Settings


