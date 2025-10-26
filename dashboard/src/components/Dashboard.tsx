import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import StatsPage from './dashboard/StatsPage'
import RulesContainer from './rules/RulesContainer'

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('stats')

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold">WAF Dashboard</h1>
            <p className="text-sm text-gray-400">Welcome, {user?.name}</p>
          </div>
          <button
            onClick={handleLogout}
            className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded font-medium transition"
          >
            Logout
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex space-x-4">
            <button
              onClick={() => setActiveTab('stats')}
              className={`px-4 py-3 border-b-2 font-medium transition ${
                activeTab === 'stats'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Statistics
            </button>
            <button
              onClick={() => setActiveTab('rules')}
              className={`px-4 py-3 border-b-2 font-medium transition ${
                activeTab === 'rules'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Rules
            </button>
            <button
              onClick={() => setActiveTab('logs')}
              className={`px-4 py-3 border-b-2 font-medium transition ${
                activeTab === 'logs'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Logs
            </button>
            <button
              onClick={() => setActiveTab('blocklist')}
              className={`px-4 py-3 border-b-2 font-medium transition ${
                activeTab === 'blocklist'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Blocklist
            </button>
            <button
              onClick={() => setActiveTab('settings')}
              className={`px-4 py-3 border-b-2 font-medium transition ${
                activeTab === 'settings'
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Settings
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* Statistics Tab */}
        {activeTab === 'stats' && (
          <StatsPage />
        )}

        {/* Rules Tab */}
        {activeTab === 'rules' && (
          <RulesContainer />
        )}

        {/* Logs Tab */}
        {activeTab === 'logs' && (
          <div>
            <h2 className="text-2xl font-bold mb-6">Security Logs</h2>
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <p className="text-gray-400">Security logs coming soon...</p>
            </div>
          </div>
        )}

        {/* Blocklist Tab */}
        {activeTab === 'blocklist' && (
          <div>
            <h2 className="text-2xl font-bold mb-6">Blocked IPs</h2>
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <p className="text-gray-400">Blocklist management coming soon...</p>
            </div>
          </div>
        )}

        {/* Settings Tab */}
        {activeTab === 'settings' && (
          <div>
            <h2 className="text-2xl font-bold mb-6">Account Settings</h2>
            <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-3">User Information</h3>
                <div className="space-y-2">
                  <p className="text-gray-300">
                    <span className="text-gray-400">Email:</span> {user?.email}
                  </p>
                  <p className="text-gray-300">
                    <span className="text-gray-400">Name:</span> {user?.name}
                  </p>
                  <p className="text-gray-300">
                    <span className="text-gray-400">Role:</span> {user?.role}
                  </p>
                  <p className="text-gray-300">
                    <span className="text-gray-400">2FA Status:</span>{' '}
                    {user?.two_fa_enabled ? (
                      <span className="text-green-400">✓ Enabled</span>
                    ) : (
                      <span className="text-red-400">✗ Disabled</span>
                    )}
                  </p>
                </div>
              </div>

              <div className="border-t border-gray-700 pt-6">
                <h3 className="text-lg font-semibold mb-3">Security</h3>
                <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded font-medium transition">
                  Change Password
                </button>
                <button className="ml-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded font-medium transition">
                  {user?.two_fa_enabled ? 'Manage 2FA' : 'Enable 2FA'}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

export default Dashboard
