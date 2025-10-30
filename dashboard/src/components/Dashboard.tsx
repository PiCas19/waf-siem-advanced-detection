import React, { useState } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import PermissionGate from './PermissionGate'
import AvatarMenu from './common/AvatarMenu'
import StatsPage from './stats/StatsPage'
import RulesContainer from './rules/RulesContainer'
import BlocklistPage from './blocklist/BlocklistPage'
import LogsPage from './logs/LogsPage'
import Users from './admin/Users'

const Dashboard: React.FC = () => {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('stats')

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold">WAF Dashboard</h1>
            <p className="text-sm text-gray-400">Welcome, {user?.name}</p>
          </div>
          <div className="flex items-center gap-2">
            <AvatarMenu />
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex space-x-4">
            {/* Always visible */}
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

            {/* Rules - needs rules_view permission */}
            <PermissionGate permission="rules_view">
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
            </PermissionGate>

            {/* Logs - needs logs_view permission */}
            <PermissionGate permission="logs_view">
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
            </PermissionGate>

            {/* Access Control - needs blocklist_view permission */}
            <PermissionGate permission="blocklist_view">
              <button
                onClick={() => setActiveTab('blocklist')}
                className={`px-4 py-3 border-b-2 font-medium transition ${
                  activeTab === 'blocklist'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                Access Control
              </button>
            </PermissionGate>

            {/* Users Management - needs users_view permission */}
            <PermissionGate permission="users_view">
              <button
                onClick={() => setActiveTab('users')}
                className={`px-4 py-3 border-b-2 font-medium transition ${
                  activeTab === 'users'
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                Users
              </button>
            </PermissionGate>
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
          <LogsPage />
        )}

        {/* Blocklist Tab */}
        {activeTab === 'blocklist' && (
          <BlocklistPage />
        )}

        {/* Users Tab (Admin Only) */}
        {activeTab === 'users' && user && String(user.role).toLowerCase().trim() === 'admin' && (
          <Users />
        )}

        {/* Settings moved: use the header Settings button */}
      </main>
    </div>
  )
}

export default Dashboard
