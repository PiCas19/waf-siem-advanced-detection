import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/contexts/AuthContext'
import AvatarMenu from './common/AvatarMenu'
import StatsPage from './stats/StatsPage'
import RulesContainer from './rules/RulesContainer'
import BlocklistPage from './blocklist/BlocklistPage'
import LogsPage from './logs/LogsPage'

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
          <div className="flex items-center gap-2">
            <AvatarMenu />
          </div>
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
              Access Control
            </button>
            {/* Settings moved to a dedicated page */}
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

        {/* Settings moved: use the header Settings button */}
      </main>
    </div>
  )
}

export default Dashboard
