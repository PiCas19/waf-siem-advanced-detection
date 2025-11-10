import React, { useState, useEffect } from 'react';
import { Lock, CheckCircle, AlertTriangle, Trash2, Clock, Zap } from 'lucide-react';
import { useToast } from '@/contexts/SnackbarContext';

interface BlockedEntry {
  id: string | number;
  ip_address: string;
  description: string;
  reason: string;
  created_at: string;
  expires_at: string | null;
  permanent: boolean;
}

interface WhitelistedEntry {
  id: string | number;
  ip_address: string;
  reason: string;
  created_at: string;
}

interface FalsePositive {
  id: string | number;
  threat_type: string;
  client_ip: string;
  method: string;
  url: string;
  payload?: string;
  review_notes?: string;
  created_at: string;
  status: 'pending' | 'reviewed' | 'whitelisted';
}

type Tab = 'blocklist' | 'whitelist' | 'false-positives';

const BlocklistPage: React.FC = () => {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<Tab>('blocklist');
  const [blocklist, setBlocklist] = useState<BlockedEntry[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistedEntry[]>([]);
  const [falsePositives, setFalsePositives] = useState<FalsePositive[]>([]);

  const [showAddBlockForm, setShowAddBlockForm] = useState(false);
  const [showAddWhiteForm, setShowAddWhiteForm] = useState(false);

  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'permanent' | 'temporary'>('all');

  // Form states
  const [blockForm, setBlockForm] = useState({ ip: '', reason: '', duration: '24h' });
  const [blockDuration, setBlockDuration] = useState<number | 'permanent' | 'custom'>(24);
  const [customBlockDuration, setCustomBlockDuration] = useState<number>(24);
  const [customBlockDurationUnit, setCustomBlockDurationUnit] = useState<'hours' | 'days'>('hours');
  const [whiteForm, setWhiteForm] = useState({ ip: '', reason: '' });

  // Carica dati
  useEffect(() => {
    loadData();
  }, [activeTab]);

  const loadData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('authToken');

      if (activeTab === 'blocklist') {
        const res = await fetch('/api/blocklist', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setBlocklist(data.blocked_ips || []);
        }
      } else if (activeTab === 'whitelist') {
        const res = await fetch('/api/whitelist', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setWhitelist(data.whitelisted_ips || []);
        }
      } else if (activeTab === 'false-positives') {
        const res = await fetch('/api/false-positives', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setFalsePositives(data.false_positives || []);
        }
      }
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!blockForm.ip) {
      showToast('IP is required', 'info', 4000);
      return;
    }

    // Calcola la durata in ore
    let durationHours = 24;

    if (blockDuration === 'permanent') {
      durationHours = -1;
    } else if (blockDuration === 'custom') {
      durationHours = customBlockDurationUnit === 'hours' ? customBlockDuration : customBlockDuration * 24;
    } else {
      // blockDuration è un numero che rappresenta le ore
      durationHours = blockDuration as number;
    }

    try {
      const token = localStorage.getItem('authToken');
      const payloadToSend = {
        ip: blockForm.ip,
        threat: blockForm.reason || 'Manually blocked',
        reason: blockForm.reason || 'Manually blocked',
        permanent: blockDuration === 'permanent',
        duration_hours: durationHours,
      };

      const response = await fetch('/api/blocklist', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payloadToSend),
      });

      if (response.ok) {
        await response.json(); // Parse but don't use
        showToast('IP blocked successfully', 'success', 4000);
        // Reset form after successful block
        setBlockForm({ ip: '', reason: '', duration: '24h' });
        setBlockDuration(24);
        setCustomBlockDuration(24);
        setCustomBlockDurationUnit('hours');
        setShowAddBlockForm(false);
        loadData();
      } else {
        showToast('Failed to block IP', 'error', 4000);
      }
    } catch (error) {
      showToast('Failed to block IP', 'error', 4000);
    }
  };

  const handleAddWhite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!whiteForm.ip) {
      showToast('IP is required', 'info', 4000);
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/api/whitelist', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip_address: whiteForm.ip,
          reason: whiteForm.reason || 'Manually whitelisted',
        }),
      });

      if (response.ok) {
        showToast('IP whitelisted successfully', 'success', 4000);
        setWhiteForm({ ip: '', reason: '' });
        setShowAddWhiteForm(false);
        loadData();
      }
    } catch (error) {
      showToast('Failed to whitelist IP', 'error', 4000);
    }
  };

  const handleDeleteBlock = async (ip: string, description: string) => {
    if (!confirm('Are you sure you want to remove this entry?')) return;

    // Optimistic update: rimuovi dalla lista locale
    const backupList = blocklist;
    setBlocklist(blocklist.filter(entry => !(entry.ip_address === ip && entry.description === description)));

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/blocklist/${ip}?threat=${encodeURIComponent(description)}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.ok) {
        showToast('Entry removed successfully', 'success', 4000);
      } else {
        // Rollback on error
        setBlocklist(backupList);
        showToast('Failed to delete entry', 'error', 4000);
      }
    } catch (error) {
      // Rollback on error
      setBlocklist(backupList);
      showToast('Failed to delete entry', 'error', 4000);
    }
  };

  const handleDeleteWhite = async (id: string | number) => {
    if (!confirm('Are you sure you want to remove this entry?')) return;

    // Optimistic update: rimuovi dalla lista locale
    const backupList = whitelist;
    setWhitelist(whitelist.filter(entry => entry.id !== id));

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/whitelist/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.ok) {
        showToast('Entry removed successfully', 'success', 4000);
      } else {
        // Rollback on error
        setWhitelist(backupList);
        showToast('Failed to delete entry', 'error', 4000);
      }
    } catch (error) {
      // Rollback on error
      setWhitelist(backupList);
      showToast('Failed to delete entry', 'error', 4000);
    }
  };

  const handleMarkFalsePositive = async (id: string | number, status: 'reviewed' | 'whitelisted') => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/false-positives/${id}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status }),
      });

      if (response.ok) {
        showToast('Status updated successfully', 'success', 4000);
        // Update local state immediately for responsive UI
        setFalsePositives(falsePositives.map(fp =>
          fp.id === id ? { ...fp, status } : fp
        ));
        // Also reload whitelist if whitelisted status
        if (status === 'whitelisted') {
          const whiteRes = await fetch('/api/whitelist', {
            headers: { 'Authorization': `Bearer ${token}` },
          });
          if (whiteRes.ok) {
            const whiteData = await whiteRes.json();
            setWhitelist(whiteData.whitelisted_ips || []);
          }
        }
      }
    } catch (error) {
      showToast('Failed to update status', 'error', 4000);
    }
  };

  const handleDeleteFalsePositive = async (id: string | number) => {
    if (!confirm('Are you sure you want to delete this false positive record?')) return;

    // Optimistic update: rimuovi dalla lista locale
    const backupList = falsePositives;
    setFalsePositives(falsePositives.filter(entry => entry.id !== id));

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/false-positives/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.ok) {
        showToast('False positive deleted successfully', 'success', 4000);
      } else {
        // Rollback on error
        setFalsePositives(backupList);
        showToast('Failed to delete false positive', 'error', 4000);
      }
    } catch (error) {
      // Rollback on error
      setFalsePositives(backupList);
      showToast('Failed to delete false positive', 'error', 4000);
    }
  };

  const filteredBlocklist = blocklist.filter((entry) => {
    const matchesSearch = (entry.ip_address?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
                         (entry.reason?.toLowerCase() || '').includes(searchTerm.toLowerCase());

    if (filterStatus === 'permanent') return matchesSearch && entry.permanent;
    if (filterStatus === 'temporary') return matchesSearch && !entry.permanent;
    return matchesSearch;
  });

  const filteredWhitelist = whitelist.filter((entry) =>
    (entry.ip_address?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
    (entry.reason?.toLowerCase() || '').includes(searchTerm.toLowerCase())
  );

  const filteredFalsePositives = falsePositives.filter((entry) =>
    (entry.threat_type?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
    (entry.client_ip?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
    (entry.url?.toLowerCase() || '').includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Blocklist</h1>
          <p className="text-gray-400">Manage blocked IPs, whitelisted IPs, and false positives</p>
        </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-gray-700">
        <button
          onClick={() => setActiveTab('blocklist')}
          className={`px-6 py-3 font-medium transition border-b-2 flex items-center gap-2 ${
            activeTab === 'blocklist'
              ? 'border-red-500 text-red-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Lock size={18} />
          Blocklist ({blocklist.length})
        </button>
        <button
          onClick={() => setActiveTab('whitelist')}
          className={`px-6 py-3 font-medium transition border-b-2 flex items-center gap-2 ${
            activeTab === 'whitelist'
              ? 'border-green-500 text-green-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <CheckCircle size={18} />
          Whitelist ({whitelist.length})
        </button>
        <button
          onClick={() => setActiveTab('false-positives')}
          className={`px-6 py-3 font-medium transition border-b-2 flex items-center gap-2 ${
            activeTab === 'false-positives'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <AlertTriangle size={18} />
          False Positives ({falsePositives.filter(fp => fp.status === 'pending').length})
        </button>
      </div>

      {/* Search & Filter */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <input
            type="text"
            placeholder="Search..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="col-span-2 px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
          {activeTab === 'blocklist' && (
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value as any)}
              className="px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All</option>
              <option value="permanent">Permanent</option>
              <option value="temporary">Temporary (24h)</option>
            </select>
          )}
        </div>
      </div>

      {/* Content */}
      {activeTab === 'blocklist' && (
        <div className="space-y-6">
          {/* Add Block Form */}
          {showAddBlockForm && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Block New IP</h3>
              <form onSubmit={handleAddBlock} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">IP Address *</label>
                  <input
                    type="text"
                    placeholder="192.168.1.100"
                    value={blockForm.ip}
                    onChange={(e) => setBlockForm({ ...blockForm, ip: e.target.value })}
                    className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-red-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Reason</label>
                  <input
                    type="text"
                    placeholder="e.g., SQL Injection attempts"
                    value={blockForm.reason}
                    onChange={(e) => setBlockForm({ ...blockForm, reason: e.target.value })}
                    className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-red-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-3">Block Duration</label>

                  {/* Quick Duration Options */}
                  <div className="grid grid-cols-2 gap-2 mb-4">
                    {/* 24 Hours */}
                    <button
                      type="button"
                      onClick={() => setBlockDuration(24)}
                      className={`px-3 py-2.5 rounded-lg font-medium transition-all border text-sm ${
                        blockDuration === 24
                          ? 'bg-blue-600 text-white border-blue-500 shadow-lg shadow-blue-500/30'
                          : 'bg-gray-700/50 text-gray-300 border-gray-600 hover:bg-gray-700 hover:border-gray-500'
                      }`}
                    >
                      <p className="font-semibold text-xs">24 Hours</p>
                      <p className="text-xs opacity-75">1 day</p>
                    </button>

                    {/* 7 Days */}
                    <button
                      type="button"
                      onClick={() => setBlockDuration(168)}
                      className={`px-3 py-2.5 rounded-lg font-medium transition-all border text-sm ${
                        blockDuration === 168
                          ? 'bg-blue-600 text-white border-blue-500 shadow-lg shadow-blue-500/30'
                          : 'bg-gray-700/50 text-gray-300 border-gray-600 hover:bg-gray-700 hover:border-gray-500'
                      }`}
                    >
                      <p className="font-semibold text-xs">7 Days</p>
                      <p className="text-xs opacity-75">1 week</p>
                    </button>

                    {/* 30 Days */}
                    <button
                      type="button"
                      onClick={() => setBlockDuration(720)}
                      className={`px-3 py-2.5 rounded-lg font-medium transition-all border text-sm ${
                        blockDuration === 720
                          ? 'bg-blue-600 text-white border-blue-500 shadow-lg shadow-blue-500/30'
                          : 'bg-gray-700/50 text-gray-300 border-gray-600 hover:bg-gray-700 hover:border-gray-500'
                      }`}
                    >
                      <p className="font-semibold text-xs">30 Days</p>
                      <p className="text-xs opacity-75">1 month</p>
                    </button>

                    {/* Permanent */}
                    <button
                      type="button"
                      onClick={() => setBlockDuration('permanent')}
                      className={`px-3 py-2.5 rounded-lg font-medium transition-all border text-sm ${
                        blockDuration === 'permanent'
                          ? 'bg-red-600 text-white border-red-500 shadow-lg shadow-red-500/30'
                          : 'bg-gray-700/50 text-gray-300 border-gray-600 hover:bg-gray-700 hover:border-gray-500'
                      }`}
                    >
                      <p className="font-semibold text-xs">Permanent</p>
                      <p className="text-xs opacity-75">Forever</p>
                    </button>
                  </div>

                  {/* Custom Duration Option */}
                  <button
                    type="button"
                    onClick={() => setBlockDuration('custom')}
                    className={`w-full px-3 py-2.5 rounded-lg font-medium transition-all border mb-3 text-sm ${
                      blockDuration === 'custom'
                        ? 'bg-amber-600 text-white border-amber-500 shadow-lg shadow-amber-500/30'
                        : 'bg-gray-700/50 text-gray-300 border-gray-600 hover:bg-gray-700 hover:border-gray-500'
                    }`}
                  >
                    <p className="font-semibold text-xs">Custom Duration</p>
                  </button>

                  {/* Custom Duration Input */}
                  {blockDuration === 'custom' && (
                    <div className="bg-gray-700/30 border border-gray-600 rounded-lg p-3 space-y-2">
                      <div className="flex gap-2">
                        <input
                          type="number"
                          min="1"
                          value={customBlockDuration}
                          onChange={(e) => setCustomBlockDuration(Math.max(1, parseInt(e.target.value) || 1))}
                          className="flex-1 px-3 py-2 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-amber-500 focus:outline-none transition text-sm"
                          placeholder="Duration"
                        />
                        <select
                          value={customBlockDurationUnit}
                          onChange={(e) => setCustomBlockDurationUnit(e.target.value as 'hours' | 'days')}
                          className="px-3 py-2 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-amber-500 focus:outline-none transition text-sm"
                        >
                          <option value="hours">Hours</option>
                          <option value="days">Days</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>
                <div className="flex gap-3">
                  <button
                    type="submit"
                    className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium transition"
                  >
                    Block IP
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowAddBlockForm(false)}
                    className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Blocklist Table */}
          {!showAddBlockForm && (
            <div className="flex justify-end">
              <button
                onClick={() => setShowAddBlockForm(true)}
                className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium transition"
              >
                + Block IP
              </button>
            </div>
          )}

          {loading ? (
            <div className="text-center py-12 text-gray-400">Loading...</div>
          ) : filteredBlocklist.length > 0 ? (
            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">IP Address</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Threat/Rule</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Reason</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Type</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Blocked Date</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Expires</th>
                      <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredBlocklist.map((entry) => (
                      <tr key={entry.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                        <td className="py-3 px-4 text-white font-mono">{entry.ip_address}</td>
                        <td className="py-3 px-4 text-gray-300 font-medium">{entry.description}</td>
                        <td className="py-3 px-4 text-gray-300">{entry.reason}</td>
                        <td className="py-3 px-4">
                          <span className={`px-3 py-1 rounded text-xs font-medium inline-flex items-center gap-1 ${
                            entry.permanent
                              ? 'bg-red-500/20 text-red-300'
                              : 'bg-yellow-500/20 text-yellow-300'
                          }`}>
                            {entry.permanent ? (
                              <>
                                <Zap size={12} />
                                Permanent
                              </>
                            ) : (
                              <>
                                <Clock size={12} />
                                Temporary
                              </>
                            )}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {new Date(entry.created_at).toLocaleDateString('it-IT')}
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {entry.expires_at ? new Date(entry.expires_at).toLocaleDateString('it-IT') : 'Never'}
                        </td>
                        <td className="py-3 px-4 text-center">
                          <button
                            onClick={() => handleDeleteBlock(entry.ip_address, entry.description)}
                            className="inline-flex items-center gap-2 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                          >
                            <Trash2 size={14} />
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center text-gray-400">
              <p>No blocked IPs</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'whitelist' && (
        <div className="space-y-6">
          {/* Add Whitelist Form */}
          {showAddWhiteForm && (
            <div className="bg-green-900/20 border border-green-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Whitelist New IP</h3>
              <form onSubmit={handleAddWhite} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">IP Address *</label>
                  <input
                    type="text"
                    placeholder="192.168.1.100"
                    value={whiteForm.ip}
                    onChange={(e) => setWhiteForm({ ...whiteForm, ip: e.target.value })}
                    className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-green-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Reason</label>
                  <input
                    type="text"
                    placeholder="e.g., Internal server, whitelisted user"
                    value={whiteForm.reason}
                    onChange={(e) => setWhiteForm({ ...whiteForm, reason: e.target.value })}
                    className="w-full px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-green-500 focus:outline-none"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    type="submit"
                    className="px-6 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium transition"
                  >
                    Whitelist IP
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowAddWhiteForm(false)}
                    className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded font-medium transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}

          {!showAddWhiteForm && (
            <div className="flex justify-end">
              <button
                onClick={() => setShowAddWhiteForm(true)}
                className="px-6 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium transition"
              >
                + Whitelist IP
              </button>
            </div>
          )}

          {loading ? (
            <div className="text-center py-12 text-gray-400">Loading...</div>
          ) : filteredWhitelist.length > 0 ? (
            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">IP Address</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Reason</th>
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Added Date</th>
                      <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredWhitelist.map((entry) => (
                      <tr key={entry.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                        <td className="py-3 px-4 text-white font-mono">{entry.ip_address}</td>
                        <td className="py-3 px-4 text-gray-300 text-sm">{entry.reason || '-'}</td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {new Date(entry.created_at).toLocaleDateString('it-IT')}
                        </td>
                        <td className="py-3 px-4 text-center">
                          <button
                            onClick={() => handleDeleteWhite(entry.id)}
                            className="inline-flex items-center gap-2 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                          >
                            <Trash2 size={14} />
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center text-gray-400">
              <p>No whitelisted IPs</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'false-positives' && (
        <div className="space-y-6">
          {loading ? (
            <div className="text-center py-12 text-gray-400">Loading...</div>
          ) : filteredFalsePositives.length > 0 ? (
            <div className="space-y-4">
              {filteredFalsePositives.map((fp) => (
                <div key={fp.id} className={`border rounded-lg p-4 ${
                  fp.status === 'pending' ? 'bg-blue-900/20 border-blue-700' :
                  fp.status === 'whitelisted' ? 'bg-green-900/20 border-green-700' :
                  'bg-gray-900/20 border-gray-700'
                }`}>
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <p className="text-white font-medium">{fp.threat_type}</p>
                        <span className={`px-2 py-1 rounded text-xs font-medium inline-flex items-center gap-1 ${
                          fp.status === 'pending' ? 'bg-blue-500/20 text-blue-300' :
                          fp.status === 'whitelisted' ? 'bg-green-500/20 text-green-300' :
                          'bg-gray-500/20 text-gray-300'
                        }`}>
                          {fp.status === 'pending' ? (
                            <>
                              <Clock size={12} />
                              Pending
                            </>
                          ) : fp.status === 'whitelisted' ? (
                            <>
                              <CheckCircle size={12} />
                              Whitelisted
                            </>
                          ) : (
                            <>
                              <AlertTriangle size={12} />
                              Reviewed
                            </>
                          )}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm">{fp.method} {fp.url}</p>
                      <p className="text-gray-500 text-xs mt-1">IP: {fp.client_ip}</p>
                      {fp.payload && (
                        <p className="text-gray-500 text-xs mt-1">Payload: {fp.payload}</p>
                      )}
                    </div>
                  </div>

                  <div className="flex gap-2 pt-3 border-t border-gray-700">
                    {fp.status === 'pending' && (
                      <>
                        <button
                          onClick={() => handleMarkFalsePositive(fp.id, 'reviewed')}
                          className="inline-flex items-center gap-2 px-4 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                        >
                          <AlertTriangle size={14} />
                          Mark as Reviewed
                        </button>
                        <button
                          onClick={() => handleMarkFalsePositive(fp.id, 'whitelisted')}
                          className="inline-flex items-center gap-2 px-4 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition"
                        >
                          <CheckCircle size={14} />
                          Whitelist IP
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => handleDeleteFalsePositive(fp.id)}
                      className="ml-auto inline-flex items-center gap-2 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                    >
                      <Trash2 size={14} />
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center text-gray-400">
              <p>No false positives</p>
            </div>
          )}
        </div>
      )}
      </div>
    </div>
  );
};

export default BlocklistPage;
