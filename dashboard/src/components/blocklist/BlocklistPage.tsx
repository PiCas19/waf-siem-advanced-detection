import React, { useState, useEffect } from 'react';

interface BlockedEntry {
  id: string | number;
  ip_address: string;
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
  created_at: string;
  status: 'pending' | 'reviewed' | 'whitelisted';
}

type Tab = 'blocklist' | 'whitelist' | 'false-positives';

const BlocklistPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('blocklist');
  const [blocklist, setBlocklist] = useState<BlockedEntry[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistedEntry[]>([]);
  const [falsePositives, setFalsePositives] = useState<FalsePositive[]>([]);

  const [showAddBlockForm, setShowAddBlockForm] = useState(false);
  const [showAddWhiteForm, setShowAddWhiteForm] = useState(false);
  const [editingEntry, setEditingEntry] = useState<BlockedEntry | null>(null);

  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'permanent' | 'temporary'>('all');

  // Form states
  const [blockForm, setBlockForm] = useState({ ip: '', reason: '', permanent: false });
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
      alert('IP is required');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/api/blocklist', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip: blockForm.ip,
          reason: blockForm.reason || 'Manually blocked',
          permanent: blockForm.permanent,
        }),
      });

      if (response.ok) {
        alert('IP blocked successfully');
        setBlockForm({ ip: '', reason: '', permanent: false });
        setShowAddBlockForm(false);
        loadData();
      }
    } catch (error) {
      console.error('Error blocking IP:', error);
      alert('Failed to block IP');
    }
  };

  const handleAddWhite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!whiteForm.ip) {
      alert('IP is required');
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
        alert('IP whitelisted successfully');
        setWhiteForm({ ip: '', reason: '' });
        setShowAddWhiteForm(false);
        loadData();
      }
    } catch (error) {
      console.error('Error whitelisting IP:', error);
      alert('Failed to whitelist IP');
    }
  };

  const handleDeleteBlock = async (id: string | number) => {
    if (!confirm('Are you sure you want to remove this entry?')) return;

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/blocklist/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.ok) {
        alert('Entry removed successfully');
        loadData();
      }
    } catch (error) {
      console.error('Error deleting entry:', error);
      alert('Failed to delete entry');
    }
  };

  const handleDeleteWhite = async (id: string | number) => {
    if (!confirm('Are you sure you want to remove this entry?')) return;

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/whitelist/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
      });

      if (response.ok) {
        alert('Entry removed successfully');
        loadData();
      }
    } catch (error) {
      console.error('Error deleting entry:', error);
      alert('Failed to delete entry');
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
        alert('Status updated successfully');
        loadData();
      }
    } catch (error) {
      console.error('Error updating status:', error);
      alert('Failed to update status');
    }
  };

  const filteredBlocklist = blocklist.filter((entry) => {
    const matchesSearch = entry.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         entry.reason.toLowerCase().includes(searchTerm.toLowerCase());

    if (filterStatus === 'permanent') return matchesSearch && entry.permanent;
    if (filterStatus === 'temporary') return matchesSearch && !entry.permanent;
    return matchesSearch;
  });

  const filteredWhitelist = whitelist.filter((entry) =>
    entry.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
    entry.reason.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredFalsePositives = falsePositives.filter((entry) =>
    entry.threat_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    entry.client_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
    entry.url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
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
          className={`px-6 py-3 font-medium transition border-b-2 ${
            activeTab === 'blocklist'
              ? 'border-red-500 text-red-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          🚫 Blocklist ({blocklist.length})
        </button>
        <button
          onClick={() => setActiveTab('whitelist')}
          className={`px-6 py-3 font-medium transition border-b-2 ${
            activeTab === 'whitelist'
              ? 'border-green-500 text-green-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          ✅ Whitelist ({whitelist.length})
        </button>
        <button
          onClick={() => setActiveTab('false-positives')}
          className={`px-6 py-3 font-medium transition border-b-2 ${
            activeTab === 'false-positives'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          ⚠️ False Positives ({falsePositives.filter(fp => fp.status === 'pending').length})
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
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={blockForm.permanent}
                    onChange={(e) => setBlockForm({ ...blockForm, permanent: e.target.checked })}
                    className="w-4 h-4"
                  />
                  <span className="text-gray-300">Permanent block (otherwise 24 hours)</span>
                </label>
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
                        <td className="py-3 px-4 text-gray-300">{entry.reason}</td>
                        <td className="py-3 px-4">
                          <span className={`px-3 py-1 rounded text-xs font-medium ${
                            entry.permanent
                              ? 'bg-red-500/20 text-red-300'
                              : 'bg-yellow-500/20 text-yellow-300'
                          }`}>
                            {entry.permanent ? '⏳ Permanent' : '⏱️ 24 Hours'}
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
                            onClick={() => handleDeleteBlock(entry.id)}
                            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                          >
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
                      <th className="text-left py-3 px-4 text-gray-300 font-medium">Whitelisted Date</th>
                      <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredWhitelist.map((entry) => (
                      <tr key={entry.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                        <td className="py-3 px-4 text-white font-mono">{entry.ip_address}</td>
                        <td className="py-3 px-4 text-gray-300">{entry.reason}</td>
                        <td className="py-3 px-4 text-gray-400 text-sm">
                          {new Date(entry.created_at).toLocaleDateString('it-IT')}
                        </td>
                        <td className="py-3 px-4 text-center">
                          <button
                            onClick={() => handleDeleteWhite(entry.id)}
                            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                          >
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
                    <div>
                      <p className="text-white font-medium">{fp.threat_type}</p>
                      <p className="text-gray-400 text-sm">{fp.method} {fp.url}</p>
                      <p className="text-gray-500 text-xs mt-1">IP: {fp.client_ip}</p>
                    </div>
                    <span className={`px-3 py-1 rounded text-xs font-medium ${
                      fp.status === 'pending' ? 'bg-blue-500/20 text-blue-300' :
                      fp.status === 'whitelisted' ? 'bg-green-500/20 text-green-300' :
                      'bg-gray-500/20 text-gray-300'
                    }`}>
                      {fp.status === 'pending' ? '⏳ Pending' :
                       fp.status === 'whitelisted' ? '✅ Whitelisted' :
                       '👁️ Reviewed'}
                    </span>
                  </div>

                  {fp.status === 'pending' && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleMarkFalsePositive(fp.id, 'reviewed')}
                        className="px-4 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                      >
                        Mark as Reviewed
                      </button>
                      <button
                        onClick={() => handleMarkFalsePositive(fp.id, 'whitelisted')}
                        className="px-4 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition"
                      >
                        Whitelist IP
                      </button>
                    </div>
                  )}
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
  );
};

export default BlocklistPage;
