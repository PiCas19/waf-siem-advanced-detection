import React, { useState, useEffect, useRef } from 'react';
import { Lock, CheckCircle, AlertTriangle, Trash2, Clock, Zap, AlertCircle, ArrowUp, ArrowDown } from 'lucide-react';
import { useToast } from '@/contexts/SnackbarContext';

// Validation helpers
const validateIP = (ip: string): { valid: boolean; error?: string } => {
  const trimmed = ip.trim();
  if (!trimmed) return { valid: false, error: 'IP address is required' };

  // Simple IPv4 validation
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // Simple IPv6 validation
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$/;

  if (!ipv4Regex.test(trimmed) && !ipv6Regex.test(trimmed)) {
    return { valid: false, error: 'Invalid IP address format (IPv4 or IPv6 required)' };
  }

  // Reject loopback
  if (trimmed === '127.0.0.1' || trimmed === '::1' || trimmed.startsWith('127.')) {
    return { valid: false, error: 'Cannot block loopback IP address (127.0.0.1, ::1)' };
  }

  return { valid: true };
};

const validateReason = (reason: string): { valid: boolean; error?: string } => {
  const trimmed = reason.trim();
  if (!trimmed) return { valid: false, error: 'Reason is required' };
  if (trimmed.length > 500) return { valid: false, error: 'Reason cannot exceed 500 characters' };

  // Check for potentially dangerous characters
  const validPattern = /^[a-zA-Z0-9\s\-_.(),;:'"\/\[\]]+$/;
  if (!validPattern.test(trimmed)) {
    return { valid: false, error: 'Reason contains invalid characters' };
  }

  return { valid: true };
};

const validateThreat = (threat: string): { valid: boolean; error?: string } => {
  const trimmed = threat.trim();
  if (!trimmed) return { valid: false, error: 'Threat type is required' };
  if (trimmed.length > 255) return { valid: false, error: 'Threat type cannot exceed 255 characters' };

  const validPattern = /^[a-zA-Z0-9\-_\s]+$/;
  if (!validPattern.test(trimmed)) {
    return { valid: false, error: 'Threat type contains invalid characters' };
  }

  return { valid: true };
};

interface BlockedEntry {
  id: string | number;
  ip_address: string;
  description: string;
  reason: string;
  created_at: string;
  expires_at: string | null;
  permanent: boolean;
  url?: string;
  user_agent?: string;
  payload?: string;
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
  description?: string;
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

  // Form states
  const [blockForm, setBlockForm] = useState({ ip: '', reason: '', duration: '24h' });
  const [blockDuration, setBlockDuration] = useState<number | 'permanent' | 'custom'>(24);
  const [customBlockDuration, setCustomBlockDuration] = useState<number>(24);
  const [customBlockDurationUnit, setCustomBlockDurationUnit] = useState<'hours' | 'days'>('hours');
  const [whiteForm, setWhiteForm] = useState({ ip: '', reason: '' });

  // Validation error states
  const [blockFormErrors, setBlockFormErrors] = useState<{ ip?: string; reason?: string; threat?: string }>({});
  const [whiteFormErrors, setWhiteFormErrors] = useState<{ ip?: string; reason?: string }>({});

  // Ref to track when whitelist was just loaded (to avoid reloading immediately)
  const whitelistJustLoadedRef = useRef(false);

  // Pagination states
  const [blocklistPage, setBlocklistPage] = useState(1);
  const [whitelistPage, setWhitelistPage] = useState(1);
  const [falsePositivesPage, setFalsePositivesPage] = useState(1);
  const itemsPerPage = 10;

  // Sorting states for blocklist
  const [blocklistSortColumn, setBlocklistSortColumn] = useState<'ip' | 'threat' | 'reason' | 'type' | 'blockedDate' | 'expires'>('blockedDate');
  const [blocklistSortOrder, setBlocklistSortOrder] = useState<'asc' | 'desc'>('desc');

  // Sorting states for whitelist
  const [whitelistSortColumn, setWhitelistSortColumn] = useState<'ip' | 'reason' | 'addedDate'>('addedDate');
  const [whitelistSortOrder, setWhitelistSortOrder] = useState<'asc' | 'desc'>('desc');

  // Sorting states for false positives
  const [fpSortColumn, setFpSortColumn] = useState<'threatType' | 'ip' | 'method' | 'status' | 'date'>('date');
  const [fpSortOrder, setFpSortOrder] = useState<'asc' | 'desc'>('desc');

  // Additional filters
  const [blocklistTypeFilter, setBlocklistTypeFilter] = useState<'all' | 'permanent' | 'temporary'>('all');
  const [fpStatusFilter, setFpStatusFilter] = useState<'all' | 'pending' | 'reviewed' | 'whitelisted'>('all');

  // Carica dati all'avvio e quando il tab cambia
  useEffect(() => {
    if (activeTab === 'whitelist' && whitelistJustLoadedRef.current) {
      // Whitelist was just loaded, don't reload
      whitelistJustLoadedRef.current = false;
      return;
    }
    loadData();
  }, [activeTab]);

  // Carica TUTTI i dati in real-time (non solo il tab attivo)
  useEffect(() => {
    const loadAllData = async () => {
      try {
        const token = localStorage.getItem('authToken');

        // Load blocklist - API returns { data: [...], pagination: {...} }
        const blockRes = await fetch('/api/blocklist', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (blockRes.ok) {
          const data = await blockRes.json();
          const blocklistData = data.data || data.blocked_ips || [];
          setBlocklist(blocklistData);
        }

        // Load whitelist - API returns { data: [...], pagination: {...} }
        const whiteRes = await fetch('/api/whitelist', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (whiteRes.ok) {
          const data = await whiteRes.json();
          const whitelistData = data.data || data.whitelisted_ips || [];
          setWhitelist(whitelistData);
        }

        // Load false positives - API returns { false_positives: [...], pagination: {...}, count: X }
        const fpRes = await fetch('/api/false-positives', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (fpRes.ok) {
          const data = await fpRes.json();
          // Check false_positives first (actual API response), then data as fallback
          const fpData = data.false_positives || data.data || [];
          setFalsePositives(fpData);
        }
      } catch (error) {
        console.error('Failed to load data:', error);
      }
    };

    // Load on mount
    loadAllData();

    // Reload every 5 seconds for real-time counts
    const interval = setInterval(loadAllData, 5000);
    return () => clearInterval(interval);
  }, []);

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
          const blocklistData = data.data || data.blocked_ips || [];
          setBlocklist(blocklistData);
        }
      } else if (activeTab === 'whitelist') {
        const res = await fetch('/api/whitelist', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          const whitelistData = data.data || data.whitelisted_ips || [];
          setWhitelist(whitelistData);
        }
      } else if (activeTab === 'false-positives') {
        const res = await fetch('/api/false-positives', {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          // API returns { false_positives: [...], pagination: {...}, count: X }
          const fpData = data.false_positives || data.data || [];
          setFalsePositives(fpData);
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

    // Validate all fields
    const errors: typeof blockFormErrors = {};
    const ipValidation = validateIP(blockForm.ip);
    const reasonValidation = validateReason(blockForm.reason);
    const threatValidation = validateThreat(blockForm.reason);

    if (!ipValidation.valid) errors.ip = ipValidation.error;
    if (!reasonValidation.valid) errors.reason = reasonValidation.error;
    if (!threatValidation.valid) errors.threat = threatValidation.error;

    if (Object.keys(errors).length > 0) {
      setBlockFormErrors(errors);
      showToast('Please fix the errors in the form', 'error', 4000);
      return;
    }

    setBlockFormErrors({});

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
        ip: blockForm.ip.trim(),
        threat: blockForm.reason.trim(),
        reason: blockForm.reason.trim(),
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
        setBlockFormErrors({});
        setShowAddBlockForm(false);
        loadData();
      } else {
        const errorData = await response.json().catch(() => ({}));
        showToast(errorData.error || 'Failed to block IP', 'error', 4000);
      }
    } catch (error) {
      showToast('Failed to block IP', 'error', 4000);
    }
  };

  const handleAddWhite = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate all fields
    const errors: typeof whiteFormErrors = {};
    const ipValidation = validateIP(whiteForm.ip);
    const reasonValidation = validateReason(whiteForm.reason);

    if (!ipValidation.valid) errors.ip = ipValidation.error;
    if (!reasonValidation.valid) errors.reason = reasonValidation.error;

    if (Object.keys(errors).length > 0) {
      setWhiteFormErrors(errors);
      showToast('Please fix the errors in the form', 'error', 4000);
      return;
    }

    setWhiteFormErrors({});

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/api/whitelist', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip_address: whiteForm.ip.trim(),
          reason: whiteForm.reason.trim(),
        }),
      });

      if (response.ok) {
        showToast('IP whitelisted successfully', 'success', 4000);
        setWhiteForm({ ip: '', reason: '' });
        setWhiteFormErrors({});
        setShowAddWhiteForm(false);
        loadData();
      } else {
        const errorData = await response.json().catch(() => ({}));
        showToast(errorData.error || 'Failed to whitelist IP', 'error', 4000);
      }
    } catch (error) {
      showToast('Failed to whitelist IP', 'error', 4000);
    }
  };

  const handleDeleteBlock = async (ip: string, description: string) => {
    if (!confirm('Are you sure you want to remove this entry?')) return;

    // Optimistic update: rimuovi dalla lista locale
    const backupList = blocklist;
    const entry = blocklist.find(e => e.ip_address === ip && e.description === description);
    setBlocklist(blocklist.filter(entry => !(entry.ip_address === ip && entry.description === description)));

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`/api/blocklist/${ip}?threat=${encodeURIComponent(description)}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: entry?.url || '',
          user_agent: entry?.user_agent || '',
          payload: entry?.payload || '',
        }),
      });

      if (response.ok) {
        showToast('Entry removed successfully', 'success', 4000);

        // Log the manual unblock to WAF logs
        try {
          const token = localStorage.getItem('authToken');
          await fetch('/api/logs/manual-unblock', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              ip: ip,
              threat_type: description,
              severity: 'medium',
              description: description,
              url: entry?.url || '',
              user_agent: entry?.user_agent || '',
              payload: entry?.payload || '',
            }),
          });
        } catch (logError) {
          console.error('Failed to log manual unblock to WAF logs:', logError);
          // Don't fail the whole operation if logging fails
        }
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

      // If whitelisting, first add to whitelist
      if (status === 'whitelisted') {
        const fp = falsePositives.find(f => f.id === id);
        if (fp) {
          const whiteRes = await fetch('/api/whitelist', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              ip_address: fp.client_ip,
              reason: `Auto-whitelisted from false positive`,
            }),
          });

          if (!whiteRes.ok) {
            showToast('Failed to add to whitelist', 'error', 4000);
            return;
          }

          // Get the response to add to local state immediately
          try {
            const responseData = await whiteRes.json();
            // Add the new entry to local whitelist state immediately
            const newEntry: WhitelistedEntry = {
              id: responseData.entry?.id || Date.now(),
              ip_address: fp.client_ip,
              reason: 'Auto-whitelisted from false positive',
              created_at: new Date().toISOString(),
            };
            setWhitelist([...whitelist, newEntry]);
            // Mark that whitelist was just loaded, so don't reload on tab change
            whitelistJustLoadedRef.current = true;
            showToast('IP added to whitelist', 'success', 2000);
          } catch (err) {
            showToast('Error processing whitelist response', 'error', 4000);
            return;
          }
        }
      }

      // Then update false positive status
      const response = await fetch(`/api/false-positives/${id}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status }),
      });

      if (response.ok) {
        // Update local state immediately for responsive UI
        setFalsePositives(falsePositives.map(fp =>
          fp.id === id ? { ...fp, status } : fp
        ));
        // Auto-navigate to whitelist tab if whitelisted
        // Note: whitelist was already loaded above and marked with whitelistJustLoadedRef,
        // so the useEffect won't reload it when activeTab changes
        if (status === 'whitelisted') {
          setTimeout(() => {
            setActiveTab('whitelist');
          }, 100);
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

    if (blocklistTypeFilter === 'permanent') return matchesSearch && entry.permanent;
    if (blocklistTypeFilter === 'temporary') return matchesSearch && !entry.permanent;
    return matchesSearch;
  });

  const filteredWhitelist = whitelist.filter((entry) =>
    (entry.ip_address?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
    (entry.reason?.toLowerCase() || '').includes(searchTerm.toLowerCase())
  );

  const filteredFalsePositives = falsePositives.filter((entry) => {
    const matchesSearch = (entry.threat_type?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
                         (entry.client_ip?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
                         (entry.url?.toLowerCase() || '').includes(searchTerm.toLowerCase());

    if (fpStatusFilter === 'pending') return matchesSearch && entry.status === 'pending';
    if (fpStatusFilter === 'reviewed') return matchesSearch && entry.status === 'reviewed';
    if (fpStatusFilter === 'whitelisted') return matchesSearch && entry.status === 'whitelisted';
    return matchesSearch;
  });

  // Sorting functions
  const sortBlocklist = (list: BlockedEntry[]): BlockedEntry[] => {
    return [...list].sort((a, b) => {
      let aVal: any, bVal: any;

      if (blocklistSortColumn === 'ip') {
        aVal = a.ip_address;
        bVal = b.ip_address;
      } else if (blocklistSortColumn === 'threat') {
        aVal = a.description;
        bVal = b.description;
      } else if (blocklistSortColumn === 'reason') {
        aVal = a.reason;
        bVal = b.reason;
      } else if (blocklistSortColumn === 'type') {
        aVal = a.permanent ? 'permanent' : 'temporary';
        bVal = b.permanent ? 'permanent' : 'temporary';
      } else if (blocklistSortColumn === 'blockedDate') {
        aVal = new Date(a.created_at).getTime();
        bVal = new Date(b.created_at).getTime();
      } else if (blocklistSortColumn === 'expires') {
        aVal = a.expires_at ? new Date(a.expires_at).getTime() : 0;
        bVal = b.expires_at ? new Date(b.expires_at).getTime() : 0;
      }

      if (blocklistSortOrder === 'asc') {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });
  };

  const sortWhitelist = (list: WhitelistedEntry[]): WhitelistedEntry[] => {
    return [...list].sort((a, b) => {
      let aVal: any, bVal: any;

      if (whitelistSortColumn === 'ip') {
        aVal = a.ip_address;
        bVal = b.ip_address;
      } else if (whitelistSortColumn === 'reason') {
        aVal = a.reason;
        bVal = b.reason;
      } else if (whitelistSortColumn === 'addedDate') {
        aVal = new Date(a.created_at).getTime();
        bVal = new Date(b.created_at).getTime();
      }

      if (whitelistSortOrder === 'asc') {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });
  };

  const sortFalsePositives = (list: FalsePositive[]): FalsePositive[] => {
    return [...list].sort((a, b) => {
      let aVal: any, bVal: any;

      if (fpSortColumn === 'threatType') {
        aVal = a.threat_type;
        bVal = b.threat_type;
      } else if (fpSortColumn === 'ip') {
        aVal = a.client_ip;
        bVal = b.client_ip;
      } else if (fpSortColumn === 'method') {
        aVal = a.method;
        bVal = b.method;
      } else if (fpSortColumn === 'status') {
        aVal = a.status;
        bVal = b.status;
      } else if (fpSortColumn === 'date') {
        aVal = new Date(a.created_at).getTime();
        bVal = new Date(b.created_at).getTime();
      }

      if (fpSortOrder === 'asc') {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });
  };

  // Apply sorting to filtered data
  const sortedBlocklist = sortBlocklist(filteredBlocklist);
  const sortedWhitelist = sortWhitelist(filteredWhitelist);
  const sortedFalsePositives = sortFalsePositives(filteredFalsePositives);

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
              value={blocklistTypeFilter}
              onChange={(e) => {
                setBlocklistTypeFilter(e.target.value as any);
                setBlocklistPage(1);
              }}
              className="px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Types</option>
              <option value="permanent">Permanent</option>
              <option value="temporary">Temporary</option>
            </select>
          )}
          {activeTab === 'false-positives' && (
            <select
              value={fpStatusFilter}
              onChange={(e) => {
                setFpStatusFilter(e.target.value as any);
                setFalsePositivesPage(1);
              }}
              className="px-4 py-2 bg-gray-700 text-white rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Status</option>
              <option value="pending">Pending</option>
              <option value="reviewed">Reviewed</option>
              <option value="whitelisted">Whitelisted</option>
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
                    placeholder="192.168.1.100 or IPv6 address"
                    value={blockForm.ip}
                    onChange={(e) => {
                      setBlockForm({ ...blockForm, ip: e.target.value });
                      const validation = validateIP(e.target.value);
                      if (validation.error) {
                        setBlockFormErrors({ ...blockFormErrors, ip: validation.error });
                      } else {
                        const { ip, ...rest } = blockFormErrors;
                        setBlockFormErrors(rest);
                      }
                    }}
                    className={`w-full px-4 py-2 bg-gray-700 text-white rounded border transition-colors focus:outline-none ${
                      blockFormErrors.ip ? 'border-red-500 focus:border-red-500' : 'border-gray-600 focus:border-red-500'
                    }`}
                  />
                  {blockFormErrors.ip && (
                    <div className="flex items-center gap-2 mt-2 text-red-400 text-sm">
                      <AlertCircle size={14} />
                      {blockFormErrors.ip}
                    </div>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Reason/Threat Type * ({blockForm.reason.length}/500)</label>
                  <input
                    type="text"
                    placeholder="e.g., SQL Injection attempts, Brute Force Attack"
                    value={blockForm.reason}
                    onChange={(e) => {
                      setBlockForm({ ...blockForm, reason: e.target.value });
                      const validation = validateReason(e.target.value);
                      if (validation.error) {
                        setBlockFormErrors({ ...blockFormErrors, reason: validation.error });
                      } else {
                        const { reason, ...rest } = blockFormErrors;
                        setBlockFormErrors(rest);
                      }
                    }}
                    className={`w-full px-4 py-2 bg-gray-700 text-white rounded border transition-colors focus:outline-none ${
                      blockFormErrors.reason ? 'border-red-500 focus:border-red-500' : 'border-gray-600 focus:border-red-500'
                    }`}
                  />
                  {blockFormErrors.reason && (
                    <div className="flex items-center gap-2 mt-2 text-red-400 text-sm">
                      <AlertCircle size={14} />
                      {blockFormErrors.reason}
                    </div>
                  )}
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
                    disabled={Object.keys(blockFormErrors).length > 0 || !blockForm.ip || !blockForm.reason}
                    className={`px-6 py-2 text-white rounded font-medium transition flex items-center gap-2 ${
                      Object.keys(blockFormErrors).length > 0 || !blockForm.ip || !blockForm.reason
                        ? 'bg-red-600/50 text-red-300 cursor-not-allowed'
                        : 'bg-red-600 hover:bg-red-700 cursor-pointer'
                    }`}
                  >
                    Block IP
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowAddBlockForm(false);
                      setBlockFormErrors({});
                    }}
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
          ) : sortedBlocklist.length > 0 ? (
            <>
              <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-gray-700">
                      <tr>
                        <th
                          onClick={() => {
                            if (blocklistSortColumn === 'ip') {
                              setBlocklistSortOrder(blocklistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setBlocklistSortColumn('ip');
                              setBlocklistSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            IP Address
                            {blocklistSortColumn === 'ip' && (
                              blocklistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (blocklistSortColumn === 'threat') {
                              setBlocklistSortOrder(blocklistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setBlocklistSortColumn('threat');
                              setBlocklistSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Threat/Rule
                            {blocklistSortColumn === 'threat' && (
                              blocklistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (blocklistSortColumn === 'reason') {
                              setBlocklistSortOrder(blocklistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setBlocklistSortColumn('reason');
                              setBlocklistSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Reason
                            {blocklistSortColumn === 'reason' && (
                              blocklistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (blocklistSortColumn === 'type') {
                              setBlocklistSortOrder(blocklistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setBlocklistSortColumn('type');
                              setBlocklistSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Type
                            {blocklistSortColumn === 'type' && (
                              blocklistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (blocklistSortColumn === 'blockedDate') {
                              setBlocklistSortOrder(blocklistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setBlocklistSortColumn('blockedDate');
                              setBlocklistSortOrder('desc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Blocked Date
                            {blocklistSortColumn === 'blockedDate' && (
                              blocklistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (blocklistSortColumn === 'expires') {
                              setBlocklistSortOrder(blocklistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setBlocklistSortColumn('expires');
                              setBlocklistSortOrder('desc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Expires
                            {blocklistSortColumn === 'expires' && (
                              blocklistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedBlocklist.slice((blocklistPage - 1) * itemsPerPage, blocklistPage * itemsPerPage).map((entry) => (
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

              {/* Pagination */}
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 flex items-center justify-between">
                <div className="text-sm text-gray-400">
                  Showing {Math.min((blocklistPage - 1) * itemsPerPage + 1, sortedBlocklist.length)} to {Math.min(blocklistPage * itemsPerPage, sortedBlocklist.length)} of {sortedBlocklist.length} items
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setBlocklistPage(Math.max(1, blocklistPage - 1))}
                    disabled={blocklistPage === 1}
                    className={`px-3 py-1 rounded text-sm font-medium transition ${
                      blocklistPage === 1
                        ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
                    }`}
                  >
                    Previous
                  </button>
                  {Array.from({ length: Math.ceil(sortedBlocklist.length / itemsPerPage) }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => setBlocklistPage(page)}
                      className={`px-3 py-1 rounded text-sm font-medium transition ${
                        blocklistPage === page
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 text-white hover:bg-gray-600'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                  <button
                    onClick={() => setBlocklistPage(Math.min(Math.ceil(sortedBlocklist.length / itemsPerPage), blocklistPage + 1))}
                    disabled={blocklistPage >= Math.ceil(sortedBlocklist.length / itemsPerPage)}
                    className={`px-3 py-1 rounded text-sm font-medium transition ${
                      blocklistPage >= Math.ceil(sortedBlocklist.length / itemsPerPage)
                        ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
                    }`}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
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
                    placeholder="192.168.1.100 or IPv6 address"
                    value={whiteForm.ip}
                    onChange={(e) => {
                      setWhiteForm({ ...whiteForm, ip: e.target.value });
                      const validation = validateIP(e.target.value);
                      if (validation.error) {
                        setWhiteFormErrors({ ...whiteFormErrors, ip: validation.error });
                      } else {
                        const { ip, ...rest } = whiteFormErrors;
                        setWhiteFormErrors(rest);
                      }
                    }}
                    className={`w-full px-4 py-2 bg-gray-700 text-white rounded border transition-colors focus:outline-none ${
                      whiteFormErrors.ip ? 'border-red-500 focus:border-red-500' : 'border-gray-600 focus:border-green-500'
                    }`}
                  />
                  {whiteFormErrors.ip && (
                    <div className="flex items-center gap-2 mt-2 text-red-400 text-sm">
                      <AlertCircle size={14} />
                      {whiteFormErrors.ip}
                    </div>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Reason * ({whiteForm.reason.length}/500)</label>
                  <input
                    type="text"
                    placeholder="e.g., Internal server, Trusted partner IP, Development machine"
                    value={whiteForm.reason}
                    onChange={(e) => {
                      setWhiteForm({ ...whiteForm, reason: e.target.value });
                      const validation = validateReason(e.target.value);
                      if (validation.error) {
                        setWhiteFormErrors({ ...whiteFormErrors, reason: validation.error });
                      } else {
                        const { reason, ...rest } = whiteFormErrors;
                        setWhiteFormErrors(rest);
                      }
                    }}
                    className={`w-full px-4 py-2 bg-gray-700 text-white rounded border transition-colors focus:outline-none ${
                      whiteFormErrors.reason ? 'border-red-500 focus:border-red-500' : 'border-gray-600 focus:border-green-500'
                    }`}
                  />
                  {whiteFormErrors.reason && (
                    <div className="flex items-center gap-2 mt-2 text-red-400 text-sm">
                      <AlertCircle size={14} />
                      {whiteFormErrors.reason}
                    </div>
                  )}
                </div>
                <div className="flex gap-3">
                  <button
                    type="submit"
                    disabled={Object.keys(whiteFormErrors).length > 0 || !whiteForm.ip || !whiteForm.reason}
                    className={`px-6 py-2 text-white rounded font-medium transition flex items-center gap-2 ${
                      Object.keys(whiteFormErrors).length > 0 || !whiteForm.ip || !whiteForm.reason
                        ? 'bg-green-600/50 text-green-300 cursor-not-allowed'
                        : 'bg-green-600 hover:bg-green-700 cursor-pointer'
                    }`}
                  >
                    Whitelist IP
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowAddWhiteForm(false);
                      setWhiteFormErrors({});
                    }}
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
          ) : sortedWhitelist.length > 0 ? (
            <>
              <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-gray-700">
                      <tr>
                        <th
                          onClick={() => {
                            if (whitelistSortColumn === 'ip') {
                              setWhitelistSortOrder(whitelistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setWhitelistSortColumn('ip');
                              setWhitelistSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            IP Address
                            {whitelistSortColumn === 'ip' && (
                              whitelistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (whitelistSortColumn === 'reason') {
                              setWhitelistSortOrder(whitelistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setWhitelistSortColumn('reason');
                              setWhitelistSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Reason
                            {whitelistSortColumn === 'reason' && (
                              whitelistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (whitelistSortColumn === 'addedDate') {
                              setWhitelistSortOrder(whitelistSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setWhitelistSortColumn('addedDate');
                              setWhitelistSortOrder('desc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Added Date
                            {whitelistSortColumn === 'addedDate' && (
                              whitelistSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedWhitelist.slice((whitelistPage - 1) * itemsPerPage, whitelistPage * itemsPerPage).map((entry) => (
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

              {/* Pagination */}
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 flex items-center justify-between">
                <div className="text-sm text-gray-400">
                  Showing {Math.min((whitelistPage - 1) * itemsPerPage + 1, sortedWhitelist.length)} to {Math.min(whitelistPage * itemsPerPage, sortedWhitelist.length)} of {sortedWhitelist.length} items
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setWhitelistPage(Math.max(1, whitelistPage - 1))}
                    disabled={whitelistPage === 1}
                    className={`px-3 py-1 rounded text-sm font-medium transition ${
                      whitelistPage === 1
                        ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
                    }`}
                  >
                    Previous
                  </button>
                  {Array.from({ length: Math.ceil(sortedWhitelist.length / itemsPerPage) }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => setWhitelistPage(page)}
                      className={`px-3 py-1 rounded text-sm font-medium transition ${
                        whitelistPage === page
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 text-white hover:bg-gray-600'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                  <button
                    onClick={() => setWhitelistPage(Math.min(Math.ceil(sortedWhitelist.length / itemsPerPage), whitelistPage + 1))}
                    disabled={whitelistPage >= Math.ceil(sortedWhitelist.length / itemsPerPage)}
                    className={`px-3 py-1 rounded text-sm font-medium transition ${
                      whitelistPage >= Math.ceil(sortedWhitelist.length / itemsPerPage)
                        ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
                    }`}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
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
          ) : sortedFalsePositives.length > 0 ? (
            <>
              <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-gray-700">
                      <tr>
                        <th
                          onClick={() => {
                            if (fpSortColumn === 'threatType') {
                              setFpSortOrder(fpSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setFpSortColumn('threatType');
                              setFpSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Threat Type
                            {fpSortColumn === 'threatType' && (
                              fpSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (fpSortColumn === 'ip') {
                              setFpSortOrder(fpSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setFpSortColumn('ip');
                              setFpSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            IP Address
                            {fpSortColumn === 'ip' && (
                              fpSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (fpSortColumn === 'method') {
                              setFpSortOrder(fpSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setFpSortColumn('method');
                              setFpSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Method
                            {fpSortColumn === 'method' && (
                              fpSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (fpSortColumn === 'status') {
                              setFpSortOrder(fpSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setFpSortColumn('status');
                              setFpSortOrder('asc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Status
                            {fpSortColumn === 'status' && (
                              fpSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th
                          onClick={() => {
                            if (fpSortColumn === 'date') {
                              setFpSortOrder(fpSortOrder === 'asc' ? 'desc' : 'asc');
                            } else {
                              setFpSortColumn('date');
                              setFpSortOrder('desc');
                            }
                          }}
                          className="text-left py-3 px-4 text-gray-300 font-medium cursor-pointer hover:text-white transition"
                        >
                          <div className="flex items-center gap-2">
                            Date
                            {fpSortColumn === 'date' && (
                              fpSortOrder === 'asc' ? (
                                <ArrowUp size={14} />
                              ) : (
                                <ArrowDown size={14} />
                              )
                            )}
                          </div>
                        </th>
                        <th className="text-center py-3 px-4 text-gray-300 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedFalsePositives.slice((falsePositivesPage - 1) * itemsPerPage, falsePositivesPage * itemsPerPage).map((fp) => (
                        <tr key={fp.id} className="border-t border-gray-700 hover:bg-gray-700/50 transition">
                          <td className="py-3 px-4 text-gray-300">{fp.threat_type}</td>
                          <td className="py-3 px-4 text-white font-mono text-sm">{fp.client_ip}</td>
                          <td className="py-3 px-4 text-gray-300 text-sm">{fp.method || '-'}</td>
                          <td className="py-3 px-4">
                            <span className={`px-3 py-1 rounded text-xs font-medium inline-flex items-center gap-1 ${
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
                          </td>
                          <td className="py-3 px-4 text-gray-400 text-sm">
                            {new Date(fp.created_at).toLocaleDateString('it-IT')}
                          </td>
                          <td className="py-3 px-4 text-center">
                            {fp.status === 'pending' && (
                              <div className="inline-flex gap-1 whitespace-nowrap">
                                <button
                                  onClick={() => handleMarkFalsePositive(fp.id, 'reviewed')}
                                  className="inline-flex items-center gap-1 px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition"
                                  title="Mark as reviewed"
                                >
                                  <AlertTriangle size={12} />
                                  Review
                                </button>
                                <button
                                  onClick={() => handleMarkFalsePositive(fp.id, 'whitelisted')}
                                  className="inline-flex items-center gap-1 px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-xs font-medium transition"
                                  title="Add to whitelist"
                                >
                                  <CheckCircle size={12} />
                                  Whitelist
                                </button>
                                <button
                                  onClick={() => handleDeleteFalsePositive(fp.id)}
                                  className="inline-flex items-center gap-1 px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                                  title="Delete"
                                >
                                  <Trash2 size={12} />
                                  Delete
                                </button>
                              </div>
                            )}
                            {fp.status !== 'pending' && (
                              <button
                                onClick={() => handleDeleteFalsePositive(fp.id)}
                                className="inline-flex items-center gap-1 px-2 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-medium transition"
                                title="Delete"
                              >
                                <Trash2 size={12} />
                                Delete
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Pagination */}
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 flex items-center justify-between">
                <div className="text-sm text-gray-400">
                  Showing {Math.min((falsePositivesPage - 1) * itemsPerPage + 1, sortedFalsePositives.length)} to {Math.min(falsePositivesPage * itemsPerPage, sortedFalsePositives.length)} of {sortedFalsePositives.length} items
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setFalsePositivesPage(Math.max(1, falsePositivesPage - 1))}
                    disabled={falsePositivesPage === 1}
                    className={`px-3 py-1 rounded text-sm font-medium transition ${
                      falsePositivesPage === 1
                        ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
                    }`}
                  >
                    Previous
                  </button>
                  {Array.from({ length: Math.ceil(sortedFalsePositives.length / itemsPerPage) }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => setFalsePositivesPage(page)}
                      className={`px-3 py-1 rounded text-sm font-medium transition ${
                        falsePositivesPage === page
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 text-white hover:bg-gray-600'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                  <button
                    onClick={() => setFalsePositivesPage(Math.min(Math.ceil(sortedFalsePositives.length / itemsPerPage), falsePositivesPage + 1))}
                    disabled={falsePositivesPage >= Math.ceil(sortedFalsePositives.length / itemsPerPage)}
                    className={`px-3 py-1 rounded text-sm font-medium transition ${
                      falsePositivesPage >= Math.ceil(sortedFalsePositives.length / itemsPerPage)
                        ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
                    }`}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
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
