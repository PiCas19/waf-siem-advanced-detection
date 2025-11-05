import React, { useState, useEffect } from 'react';
import {
  ChevronDown, Search, Download, Filter,
  AlertTriangle, Database, Shield, File, FolderOpen, Zap,
  KeyRound, Bot, Lock, Eye, BlocksIcon, Activity, History
} from 'lucide-react';

interface Log {
  id: number;
  created_at: string;
  threat_type: string;
  severity: string;
  description: string;
  client_ip: string;
  method: string;
  url: string;
  user_agent: string;
  payload: string;
  blocked: boolean;
  blocked_by?: string;
}

interface AuditLog {
  id: number;
  created_at: string;
  user_id: number;
  user_email: string;
  action: string;
  category: string;
  description: string;
  resource_type: string;
  resource_id: string;
  details?: string;
  status: string;
  error?: string;
  ip_address: string;
}

type TimeRangeFilter = 'today' | 'week' | '15m' | '30m' | '1h' | '24h' | '7d' | '30d' | '90d' | '1y' | 'all';
type LogType = 'security' | 'audit';

interface FilterState {
  search: string;
  threatType: string;
  severity: string;
  blocked: string;
  timeRange: TimeRangeFilter;
}

export default function LogsPage(): React.ReactElement {
  const [logs, setLogs] = useState<Log[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<Log[]>([]);
  const [filteredAuditLogs, setFilteredAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [logType, setLogType] = useState<LogType>('security');
  const [filter, setFilter] = useState<FilterState>({
    search: '',
    threatType: 'all',
    severity: 'all',
    blocked: 'all',
    timeRange: '24h',
  });

  // Funzione utility per calcolare il timeMs
  const getTimeMs = (timeRange: TimeRangeFilter): number | null => {
    const now = new Date();
    switch (timeRange) {
      case 'today':
        return now.getTime() - new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
      case 'week':
        return 7 * 24 * 60 * 60 * 1000;
      case '15m':
        return 15 * 60 * 1000;
      case '30m':
        return 30 * 60 * 1000;
      case '1h':
        return 60 * 60 * 1000;
      case '24h':
        return 24 * 60 * 60 * 1000;
      case '7d':
        return 7 * 24 * 60 * 60 * 1000;
      case '30d':
        return 30 * 24 * 60 * 60 * 1000;
      case '90d':
        return 90 * 24 * 60 * 60 * 1000;
      case '1y':
        return 365 * 24 * 60 * 60 * 1000;
      case 'all':
        return null;
      default:
        return 24 * 60 * 60 * 1000;
    }
  };

  const itemsPerPage = 15;
  const severityColors: Record<string, string> = {
    CRITICAL: 'bg-red-500/20 text-red-300 border-red-500/30',
    HIGH: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    LOW: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    INFO: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  };

  const getThreatIcon = (threatType: string) => {
    const iconMap: Record<string, React.ReactNode> = {
      'XSS': <AlertTriangle size={16} />,
      'SQL Injection': <Database size={16} />,
      'CSRF': <Shield size={16} />,
      'XXE': <File size={16} />,
      'Path Traversal': <FolderOpen size={16} />,
      'Command Injection': <Zap size={16} />,
      'Directory Listing': <FolderOpen size={16} />,
      'Malicious Pattern': <AlertTriangle size={16} />,
      'Brute Force': <KeyRound size={16} />,
      'Bot Detection': <Bot size={16} />,
      'Unauthorized Access': <Lock size={16} />,
      'Suspicious Activity': <Eye size={16} />,
    };
    return iconMap[threatType] || <AlertTriangle size={16} />;
  };

  // Load logs from API
  useEffect(() => {
    const loadLogs = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem('authToken');
        const response = await fetch('/api/logs', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          setLogs(data.security_logs || data.logs || []);
          setAuditLogs(data.audit_logs || []);
        }
      } catch (error) {
        console.error('Error loading logs:', error);
      } finally {
        setLoading(false);
      }
    };

    loadLogs();
  }, []);

  // Apply filters
  useEffect(() => {
    let filtered = [...logs];

    // Time range filter
    const now = new Date();
    const timeMs = getTimeMs(filter.timeRange);

    if (filter.timeRange !== 'all' && timeMs !== null) {
      filtered = filtered.filter((log) => {
        const logTime = new Date(log.created_at).getTime();
        return now.getTime() - logTime < timeMs;
      });
    }

    // Threat type filter
    if (filter.threatType !== 'all') {
      filtered = filtered.filter((log) => log.threat_type === filter.threatType);
    }

    // Severity filter
    if (filter.severity !== 'all') {
      filtered = filtered.filter((log) => log.severity === filter.severity);
    }

    // Blocked filter
    if (filter.blocked !== 'all') {
      filtered = filtered.filter((log) => log.blocked === (filter.blocked === 'blocked'));
    }

    // Search filter
    if (filter.search) {
      const searchLower = filter.search.toLowerCase();
      filtered = filtered.filter(
        (log) =>
          (log.client_ip?.toLowerCase() || '').includes(searchLower) ||
          (log.threat_type?.toLowerCase() || '').includes(searchLower) ||
          (log.url?.toLowerCase() || '').includes(searchLower) ||
          (log.payload?.toLowerCase() || '').includes(searchLower)
      );
    }

    // Sort by date descending
    filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    setCurrentPage(1);
    setFilteredLogs(filtered);

    // Filter audit logs
    let filteredAudit = [...auditLogs];
    const nowAudit = new Date();
    const timeMsAudit = getTimeMs(filter.timeRange);

    if (filter.timeRange !== 'all' && timeMsAudit !== null) {
      filteredAudit = filteredAudit.filter((log) => {
        const logTime = new Date(log.created_at).getTime();
        return nowAudit.getTime() - logTime < timeMsAudit;
      });
    }

    // Search filter for audit logs
    if (filter.search) {
      const searchLower = filter.search.toLowerCase();
      filteredAudit = filteredAudit.filter(
        (log) =>
          (log.user_email?.toLowerCase() || '').includes(searchLower) ||
          (log.action?.toLowerCase() || '').includes(searchLower) ||
          (log.category?.toLowerCase() || '').includes(searchLower) ||
          (log.description?.toLowerCase() || '').includes(searchLower) ||
          (log.ip_address?.toLowerCase() || '').includes(searchLower)
      );
    }

    // Sort by date descending
    filteredAudit.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    setFilteredAuditLogs(filteredAudit);
  }, [logs, auditLogs, filter]);

  const uniqueThreatTypes = Array.from(new Set(logs.map((log) => log.threat_type)));

  const currentLogs = logType === 'security' ? filteredLogs : filteredAuditLogs;
  const totalPages = Math.ceil(currentLogs.length / itemsPerPage);
  const paginatedLogs = currentLogs.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const handleDownloadLogs = () => {
    const jsonString = JSON.stringify(currentLogs, null, 2);
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/json;charset=utf-8,' + encodeURIComponent(jsonString));
    element.setAttribute('download', `logs_${logType}_${new Date().toISOString().split('T')[0]}.json`);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-4">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Logs</h1>
          <p className="text-gray-400">View all security events, threat detections, and system actions</p>
        </div>
        <button
          onClick={handleDownloadLogs}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg font-medium text-white transition"
        >
          <Download size={18} />
          Export JSON
        </button>
      </div>

      {/* Tab Buttons */}
      <div className="flex gap-2 border-b border-gray-700">
        <button
          onClick={() => {
            setLogType('security');
            setCurrentPage(1);
          }}
          className={`flex items-center gap-2 px-4 py-3 font-medium transition border-b-2 ${
            logType === 'security'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Activity size={18} />
          Security Logs ({filteredLogs.length})
        </button>
        <button
          onClick={() => {
            setLogType('audit');
            setCurrentPage(1);
          }}
          className={`flex items-center gap-2 px-4 py-3 font-medium transition border-b-2 ${
            logType === 'audit'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <History size={18} />
          Audit Logs ({filteredAuditLogs.length})
        </button>
      </div>

      {/* Filter Section */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-center gap-2 mb-4">
          <Filter size={20} className="text-gray-400" />
          <h2 className="text-lg font-semibold text-white">Filters</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {/* Search */}
          <div className="relative">
            <Search size={18} className="absolute left-3 top-3 text-gray-500" />
            <input
              type="text"
              placeholder={logType === 'security' ? "Search IP, threat, URL..." : "Search user, action, email..."}
              value={filter.search}
              onChange={(e) => setFilter({ ...filter, search: e.target.value })}
              className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-blue-500 focus:outline-none"
            />
          </div>

          {/* Time Range */}
          <select
            value={filter.timeRange}
            onChange={(e) => setFilter({ ...filter, timeRange: e.target.value as TimeRangeFilter })}
            className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
          >
            <option value="today">Today</option>
            <option value="week">This week</option>
            <option value="15m">Last 15 minutes</option>
            <option value="30m">Last 30 minutes</option>
            <option value="1h">Last 1 hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last 1 year</option>
            <option value="all">All time</option>
          </select>

          {/* Threat Type - Only for Security Logs */}
          {logType === 'security' && (
            <select
              value={filter.threatType}
              onChange={(e) => setFilter({ ...filter, threatType: e.target.value })}
              className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Threats</option>
              {uniqueThreatTypes.map((threat) => (
                <option key={threat} value={threat}>
                  {threat}
                </option>
              ))}
            </select>
          )}

          {/* Severity - Only for Security Logs */}
          {logType === 'security' && (
            <select
              value={filter.severity}
              onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
              className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          )}

          {/* Blocked Status - Only for Security Logs */}
          {logType === 'security' && (
            <select
              value={filter.blocked}
              onChange={(e) => setFilter({ ...filter, blocked: e.target.value })}
              className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Status</option>
              <option value="blocked">Blocked</option>
              <option value="detected">Detected</option>
            </select>
          )}
        </div>

        {/* Results Info */}
        <div className="mt-4 text-sm text-gray-400">
          Found <span className="text-blue-400 font-semibold">{filteredLogs.length}</span> logs
          {logs.length > filteredLogs.length && ` (filtered from ${logs.length} total)`}
        </div>
      </div>

      {/* Logs Table */}
      {loading ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 flex items-center justify-center">
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mb-4"></div>
            <p className="text-gray-400">Loading logs...</p>
          </div>
        </div>
      ) : currentLogs.length === 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 flex items-center justify-center">
          <div className="text-center">
            <p className="text-gray-400 text-lg">No logs found</p>
            <p className="text-gray-500 text-sm mt-2">Try adjusting your filters</p>
          </div>
        </div>
      ) : logType === 'security' ? (
        <>
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            {/* Table Header */}
            <div className="grid grid-cols-12 gap-4 p-4 bg-gray-750 border-b border-gray-700">
              <div className="col-span-1 text-xs font-semibold text-gray-400 uppercase">Time</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">Threat</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">IP Address</div>
              <div className="col-span-3 text-xs font-semibold text-gray-400 uppercase">URL</div>
              <div className="col-span-1 text-xs font-semibold text-gray-400 uppercase">Severity</div>
              <div className="col-span-1 text-xs font-semibold text-gray-400 uppercase">Status</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">Method</div>
            </div>

            {/* Table Body */}
            <div className="divide-y divide-gray-700">
              {paginatedLogs.map((logItem: any) => {
                const log = logItem as Log;
                return (
                <div key={log.id}>
                  {/* Main Row */}
                  <div
                    onClick={() =>
                      setExpandedRow(expandedRow === log.id ? null : log.id)
                    }
                    className="grid grid-cols-12 gap-4 p-4 hover:bg-gray-750 transition cursor-pointer border-b border-gray-700/50"
                  >
                    <div className="col-span-1 text-xs text-gray-300">
                      {new Date(log.created_at).toLocaleTimeString('it-IT')}
                    </div>
                    <div className="col-span-2 text-sm text-white font-medium flex items-center gap-2">
                      <span className="text-gray-400">
                        {getThreatIcon(log.threat_type)}
                      </span>
                      {log.threat_type}
                    </div>
                    <div className="col-span-2 text-sm text-gray-300 font-mono">
                      {log.client_ip}
                    </div>
                    <div className="col-span-3 text-xs text-gray-400 truncate" title={log.url}>
                      {log.url}
                    </div>
                    <div className="col-span-1">
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold border ${
                          severityColors[log.severity?.toUpperCase()] || 'bg-gray-500/20 text-gray-300 border-gray-500/30'
                        }`}
                      >
                        {log.severity?.toUpperCase() || 'N/A'}
                      </span>
                    </div>
                    <div className="col-span-1">
                      {log.blocked ? (
                        <span className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs font-medium border border-red-500/30 flex items-center gap-1 w-fit">
                          <BlocksIcon size={14} />
                          Blocked
                        </span>
                      ) : (
                        <span className="px-2 py-1 bg-yellow-500/20 text-yellow-300 rounded text-xs font-medium border border-yellow-500/30 flex items-center gap-1 w-fit">
                          <AlertTriangle size={14} />
                          Detected
                        </span>
                      )}
                    </div>
                    <div className="col-span-2 flex items-center justify-between">
                      <span className="px-2 py-1 bg-blue-500/10 text-blue-300 rounded text-xs font-medium">
                        {log.method}
                      </span>
                      <ChevronDown
                        size={18}
                        className={`text-gray-500 transition ${
                          expandedRow === log.id ? 'rotate-180' : ''
                        }`}
                      />
                    </div>
                  </div>

                  {/* Expanded Row */}
                  {expandedRow === log.id && (
                    <div className="bg-gray-750 p-6 border-b border-gray-700">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Left Column */}
                        <div className="space-y-4">
                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Description
                            </h4>
                            <p className="text-sm text-gray-300">{log.description}</p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Client IP
                            </h4>
                            <p className="text-sm font-mono text-gray-300">{log.client_ip}</p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              HTTP Method
                            </h4>
                            <span className="px-3 py-1 bg-blue-500/20 text-blue-300 rounded text-xs font-semibold">
                              {log.method}
                            </span>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Timestamp
                            </h4>
                            <p className="text-sm text-gray-300">
                              {new Date(log.created_at).toLocaleString('it-IT')}
                            </p>
                          </div>
                        </div>

                        {/* Right Column */}
                        <div className="space-y-4">
                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Full URL
                            </h4>
                            <p className="text-xs font-mono text-gray-400 break-all bg-gray-800 p-2 rounded border border-gray-700">
                              {log.url}
                            </p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Detected Payload
                            </h4>
                            {log.payload ? (
                              <p className="text-xs font-mono text-red-400 break-all bg-gray-800 p-2 rounded border border-red-500/30 max-h-24 overflow-y-auto">
                                {log.payload}
                              </p>
                            ) : (
                              <p className="text-xs text-gray-500 italic">No payload captured</p>
                            )}
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              User Agent
                            </h4>
                            <p className="text-xs text-gray-400 break-all bg-gray-800 p-2 rounded border border-gray-700 max-h-16 overflow-y-auto">
                              {log.user_agent || 'N/A'}
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
              })}
            </div>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-400">
                Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
                {Math.min(currentPage * itemsPerPage, currentLogs.length)} of {currentLogs.length}{' '}
                logs
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                >
                  ← Previous
                </button>
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => setCurrentPage(page)}
                      className={`px-3 py-1 rounded text-xs font-medium transition ${
                        currentPage === page
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        <>
          {/* AUDIT LOGS TABLE */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            {/* Table Header */}
            <div className="grid grid-cols-12 gap-4 p-4 bg-gray-750 border-b border-gray-700">
              <div className="col-span-1 text-xs font-semibold text-gray-400 uppercase">Time</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">User</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">Action</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">Category</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">IP Address</div>
              <div className="col-span-2 text-xs font-semibold text-gray-400 uppercase">Status</div>
              <div className="col-span-1 text-xs font-semibold text-gray-400 uppercase">Details</div>
            </div>

            {/* Table Body */}
            <div className="divide-y divide-gray-700">
              {paginatedLogs.map((log: any) => (
                <div key={log.id}>
                  {/* Main Row */}
                  <div
                    onClick={() =>
                      setExpandedRow(expandedRow === log.id ? null : log.id)
                    }
                    className="grid grid-cols-12 gap-4 p-4 hover:bg-gray-750 transition cursor-pointer border-b border-gray-700/50"
                  >
                    <div className="col-span-1 text-xs text-gray-300">
                      {new Date(log.created_at).toLocaleTimeString('it-IT')}
                    </div>
                    <div className="col-span-2 text-sm text-white font-medium truncate">
                      {log.user_email}
                    </div>
                    <div className="col-span-2 text-sm text-blue-300 font-medium truncate">
                      {log.action}
                    </div>
                    <div className="col-span-2 text-xs text-gray-400">
                      <span className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-xs font-medium border border-purple-500/30">
                        {log.category}
                      </span>
                    </div>
                    <div className="col-span-2 text-xs text-gray-400 font-mono">
                      {log.ip_address}
                    </div>
                    <div className="col-span-2">
                      {log.status === 'success' ? (
                        <span className="px-2 py-1 bg-green-500/20 text-green-300 rounded text-xs font-medium border border-green-500/30">
                          Success
                        </span>
                      ) : (
                        <span className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs font-medium border border-red-500/30">
                          Failed
                        </span>
                      )}
                    </div>
                    <div className="col-span-1 flex items-center justify-end">
                      <ChevronDown
                        size={18}
                        className={`text-gray-500 transition ${
                          expandedRow === log.id ? 'rotate-180' : ''
                        }`}
                      />
                    </div>
                  </div>

                  {/* Expanded Row */}
                  {expandedRow === log.id && (
                    <div className="bg-gray-750 p-6 border-b border-gray-700">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Left Column */}
                        <div className="space-y-4">
                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Description
                            </h4>
                            <p className="text-sm text-gray-300">{log.description}</p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              User Email
                            </h4>
                            <p className="text-sm text-gray-300">{log.user_email}</p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Action
                            </h4>
                            <span className="px-3 py-1 bg-blue-500/20 text-blue-300 rounded text-xs font-semibold">
                              {log.action}
                            </span>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Timestamp
                            </h4>
                            <p className="text-sm text-gray-300">
                              {new Date(log.created_at).toLocaleString('it-IT')}
                            </p>
                          </div>
                        </div>

                        {/* Right Column */}
                        <div className="space-y-4">
                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Category
                            </h4>
                            <span className="px-3 py-1 bg-purple-500/20 text-purple-300 rounded text-xs font-semibold">
                              {log.category}
                            </span>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Resource Type
                            </h4>
                            <p className="text-sm text-gray-300">{log.resource_type}</p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              Resource ID
                            </h4>
                            <p className="text-sm font-mono text-gray-400 break-all bg-gray-800 p-2 rounded border border-gray-700">
                              {log.resource_id}
                            </p>
                          </div>

                          <div>
                            <h4 className="text-xs uppercase font-semibold text-gray-400 mb-2">
                              IP Address
                            </h4>
                            <p className="text-sm font-mono text-gray-300">{log.ip_address}</p>
                          </div>

                          {log.error && (
                            <div>
                              <h4 className="text-xs uppercase font-semibold text-red-400 mb-2">
                                Error Message
                              </h4>
                              <p className="text-xs text-red-300 bg-gray-800 p-2 rounded border border-red-500/30">
                                {log.error}
                              </p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-400">
                Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
                {Math.min(currentPage * itemsPerPage, currentLogs.length)} of {currentLogs.length}{' '}
                logs
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                >
                  ← Previous
                </button>
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => setCurrentPage(page)}
                      className={`px-3 py-1 rounded text-xs font-medium transition ${
                        currentPage === page
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
