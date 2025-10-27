import React, { useState, useEffect } from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import { useWebSocketStats } from '@/hooks/useWebSocketStats';
import { fetchStats } from '@/services/api';

interface WAFEvent {
  ip: string;
  method: string;
  path: string;
  query?: string;
  user_agent?: string;
  timestamp: string;
  threat: string;
  blocked: boolean;
  // Da API logs endpoint
  id?: number;
  client_ip?: string;
  threat_type?: string;
  created_at?: string;
  url?: string;
}

interface ChartDataPoint {
  time: string;
  threats: number;
  blocked: number;
}

const StatsPage: React.FC = () => {
  const { stats, isConnected } = useWebSocketStats();
  const [timelineData, setTimelineData] = useState<ChartDataPoint[]>([]);
  const [threatTypeData, setThreatTypeData] = useState<any[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<WAFEvent[]>([]);
  const [blockingIP, setBlockingIP] = useState<string | null>(null);

  // Filtri INDIPENDENTI per ogni sezione
  const [timelineFilter, setTimelineFilter] = useState<'1h' | '24h' | '7d'>('1h');

  const [threatDistFilter, setThreatDistFilter] = useState<'1h' | '24h' | '7d'>('1h');

  const [recentThreatsFilter, setRecentThreatsFilter] = useState<'1h' | '24h' | '7d'>('1h');

  const [alertsTimeFilter, setAlertsTimeFilter] = useState<'1h' | '24h' | '7d'>('1h');
  const [alertsThreatFilter, setAlertsThreatFilter] = useState<string>('all');

  // Dati filtrati per ogni sezione
  const [filteredAlertsByRecentThreats, setFilteredAlertsByRecentThreats] = useState<WAFEvent[]>([]);
  const [filteredAlertsByAllAlerts, setFilteredAlertsByAllAlerts] = useState<WAFEvent[]>([]);

  // Pagination states
  const [recentThreatsPage, setRecentThreatsPage] = useState(1);
  const [allAlertsPage, setAllAlertsPage] = useState(1);
  const itemsPerPage = 10;

  // Carica i dati iniziali
  useEffect(() => {
    const loadInitialData = async () => {
      try {
        // Carica stats per il timeline
        const data = await fetchStats();
        initializeTimeline();

        // Carica logs (tutte le threat) dal database
        const token = localStorage.getItem('authToken');
        const logsResponse = await fetch('/api/logs', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (logsResponse.ok) {
          const logsData = await logsResponse.json();
          // Mappa i logs al formato WAFEvent
          const mappedLogs = logsData.logs.map((log: any) => ({
            ip: log.client_ip,
            method: log.method,
            path: log.url,
            timestamp: log.created_at || new Date().toISOString(),
            threat: log.threat_type,
            blocked: log.blocked,
            user_agent: log.user_agent,
          }));
          setRecentAlerts(mappedLogs);
        } else {
          // Fallback a stats.recent se logs endpoint fallisce
          setRecentAlerts(data.recent || []);
        }
      } catch (error) {
        console.error('Failed to load initial stats:', error);
      }
    };
    loadInitialData();
  }, []);

  // Inizializza timeline con dati simulati
  const initializeTimeline = () => {
    const now = new Date();
    const points: ChartDataPoint[] = [];
    for (let i = 30; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 60000);
      points.push({
        time: time.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) || '00:00',
        threats: 0,
        blocked: 0,
      });
    }
    setTimelineData(points.length > 0 ? points : []);
  };

  // Aggiorna timeline quando arrivano nuovi eventi
  useEffect(() => {
    if (timelineData.length === 0) return;

    setTimelineData((prevData) => {
      if (!prevData || prevData.length === 0) return prevData;

      const newData = [...prevData];
      const now = new Date();
      const timeStr = now.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) || '00:00';

      let lastPoint = newData[newData.length - 1];
      if (!lastPoint) return prevData;

      if (lastPoint.time !== timeStr) {
        newData.shift();
        newData.push({
          time: timeStr,
          threats: lastPoint?.threats ?? 0,
          blocked: lastPoint?.blocked ?? 0,
        });
        lastPoint = newData[newData.length - 1];
      }

      if (lastPoint) {
        lastPoint.threats = Math.max(lastPoint.threats, stats.threats_detected);
        lastPoint.blocked = Math.max(lastPoint.blocked, stats.requests_blocked);
      }

      return newData;
    });
  }, [stats]);

  // Calcola threat types solo per Threat Distribution (con suo filtro)
  useEffect(() => {
    let filtered = [...recentAlerts];

    const now = new Date();
    const timeMs = threatDistFilter === '1h' ? 60 * 60 * 1000 : threatDistFilter === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    const threatCounts = filtered.reduce((acc: any[], alert) => {
      if (!alert || !alert.threat) return acc;
      const existing = acc.find(t => t && t.name === alert.threat);
      if (existing) {
        existing.value = (existing.value || 0) + 1;
        existing.blocked = (existing.blocked || 0) + (alert.blocked ? 1 : 0);
      } else {
        acc.push({
          name: alert.threat || 'Unknown',
          value: 1,
          blocked: alert.blocked ? 1 : 0,
        });
      }
      return acc;
    }, []);

    setThreatTypeData(threatCounts && threatCounts.length > 0 ? threatCounts : []);
  }, [recentAlerts, threatDistFilter]);

  // Filtra per Recent Threats Table (solo timeframe)
  useEffect(() => {
    let filtered = [...recentAlerts];

    const now = new Date();
    const timeMs = recentThreatsFilter === '1h' ? 60 * 60 * 1000 : recentThreatsFilter === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    setRecentThreatsPage(1); // Reset pagination
    setFilteredAlertsByRecentThreats(filtered.sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    ));
  }, [recentAlerts, recentThreatsFilter]);

  // Filtra per All Alerts Table (timeframe + threat type)
  useEffect(() => {
    let filtered = [...recentAlerts];

    if (alertsThreatFilter !== 'all') {
      filtered = filtered.filter(alert => alert.threat === alertsThreatFilter);
    }

    const now = new Date();
    const timeMs = alertsTimeFilter === '1h' ? 60 * 60 * 1000 : alertsTimeFilter === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    setAllAlertsPage(1); // Reset pagination
    setFilteredAlertsByAllAlerts(filtered.sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    ));
  }, [recentAlerts, alertsTimeFilter, alertsThreatFilter]);

  // Blocca un IP
  const handleBlockIP = async (ip: string) => {
    setBlockingIP(ip);
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('/api/blocklist', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip: ip,
          reason: 'Manually blocked from Recent Threats',
          permanent: false,
        }),
      });

      if (response.ok) {
        console.log('IP blocked successfully:', ip);

        // Aggiorna tutti gli alert da questo IP per marcarli come bloccati
        setRecentAlerts(prevAlerts =>
          prevAlerts.map(alert =>
            alert.ip === ip ? { ...alert, blocked: true } : alert
          )
        );

        alert(`IP ${ip} bloccato con successo (24 ore)`);
      } else {
        alert('Errore nel blocco dell\'IP');
      }
    } catch (error) {
      console.error('Failed to block IP:', error);
      alert('Errore nel blocco dell\'IP');
    } finally {
      setBlockingIP(null);
    }
  };

  const blockRate = stats.total_requests > 0 ? (stats.requests_blocked / stats.total_requests * 100).toFixed(1) : '0';
  const detectionRate = stats.total_requests > 0 ? (stats.threats_detected / stats.total_requests * 100).toFixed(1) : '0';

  // Get unique threats da recentAlerts
  const allUniqueThreats = Array.from(new Set(recentAlerts.map(a => a.threat)));

  return (
    <div className="space-y-8">
      {/* Header with status */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Analytics</h1>
          <p className="text-gray-400">Real-time WAF monitoring and threat detection</p>
        </div>
        <div className={`px-4 py-2 rounded-lg font-medium ${isConnected ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
          {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gradient-to-br from-red-500/10 to-red-500/5 border border-red-500/20 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm font-medium mb-2">Threats Detected</h3>
          <p className="text-3xl font-bold text-red-400">{stats.threats_detected}</p>
          <p className="text-xs text-gray-500 mt-2">{detectionRate}% of all requests</p>
        </div>

        <div className="bg-gradient-to-br from-yellow-500/10 to-yellow-500/5 border border-yellow-500/20 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm font-medium mb-2">Requests Blocked</h3>
          <p className="text-3xl font-bold text-yellow-400">{stats.requests_blocked}</p>
          <p className="text-xs text-gray-500 mt-2">{blockRate}% of all requests</p>
        </div>

        <div className="bg-gradient-to-br from-blue-500/10 to-blue-500/5 border border-blue-500/20 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm font-medium mb-2">Total Requests</h3>
          <p className="text-3xl font-bold text-blue-400">{stats.total_requests}</p>
          <p className="text-xs text-gray-500 mt-2">Last 24 hours</p>
        </div>

        <div className="bg-gradient-to-br from-green-500/10 to-green-500/5 border border-green-500/20 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm font-medium mb-2">Allowed Requests</h3>
          <p className="text-3xl font-bold text-green-400">{stats.total_requests - stats.threats_detected}</p>
          <p className="text-xs text-gray-500 mt-2">Clean traffic</p>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threats Over Time */}
        <div className="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Threats Timeline</h2>
            <select
              value={timelineFilter}
              onChange={(e) => setTimelineFilter(e.target.value as any)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="1h">Last 1 hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timelineData && timelineData.length > 0 ? timelineData : []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" stroke="#9ca3af" style={{ fontSize: '12px' }} />
              <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#f3f4f6' }}
              />
              <Legend />
              <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} dot={false} name="Threats Detected" />
              <Line type="monotone" dataKey="blocked" stroke="#f97316" strokeWidth={2} dot={false} name="Blocked" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Block Rate Pie Chart */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Block Rate</h2>
          {stats.total_requests > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Blocked', value: parseInt(blockRate) || 0 },
                      { name: 'Allowed', value: Math.max(0, 100 - (parseInt(blockRate) || 0)) }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    <Cell fill="#ef4444" />
                    <Cell fill="#22c55e" />
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                    labelStyle={{ color: '#f3f4f6' }}
                    formatter={(value) => `${value}%`}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="text-center mt-4">
                <p className="text-2xl font-bold text-red-400">{blockRate}%</p>
                <p className="text-sm text-gray-400">Blocked Rate</p>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-80 text-gray-400">
              <p>No requests yet</p>
            </div>
          )}
        </div>
      </div>

      {/* Threat Types & Recent Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Types Chart */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Threat Types Distribution</h2>
            <select
              value={threatDistFilter}
              onChange={(e) => setThreatDistFilter(e.target.value as any)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="1h">Last 1 hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </div>
          {threatTypeData && threatTypeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={threatTypeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#f3f4f6' }}
                />
                <Legend />
                <Bar dataKey="value" fill="#3b82f6" name="Total Detected" />
                <Bar dataKey="blocked" fill="#ef4444" name="Blocked" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-80 text-gray-400">
              <p>No threats detected yet</p>
            </div>
          )}
        </div>

        {/* Recent Threats Table */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Recent Threats</h2>
            <select
              value={recentThreatsFilter}
              onChange={(e) => setRecentThreatsFilter(e.target.value as any)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="1h">Last 1 hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </div>

          {filteredAlertsByRecentThreats.length > 0 ? (
            <>
              <div className="space-y-2">
                {filteredAlertsByRecentThreats
                  .slice((recentThreatsPage - 1) * itemsPerPage, recentThreatsPage * itemsPerPage)
                  .map((alert, idx) => (
                    <div key={idx} className="bg-gray-700/50 border border-gray-600 rounded p-3 hover:bg-gray-700 transition">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <p className="text-sm font-medium text-white">
                            {alert.threat}
                            {alert.blocked ? (
                              <span className="ml-2 px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">🚫 Blocked</span>
                            ) : (
                              <span className="ml-2 px-2 py-1 bg-yellow-500/20 text-yellow-300 rounded text-xs">⚠️ Detected</span>
                            )}
                          </p>
                          <p className="text-xs text-gray-400 mt-1">
                            {alert.method} {alert.path}
                          </p>
                          <p className="text-xs text-gray-500">
                            IP: {alert.ip} | {new Date(alert.timestamp).toLocaleTimeString('it-IT')}
                          </p>
                        </div>
                        {/* Mostra pulsante Block solo se la threat NON è bloccata */}
                        {!alert.blocked && (
                          <button
                            onClick={() => handleBlockIP(alert.ip)}
                            disabled={blockingIP === alert.ip}
                            className={`px-3 py-1 rounded text-xs font-medium transition ${
                              blockingIP === alert.ip
                                ? 'bg-blue-600 text-white'
                                : 'bg-red-600 hover:bg-red-700 text-white'
                            }`}
                          >
                            {blockingIP === alert.ip ? '...' : 'Block'}
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
              </div>

              {/* Pagination Controls */}
              <div className="mt-6 flex items-center justify-between">
                <p className="text-xs text-gray-500">
                  Showing {(recentThreatsPage - 1) * itemsPerPage + 1} to {Math.min(recentThreatsPage * itemsPerPage, filteredAlertsByRecentThreats.length)} of {filteredAlertsByRecentThreats.length} threats
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setRecentThreatsPage(prev => Math.max(1, prev - 1))}
                    disabled={recentThreatsPage === 1}
                    className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                  >
                    ← Previous
                  </button>
                  <div className="flex items-center gap-1">
                    {Array.from({ length: Math.ceil(filteredAlertsByRecentThreats.length / itemsPerPage) }, (_, i) => i + 1).map(page => (
                      <button
                        key={page}
                        onClick={() => setRecentThreatsPage(page)}
                        className={`px-3 py-1 rounded text-xs font-medium transition ${
                          recentThreatsPage === page
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                        }`}
                      >
                        {page}
                      </button>
                    ))}
                  </div>
                  <button
                    onClick={() => setRecentThreatsPage(prev => Math.min(Math.ceil(filteredAlertsByRecentThreats.length / itemsPerPage), prev + 1))}
                    disabled={recentThreatsPage === Math.ceil(filteredAlertsByRecentThreats.length / itemsPerPage)}
                    className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                  >
                    Next →
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-80 text-gray-400">
              <p>No recent threats detected</p>
            </div>
          )}
        </div>
      </div>

      {/* All Alerts Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-lg font-semibold text-white">All Alerts</h2>
          <div className="flex gap-4">
            <select
              value={alertsTimeFilter}
              onChange={(e) => setAlertsTimeFilter(e.target.value as any)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="1h">Last 1 hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>

            <select
              value={alertsThreatFilter}
              onChange={(e) => setAlertsThreatFilter(e.target.value)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Types</option>
              {allUniqueThreats.map(threat => (
                <option key={threat} value={threat}>{threat}</option>
              ))}
            </select>
          </div>
        </div>

        {filteredAlertsByAllAlerts.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">Timestamp</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">IP</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">Method</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">Path</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">Threat Type</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">Status</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlertsByAllAlerts
                    .slice((allAlertsPage - 1) * itemsPerPage, allAlertsPage * itemsPerPage)
                    .map((alert, idx) => (
                      <tr key={idx} className="border-b border-gray-700 hover:bg-gray-700/50 transition">
                        <td className="py-3 px-4 text-gray-300 text-xs">
                          {new Date(alert.timestamp).toLocaleString('it-IT')}
                        </td>
                        <td className="py-3 px-4 text-gray-300">{alert.ip}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-xs font-medium">
                            {alert.method}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-300 max-w-xs truncate" title={alert.path}>
                          {alert.path}
                        </td>
                        <td className="py-3 px-4 text-gray-300">{alert.threat}</td>
                        <td className="py-3 px-4">
                          {alert.blocked ? (
                            <span className="px-3 py-1 bg-red-500/20 text-red-300 rounded text-xs font-medium">🚫 Blocked</span>
                          ) : (
                            <span className="px-3 py-1 bg-yellow-500/20 text-yellow-300 rounded text-xs font-medium">⚠️ Detected</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {!alert.blocked && (
                            <button
                              onClick={() => handleBlockIP(alert.ip)}
                              disabled={blockingIP === alert.ip}
                              className={`px-2 py-1 rounded text-xs font-medium transition ${
                                blockingIP === alert.ip
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-red-600 hover:bg-red-700 text-white'
                              }`}
                            >
                              {blockingIP === alert.ip ? '...' : 'Block'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="mt-6 flex items-center justify-between">
              <p className="text-xs text-gray-500">
                Showing {(allAlertsPage - 1) * itemsPerPage + 1} to {Math.min(allAlertsPage * itemsPerPage, filteredAlertsByAllAlerts.length)} of {filteredAlertsByAllAlerts.length} alerts
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setAllAlertsPage(prev => Math.max(1, prev - 1))}
                  disabled={allAlertsPage === 1}
                  className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                >
                  ← Previous
                </button>
                <div className="flex items-center gap-1">
                  {Array.from({ length: Math.ceil(filteredAlertsByAllAlerts.length / itemsPerPage) }, (_, i) => i + 1).map(page => (
                    <button
                      key={page}
                      onClick={() => setAllAlertsPage(page)}
                      className={`px-3 py-1 rounded text-xs font-medium transition ${
                        allAlertsPage === page
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                      }`}
                    >
                      {page}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => setAllAlertsPage(prev => Math.min(Math.ceil(filteredAlertsByAllAlerts.length / itemsPerPage), prev + 1))}
                  disabled={allAlertsPage === Math.ceil(filteredAlertsByAllAlerts.length / itemsPerPage)}
                  className="px-3 py-1 rounded text-xs font-medium bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-300 transition"
                >
                  Next →
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex items-center justify-center h-80 text-gray-400">
            <p>No alerts found</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default StatsPage;
