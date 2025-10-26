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
  query: string;
  user_agent: string;
  timestamp: string;
  threat: string;
  blocked: boolean;
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
  const [timeFilter, setTimeFilter] = useState<'1h' | '24h' | '7d'>('1h');
  const [threatFilter, setThreatFilter] = useState<string>('all');
  const [filteredAlerts, setFilteredAlerts] = useState<WAFEvent[]>([]);

  // Carica i dati iniziali
  useEffect(() => {
    const loadInitialData = async () => {
      try {
        const data = await fetchStats();
        setRecentAlerts(data.recent || []);
        initializeTimeline();
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
        time: time.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }),
        threats: 0,
        blocked: 0,
      });
    }
    setTimelineData(points);
  };

  // Aggiorna timeline e threat types quando arrivano nuovi eventi
  useEffect(() => {
    setTimelineData((prevData) => {
      const newData = [...prevData];
      const now = new Date();
      const timeStr = now.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' });

      // Trova o crea punto per l'ora corrente
      let lastPoint = newData[newData.length - 1];
      if (lastPoint.time !== timeStr) {
        newData.shift(); // Rimuovi il più vecchio
        newData.push({
          time: timeStr,
          threats: lastPoint.threats,
          blocked: lastPoint.blocked,
        });
        lastPoint = newData[newData.length - 1];
      }

      // Incrementa i valori
      lastPoint.threats = stats.threats_detected;
      lastPoint.blocked = stats.requests_blocked;

      return newData;
    });

    // Aggiorna threat types
    const threatCounts = (recentAlerts || []).reduce((acc, alert) => {
      const existing = acc.find(t => t.name === alert.threat);
      if (existing) {
        existing.value++;
        existing.blocked += alert.blocked ? 1 : 0;
      } else {
        acc.push({
          name: alert.threat,
          value: 1,
          blocked: alert.blocked ? 1 : 0,
        });
      }
      return acc;
    }, [] as any[]);

    setThreatTypeData(threatCounts);
  }, [stats, recentAlerts]);

  // Applica filtri agli alert
  useEffect(() => {
    let filtered = [...recentAlerts];

    // Filtra per threat type
    if (threatFilter !== 'all') {
      filtered = filtered.filter(alert => alert.threat === threatFilter);
    }

    // Filtra per timeframe
    const now = new Date();
    const timeMs = timeFilter === '1h' ? 60 * 60 * 1000 : timeFilter === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    setFilteredAlerts(filtered.sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    ));
  }, [recentAlerts, timeFilter, threatFilter]);

  const blockRate = stats.total_requests > 0 ? (stats.requests_blocked / stats.total_requests * 100).toFixed(1) : '0';
  const detectionRate = stats.total_requests > 0 ? (stats.threats_detected / stats.total_requests * 100).toFixed(1) : '0';

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6'];

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
          <h2 className="text-lg font-semibold text-white mb-4">Threats Timeline</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timelineData}>
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
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={[
                  { name: 'Blocked', value: parseInt(blockRate) },
                  { name: 'Allowed', value: 100 - parseInt(blockRate) }
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
        </div>
      </div>

      {/* Threat Types Chart */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Threat Types Distribution</h2>
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
      </div>

      {/* Recent Alerts */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>
          <p className="text-sm text-gray-400">{filteredAlerts.length} alerts</p>
        </div>

        {/* Filters */}
        <div className="flex gap-4 mb-6 flex-wrap">
          <div>
            <label className="text-sm text-gray-400 block mb-2">Timeframe</label>
            <select
              value={timeFilter}
              onChange={(e) => setTimeFilter(e.target.value as any)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="1h">Last 1 hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </div>

          <div>
            <label className="text-sm text-gray-400 block mb-2">Threat Type</label>
            <select
              value={threatFilter}
              onChange={(e) => setThreatFilter(e.target.value)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Types</option>
              {Array.from(new Set(recentAlerts.map(a => a.threat))).map(threat => (
                <option key={threat} value={threat}>{threat}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Alerts Table */}
        {filteredAlerts.length > 0 ? (
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
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert, idx) => (
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
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-400">No alerts found</p>
            <p className="text-sm text-gray-500 mt-2">No security incidents detected in the selected timeframe</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default StatsPage;
