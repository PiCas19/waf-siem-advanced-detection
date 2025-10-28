import React, { useState, useEffect } from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import {
  AlertTriangle, Lock,
  ArrowUp, ArrowDown, Circle
} from 'lucide-react';
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

  // Type per i filtri di tempo
  type TimeFilter = 'today' | '15m' | '30m' | '1h' | '24h' | 'week' | '7d' | '30d' | '90d' | '1y';

  // Funzione utility per calcolare il timeMs da TimeFilter
  const getTimeMs = (filter: TimeFilter): number => {
    const now = new Date();
    switch (filter) {
      case 'today':
        return now.getTime() - new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
      case '15m':
        return 15 * 60 * 1000;
      case '30m':
        return 30 * 60 * 1000;
      case '1h':
        return 60 * 60 * 1000;
      case '24h':
        return 24 * 60 * 60 * 1000;
      case 'week':
        return 7 * 24 * 60 * 60 * 1000;
      case '7d':
        return 7 * 24 * 60 * 60 * 1000;
      case '30d':
        return 30 * 24 * 60 * 60 * 1000;
      case '90d':
        return 90 * 24 * 60 * 60 * 1000;
      case '1y':
        return 365 * 24 * 60 * 60 * 1000;
      default:
        return 24 * 60 * 60 * 1000;
    }
  };

  // Filtri INDIPENDENTI per ogni sezione
  const [timelineFilter, setTimelineFilter] = useState<TimeFilter>('1h');

  const [threatDistFilter, setThreatDistFilter] = useState<TimeFilter>('24h');

  const [alertsTimeFilter, setAlertsTimeFilter] = useState<TimeFilter>('24h');
  const [alertsThreatFilter, setAlertsThreatFilter] = useState<string>('all');

  // Filtri per i tre nuovi grafici
  const [maliciousIPsFilter, setMaliciousIPsFilter] = useState<TimeFilter>('24h');
  const [geolocationFilter, setGeolocationFilter] = useState<TimeFilter>('24h');
  const [threatLevelFilter, setThreatLevelFilter] = useState<TimeFilter>('24h');

  // Dati per i tre nuovi grafici
  const [maliciousIPsData, setMaliciousIPsData] = useState<any[]>([]);
  const [geolocationData, setGeolocationData] = useState<any[]>([]);
  const [threatLevelData, setThreatLevelData] = useState<any[]>([]);

  // Dati filtrati per ogni sezione
  const [filteredAlertsByAllAlerts, setFilteredAlertsByAllAlerts] = useState<WAFEvent[]>([]);

  // Pagination states
  const [allAlertsPage, setAllAlertsPage] = useState(1);
  const itemsPerPage = 10;

  // Sorting states (solo per All Alerts table)
  const [allAlertsSortColumn, setAllAlertsSortColumn] = useState<'timestamp' | 'ip' | 'method' | 'path' | 'threat'>('timestamp');
  const [allAlertsSortOrder, setAllAlertsSortOrder] = useState<'asc' | 'desc'>('desc');

  // Search states
  const [allAlertsSearchQuery, setAllAlertsSearchQuery] = useState<string>('');

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

  // Inizializza timeline con dati dai logs storici
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

  // Aggiorna timeline in base ai logs e ai nuovi events dal WebSocket
  useEffect(() => {
    if (recentAlerts.length === 0) {
      // Se non abbiamo logs, inizializza vuoto
      initializeTimeline();
      return;
    }

    const now = new Date();
    const timeMs = getTimeMs(timelineFilter);
    const points: ChartDataPoint[] = [];

    // Filtra gli alerts in base al timelineFilter
    const filteredAlerts = recentAlerts.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    if (filteredAlerts.length === 0) {
      // Se nessun dato nel periodo, mostra il periodo vuoto
      const periodInMinutes = Math.ceil(timeMs / 60000);
      for (let i = periodInMinutes; i >= 0; i--) {
        const startTime = new Date(now.getTime() - i * 60000);
        const timeStr = startTime.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) || '00:00';
        points.push({
          time: timeStr,
          threats: 0,
          blocked: 0,
        });
      }
      setTimelineData(points);
      return;
    }

    // Determina il numero di intervalli in base al timelineFilter
    let intervalMinutes = 1;
    if (timelineFilter === '24h' || timelineFilter === '7d') {
      intervalMinutes = 60; // Un punto per ora
    } else if (timelineFilter === '30d' || timelineFilter === '90d' || timelineFilter === '1y') {
      intervalMinutes = 24 * 60; // Un punto per giorno
    }

    // Calcola il numero di intervalli
    const periodInMinutes = Math.ceil(timeMs / 60000);
    const numIntervals = Math.ceil(periodInMinutes / intervalMinutes);

    // Crea i punti del grafico
    for (let i = numIntervals; i >= 0; i--) {
      const startTime = new Date(now.getTime() - i * intervalMinutes * 60000);
      const endTime = new Date(startTime.getTime() + intervalMinutes * 60000);

      const timeStr = intervalMinutes === 1
        ? startTime.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) || '00:00'
        : intervalMinutes === 60
        ? startTime.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) || '00:00'
        : startTime.toLocaleDateString('it-IT', { month: 'short', day: 'numeric' }) || 'Data';

      // Conta i logs in questo intervallo
      const threatsInInterval = filteredAlerts.filter(alert => {
        const alertTime = new Date(alert.timestamp).getTime();
        return alertTime >= startTime.getTime() && alertTime < endTime.getTime();
      }).length;

      const blockedInInterval = filteredAlerts.filter(alert => {
        const alertTime = new Date(alert.timestamp).getTime();
        return alertTime >= startTime.getTime() && alertTime < endTime.getTime() && alert.blocked;
      }).length;

      points.push({
        time: timeStr,
        threats: threatsInInterval,
        blocked: blockedInInterval,
      });
    }

    setTimelineData(points);
  }, [recentAlerts, timelineFilter]);

  // Calcola threat types solo per Threat Distribution (con suo filtro)
  useEffect(() => {
    let filtered = [...recentAlerts];

    const now = new Date();
    const timeMs = getTimeMs(threatDistFilter);
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

  // Calcola Top 10 Malicious IPs
  useEffect(() => {
    let filtered = [...recentAlerts];

    const now = new Date();
    const timeMs = getTimeMs(maliciousIPsFilter);
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    // Conta occorrenze per IP
    const ipCounts = filtered.reduce((acc: any[], alert) => {
      if (!alert || !alert.ip) return acc;
      const existing = acc.find(ip => ip && ip.name === alert.ip);
      if (existing) {
        existing.value = (existing.value || 0) + 1;
        existing.blocked = (existing.blocked || 0) + (alert.blocked ? 1 : 0);
      } else {
        acc.push({
          name: alert.ip || 'Unknown',
          value: 1,
          blocked: alert.blocked ? 1 : 0,
        });
      }
      return acc;
    }, []);

    // Ordina e prendi top 10
    const top10 = ipCounts
      .sort((a, b) => (b.value || 0) - (a.value || 0))
      .slice(0, 10);

    setMaliciousIPsData(top10 && top10.length > 0 ? top10 : []);
  }, [recentAlerts, maliciousIPsFilter]);

  // Funzione per mappare IP a paese (basato su IP ranges comuni)
  const getCountryFromIP = (ip: string): string => {
    if (!ip) return 'Unknown';

    // Parsing dell'IP
    const parts = ip.split('.').map(p => parseInt(p, 10));
    if (parts.length !== 4 || parts.some(p => isNaN(p))) return 'Unknown';

    const [octet1] = parts;

    // Mappatura semplice dei range IP a paesi
    // Questi sono range reali ma semplificati per demo
    if (octet1 >= 1 && octet1 <= 11) return 'United States';
    if (octet1 >= 12 && octet1 <= 21) return 'China';
    if (octet1 >= 22 && octet1 <= 29) return 'Russia';
    if (octet1 >= 30 && octet1 <= 47) return 'India';
    if (octet1 >= 48 && octet1 <= 63) return 'Brazil';
    if (octet1 >= 64 && octet1 <= 127) return 'Europe';
    if (octet1 >= 128 && octet1 <= 191) return 'Asia-Pacific';
    if (octet1 >= 192 && octet1 <= 223) return 'North America';

    return 'Unknown';
  };

  // Calcola Geolocation Data (paese di provenienza)
  useEffect(() => {
    let filtered = [...recentAlerts];

    const now = new Date();
    const timeMs = getTimeMs(geolocationFilter);
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    // Raggruppa per paese usando la funzione getCountryFromIP
    const countryCounts: { [key: string]: number } = {};
    filtered.forEach(alert => {
      const country = getCountryFromIP(alert.ip);
      countryCounts[country] = (countryCounts[country] || 0) + 1;
    });

    // Converti in array e ordina per count decrescente
    const geoData = Object.entries(countryCounts)
      .map(([country, value]) => ({
        country,
        value
      }))
      .sort((a, b) => (b.value || 0) - (a.value || 0));

    setGeolocationData(geoData && geoData.length > 0 ? geoData : []);
  }, [recentAlerts, geolocationFilter]);

  // Calcola Threat Level Distribution
  useEffect(() => {
    let filtered = [...recentAlerts];

    const now = new Date();
    const timeMs = getTimeMs(threatLevelFilter);
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    // Mappiamo threat types a severity levels
    const threatSeverityMap: { [key: string]: string } = {
      'XSS': 'HIGH',
      'SQL Injection': 'CRITICAL',
      'CSRF': 'MEDIUM',
      'XXE': 'HIGH',
      'Path Traversal': 'HIGH',
      'Command Injection': 'CRITICAL',
      'Directory Listing': 'MEDIUM',
      'Malicious Pattern': 'HIGH',
      'Brute Force': 'HIGH',
      'Bot Detection': 'MEDIUM',
      'Unauthorized Access': 'HIGH',
      'Suspicious Activity': 'LOW'
    };

    // Conta per severity level
    const severityCounts: { [key: string]: number } = {
      'CRITICAL': 0,
      'HIGH': 0,
      'MEDIUM': 0,
      'LOW': 0,
    };

    filtered.forEach(alert => {
      const severity = threatSeverityMap[alert.threat] || 'LOW';
      severityCounts[severity]++;
    });

    const threatLevelDistribution = [
      { name: 'Critical', value: severityCounts['CRITICAL'] },
      { name: 'High', value: severityCounts['HIGH'] },
      { name: 'Medium', value: severityCounts['MEDIUM'] },
      { name: 'Low', value: severityCounts['LOW'] },
    ].filter(item => item.value > 0);

    setThreatLevelData(threatLevelDistribution && threatLevelDistribution.length > 0 ? threatLevelDistribution : []);
  }, [recentAlerts, threatLevelFilter]);

  // Funzione per eseguire la ricerca elastica su All Alerts
  const searchAllAlerts = (alerts: WAFEvent[], query: string): WAFEvent[] => {
    if (!query.trim()) return alerts;
    const lowerQuery = query.toLowerCase();
    return alerts.filter(alert => {
      return (
        alert.ip?.toLowerCase().includes(lowerQuery) ||
        alert.threat?.toLowerCase().includes(lowerQuery) ||
        alert.method?.toLowerCase().includes(lowerQuery) ||
        alert.path?.toLowerCase().includes(lowerQuery) ||
        new Date(alert.timestamp).toLocaleString('it-IT').toLowerCase().includes(lowerQuery)
      );
    });
  };

  // Funzione per ordinare All Alerts
  const sortAllAlerts = (alerts: WAFEvent[]): WAFEvent[] => {
    return [...alerts].sort((a, b) => {
      let aVal: any, bVal: any;

      if (allAlertsSortColumn === 'threat') {
        aVal = a.threat;
        bVal = b.threat;
      } else if (allAlertsSortColumn === 'ip') {
        aVal = a.ip;
        bVal = b.ip;
      } else if (allAlertsSortColumn === 'method') {
        aVal = a.method;
        bVal = b.method;
      } else if (allAlertsSortColumn === 'path') {
        aVal = a.path;
        bVal = b.path;
      } else {
        aVal = new Date(a.timestamp).getTime();
        bVal = new Date(b.timestamp).getTime();
      }

      if (allAlertsSortOrder === 'asc') {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });
  };

  // Filtra per All Alerts Table (timeframe + threat type + ricerca + ordinamento)
  useEffect(() => {
    let filtered = [...recentAlerts];

    if (alertsThreatFilter !== 'all') {
      filtered = filtered.filter(alert => alert.threat === alertsThreatFilter);
    }

    const now = new Date();
    const timeMs = getTimeMs(alertsTimeFilter);
    filtered = filtered.filter(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      return now.getTime() - alertTime < timeMs;
    });

    // Applica ricerca
    filtered = searchAllAlerts(filtered, allAlertsSearchQuery);

    // Applica ordinamento
    filtered = sortAllAlerts(filtered);

    setAllAlertsPage(1); // Reset pagination
    setFilteredAlertsByAllAlerts(filtered);
  }, [recentAlerts, alertsTimeFilter, alertsThreatFilter, allAlertsSearchQuery, allAlertsSortColumn, allAlertsSortOrder]);

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
        <div className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium ${isConnected ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
          <Circle size={8} className={isConnected ? 'fill-green-400' : 'fill-red-400'} />
          {isConnected ? 'Connected' : 'Disconnected'}
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
          <p className="text-3xl font-bold text-green-400">{stats.total_requests - stats.requests_blocked}</p>
          <p className="text-xs text-gray-500 mt-2">Requests passed through</p>
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
              onChange={(e) => setTimelineFilter(e.target.value as TimeFilter)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="15m">Last 15 minutes</option>
              <option value="30m">Last 30 minutes</option>
              <option value="1h">Last 1 hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
              <option value="1y">Last 1 year</option>
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
              onChange={(e) => setThreatDistFilter(e.target.value as TimeFilter)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
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

      </div>

      {/* Three New Charts: Top IPs, Geolocation, Threat Levels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top 10 Malicious IPs - 2 columns */}
        <div className="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Top 10 Malicious IPs</h2>
            <select
              value={maliciousIPsFilter}
              onChange={(e) => setMaliciousIPsFilter(e.target.value as TimeFilter)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
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
            </select>
          </div>
          {maliciousIPsData && maliciousIPsData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={maliciousIPsData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" stroke="#9ca3af" style={{ fontSize: '12px' }} />
                <YAxis dataKey="name" type="category" stroke="#9ca3af" style={{ fontSize: '11px' }} width={100} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#f3f4f6' }}
                />
                <Legend />
                <Bar dataKey="value" fill="#ef4444" name="Total Attacks" />
                <Bar dataKey="blocked" fill="#22c55e" name="Blocked" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-80 text-gray-400">
              <p>No IP data available</p>
            </div>
          )}
        </div>

        {/* Threat Types Distribution - right side, 1 column */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Threat Types Distribution</h2>
            <select
              value={threatDistFilter}
              onChange={(e) => setThreatDistFilter(e.target.value as TimeFilter)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
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

        {/* Geolocation Heatmap - left side, 2 columns */}
        <div className="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Geolocation Heatmap</h2>
            <select
              value={geolocationFilter}
              onChange={(e) => setGeolocationFilter(e.target.value as TimeFilter)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
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
            </select>
          </div>
          {geolocationData && geolocationData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={geolocationData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="country" stroke="#9ca3af" style={{ fontSize: '12px' }} angle={-45} textAnchor="end" height={100} />
                <YAxis stroke="#9ca3af" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#f3f4f6' }}
                />
                <Legend />
                <Bar dataKey="value" fill="#f97316" name="Attack Count" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-80 text-gray-400">
              <p>No geolocation data available</p>
            </div>
          )}
        </div>

        {/* Threat Level Distribution - right side, 1 column */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Threat Level Distribution</h2>
            <select
              value={threatLevelFilter}
              onChange={(e) => setThreatLevelFilter(e.target.value as TimeFilter)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
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
            </select>
          </div>
          {threatLevelData && threatLevelData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={threatLevelData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={(entry) => entry.name}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  <Cell fill="#dc2626" />
                  <Cell fill="#f97316" />
                  <Cell fill="#eab308" />
                  <Cell fill="#3b82f6" />
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#f3f4f6' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-80 text-gray-400">
              <p>No threat level data available</p>
            </div>
          )}
        </div>
      </div>

      {/* Threat Detection Log */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Threat Detection Log</h2>
            <div className="flex gap-4">
              <select
                value={alertsTimeFilter}
                onChange={(e) => setAlertsTimeFilter(e.target.value as TimeFilter)}
                className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
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

          {/* Search Bar for All Alerts */}
          <div>
            <input
              type="text"
              placeholder="Search alerts by timestamp, IP, method, path, threat type..."
              value={allAlertsSearchQuery}
              onChange={(e) => setAllAlertsSearchQuery(e.target.value)}
              className="w-full bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </div>
        </div>

        {filteredAlertsByAllAlerts.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-collapse">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th
                      onClick={() => {
                        if (allAlertsSortColumn === 'timestamp') {
                          setAllAlertsSortOrder(allAlertsSortOrder === 'asc' ? 'desc' : 'asc');
                        } else {
                          setAllAlertsSortColumn('timestamp');
                          setAllAlertsSortOrder('desc');
                        }
                      }}
                      className="text-left py-3 px-4 text-gray-400 font-medium cursor-pointer hover:text-gray-300 transition w-32"
                    >
                      <div className="flex items-center gap-2">
                        Timestamp
                        {allAlertsSortColumn === 'timestamp' && (
                          allAlertsSortOrder === 'asc' ? (
                            <ArrowUp size={14} />
                          ) : (
                            <ArrowDown size={14} />
                          )
                        )}
                      </div>
                    </th>
                    <th
                      onClick={() => {
                        if (allAlertsSortColumn === 'ip') {
                          setAllAlertsSortOrder(allAlertsSortOrder === 'asc' ? 'desc' : 'asc');
                        } else {
                          setAllAlertsSortColumn('ip');
                          setAllAlertsSortOrder('asc');
                        }
                      }}
                      className="text-left py-3 px-4 text-gray-400 font-medium cursor-pointer hover:text-gray-300 transition w-28"
                    >
                      <div className="flex items-center gap-2">
                        IP
                        {allAlertsSortColumn === 'ip' && (
                          allAlertsSortOrder === 'asc' ? (
                            <ArrowUp size={14} />
                          ) : (
                            <ArrowDown size={14} />
                          )
                        )}
                      </div>
                    </th>
                    <th
                      onClick={() => {
                        if (allAlertsSortColumn === 'method') {
                          setAllAlertsSortOrder(allAlertsSortOrder === 'asc' ? 'desc' : 'asc');
                        } else {
                          setAllAlertsSortColumn('method');
                          setAllAlertsSortOrder('asc');
                        }
                      }}
                      className="text-left py-3 px-4 text-gray-400 font-medium cursor-pointer hover:text-gray-300 transition w-20"
                    >
                      <div className="flex items-center gap-2">
                        Method
                        {allAlertsSortColumn === 'method' && (
                          allAlertsSortOrder === 'asc' ? (
                            <ArrowUp size={14} />
                          ) : (
                            <ArrowDown size={14} />
                          )
                        )}
                      </div>
                    </th>
                    <th
                      onClick={() => {
                        if (allAlertsSortColumn === 'path') {
                          setAllAlertsSortOrder(allAlertsSortOrder === 'asc' ? 'desc' : 'asc');
                        } else {
                          setAllAlertsSortColumn('path');
                          setAllAlertsSortOrder('asc');
                        }
                      }}
                      className="text-left py-3 px-4 text-gray-400 font-medium cursor-pointer hover:text-gray-300 transition flex-1"
                    >
                      <div className="flex items-center gap-2">
                        Path
                        {allAlertsSortColumn === 'path' && (
                          allAlertsSortOrder === 'asc' ? (
                            <ArrowUp size={14} />
                          ) : (
                            <ArrowDown size={14} />
                          )
                        )}
                      </div>
                    </th>
                    <th
                      onClick={() => {
                        if (allAlertsSortColumn === 'threat') {
                          setAllAlertsSortOrder(allAlertsSortOrder === 'asc' ? 'desc' : 'asc');
                        } else {
                          setAllAlertsSortColumn('threat');
                          setAllAlertsSortOrder('asc');
                        }
                      }}
                      className="text-left py-3 px-4 text-gray-400 font-medium cursor-pointer hover:text-gray-300 transition w-28"
                    >
                      <div className="flex items-center gap-2">
                        Threat Type
                        {allAlertsSortColumn === 'threat' && (
                          allAlertsSortOrder === 'asc' ? (
                            <ArrowUp size={14} />
                          ) : (
                            <ArrowDown size={14} />
                          )
                        )}
                      </div>
                    </th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium w-20">Status</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-medium w-20">Action</th>
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
                            <span className="px-3 py-1 bg-red-500/20 text-red-300 rounded text-xs font-medium inline-flex items-center gap-1">
                              <Lock size={12} />
                              Blocked
                            </span>
                          ) : (
                            <span className="px-3 py-1 bg-yellow-500/20 text-yellow-300 rounded text-xs font-medium inline-flex items-center gap-1">
                              <AlertTriangle size={12} />
                              Detected
                            </span>
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
