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
import WorldMapSVG from '@/components/stats/WorldMap';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/SnackbarContext';
import { hasPermission } from '@/types/rbac';

interface WAFEvent {
  ip: string;
  method: string;
  path: string;
  query?: string;
  user_agent?: string;
  timestamp: string;
  threat: string;
  blocked: boolean;
  blockedBy?: string; // "auto" = automatically blocked by rule, "manual" = manually blocked by operator, "" = not blocked
  description?: string; // Rule name/description for per-rule blocking
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

// Custom Tooltip for Timeline - shows colors based on blocked status
const TimelineTooltip: React.FC<any> = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-gray-900 border border-gray-600 rounded-lg p-3">
        <p className="text-gray-300 text-sm">{payload[0]?.payload?.time}</p>
        {payload.map((entry: any, index: number) => (
          <p key={index} style={{ color: entry.color }} className="text-sm font-medium">
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  }
};

// Custom Tooltip for Pie Charts (Block Rate, Threat Level)
const PieChartTooltip: React.FC<any> = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    let tooltipColor = '#f3f4f6'; // default light gray

    // Assign colors based on the data name
    if (data.payload.name === 'Blocked' || data.payload.name === 'Critical') {
      tooltipColor = '#ef4444'; // red
    } else if (data.payload.name === 'High') {
      tooltipColor = '#f97316'; // orange
    } else if (data.payload.name === 'Allowed' || data.payload.name === 'Medium') {
      tooltipColor = '#eab308'; // yellow
    } else if (data.payload.name === 'Low') {
      tooltipColor = '#3b82f6'; // blue
    }

    // Calcola percentuale dal valore vero
    const actualValue = data.payload.value || 0;

    // Per Threat Level Distribution, usa globalTotal per percentuale corretta
    // Per Block Rate, usa data.value (percentuale di Recharts)
    let percentage = data.value || 0;
    if (data.payload.globalTotal) {
      // È un dato Threat Level, calcola percentuale su totale globale
      percentage = (actualValue / data.payload.globalTotal) * 100;
    }

    return (
      <div className="bg-gray-900 border border-gray-600 rounded-lg p-3">
        <p style={{ color: tooltipColor }} className="text-sm font-medium">
          {data.payload.name}: {actualValue} ({percentage.toFixed(1)}%)
        </p>
      </div>
    );
  }
  return null;
};

// TODO: Custom Tooltip for Bar Charts - shows colors based on blocked/allowed
// Will be used for Threat Types, Malicious IPs, and Geolocation charts
// const BarChartTooltip: React.FC<any> = ({ active, payload }) => {
//   if (active && payload && payload.length) {
//     return (
//       <div className="bg-gray-900 border border-gray-600 rounded-lg p-3">
//         <p className="text-gray-300 text-sm font-semibold">{payload[0]?.payload?.name || payload[0]?.name}</p>
//         {payload.map((entry: any, index: number) => {
//           const isBlocked = entry.name === 'Blocked' || entry.dataKey === 'blocked';
//           const color = isBlocked ? '#ef4444' : '#22c55e';
//           return (
//             <p key={index} style={{ color }} className="text-sm font-medium">
//               {entry.name}: {entry.value}
//             </p>
//           );
//         })}
//       </div>
//     );
//   }
//   return null;
// };

// Country coordinates for map visualization
const countryCoordinates: { [key: string]: [number, number] } = {
  'United States': [37.0902, -95.7129],
  'China': [35.8617, 104.1954],
  'Russia': [61.5240, 105.3188],
  'India': [20.5937, 78.9629],
  'Brazil': [-14.2350, -51.9253],
  'Japan': [36.2048, 138.2529],
  'Germany': [51.1657, 10.4515],
  'United Kingdom': [55.3781, -3.4360],
  'France': [46.2276, 2.2137],
  'Italy': [41.8719, 12.5674],
  'Australia': [-25.2744, 133.7751],
  'Canada': [56.1304, -106.3468],
  'South Korea': [35.9078, 127.7669],
  'Mexico': [23.6345, -102.5528],
  'Spain': [40.4637, -3.7492],
  'Netherlands': [52.1326, 5.2913],
  'Saudi Arabia': [23.8859, 45.0792],
  'Turkey': [38.9637, 35.2433],
  'Switzerland': [46.8182, 8.2275],
  'Sweden': [60.1282, 18.6435],
  'Poland': [51.9194, 19.1451],
  'Belgium': [50.5039, 4.4699],
  'Thailand': [15.8700, 100.9925],
  'Indonesia': [-0.7893, 113.9213],
  'Malaysia': [4.2105, 101.6964],
  'Singapore': [1.3521, 103.8198],
  'Hong Kong': [22.3193, 114.1694],
  'Taiwan': [23.6978, 120.9605],
  'Vietnam': [14.0583, 108.2772],
  'Philippines': [12.8797, 121.7740],
  'Pakistan': [30.3753, 69.3451],
  'Bangladesh': [23.6850, 90.3563],
  'Egypt': [26.8206, 30.8025],
  'Nigeria': [9.0820, 8.6753],
  'South Africa': [-30.5595, 22.9375],
  'Kenya': [-0.0236, 37.9062],
  'Ukraine': [48.3794, 31.1656],
  'Argentina': [-38.4161, -63.6167],
  'Chile': [-35.6751, -71.5430],
  'Colombia': [4.5709, -74.2973],
  'Peru': [-9.1900, -75.0152],
  'Venezuela': [6.4238, -66.5897],
  'Greece': [39.0742, 21.8243],
  'Portugal': [39.3999, -8.2245],
  'Austria': [47.5162, 14.5501],
  'Czech Republic': [49.8175, 15.4730],
  'Hungary': [47.1625, 19.5033],
  'Romania': [45.9432, 24.9668],
  'Serbia': [44.0165, 21.0059],
  'Croatia': [45.1000, 15.2000],
  'Finland': [61.9241, 25.7482],
  'Norway': [60.4720, 8.4689],
  'Denmark': [56.2639, 9.5018],
  'Ireland': [53.4129, -8.2439],
  'Israel': [31.0461, 34.8516],
  'UAE': [23.4241, 53.8478],
  'Qatar': [25.2548, 51.6224],
  'Kuwait': [29.3117, 47.4818],
  'Bahrain': [26.0667, 50.5577],
  'Oman': [21.4735, 55.9754],
  'Morocco': [31.7917, -7.0926],
  'Algeria': [28.0339, 1.6596],
  'Tunisia': [33.8869, 9.5375],
  'Libya': [26.3351, 17.2283],
  'Sudan': [12.8628, 30.8025],
  'Ethiopia': [9.1450, 40.4897],
  'Uganda': [1.3733, 32.2903],
  'Tanzania': [-6.3690, 34.8888],
  'Zimbabwe': [-19.0154, 29.1549],
  'Botswana': [-22.3285, 24.6849],
  'Namibia': [-22.9375, 18.6947],
  'Lesotho': [-29.6100, 28.2336],
  'Mauritius': [-20.3484, 57.5522],
  'New Zealand': [-40.9006, 174.8860],
  'Papua New Guinea': [-6.3150, 143.9555],
  'Malaysia (Peninsular)': [4.2105, 101.6964],
  'Unknown': [20.0, 0.0]
};

// Get severity color for map markers
const getSeverityColor = (count: number): string => {
  if (count >= 50) return '#dc2626'; // Red for critical
  if (count >= 20) return '#f97316'; // Orange for high
  if (count >= 10) return '#eab308'; // Yellow for medium
  return '#3b82f6'; // Blue for low
};

interface BlockDurationOption {
  label: string;
  value: number | 'permanent'; // minutes or 'permanent'
}

const BLOCK_DURATION_OPTIONS: BlockDurationOption[] = [
  { label: '24 Hours', value: 24 * 60 },
  { label: '7 Days', value: 7 * 24 * 60 },
  { label: '30 Days', value: 30 * 24 * 60 },
  { label: 'Permanent', value: 'permanent' },
];

const StatsPage: React.FC = () => {
  const { stats, isConnected, onAlertReceived } = useWebSocketStats();
  const { user } = useAuth();
  const { showToast } = useToast();
  const [timelineData, setTimelineData] = useState<ChartDataPoint[]>([]);
  const [threatTypeData, setThreatTypeData] = useState<any[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<WAFEvent[]>([]);
  const [processingKey, setProcessingKey] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0); // Trigger per refresh stats

  // Block duration modal state
  const [blockModalOpen, setBlockModalOpen] = useState(false);
  const [pendingBlockIP, setPendingBlockIP] = useState<string | null>(null);
  const [pendingBlockDescription, setPendingBlockDescription] = useState<string | null>(null);
  const [selectedDuration, setSelectedDuration] = useState<number | 'permanent'>(24 * 60);
  const [customDuration, setCustomDuration] = useState<number>(24);
  const [customDurationUnit, setCustomDurationUnit] = useState<'hours' | 'days'>('hours');

  // Calcola i permessi dell'utente
  const canBlockThreats = user && hasPermission(user.role as any, 'threats_block');
  const canUnblockThreats = user && hasPermission(user.role as any, 'threats_unblock');

  // Registra callback per aggiornamenti real-time degli alert
  useEffect(() => {
    const unsubscribe = onAlertReceived((alert: WAFEvent) => {
      setRecentAlerts(prevAlerts => [alert, ...prevAlerts.slice(0, 999)]);
    });

    return unsubscribe;
  }, [onAlertReceived]);

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
  const [geolocationCountryFilter, setGeolocationCountryFilter] = useState<string>('all');
  const [threatLevelFilter, setThreatLevelFilter] = useState<TimeFilter>('24h');
  const [threatLevelSeverityFilter, setThreatLevelSeverityFilter] = useState<string>('all');

  // Dati per i tre nuovi grafici
  const [maliciousIPsData, setMaliciousIPsData] = useState<any[]>([]);
  const [geolocationData, setGeolocationData] = useState<any[]>([]);
  const [geolocationMapData, setGeolocationMapData] = useState<any[]>([]);
  const [availableCountries, setAvailableCountries] = useState<string[]>([]);
  const [threatLevelData, setThreatLevelData] = useState<any[]>([]);
  const [availableSeverities, setAvailableSeverities] = useState<string[]>([]);

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

  // Carica i dati iniziali e quando refreshTrigger cambia
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
            blockedBy: log.blocked_by || '', // "auto", "manual", or ""
            user_agent: log.user_agent,
            description: log.description || log.threat_type,
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
  }, [refreshTrigger]); // Ricarica quando refreshTrigger cambia

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

  // Calcola Geolocation Data (paese di provenienza) usando API backend
  useEffect(() => {
    const fetchGeolocation = async () => {
      try {
        const token = localStorage.getItem('authToken');
        const response = await fetch('/api/geolocation', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const data = await response.json();

          // Filtra per il timeframe selezionato
          const now = new Date();
          const timeMs = getTimeMs(geolocationFilter);

          // Filtra gli alert nel timeframe
          const filteredAlerts = recentAlerts.filter(alert => {
            const alertTime = new Date(alert.timestamp).getTime();
            return now.getTime() - alertTime < timeMs;
          });

          // Riconta per paese basato sui dati del backend
          const countryCounts: { [key: string]: number } = {};
          filteredAlerts.forEach(() => {
            // Trova il paese per questo IP dal backend
            const geoItem = (data.data || []).find((item: any) => item.country);
            if (geoItem) {
              countryCounts[geoItem.country] = (countryCounts[geoItem.country] || 0) + 1;
            }
          });

          // Se non abbiamo dati filtrati, usa direttamente i dati del backend
          let filtered = data.data || [];
          if (Object.keys(countryCounts).length > 0) {
            filtered = Object.entries(countryCounts)
              .map(([country, count]) => ({
                country,
                count
              }))
              .sort((a, b) => (b.count || 0) - (a.count || 0));
          }

          // Estrai i paesi disponibili per il dropdown filter
          const countries = filtered.map((item: any) => item.country).filter((c: any) => c);
          setAvailableCountries(countries);

          // Filtra in base al country selezionato
          let geoData = (filtered as any[]).map(item => ({
            country: item.country,
            value: item.count
          }));

          if (geolocationCountryFilter !== 'all') {
            geoData = geoData.filter(item => item.country === geolocationCountryFilter);
          }

          setGeolocationData(geoData && geoData.length > 0 ? geoData : []);
        }
      } catch (error) {
        console.error('Error fetching geolocation data:', error);
        setGeolocationData([]);
      }
    };

    fetchGeolocation();
  }, [recentAlerts, geolocationFilter, geolocationCountryFilter, setAvailableCountries]);

  // Prepara i dati per la mappa Leaflet
  useEffect(() => {
    if (geolocationData.length > 0) {
      const mapMarkers = geolocationData.map(item => {
        const coords = countryCoordinates[item.country] || countryCoordinates['Unknown'];
        return {
          country: item.country,
          count: item.value,
          lat: coords[0],
          lng: coords[1],
          color: getSeverityColor(item.value)
        };
      });
      setGeolocationMapData(mapMarkers);
    } else {
      setGeolocationMapData([]);
    }
  }, [geolocationData]);

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

    // Estrai i severity disponibili per il dropdown filter
    const availableSevs = Object.entries(severityCounts)
      .filter(([_, count]) => count > 0)
      .map(([severity, _]) => severity);
    setAvailableSeverities(availableSevs);

    // Calcola il totale globale di tutti gli attacchi (per il calcolo percentuale corretto nel tooltip)
    const globalTotal = Object.values(severityCounts).reduce((sum, count) => sum + count, 0);

    let threatLevelDistribution = [
      { name: 'Critical', value: severityCounts['CRITICAL'], severity: 'CRITICAL', globalTotal },
      { name: 'High', value: severityCounts['HIGH'], severity: 'HIGH', globalTotal },
      { name: 'Medium', value: severityCounts['MEDIUM'], severity: 'MEDIUM', globalTotal },
      { name: 'Low', value: severityCounts['LOW'], severity: 'LOW', globalTotal },
    ].filter(item => item.value > 0);

    // Filtra in base al severity selezionato
    if (threatLevelSeverityFilter !== 'all') {
      threatLevelDistribution = threatLevelDistribution.filter(item => item.severity === threatLevelSeverityFilter);
    }

    setThreatLevelData(threatLevelDistribution && threatLevelDistribution.length > 0 ? threatLevelDistribution : []);
  }, [recentAlerts, threatLevelFilter, threatLevelSeverityFilter, setAvailableSeverities]);

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

  // Util: chiave composta per azioni su alert specifico/gruppo
  const getAlertKey = (ip?: string, description?: string) => `${ip || ''}::${description || ''}`;

  // Util: controlla se una threat è di tipo default (sempre bloccata automaticamente)
  const isDefaultThreat = (threatType: string): boolean => {
    const defaultThreats = [
      'XSS',
      'SQL_INJECTION',
      'LFI',
      'RFI',
      'COMMAND_INJECTION',
      'XXE',
      'LDAP_INJECTION',
      'SSTI',
      'HTTP_RESPONSE_SPLITTING',
      'PROTOTYPE_POLLUTION',
      'PATH_TRAVERSAL',
      'SSRF',
      'NOSQL_INJECTION',
    ];
    return defaultThreats.includes(threatType);
  };

  // Apri modal per selezionare duration del blocco
  const handleBlockThreat = (ip: string, description: string) => {
    setPendingBlockIP(ip);
    setPendingBlockDescription(description);
    setSelectedDuration(24 * 60); // Default 24 hours
    setBlockModalOpen(true);
  };

  // Conferma blocco con duration selezionato
  const confirmBlockThreat = async () => {
    if (!pendingBlockIP || !pendingBlockDescription) return;

    const key = getAlertKey(pendingBlockIP, pendingBlockDescription);
    setProcessingKey(key);

    // Calcola la duration in ore
    let durationHours = 24;
    if (selectedDuration === 'permanent') {
      durationHours = -1; // -1 per indicare permanente
    } else if (selectedDuration === 'custom') {
      durationHours = customDurationUnit === 'hours' ? customDuration : customDuration * 24;
    } else {
      durationHours = (selectedDuration as number) / 60; // Converti da minuti a ore
    }

    // Optimistic update: marca come blocked
    setRecentAlerts(prev => prev.map(a => (a.ip === pendingBlockIP && (a.description || a.threat) === pendingBlockDescription ? { ...a, blocked: true, blockedBy: 'manual' } : a)));

    try {
      const token = localStorage.getItem('authToken');
      const resp = await fetch('/api/blocklist', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip: pendingBlockIP,
          threat: pendingBlockDescription,
          reason: `Blocked threat: ${pendingBlockDescription}`,
          permanent: selectedDuration === 'permanent',
          durationHours: durationHours,
        }),
      });

      if (!resp.ok) {
        // rollback
        setRecentAlerts(prev => prev.map(a => (a.ip === pendingBlockIP && (a.description || a.threat) === pendingBlockDescription ? { ...a, blocked: false, blockedBy: '' } : a)));
        showToast('Error blocking threat', 'error');
      } else {
        showToast('Threat blocked successfully', 'success');
        // Trigger refresh degli stats dopo il blocco
        setRefreshTrigger(prev => prev + 1);
      }
    } catch (e) {
      // rollback
      setRecentAlerts(prev => prev.map(a => (a.ip === pendingBlockIP && (a.description || a.threat) === pendingBlockDescription ? { ...a, blocked: false, blockedBy: '' } : a)));
      showToast('Network error blocking threat', 'error');
    } finally {
      setProcessingKey(null);
      setBlockModalOpen(false);
      setPendingBlockIP(null);
      setPendingBlockDescription(null);
    }
  };

  // Sblocca tutte le threat dello stesso IP + descrizione regola dell'alert selezionato
  const handleUnblockThreat = async (ip: string, description: string) => {
    const key = getAlertKey(ip, description);
    setProcessingKey(key);

    // Optimistic update: marca come unblocked tutti gli alert con stesso ip+description
    setRecentAlerts(prev => prev.map(a => (a.ip === ip && (a.description || a.threat) === description ? { ...a, blocked: false, blockedBy: '' } : a)));

    try {
      const token = localStorage.getItem('authToken');
      const resp = await fetch(`/api/blocklist/${ip}?threat=${encodeURIComponent(description)}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!resp.ok) {
        // rollback
        setRecentAlerts(prev => prev.map(a => (a.ip === ip && (a.description || a.threat) === description ? { ...a, blocked: true, blockedBy: 'manual' } : a)));
        showToast('Error unblocking threat', 'error');
      } else {
        showToast('Threat unblocked successfully', 'success');
        // Trigger refresh degli stats dopo lo sblocco
        setRefreshTrigger(prev => prev + 1);
      }
    } catch (e) {
      // rollback
      setRecentAlerts(prev => prev.map(a => (a.ip === ip && (a.description || a.threat) === description ? { ...a, blocked: true, blockedBy: 'manual' } : a)));
      showToast('Network error unblocking threat', 'error');
    } finally {
      setProcessingKey(null);
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
              <Tooltip content={<TimelineTooltip />} />
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
                  <Tooltip content={<PieChartTooltip />} />
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

      {/* Row 2 & 3: Threat Types Distribution, Top IPs, Geolocation, Threat Levels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Types Distribution - left side, 1 column */}
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

        {/* Top 10 Malicious IPs - right side, 2 columns */}
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

      </div>

      {/* Attack Hotspots Section - Single Card with Internal Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-6 gap-6">
        {/* Main Card - Left side 4 columns */}
        <div className="lg:col-span-4 bg-gray-800 border border-gray-700 rounded-lg p-6">
          {/* Header with filters */}
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-white">Attack Hotspots</h2>
            <div className="flex gap-2">
              <select
                value={geolocationCountryFilter}
                onChange={(e) => setGeolocationCountryFilter(e.target.value)}
                className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
              >
                <option value="all">All Countries</option>
                {availableCountries.map(country => (
                  <option key={country} value={country}>{country}</option>
                ))}
              </select>
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
          </div>

          {/* Internal Grid: Map + Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
            {/* World Map - Left side, 2 columns */}
            <div className="lg:col-span-2">
              {geolocationMapData && geolocationMapData.length > 0 ? (
                <WorldMapSVG data={geolocationMapData} height={350} />
              ) : (
                <div className="flex items-center justify-center h-80 text-gray-400 bg-gray-900 rounded-lg border border-gray-700">
                  <p>No attack data available</p>
                </div>
              )}
            </div>

            {/* Countries Attack Breakdown - Right side, 1 column */}
            <div className="flex flex-col">
              <h3 className="text-sm font-semibold text-white mb-3">Countries Breakdown</h3>
              {geolocationData && geolocationData.length > 0 ? (
                <div className="overflow-y-auto flex-1 max-h-80 space-y-2 pr-2">
                  {(() => {
                    // Determina quale array mostrare
                    const displayData = geolocationCountryFilter !== 'all'
                      ? geolocationData.filter(item => item.country === geolocationCountryFilter)
                      : geolocationData;

                    // Calcola il totale globale per percentuali e per la larghezza barra
                    const totalAttacks = geolocationData.reduce((sum, d) => sum + d.value, 0);
                    // Usa il max GLOBALE, non solo dei dati visualizzati, per proporzioni corrette
                    const maxValueGlobal = Math.max(...geolocationData.map(d => d.value), 0);

                    return displayData.map((item, idx) => {
                      // Percentuale rispetto al TOTALE MONDIALE
                      const percentage = ((item.value / totalAttacks) * 100).toFixed(1);
                      // Larghezza barra proporzionata al massimo GLOBALE
                      const barWidth = (item.value / maxValueGlobal) * 100;
                      // Colore basato sulla severità del conteggio
                      const barColor = getSeverityColor(item.value);
                      return (
                        <div key={idx} className="text-xs">
                          <div className="flex justify-between mb-1">
                            <span className="text-gray-300 font-medium">{item.country}</span>
                            <span className="text-gray-400">{item.value} ({percentage}%)</span>
                          </div>
                          <div className="w-full bg-gray-700 rounded h-2 overflow-hidden">
                            <div
                              className="h-full transition-all duration-300"
                              style={{ width: `${barWidth}%`, backgroundColor: barColor }}
                            ></div>
                          </div>
                        </div>
                      );
                    });
                  })()}
                </div>
              ) : (
                <div className="flex items-center justify-center h-80 text-gray-400">
                  <p>No data available</p>
                </div>
              )}
            </div>
          </div>

          {/* Intensity Legend - Below Map and Breakdown (Full width) */}
          <div className="border-t border-gray-700 pt-4">
            <h3 className="text-sm font-semibold text-white mb-3">Attack Intensity Legend</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full" style={{ backgroundColor: '#dc2626' }}></div>
                <div>
                  <p className="font-semibold text-red-500 text-xs">Critical</p>
                  <p className="text-xs text-gray-400">50+ attacks</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full" style={{ backgroundColor: '#f97316' }}></div>
                <div>
                  <p className="font-semibold text-orange-500 text-xs">High</p>
                  <p className="text-xs text-gray-400">20-50 attacks</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full" style={{ backgroundColor: '#eab308' }}></div>
                <div>
                  <p className="font-semibold text-yellow-500 text-xs">Medium</p>
                  <p className="text-xs text-gray-400">10-20 attacks</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded-full" style={{ backgroundColor: '#3b82f6' }}></div>
                <div>
                  <p className="font-semibold text-blue-500 text-xs">Low</p>
                  <p className="text-xs text-gray-400">&lt;10 attacks</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Threat Level Distribution - Right side, 2 columns */}
        <div className="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-3">Threat Level Distribution</h2>
          <div className="flex gap-2 mb-4">
            <select
              value={threatLevelSeverityFilter}
              onChange={(e) => setThreatLevelSeverityFilter(e.target.value)}
              className="bg-gray-700 text-white rounded px-3 py-2 text-sm border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Severities</option>
              {availableSeverities.map(severity => (
                <option key={severity} value={severity}>{severity}</option>
              ))}
            </select>
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
                <Tooltip content={<PieChartTooltip />} />
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
                          {alert.blockedBy === 'auto' ? (
                            <span className="px-3 py-1 bg-red-500/20 text-red-300 rounded text-xs font-medium inline-flex items-center gap-1">
                              <Lock size={12} />
                              Blocked
                            </span>
                          ) : alert.blockedBy === 'manual' ? (
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
                          {isDefaultThreat(alert.threat) ? (
                            // Default threats (XSS, SQLi, etc.) are ALWAYS auto-blocked - no action button
                            <span className="text-gray-500 text-xs">—</span>
                          ) : alert.blockedBy === 'auto' ? (
                            // Custom threat automatically blocked by rule - no action button
                            <span className="text-gray-500 text-xs">—</span>
                          ) : alert.blockedBy === 'manual' ? (
                            // Custom threat manually blocked by operator - show Unblock button
                            <button
                              onClick={() => handleUnblockThreat(alert.ip, alert.description || alert.threat)}
                              disabled={processingKey === getAlertKey(alert.ip, alert.description || alert.threat) || !canUnblockThreats}
                              className={`px-2 py-1 rounded text-xs font-medium transition ${
                                !canUnblockThreats
                                  ? 'bg-gray-600 text-gray-400 cursor-not-allowed opacity-50'
                                  : processingKey === getAlertKey(alert.ip, alert.description || alert.threat)
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-green-600 hover:bg-green-700 text-white'
                              }`}
                              title={!canUnblockThreats ? 'You do not have permission to unblock threats' : ''}
                            >
                              {processingKey === getAlertKey(alert.ip, alert.description || alert.threat) ? '...' : 'Unblock'}
                            </button>
                          ) : (
                            // Custom threat Detected (not blocked) - show Block button
                            <button
                              onClick={() => handleBlockThreat(alert.ip, alert.description || alert.threat)}
                              disabled={processingKey === getAlertKey(alert.ip, alert.description || alert.threat) || !canBlockThreats}
                              className={`px-2 py-1 rounded text-xs font-medium transition ${
                                !canBlockThreats
                                  ? 'bg-gray-600 text-gray-400 cursor-not-allowed opacity-50'
                                  : processingKey === getAlertKey(alert.ip, alert.description || alert.threat)
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-red-600 hover:bg-red-700 text-white'
                              }`}
                              title={!canBlockThreats ? 'You do not have permission to block threats' : ''}
                            >
                              {processingKey === getAlertKey(alert.ip, alert.description || alert.threat) ? '...' : 'Block'}
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

      {/* Block Duration Selection Modal */}
      {blockModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4">
            <h2 className="text-xl font-bold text-white mb-4">Select Block Duration</h2>

            <div className="space-y-3 mb-6">
              {BLOCK_DURATION_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  onClick={() => {
                    setSelectedDuration(option.value);
                  }}
                  className={`w-full px-4 py-3 rounded-lg font-medium transition ${
                    selectedDuration === option.value
                      ? 'bg-blue-600 text-white border border-blue-500'
                      : 'bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700'
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>

            {/* Custom Duration Input */}
            <div className="mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
              <label className="text-gray-300 text-sm font-medium mb-2 block">Custom Duration</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  min="1"
                  value={customDuration}
                  onChange={(e) => setCustomDuration(parseInt(e.target.value) || 1)}
                  className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
                <select
                  value={customDurationUnit}
                  onChange={(e) => setCustomDurationUnit(e.target.value as 'hours' | 'days')}
                  className="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="hours">Hours</option>
                  <option value="days">Days</option>
                </select>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3">
              <button
                onClick={() => setBlockModalOpen(false)}
                className="flex-1 px-4 py-2 rounded-lg font-medium bg-gray-800 text-gray-300 hover:bg-gray-700 transition border border-gray-700"
              >
                Cancel
              </button>
              <button
                onClick={confirmBlockThreat}
                className="flex-1 px-4 py-2 rounded-lg font-medium bg-red-600 text-white hover:bg-red-700 transition"
              >
                Block IP
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default StatsPage;