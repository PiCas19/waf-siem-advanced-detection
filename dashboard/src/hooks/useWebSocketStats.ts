import { useEffect, useState, useRef } from 'react';
import { fetchStats } from '@/services/api';

interface Stats {
  threats_detected: number;
  requests_blocked: number;
  total_requests: number;
}

interface WAFEvent {
  ip: string;
  method: string;
  path: string;
  timestamp: string;
  threat: string;
  blocked: boolean;
  blockedBy?: string;
  user_agent?: string;
  description?: string; // Rule name/description for per-rule blocking
}

// WebSocket globale - mantiene la connessione tra i re-render
let globalWs: WebSocket | null = null;
let isConnecting = false;

export function useWebSocketStats() {
  const [stats, setStats] = useState<Stats>({
    threats_detected: 0,
    requests_blocked: 0,
    total_requests: 0,
  });
  const [isConnected, setIsConnected] = useState(false);
  const [newAlert, setNewAlert] = useState<WAFEvent | null>(null);
  const statsRef = useRef(stats);
  const lastStatsRef = useRef({ threats: 0, blocked: 0 }); // Traccia gli ultimi valori
  const alertCallbacksRef = useRef<Array<(alert: WAFEvent) => void>>([]); // Callbacks per gli alert

  // Carica gli stats iniziali dal server
  useEffect(() => {
    const loadInitialStats = async () => {
      try {
        const data = await fetchStats();

        const newStats = {
          threats_detected: data.threats_detected || 0,
          requests_blocked: data.requests_blocked || 0,
          total_requests: data.total_requests || 0,
        };

        setStats(newStats);
        lastStatsRef.current = {
          threats: newStats.threats_detected,
          blocked: newStats.requests_blocked,
        };
      } catch (error) {
        // Fallback: se l'API fallisce, gli stats rimangono a 0
      }
    };

    loadInitialStats();
    // Ricarica gli stats ogni 10 secondi come backup
    const interval = setInterval(loadInitialStats, 10000);
    return () => clearInterval(interval);
  }, []);

  // Aggiorna il ref quando stats cambia
  useEffect(() => {
    statsRef.current = stats;
  }, [stats]);

  // Setup WebSocket persistente per aggiornamenti real-time
  useEffect(() => {
    const connectWebSocket = () => {
      // Se già connesso o connettando, non fare nulla
      if (globalWs && (globalWs.readyState === WebSocket.OPEN || globalWs.readyState === WebSocket.CONNECTING)) {
        setIsConnected(globalWs.readyState === WebSocket.OPEN);
        return;
      }

      if (isConnecting) {
        return;
      }

      isConnecting = true;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      // Usa la stessa host e porta del frontend (Caddy fa da proxy per /ws)
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        globalWs = ws;
        isConnecting = false;
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);

          // Se ricevi un evento WAF, aggiorna gli stats e invia agli alert
          if (message.type === 'waf_event' && message.data) {
            const wafEvent = message.data;

            // Aggiorna stats
            setStats((prevStats) => ({
              threats_detected: prevStats.threats_detected + 1,
              requests_blocked: prevStats.requests_blocked + (wafEvent.blocked ? 1 : 0),
              total_requests: prevStats.total_requests + 1,
            }));

            // Crea evento alert formattato e passa ai callback
            const alert: WAFEvent = {
              ip: wafEvent.ip || 'Unknown',
              method: wafEvent.method || 'UNKNOWN',
              path: wafEvent.path || wafEvent.url || '/',
              timestamp: wafEvent.timestamp || new Date().toISOString(),
              threat: wafEvent.threat || 'Unknown',
              blocked: wafEvent.blocked || false,
              blockedBy: wafEvent.blocked_by || wafEvent.blockedBy || '',
              user_agent: wafEvent.user_agent,
            };

            // Chiama tutti i callback registrati
            alertCallbacksRef.current.forEach(callback => callback(alert));
            setNewAlert(alert);
          }
        } catch (error) {
          // Silently ignore parse errors
        }
      };

      ws.onerror = () => {
        isConnecting = false;
        setIsConnected(false);
      };

      ws.onclose = () => {
        globalWs = null;
        isConnecting = false;
        setIsConnected(false);

        // Reconnect automaticamente dopo 3 secondi
        setTimeout(() => {
          connectWebSocket();
        }, 3000);
      };

      globalWs = ws;
    };

    connectWebSocket();

    // Non chiudere il WebSocket - mantieni la connessione attiva
    return () => {
      // Component unmounted, keeping WebSocket alive
    };
  }, []);

  // Funzione per registrare un callback per i nuovi alert
  const onAlertReceived = (callback: (alert: WAFEvent) => void) => {
    alertCallbacksRef.current.push(callback);
    return () => {
      alertCallbacksRef.current = alertCallbacksRef.current.filter(cb => cb !== callback);
    };
  };

  return { stats, isConnected, newAlert, onAlertReceived };
}
