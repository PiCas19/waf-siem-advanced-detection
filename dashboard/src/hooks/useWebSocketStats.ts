import { useEffect, useState, useRef } from 'react';
import { fetchStats } from '@/services/api';

interface Stats {
  threats_detected: number;
  requests_blocked: number;
  total_requests: number;
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
  const statsRef = useRef(stats);

  // Carica gli stats iniziali dal server
  useEffect(() => {
    const loadInitialStats = async () => {
      try {
        const token = localStorage.getItem('authToken');
        console.log('[Stats Hook] Loading initial stats - Token exists:', !!token);

        const data = await fetchStats();
        console.log('[Stats Hook] Stats loaded successfully:', data);

        setStats({
          threats_detected: data.threats_detected || 0,
          requests_blocked: data.requests_blocked || 0,
          total_requests: data.total_requests || 0,
        });
      } catch (error) {
        console.error('[Stats Hook] Failed to load initial stats:', error);
        console.error('[Stats Hook] Error details:', {
          message: error instanceof Error ? error.message : 'Unknown error',
          status: (error as any)?.response?.status,
          statusText: (error as any)?.response?.statusText,
        });
      }
    };

    loadInitialStats();
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
        console.log('[WebSocket] Already connected or connecting, skipping new connection');
        setIsConnected(globalWs.readyState === WebSocket.OPEN);
        return;
      }

      if (isConnecting) {
        console.log('[WebSocket] Already attempting to connect, skipping duplicate attempt');
        return;
      }

      isConnecting = true;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      // Se siamo su HTTP:80, connettiti al backend su 8081
      // Se siamo su HTTPS:8443 (LAN), connettiti al backend su 8081
      // Se siamo su HTTPS:443 (WAN), connettiti al backend su 8081
      const host = window.location.hostname;
      const wsUrl = `${protocol}//${host}:8081/ws`;
      console.log('[WebSocket] Attempting to connect to:', wsUrl);

      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('[WebSocket] ✅ Connected to stats stream');
        globalWs = ws;
        isConnecting = false;
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          console.log('[WebSocket] Received message:', message);

          // Se ricevi un evento WAF, aggiorna gli stats
          if (message.type === 'waf_event' && message.data) {
            const wafEvent = message.data;
            console.log('[WebSocket] Processing WAF event:', {
              threat: wafEvent.threat,
              blocked: wafEvent.blocked,
              ip: wafEvent.ip,
            });

            setStats((prevStats) => ({
              threats_detected: prevStats.threats_detected + 1,
              requests_blocked: prevStats.requests_blocked + (wafEvent.blocked ? 1 : 0),
              total_requests: prevStats.total_requests + 1,
            }));
          } else {
            console.log('[WebSocket] Ignoring message - type:', message.type, 'has data:', !!message.data);
          }
        } catch (error) {
          console.error('[WebSocket] Failed to parse message:', error);
        }
      };

      ws.onerror = (error) => {
        console.error('[WebSocket] ❌ Error:', error);
        isConnecting = false;
        setIsConnected(false);
      };

      ws.onclose = () => {
        console.log('[WebSocket] 🔴 Disconnected from stats stream. Reconnecting in 3 seconds...');
        globalWs = null;
        isConnecting = false;
        setIsConnected(false);

        // Reconnect automaticamente dopo 3 secondi
        setTimeout(() => {
          console.log('[WebSocket] Attempting automatic reconnect...');
          connectWebSocket();
        }, 3000);
      };

      globalWs = ws;
    };

    connectWebSocket();

    // Non chiudere il WebSocket - mantieni la connessione attiva
    return () => {
      console.log('[WebSocket] Component unmounted, keeping WebSocket alive');
    };
  }, []);

  return { stats, isConnected };
}
