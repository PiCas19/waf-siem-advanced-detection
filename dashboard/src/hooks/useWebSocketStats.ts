import { useEffect, useState } from 'react';
import { fetchStats } from '@/services/api';

interface Stats {
  threats_detected: number;
  requests_blocked: number;
  total_requests: number;
}

export function useWebSocketStats() {
  const [stats, setStats] = useState<Stats>({
    threats_detected: 0,
    requests_blocked: 0,
    total_requests: 0,
  });
  const [isConnected, setIsConnected] = useState(false);

  // Carica gli stats iniziali dal server
  useEffect(() => {
    const loadInitialStats = async () => {
      try {
        const data = await fetchStats();
        setStats({
          threats_detected: data.threats_detected || 0,
          requests_blocked: data.requests_blocked || 0,
          total_requests: data.total_requests || 0,
        });
      } catch (error) {
        console.error('Failed to load initial stats:', error);
      }
    };

    loadInitialStats();
  }, []);

  // Setup WebSocket per aggiornamenti real-time
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
      console.log('[WebSocket] Connected to stats stream');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);

        // Se ricevi un evento WAF, aggiorna gli stats
        if (message.type === 'waf_event' || message.threat) {
          setStats((prevStats) => ({
            threats_detected: prevStats.threats_detected + 1,
            requests_blocked: prevStats.requests_blocked + (message.blocked ? 1 : 0),
            total_requests: prevStats.total_requests + 1,
          }));
        }
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('[WebSocket] Error:', error);
      setIsConnected(false);
    };

    ws.onclose = () => {
      console.log('[WebSocket] Disconnected from stats stream');
      setIsConnected(false);
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  }, []);

  return { stats, isConnected };
}
