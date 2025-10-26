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

  // Setup WebSocket per aggiornamenti real-time
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    console.log('[WebSocket] Attempting to connect to:', wsUrl);

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('[WebSocket] ✅ Connected to stats stream');
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
      setIsConnected(false);
    };

    ws.onclose = () => {
      console.log('[WebSocket] 🔴 Disconnected from stats stream');
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
