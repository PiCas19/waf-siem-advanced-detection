import { useEffect, useState } from 'react';

interface WAFEvent {
  ip: string;
  threat: string;
  timestamp: string;
}

export function useWebSocket() {
  const [lastEvent, setLastEvent] = useState<WAFEvent | null>(null);

  useEffect(() => {
    const ws = new WebSocket(`ws://${window.location.host}/ws`);
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'waf_event') {
        setLastEvent(msg.data);
      }
    };
    return () => ws.close();
  }, []);

  return { lastEvent };
}