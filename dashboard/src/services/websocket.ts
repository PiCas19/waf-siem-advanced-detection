// dashboard/src/services/websocket.ts
let socket: WebSocket | null = null;
let listeners: ((data: any) => void)[] = [];

export const connectWebSocket = () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${window.location.host}/ws`;

  socket = new WebSocket(url);

  socket.onopen = () => {
    console.log('WebSocket connected');
  };

  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'waf_event') {
      listeners.forEach(fn => fn(msg.data));
    }
  };

  socket.onclose = () => {
    console.log('WebSocket disconnected. Reconnecting...');
    setTimeout(connectWebSocket, 2000);
  };
};

export const onWAFEvent = (callback: (data: any) => void) => {
  listeners.push(callback);
};

// Avvia al caricamento
if (typeof window !== 'undefined') {
  connectWebSocket();
}