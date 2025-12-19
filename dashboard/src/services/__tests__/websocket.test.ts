import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

// Mock WebSocket before importing the module
class MockWebSocket {
  url: string;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  
  static instances: MockWebSocket[] = [];
  static lastInstance: MockWebSocket | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    MockWebSocket.lastInstance = this;
    
    // Simulate async connection
    setTimeout(() => {
      if (this.onopen) this.onopen();
    }, 0);
  }

  close() {
    if (this.onclose) {
      setTimeout(() => {
        this.onclose?.();
      }, 0);
    }
  }

  static clearInstances() {
    MockWebSocket.instances = [];
    MockWebSocket.lastInstance = null;
  }

  static getLastInstance(): MockWebSocket | null {
    return MockWebSocket.lastInstance;
  }
}

global.WebSocket = MockWebSocket as any;

// Now import the module
import { connectWebSocket, onWAFEvent } from '../websocket';

describe('websocket', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    MockWebSocket.clearInstances();

    // Mock window.location
    Object.defineProperty(window, 'location', {
      value: {
        protocol: 'http:',
        host: 'localhost:5173',
      },
      writable: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('connectWebSocket', () => {
    it('should create WebSocket with correct URL for http', () => {
      connectWebSocket();
      vi.advanceTimersByTime(100);

      expect(MockWebSocket.instances.length).toBe(1);
      expect(MockWebSocket.instances[0].url).toBe('ws://localhost:5173/ws');
    });

    it('should create WebSocket with wss:// for https', () => {
      Object.defineProperty(window, 'location', {
        value: {
          protocol: 'https:',
          host: 'example.com',
        },
        writable: true,
      });

      connectWebSocket();
      vi.advanceTimersByTime(100);

      expect(MockWebSocket.instances.length).toBe(1);
      expect(MockWebSocket.instances[0].url).toBe('wss://example.com/ws');
    });

    it('should handle connection open event', () => {
      connectWebSocket();
      vi.advanceTimersByTime(100);

      expect(MockWebSocket.instances.length).toBe(1);
    });

    it('should reconnect on close', () => {
      connectWebSocket();
      vi.advanceTimersByTime(100);

      expect(MockWebSocket.instances.length).toBe(1);
      
      // Simulate close
      const ws = MockWebSocket.getLastInstance();
      if (ws && ws.onclose) {
        ws.onclose();
      }
      
      // Should schedule reconnection after 2000ms
      vi.advanceTimersByTime(2000);
      
      // Should create a new WebSocket instance
      expect(MockWebSocket.instances.length).toBe(2);
    });
  });

  describe('onWAFEvent', () => {
    it('should register event listener', () => {
      const callback = vi.fn();
      onWAFEvent(callback);
      expect(callback).not.toHaveBeenCalled();
    });

    it('should call listeners on waf_event message', () => {
      const callback1 = vi.fn();
      const callback2 = vi.fn();

      onWAFEvent(callback1);
      onWAFEvent(callback2);

      // Create WebSocket and trigger message
      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();
      const eventData = {
        ip: '192.168.1.1',
        attack_type: 'SQL Injection',
        blocked: true,
      };

      const message = {
        type: 'waf_event',
        data: eventData,
      };

      // Simulate message reception
      if (ws && ws.onmessage) {
        ws.onmessage({ data: JSON.stringify(message) });
      }

      expect(callback1).toHaveBeenCalledWith(eventData);
      expect(callback2).toHaveBeenCalledWith(eventData);
    });

    it('should ignore messages with other types', () => {
      const callback = vi.fn();
      onWAFEvent(callback);

      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();
      const message = {
        type: 'other_event',
        data: { some: 'data' },
      };

      if (ws && ws.onmessage) {
        ws.onmessage({ data: JSON.stringify(message) });
      }

      expect(callback).not.toHaveBeenCalled();
    });

    it('should handle malformed JSON gracefully', () => {
      const callback = vi.fn();
      onWAFEvent(callback);

      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();

      // Send invalid JSON
      if (ws && ws.onmessage) {
        ws.onmessage({ data: 'invalid json {[' });
      }

      expect(callback).not.toHaveBeenCalled();
    });

    it('should handle multiple different events', () => {
      const callback = vi.fn();
      onWAFEvent(callback);

      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();

      const events = [
        {
          type: 'waf_event',
          data: { ip: '10.0.0.1', attack: 'XSS' },
        },
        {
          type: 'waf_event',
          data: { ip: '10.0.0.2', attack: 'SQLi' },
        },
        {
          type: 'other',
          data: { ignored: true },
        },
      ];

      events.forEach((event) => {
        if (ws && ws.onmessage) {
          ws.onmessage({ data: JSON.stringify(event) });
        }
      });

      expect(callback).toHaveBeenCalledTimes(2);
      expect(callback).toHaveBeenCalledWith({ ip: '10.0.0.1', attack: 'XSS' });
      expect(callback).toHaveBeenCalledWith({ ip: '10.0.0.2', attack: 'SQLi' });
    });
  });

  describe('multiple listeners', () => {
    it('should call all registered listeners', () => {
      const listeners = [vi.fn(), vi.fn(), vi.fn()];
      listeners.forEach((listener) => onWAFEvent(listener));

      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();
      const eventData = { test: 'data' };
      const message = {
        type: 'waf_event',
        data: eventData,
      };

      if (ws && ws.onmessage) {
        ws.onmessage({ data: JSON.stringify(message) });
      }

      listeners.forEach((listener) => {
        expect(listener).toHaveBeenCalledWith(eventData);
      });
    });
  });

  describe('edge cases', () => {
    it('should handle empty event data', () => {
      const callback = vi.fn();
      onWAFEvent(callback);

      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();
      const message = {
        type: 'waf_event',
        data: null,
      };

      if (ws && ws.onmessage) {
        ws.onmessage({ data: JSON.stringify(message) });
      }

      expect(callback).toHaveBeenCalledWith(null);
    });

    it('should handle message without data field', () => {
      const callback = vi.fn();
      onWAFEvent(callback);

      connectWebSocket();
      vi.advanceTimersByTime(100);

      const ws = MockWebSocket.getLastInstance();
      const message = {
        type: 'waf_event',
      };

      if (ws && ws.onmessage) {
        ws.onmessage({ data: JSON.stringify(message) });
      }

      expect(callback).toHaveBeenCalledWith(undefined);
    });
  });

  // TEST PER COPRIRE LINEA 36: check per ambiente browser (typeof window !== 'undefined')
  describe('browser environment check', () => {
    it('should not call connectWebSocket when window is undefined', async () => {
      // Salva il riferimento originale di window
      const originalWindow = global.window;

      // Pulisci i moduli per re-import
      await vi.resetModules();
      MockWebSocket.clearInstances();

      // Rimuovi temporaneamente window per simulare ambiente non-browser (Node.js SSR)
      // @ts-ignore
      delete global.window;

      // Re-import il modulo in ambiente senza window
      await import('../websocket');

      // LINEA 36: Verifica che connectWebSocket NON sia stato chiamato automaticamente
      // Non dovrebbero esserci istanze WebSocket create
      expect(MockWebSocket.instances.length).toBe(0);

      // Ripristina window
      global.window = originalWindow;
    });

    it('should call connectWebSocket when window is defined', async () => {
      // Assicurati che window sia definito
      expect(typeof window).toBe('object');

      // Pulisci e re-import
      await vi.resetModules();
      MockWebSocket.clearInstances();

      // Re-import il modulo in ambiente con window
      await import('../websocket');

      vi.advanceTimersByTime(100);

      // LINEA 36: Verifica che connectWebSocket SIA stato chiamato automaticamente
      // Dovrebbe esserci almeno un'istanza WebSocket creata
      expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
  });
});