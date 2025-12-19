import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';

describe('useWebSocket', () => {
  // Variabili per tracciare le istanze WebSocket create
  let mockWebSocketInstances: Array<{
    onmessage: ((event: any) => void) | null;
    onerror: ((event: any) => void) | null;
    onopen: ((event: any) => void) | null;
    onclose: ((event: any) => void) | null;
    close: ReturnType<typeof vi.fn>;
    send: ReturnType<typeof vi.fn>;
    url: string;
  }> = [];

  beforeEach(() => {
    // Reset delle istanze
    mockWebSocketInstances = [];
    
    // Mock di WebSocket che salva ogni istanza creata
    global.WebSocket = class MockWebSocket {
      onmessage: ((event: any) => void) | null = null;
      onerror: ((event: any) => void) | null = null;
      onopen: ((event: any) => void) | null = null;
      onclose: ((event: any) => void) | null = null;
      close = vi.fn();
      send = vi.fn();
      readyState = WebSocket.OPEN;
      url: string;

      constructor(url: string) {
        this.url = url;
        const instance = {
          onmessage: this.onmessage,
          onerror: this.onerror,
          onopen: this.onopen,
          onclose: this.onclose,
          close: this.close,
          send: this.send,
          url: this.url
        };
        
        // Override dei setter per aggiornare l'istanza quando gli handler vengono assegnati
        Object.defineProperty(this, 'onmessage', {
          get: () => instance.onmessage,
          set: (value) => {
            instance.onmessage = value;
          },
          configurable: true
        });
        
        Object.defineProperty(this, 'onerror', {
          get: () => instance.onerror,
          set: (value) => {
            instance.onerror = value;
          },
          configurable: true
        });
        
        Object.defineProperty(this, 'onopen', {
          get: () => instance.onopen,
          set: (value) => {
            instance.onopen = value;
          },
          configurable: true
        });
        
        Object.defineProperty(this, 'onclose', {
          get: () => instance.onclose,
          set: (value) => {
            instance.onclose = value;
          },
          configurable: true
        });

        mockWebSocketInstances.push(instance);
      }
    } as any;
    
    // Mock di window.location.host
    Object.defineProperty(window, 'location', {
      value: { host: 'localhost:3000' },
      writable: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('initialization', () => {
    it('should create WebSocket connection on mount', () => {
      renderHook(() => useWebSocket());

      expect(mockWebSocketInstances).toHaveLength(1);
      expect(mockWebSocketInstances[0].url).toBe('ws://localhost:3000/ws');
    });

    it('should close WebSocket connection on unmount', () => {
      const { unmount } = renderHook(() => useWebSocket());

      expect(mockWebSocketInstances[0].close).not.toHaveBeenCalled();

      unmount();

      expect(mockWebSocketInstances[0].close).toHaveBeenCalledTimes(1);
    });
  });

  describe('WebSocket event handling', () => {
    it('should set lastEvent when receiving waf_event message', () => {
      const { result } = renderHook(() => useWebSocket());

      // Simula messaggio WebSocket
      const mockEvent = {
        type: 'waf_event',
        data: {
          ip: '192.168.1.1',
          threat: 'SQL Injection',
          timestamp: '2024-01-01T12:00:00Z',
          description: 'SQLi attempt detected',
        },
      };

      act(() => {
        // Simula ricezione del messaggio
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(mockEvent),
          });
        }
      });

      expect(result.current.lastEvent).toEqual(mockEvent.data);
    });

    it('should ignore messages with other types', () => {
      const { result } = renderHook(() => useWebSocket());

      const otherEvent = {
        type: 'other_event',
        data: { some: 'data' },
      };

      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(otherEvent),
          });
        }
      });

      expect(result.current.lastEvent).toBeNull();
    });

    it('should handle multiple waf_event messages', () => {
      const { result } = renderHook(() => useWebSocket());

      const events = [
        {
          type: 'waf_event',
          data: {
            ip: '192.168.1.1',
            threat: 'SQL Injection',
            timestamp: '2024-01-01T12:00:00Z',
          },
        },
        {
          type: 'waf_event',
          data: {
            ip: '192.168.1.2',
            threat: 'XSS Attack',
            timestamp: '2024-01-01T12:01:00Z',
            description: 'Cross-site scripting attempt',
          },
        },
      ];

      // Primo messaggio
      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(events[0]),
          });
        }
      });

      expect(result.current.lastEvent).toEqual(events[0].data);

      // Secondo messaggio
      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(events[1]),
          });
        }
      });

      expect(result.current.lastEvent).toEqual(events[1].data);
    });
;

    it('should handle JSON without type field', () => {
      const { result } = renderHook(() => useWebSocket());

      const eventWithoutType = {
        data: { ip: '192.168.1.1' },
      };

      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(eventWithoutType),
          });
        }
      });

      expect(result.current.lastEvent).toBeNull();
    });
  });

  describe('WAFEvent interface', () => {
    it('should handle events with all fields', () => {
      const { result } = renderHook(() => useWebSocket());

      const completeEvent = {
        type: 'waf_event',
        data: {
          ip: '10.0.0.1',
          threat: 'Command Injection',
          timestamp: '2024-01-01T10:00:00Z',
          description: 'Attempt to execute system commands',
        },
      };

      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(completeEvent),
          });
        }
      });

      expect(result.current.lastEvent).toMatchObject({
        ip: expect.any(String),
        threat: expect.any(String),
        timestamp: expect.any(String),
        description: expect.any(String),
      });
    });

    it('should handle events without optional description field', () => {
      const { result } = renderHook(() => useWebSocket());

      const eventWithoutDescription = {
        type: 'waf_event',
        data: {
          ip: '10.0.0.2',
          threat: 'Path Traversal',
          timestamp: '2024-01-01T10:01:00Z',
        },
      };

      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(eventWithoutDescription),
          });
        }
      });

      expect(result.current.lastEvent).toEqual(eventWithoutDescription.data);
      expect(result.current.lastEvent?.description).toBeUndefined();
    });

    it('should handle different threat types', () => {
      const { result } = renderHook(() => useWebSocket());

      const threats = [
        'SQL Injection',
        'XSS',
        'CSRF',
        'Brute Force',
        'DDoS',
        'Zero-day Exploit',
      ];

      threats.forEach((threat, index) => {
        const event = {
          type: 'waf_event',
          data: {
            ip: `10.0.0.${index + 1}`,
            threat,
            timestamp: `2024-01-01T10:0${index}:00Z`,
          },
        };

        act(() => {
          if (mockWebSocketInstances[0].onmessage) {
            mockWebSocketInstances[0].onmessage({
              data: JSON.stringify(event),
            });
          }
        });

        expect(result.current.lastEvent?.threat).toBe(threat);
      });
    });
  });

  describe('connection lifecycle', () => {
    it('should set up event handlers correctly', () => {
      renderHook(() => useWebSocket());

      // Dopo che l'hook è montato, onmessage dovrebbe essere una funzione
      expect(typeof mockWebSocketInstances[0].onmessage).toBe('function');
    });

    it('should handle WebSocket open event', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        if (mockWebSocketInstances[0].onopen) {
          mockWebSocketInstances[0].onopen({} as Event);
        }
      });

      expect(result.current.lastEvent).toBeNull();
    });

    it('should handle WebSocket error event', () => {
      // Non mockiamo console.error perché l'implementazione reale potrebbe non loggare
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        if (mockWebSocketInstances[0].onerror) {
          mockWebSocketInstances[0].onerror({} as Event);
        }
      });

      // L'evento di errore non dovrebbe influenzare lastEvent
      expect(result.current.lastEvent).toBeNull();
    });

    it('should handle WebSocket close event', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        if (mockWebSocketInstances[0].onclose) {
          mockWebSocketInstances[0].onclose({} as CloseEvent);
        }
      });

      expect(result.current.lastEvent).toBeNull();
    });
  });

  describe('return value', () => {
    it('should return object with lastEvent property', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current).toHaveProperty('lastEvent');
      expect(result.current.lastEvent).toBeNull();
    });

    it('should maintain return structure across re-renders', () => {
      const { result, rerender } = renderHook(() => useWebSocket());

      const initialStructure = { ...result.current };

      rerender();

      expect(result.current).toEqual(initialStructure);
      expect(Object.keys(result.current)).toEqual(['lastEvent']);
    });
  });

  describe('multiple instances', () => {
    it('should create separate connections for multiple hooks', () => {
      const { unmount: unmount1 } = renderHook(() => useWebSocket());
      const { unmount: unmount2 } = renderHook(() => useWebSocket());

      expect(mockWebSocketInstances).toHaveLength(2);
      expect(mockWebSocketInstances[0].url).toBe('ws://localhost:3000/ws');
      expect(mockWebSocketInstances[1].url).toBe('ws://localhost:3000/ws');

      unmount1();
      unmount2();

      expect(mockWebSocketInstances[0].close).toHaveBeenCalledTimes(1);
      expect(mockWebSocketInstances[1].close).toHaveBeenCalledTimes(1);
    });

    it('should not share state between instances', () => {
      const { result: result1 } = renderHook(() => useWebSocket());
      const { result: result2 } = renderHook(() => useWebSocket());

      const event = {
        type: 'waf_event',
        data: {
          ip: '192.168.1.100',
          threat: 'Test Threat',
          timestamp: '2024-01-01T12:00:00Z',
        },
      };

      // Simula messaggio solo per la prima istanza
      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage({
            data: JSON.stringify(event),
          });
        }
      });

      // Solo la prima istanza dovrebbe avere l'evento
      expect(result1.current.lastEvent).toEqual(event.data);
      expect(result2.current.lastEvent).toBeNull();
    });
  });

  describe('cleanup', () => {
    it('should cleanup properly when component unmounts', () => {
      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWebSocketInstances[0].close).toHaveBeenCalledTimes(1);
    });

    it('should not throw if WebSocket is already closed', () => {
      const { unmount } = renderHook(() => useWebSocket());

      mockWebSocketInstances[0].close.mockImplementationOnce(() => {});

      unmount();

      expect(mockWebSocketInstances[0].close).toHaveBeenCalledTimes(1);
    });
  });

  describe('edge cases', () => {
    it('should handle different host values', () => {
      const hosts = [
        'localhost:3000',
        'example.com',
        '127.0.0.1:8080',
        'production-domain.com:443',
      ];

      hosts.forEach((host) => {
        // Reset delle istanze per ogni test
        mockWebSocketInstances = [];
        
        Object.defineProperty(window, 'location', {
          value: { host },
          writable: true,
        });

        renderHook(() => useWebSocket());

        expect(mockWebSocketInstances[0].url).toBe(`ws://${host}/ws`);
      });
    });
  });
});