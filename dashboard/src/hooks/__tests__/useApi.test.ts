import { describe, it, expect, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useApi } from '../useApi';

describe('useApi', () => {
  // Test per la configurazione base dell'hook
  describe('basic functionality', () => {
    it('should always return null data regardless of input', () => {
      const mockKey = ['test', 'data'];
      const mockFn = vi.fn(async () => ({ data: 'real data' }));

      const { result } = renderHook(() => useApi(mockKey, mockFn));

      // Verifica che i valori siano sempre quelli di default (hook disabilitato)
      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBe(null);
    });

    it('should not call the provided function', () => {
      const mockKey = ['users', 'list'];
      const mockFn = vi.fn(async () => ({ users: [] }));

      const { result } = renderHook(() => useApi(mockKey, mockFn));

      // La funzione non dovrebbe essere chiamata poiché l'hook è disabilitato
      expect(mockFn).not.toHaveBeenCalled();
      
      // Verifica i valori di ritorno
      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
    });

    it('should handle single key array', () => {
      const fn = vi.fn(async () => 'single');
      const { result } = renderHook(() => useApi(['single'], fn));
      expect(result.current.data).toBe(null);
      expect(fn).not.toHaveBeenCalled();
    });

    it('should handle nested path keys', () => {
      const fn = vi.fn(async () => ({ nested: true }));
      const { result } = renderHook(() => 
        useApi(['nested', 'path', 'to', 'data'], fn)
      );
      expect(result.current.data).toBe(null);
      expect(fn).not.toHaveBeenCalled();
    });

    it('should handle empty key array', () => {
      const fn = vi.fn(async () => undefined);
      const { result } = renderHook(() => useApi([], fn));
      expect(result.current.data).toBe(null);
      expect(fn).not.toHaveBeenCalled();
    });

    it('should handle different async functions', () => {
      const mockFn1 = vi.fn(async () => 'success');
      const mockFn2 = vi.fn(async () => { throw new Error('error'); });
      const mockFn3 = vi.fn(async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
        return 'delayed';
      });

      // Test 1: Funzione che ritorna successo
      const { result: result1 } = renderHook(() => useApi(['test'], mockFn1));
      expect(result1.current.data).toBe(null);
      expect(mockFn1).not.toHaveBeenCalled();

      // Test 2: Funzione che lancia errore
      const { result: result2 } = renderHook(() => useApi(['test'], mockFn2));
      expect(result2.current.data).toBe(null);
      expect(mockFn2).not.toHaveBeenCalled();

      // Test 3: Funzione asincrona con delay
      const { result: result3 } = renderHook(() => useApi(['test'], mockFn3));
      expect(result3.current.data).toBe(null);
      expect(mockFn3).not.toHaveBeenCalled();
    });
  });

  // Test per i tipi generici
  describe('type handling', () => {
    it('should work with User type', () => {
      type User = { id: number; name: string };
      const userFn = vi.fn(async (): Promise<User> => ({ id: 1, name: 'John' }));
      
      const { result } = renderHook(() => 
        useApi<User>(['user'], userFn)
      );
      expect(result.current.data).toBe(null);
    });

    it('should work with Product type', () => {
      type Product = { id: string; price: number };
      const productFn = vi.fn(async (): Promise<Product> => ({ id: 'prod-1', price: 99.99 }));
      
      const { result } = renderHook(() => 
        useApi<Product>(['product'], productFn)
      );
      expect(result.current.data).toBe(null);
    });

    it('should work with Array type', () => {
      type ArrayType = number[];
      const arrayFn = vi.fn(async (): Promise<ArrayType> => [1, 2, 3]);
      
      const { result } = renderHook(() => 
        useApi<ArrayType>(['array'], arrayFn)
      );
      expect(result.current.data).toBe(null);
    });
  });

  // Test per il comportamento in scenari diversi
  describe('scenarios', () => {
    it('should maintain same values on re-render', () => {
      const mockFn = vi.fn(async () => 'data');
      const { result, rerender } = renderHook(() => useApi(['test'], mockFn));

      const firstResult = { ...result.current };

      // Rerender più volte
      rerender();
      rerender();
      rerender();

      // I valori dovrebbero rimanere invariati
      expect(result.current.data).toBe(firstResult.data);
      expect(result.current.isLoading).toBe(firstResult.isLoading);
      expect(result.current.error).toBe(firstResult.error);
      
      // La funzione non dovrebbe mai essere chiamata
      expect(mockFn).not.toHaveBeenCalled();
    });

    it('should work with hook dependencies array changes', () => {
      const mockFn1 = vi.fn(async () => 'data1');
      const mockFn2 = vi.fn(async () => 'data2');
      
      const { result, rerender } = renderHook(
        ({ key, fn }) => useApi(key, fn),
        {
          initialProps: { 
            key: ['initial'] as string[], 
            fn: mockFn1 
          },
        }
      );

      expect(result.current.data).toBe(null);

      // Cambia le props (dovrebbero essere ignorate)
      rerender({ 
        key: ['changed'] as string[], 
        fn: mockFn2 
      });

      // I valori dovrebbero rimanere gli stessi
      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
      
      // Nessuna funzione dovrebbe essere chiamata
      expect(mockFn1).not.toHaveBeenCalled();
      expect(mockFn2).not.toHaveBeenCalled();
    });
  });

  // Test per edge cases
  describe('edge cases', () => {
    it('should handle keys with special characters', () => {
      const specialKeys = [
        ['key-with-dash'],
        ['key_with_underscore'],
        ['key.with.dots'],
        ['key with spaces'],
        ['123'],
        ['key&special@chars!#'],
      ];

      specialKeys.forEach((key) => {
        const mockFn = vi.fn(async () => 'data');
        const { result } = renderHook(() => useApi(key, mockFn));

        expect(result.current.data).toBe(null);
        expect(result.current.isLoading).toBe(false);
        expect(mockFn).not.toHaveBeenCalled();
      });
    });

    it('should not throw with throwing function', () => {
      const throwingFn = vi.fn(async () => {
        throw new Error('This should not be thrown');
      });

      // Non dovrebbe lanciare perché la funzione non viene chiamata
      const { result } = renderHook(() => useApi(['test'], throwingFn));

      expect(result.current.data).toBe(null);
      expect(result.current.error).toBe(null);
      expect(throwingFn).not.toHaveBeenCalled();
    });

    it('should work with sync functions wrapped in Promise', () => {
      const syncFn = vi.fn(() => 'sync data');
      // Wrappiamo la funzione sincrona in una Promise per soddisfare il tipo
      const asyncFn = vi.fn(async () => syncFn());
      const { result } = renderHook(() => useApi(['sync'], asyncFn));

      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
      expect(asyncFn).not.toHaveBeenCalled();
    });
  });

  // Test per la struttura del ritorno
  describe('return structure', () => {
    it('should always return the same object structure', () => {
      const mockFn = vi.fn(async () => 'any data');
      const { result } = renderHook(() => useApi(['any'], mockFn));

      const { data, isLoading, error } = result.current;
      
      expect(data).toBe(null);
      expect(isLoading).toBe(false);
      expect(error).toBe(null);
      
      // Verifica che i tipi siano corretti
      expect(typeof isLoading).toBe('boolean');
      
      // data può essere null, ma in un caso reale potrebbe essere T
      expect(data).toBeNull();
    });

    it('should match the expected API interface', () => {
      const mockFn = vi.fn(async () => ({ success: true }));
      const { result } = renderHook(() => useApi(['api'], mockFn));

      // L'oggetto ritornato dovrebbe avere queste proprietà
      expect(result.current).toHaveProperty('data');
      expect(result.current).toHaveProperty('isLoading');
      expect(result.current).toHaveProperty('error');
      
      // Con i valori specifici
      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBe(null);
    });
  });

  // Test aggiuntivi per il comportamento specifico dell'hook disabilitato
  describe('disabled hook behavior', () => {
    it('should ignore all function calls and parameters', () => {
      // Creiamo una funzione che accetta parametri ma la wrappiamo per soddisfare la firma
      const complexFnImpl = async () => {
        return { param1: 'test', param2: 123, result: 'complex' };
      };
      const complexFn = vi.fn(complexFnImpl);

      const { result } = renderHook(() => 
        useApi(['very', 'complex', 'key'], complexFn)
      );

      // Anche con parametri complessi, l'hook dovrebbe ignorarli
      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBe(null);
      expect(complexFn).not.toHaveBeenCalled();
    });

    it('should be consistent across multiple hook instances', () => {
      const mockFn1 = vi.fn(async () => 'data1');
      const mockFn2 = vi.fn(async () => 'data2');

      const { result: result1 } = renderHook(() => useApi(['key1'], mockFn1));
      const { result: result2 } = renderHook(() => useApi(['key2'], mockFn2));

      // Entrambi gli hook dovrebbero avere lo stesso comportamento
      expect(result1.current.data).toBe(null);
      expect(result2.current.data).toBe(null);
      
      expect(result1.current.isLoading).toBe(false);
      expect(result2.current.isLoading).toBe(false);
      
      expect(result1.current.error).toBe(null);
      expect(result2.current.error).toBe(null);
      
      // Nessuna funzione dovrebbe essere chiamata
      expect(mockFn1).not.toHaveBeenCalled();
      expect(mockFn2).not.toHaveBeenCalled();
    });
  });

  // Test per il commento "Hook disabled"
  describe('hook disabled message', () => {
    it('should behave as documented in the comment', () => {
      const mockFn = vi.fn(async () => 'any value');
      const { result } = renderHook(() => 
        useApi(['disabled', 'hook'], mockFn)
      );

      // Come dice il commento: "Hook disabled - using WebSocket for real-time updates instead"
      // L'hook dovrebbe sempre restituire valori nulli/fallback
      expect(result.current.data).toBe(null);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBe(null);
      
      // E non dovrebbe chiamare la funzione fornita
      expect(mockFn).not.toHaveBeenCalled();
    });
  });
});