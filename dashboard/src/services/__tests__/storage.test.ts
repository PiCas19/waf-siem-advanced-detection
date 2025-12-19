import { describe, it, expect, beforeEach, vi } from 'vitest';
import { storage } from '../storage';

describe('storage', () => {
  beforeEach(() => {
    // Clear all mocks before each test
    vi.clearAllMocks();
    localStorage.clear();
  });

  describe('setToken', () => {
    it('should store token in localStorage', () => {
      const token = 'test-token-123';
      storage.setToken(token);

      expect(localStorage.setItem).toHaveBeenCalledWith('token', token);
      expect(localStorage.setItem).toHaveBeenCalledTimes(1);
    });

    it('should store different tokens', () => {
      const token1 = 'token-1';
      const token2 = 'token-2';

      storage.setToken(token1);
      storage.setToken(token2);

      expect(localStorage.setItem).toHaveBeenCalledWith('token', token1);
      expect(localStorage.setItem).toHaveBeenCalledWith('token', token2);
      expect(localStorage.setItem).toHaveBeenCalledTimes(2);
    });

    it('should handle empty token', () => {
      storage.setToken('');
      expect(localStorage.setItem).toHaveBeenCalledWith('token', '');
    });
  });

  describe('getToken', () => {
    it('should retrieve token from localStorage', () => {
      const token = 'stored-token';
      (localStorage.getItem as any).mockReturnValue(token);

      const result = storage.getToken();

      expect(localStorage.getItem).toHaveBeenCalledWith('token');
      expect(result).toBe(token);
    });

    it('should return null when no token exists', () => {
      (localStorage.getItem as any).mockReturnValue(null);

      const result = storage.getToken();

      expect(result).toBeNull();
    });

    it('should handle multiple getToken calls', () => {
      (localStorage.getItem as any).mockReturnValue('test-token');

      storage.getToken();
      storage.getToken();
      storage.getToken();

      expect(localStorage.getItem).toHaveBeenCalledTimes(3);
    });
  });

  describe('removeToken', () => {
    it('should remove token from localStorage', () => {
      storage.removeToken();

      expect(localStorage.removeItem).toHaveBeenCalledWith('token');
      expect(localStorage.removeItem).toHaveBeenCalledTimes(1);
    });

    it('should handle multiple removeToken calls', () => {
      storage.removeToken();
      storage.removeToken();

      expect(localStorage.removeItem).toHaveBeenCalledTimes(2);
    });
  });

  describe('integration', () => {
    it('should handle complete token lifecycle', () => {
      const token = 'lifecycle-token';

      // Set token
      storage.setToken(token);
      expect(localStorage.setItem).toHaveBeenCalledWith('token', token);

      // Get token
      (localStorage.getItem as any).mockReturnValue(token);
      const retrieved = storage.getToken();
      expect(retrieved).toBe(token);

      // Remove token
      storage.removeToken();
      expect(localStorage.removeItem).toHaveBeenCalledWith('token');
    });
  });
});
