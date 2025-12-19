import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from '../AuthContext';
import axios from 'axios';

// MOCK DI AXIOS
vi.mock('axios');
const mockedAxios = vi.mocked(axios, true);

// Crea un mock storage GLOBALE che funziona
class LocalStorageMock {
  private store: Record<string, string> = {};

  clear() {
    this.store = {};
  }

  getItem(key: string) {
    return this.store[key] || null;
  }

  setItem(key: string, value: string) {
    this.store[key] = value;
  }

  removeItem(key: string) {
    delete this.store[key];
  }
}

// Crea un'istanza globale
const localStorageMock = new LocalStorageMock();

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    
    // Reset del mock localStorage
    localStorageMock.clear();
    
    // Sovrascrivi COMPLETAMENTE localStorage con il nostro mock
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    });
    
    // Anche per global
    Object.defineProperty(global, 'localStorage', {
      value: localStorageMock,
      writable: true,
    });
    
    delete (axios.defaults.headers.common as any)['Authorization'];
    mockedAxios.post.mockReset();
  });

  describe('Initial State', () => {
    it('should provide initial state with no user', async () => {
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await waitFor(() => expect(result.current.isLoading).toBe(false));
      expect(result.current.user).toBeNull();
      expect(result.current.token).toBeNull();
      expect(result.current.requiresTwoFA).toBe(false);
      expect(result.current.requiresTwoFASetup).toBe(false);
    });

    it('should load user and token from localStorage on mount', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };
      
      // Salva nei mock
      localStorage.setItem('authToken', 'test-token');
      localStorage.setItem('authUser', JSON.stringify(testUser));
      
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await waitFor(() => expect(result.current.isLoading).toBe(false));
      
      // Ora il token dovrebbe essere caricato
      expect(result.current.token).toBe('test-token');
      expect(result.current.user).toEqual(testUser);
      expect(axios.defaults.headers.common['Authorization']).toBe('Bearer test-token');
    });
  });

  describe('login', () => {
    it('should login successfully without 2FA', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };

      mockedAxios.post.mockResolvedValueOnce({
        data: { 
          token: 'new-token', 
          user: testUser,
          requires_2fa: false,
          requires_2fa_setup: false 
        },
      });

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await act(async () => {
        await result.current.login('test@example.com', 'password123');
      });

      // Verifica lo stato
      expect(result.current.token).toBe('new-token');
      expect(result.current.user).toEqual(testUser);
      expect(result.current.requiresTwoFA).toBe(false);
      expect(result.current.requiresTwoFASetup).toBe(false);
      
      // Verifica localStorage
      expect(localStorage.getItem('authToken')).toBe('new-token');
      expect(localStorage.getItem('authUser')).toBe(JSON.stringify(testUser));
      expect(axios.defaults.headers.common['Authorization']).toBe('Bearer new-token');
    });

    it('should set requiresTwoFA when 2FA is required', async () => {
      mockedAxios.post.mockResolvedValueOnce({ 
        data: { 
          requires_2fa: true 
        } 
      });

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await act(async () => {
        await result.current.login('test@example.com', 'password123');
      });

      expect(result.current.requiresTwoFA).toBe(true);
      expect(result.current.currentUserEmail).toBe('test@example.com');
    });

    it('should set requiresTwoFASetup when setup is required', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };

      mockedAxios.post.mockResolvedValueOnce({
        data: { 
          requires_2fa_setup: true, 
          token: 'temp-token', 
          user: testUser 
        },
      });

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await act(async () => {
        await result.current.login('test@example.com', 'password123');
      });

      expect(result.current.requiresTwoFASetup).toBe(true);
      expect(result.current.token).toBe('temp-token');
      expect(result.current.user).toEqual(testUser);
      expect(localStorage.getItem('authToken')).toBe('temp-token');
    });

    it('should throw error on login failure', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Login failed'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await expect(result.current.login('test@example.com', 'wrong')).rejects.toThrow('Login failed');
    });
  });

  describe('verifyOTP', () => {
    it('should verify OTP successfully', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: true };

      mockedAxios.post.mockResolvedValueOnce({
        data: { token: 'verified-token', user: testUser },
      });

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      act(() => {
        result.current.setRequiresTwoFA(true);
        result.current.setCurrentUserEmail('test@example.com');
      });

      await act(async () => {
        await result.current.verifyOTP('test@example.com', '123456');
      });

      expect(result.current.token).toBe('verified-token');
      expect(result.current.user).toEqual(testUser);
      expect(result.current.requiresTwoFA).toBe(false);
      expect(result.current.currentUserEmail).toBeNull();
    });

    it('should verify with backup code', async () => {
      mockedAxios.post.mockResolvedValueOnce({ data: {} });
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await act(async () => {
        await result.current.verifyOTP('test@example.com', '', '12345678');
      });
      expect(mockedAxios.post).toHaveBeenCalledWith('/api/auth/verify-otp', {
        email: 'test@example.com',
        otp_code: '',
        backup_code: '12345678',
      });
    });

    it('should throw error on OTP verification failure', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Invalid OTP'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await expect(result.current.verifyOTP('test@example.com', '000000')).rejects.toThrow('Invalid OTP');
    });
  });

  describe('logout', () => {
    it('should clear user and token on logout', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };
      localStorage.setItem('authToken', 'test-token');
      localStorage.setItem('authUser', JSON.stringify(testUser));

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await waitFor(() => expect(result.current.isLoading).toBe(false));

      act(() => result.current.logout());

      expect(result.current.user).toBeNull();
      expect(result.current.token).toBeNull();
      expect(localStorage.getItem('authToken')).toBeNull();
      expect(localStorage.getItem('authUser')).toBeNull();
      expect(axios.defaults.headers.common['Authorization']).toBeUndefined();
    });
  });

  describe('setupTwoFA', () => {
    it('should setup 2FA successfully', async () => {
      const twoFAData = { qr_code_url: 'otpauth://...', secret: 'SECRET123', backup_codes: ['12345678', '87654321'] };
      mockedAxios.post.mockResolvedValueOnce({ data: twoFAData });
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      let data;
      await act(async () => { data = await result.current.setupTwoFA(); });
      expect(data).toEqual(twoFAData);
      expect(mockedAxios.post).toHaveBeenCalledWith('/api/auth/2fa/setup');
    });

    it('should throw error on setup failure', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Setup failed'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await expect(result.current.setupTwoFA()).rejects.toThrow('Setup failed');
    });
  });

  describe('completeTwoFASetup', () => {
    it('should complete 2FA setup successfully', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };
      mockedAxios.post.mockResolvedValueOnce({ data: {} });
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      act(() => {
        result.current.setUser(testUser);
        result.current.setRequiresTwoFASetup(true);
      });
      await act(async () => {
        await result.current.completeTwoFASetup('SECRET123', '123456');
      });
      expect(result.current.user?.two_fa_enabled).toBe(true);
      expect(result.current.requiresTwoFASetup).toBe(false);
    });

    it('should throw error on completion failure', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Confirmation failed'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await expect(result.current.completeTwoFASetup('SECRET123', '000000')).rejects.toThrow('Confirmation failed');
    });
  });

  describe('disableTwoFA', () => {
    it('should disable 2FA successfully', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: true };
      mockedAxios.post.mockResolvedValueOnce({ data: {} });
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      act(() => result.current.setUser(testUser));
      await act(async () => {
        await result.current.disableTwoFA('password123');
      });
      expect(result.current.user?.two_fa_enabled).toBe(false);
    });

    it('should throw error on disable failure', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Disable failed'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      await expect(result.current.disableTwoFA('wrong')).rejects.toThrow('Disable failed');
    });
  });

  describe('resetTwoFASetupFlag', () => {
    it('should reset 2FA setup flag', () => {
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      act(() => result.current.setRequiresTwoFASetup(true));
      expect(result.current.requiresTwoFASetup).toBe(true);
      act(() => result.current.resetTwoFASetupFlag());
      expect(result.current.requiresTwoFASetup).toBe(false);
    });
  });

  describe('setters', () => {
    it('should set token', () => {
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      act(() => result.current.setToken('new-token'));
      expect(result.current.token).toBe('new-token');
    });

    it('should set user', () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      act(() => result.current.setUser(testUser));
      expect(result.current.user).toEqual(testUser);
    });

    it('should set requiresTwoFASetup', () => {
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      act(() => result.current.setRequiresTwoFASetup(true));
      expect(result.current.requiresTwoFASetup).toBe(true);
    });
  });

  describe('useAuth hook error', () => {
    it('should throw error when used outside AuthProvider', () => {
      expect(() => renderHook(() => useAuth())).toThrow('useAuth must be used within an AuthProvider');
    });
  });

  // Aggiungi questi test alla fine del file, prima dell'ultimo describe
  describe('Error logging', () => {
    it('should log error when login fails', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      mockedAxios.post.mockRejectedValueOnce(new Error('Network error'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      await expect(result.current.login('test@example.com', 'wrong')).rejects.toThrow('Network error');
      
      // Verifica che console.error sia stato chiamato
      expect(consoleSpy).toHaveBeenCalledWith('Login failed:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });

    it('should log error when OTP verification fails', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      mockedAxios.post.mockRejectedValueOnce(new Error('OTP error'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      await expect(result.current.verifyOTP('test@example.com', '000000')).rejects.toThrow('OTP error');
      
      // Verifica che console.error sia stato chiamato
      expect(consoleSpy).toHaveBeenCalledWith('OTP verification failed:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });

    it('should log error when 2FA setup fails', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      mockedAxios.post.mockRejectedValueOnce(new Error('Setup error'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      await expect(result.current.setupTwoFA()).rejects.toThrow('Setup error');
      
      // Verifica che console.error sia stato chiamato
      expect(consoleSpy).toHaveBeenCalledWith('2FA setup failed:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });

    it('should log error when 2FA confirmation fails', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      mockedAxios.post.mockRejectedValueOnce(new Error('Confirmation error'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      await expect(result.current.completeTwoFASetup('SECRET123', '000000')).rejects.toThrow('Confirmation error');
      
      // Verifica che console.error sia stato chiamato
      expect(consoleSpy).toHaveBeenCalledWith('2FA confirmation failed:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });

    it('should log error when 2FA disable fails', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      mockedAxios.post.mockRejectedValueOnce(new Error('Disable error'));
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      await expect(result.current.disableTwoFA('wrong')).rejects.toThrow('Disable error');
      
      // Verifica che console.error sia stato chiamato
      expect(consoleSpy).toHaveBeenCalledWith('2FA disable failed:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });
  });
  
  describe('Edge cases', () => {
    it('should handle login with 2FA setup but no token in response', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };

      mockedAxios.post.mockResolvedValueOnce({
        data: { 
          requires_2fa_setup: true, 
          // NO token in response
          user: testUser 
        },
      });

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await act(async () => {
        await result.current.login('test@example.com', 'password123');
      });

      expect(result.current.requiresTwoFASetup).toBe(true);
      expect(result.current.token).toBeNull(); // Token should remain null
      expect(result.current.user).toBeNull(); // User should remain null
      expect(localStorage.getItem('authToken')).toBeNull();
    });

    it('should handle completeTwoFASetup when user is null', async () => {
      mockedAxios.post.mockResolvedValueOnce({ data: {} });
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      // Ensure user is null
      act(() => result.current.setUser(null));
      
      await act(async () => {
        await result.current.completeTwoFASetup('SECRET123', '123456');
      });
      
      // Should not crash even when user is null
      expect(mockedAxios.post).toHaveBeenCalled();
      expect(result.current.user).toBeNull();
    });

    it('should handle disableTwoFA when user is null', async () => {
      mockedAxios.post.mockResolvedValueOnce({ data: {} });
      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
      
      // Ensure user is null
      act(() => result.current.setUser(null));
      
      await act(async () => {
        await result.current.disableTwoFA('password123');
      });
      
      // Should not crash even when user is null
      expect(mockedAxios.post).toHaveBeenCalled();
      expect(result.current.user).toBeNull();
    });

    it('should handle verifyOTP with empty email', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: true };

      mockedAxios.post.mockResolvedValueOnce({
        data: { token: 'verified-token', user: testUser },
      });

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      act(() => {
        result.current.setRequiresTwoFA(true);
        result.current.setCurrentUserEmail('');
      });

      await act(async () => {
        await result.current.verifyOTP('', '123456');
      });

      expect(mockedAxios.post).toHaveBeenCalledWith('/api/auth/verify-otp', {
        email: '',
        otp_code: '123456',
        backup_code: '',
      });
    });

    it('should handle logout when no token in axios headers', async () => {
      const testUser = { id: 1, email: 'test@example.com', name: 'Test', role: 'user', two_fa_enabled: false };
      localStorage.setItem('authToken', 'test-token');
      localStorage.setItem('authUser', JSON.stringify(testUser));

      const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });

      await waitFor(() => expect(result.current.isLoading).toBe(false));

      // Remove authorization header before logout
      delete axios.defaults.headers.common['Authorization'];

      act(() => result.current.logout());

      expect(result.current.user).toBeNull();
      expect(result.current.token).toBeNull();
      expect(localStorage.getItem('authToken')).toBeNull();
      expect(localStorage.getItem('authUser')).toBeNull();
      expect(axios.defaults.headers.common['Authorization']).toBeUndefined();
    });
  });

});

