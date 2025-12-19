import { describe, it, expect, beforeEach, vi } from 'vitest';
import axios from 'axios';
import { login, register } from '../auth';

// Mock axios
vi.mock('axios');

describe('auth', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('login', () => {
    it('should call axios.post with correct endpoint and credentials', async () => {
      const username = 'testuser';
      const password = 'testpass123';
      const mockResponse = { data: { token: 'mock-token', user: { id: 1, username } } };

      (axios.post as any).mockResolvedValue(mockResponse);

      const result = await login(username, password);

      expect(axios.post).toHaveBeenCalledWith('/api/auth/login', {
        username,
        password,
      });
      expect(axios.post).toHaveBeenCalledTimes(1);
      expect(result).toEqual(mockResponse);
    });

    it('should handle different usernames and passwords', async () => {
      const credentials = [
        { username: 'admin', password: 'admin123' },
        { username: 'user@email.com', password: 'pass456' },
      ];

      (axios.post as any).mockResolvedValue({ data: { success: true } });

      for (const { username, password } of credentials) {
        await login(username, password);
        expect(axios.post).toHaveBeenCalledWith('/api/auth/login', {
          username,
          password,
        });
      }
    });

    it('should propagate axios errors', async () => {
      const error = new Error('Network error');
      (axios.post as any).mockRejectedValue(error);

      await expect(login('user', 'pass')).rejects.toThrow('Network error');
    });

    it('should handle empty credentials', async () => {
      (axios.post as any).mockResolvedValue({ data: {} });

      await login('', '');

      expect(axios.post).toHaveBeenCalledWith('/api/auth/login', {
        username: '',
        password: '',
      });
    });
  });

  describe('register', () => {
    it('should call axios.post with correct endpoint and credentials', async () => {
      const username = 'newuser';
      const password = 'newpass123';
      const mockResponse = { data: { success: true, user: { id: 2, username } } };

      (axios.post as any).mockResolvedValue(mockResponse);

      const result = await register(username, password);

      expect(axios.post).toHaveBeenCalledWith('/api/auth/register', {
        username,
        password,
      });
      expect(axios.post).toHaveBeenCalledTimes(1);
      expect(result).toEqual(mockResponse);
    });

    it('should handle registration with various inputs', async () => {
      const testCases = [
        { username: 'john.doe@example.com', password: 'SecurePass123!' },
        { username: 'admin2025', password: 'P@ssw0rd' },
      ];

      (axios.post as any).mockResolvedValue({ data: { success: true } });

      for (const { username, password } of testCases) {
        await register(username, password);
        expect(axios.post).toHaveBeenCalledWith('/api/auth/register', {
          username,
          password,
        });
      }
    });

    it('should propagate registration errors', async () => {
      const error = new Error('User already exists');
      (axios.post as any).mockRejectedValue(error);

      await expect(register('existing', 'pass')).rejects.toThrow('User already exists');
    });

    it('should handle validation errors from server', async () => {
      const validationError = {
        response: {
          status: 400,
          data: { error: 'Password too weak' },
        },
      };
      (axios.post as any).mockRejectedValue(validationError);

      await expect(register('user', 'weak')).rejects.toEqual(validationError);
    });
  });

  describe('integration', () => {
    it('should handle login and register with same credentials', async () => {
      const username = 'testuser';
      const password = 'testpass';

      (axios.post as any)
        .mockResolvedValueOnce({ data: { success: true } })
        .mockResolvedValueOnce({ data: { token: 'login-token' } });

      await register(username, password);
      await login(username, password);

      expect(axios.post).toHaveBeenNthCalledWith(1, '/api/auth/register', {
        username,
        password,
      });
      expect(axios.post).toHaveBeenNthCalledWith(2, '/api/auth/login', {
        username,
        password,
      });
    });
  });
});
