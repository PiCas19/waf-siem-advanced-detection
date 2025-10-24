import { create } from 'zustand';
import { login, register } from '@/services/auth';
import { storage } from '@/services/storage';

interface AuthState {
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

export const useAuth = create<AuthState>((set) => ({
  isAuthenticated: !!storage.getToken(),
  login: async (username, password) => {
    const res = await login(username, password);
    storage.setToken(res.data.token);
    set({ isAuthenticated: true });
  },
  register: async (username, password) => {
    await register(username, password);
  },
  logout: () => {
    storage.removeToken();
    set({ isAuthenticated: false });
  },
}));