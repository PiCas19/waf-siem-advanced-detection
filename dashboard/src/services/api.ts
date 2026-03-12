import axios, { AxiosRequestConfig } from 'axios';

const api = axios.create({
  baseURL: '/api',
});

// Add token to all requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('authToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// --- 401 response interceptor: auto-refresh and retry ---
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (err: unknown) => void;
}> = [];

const processQueue = (error: unknown, token: string | null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else resolve(token!);
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error);
    }

    // Do not attempt refresh for the refresh endpoint itself
    if (originalRequest.url === '/auth/refresh') {
      localStorage.removeItem('authToken');
      localStorage.removeItem('authRefreshToken');
      window.location.href = '/login';
      return Promise.reject(error);
    }

    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      }).then((token) => {
        originalRequest.headers = { ...(originalRequest.headers ?? {}), Authorization: `Bearer ${token}` };
        return api(originalRequest);
      });
    }

    originalRequest._retry = true;
    isRefreshing = true;

    const storedRefresh = localStorage.getItem('authRefreshToken');
    if (!storedRefresh) {
      isRefreshing = false;
      localStorage.removeItem('authToken');
      localStorage.removeItem('authUser');
      localStorage.removeItem('authRefreshToken');
      window.location.href = '/login';
      return Promise.reject(error);
    }

    try {
      const { data } = await axios.post('/api/auth/refresh', { refresh_token: storedRefresh });
      const { token: newToken, refresh_token: newRefreshToken } = data;
      localStorage.setItem('authToken', newToken);
      if (newRefreshToken) localStorage.setItem('authRefreshToken', newRefreshToken);
      axios.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
      processQueue(null, newToken);
      originalRequest.headers = { ...(originalRequest.headers ?? {}), Authorization: `Bearer ${newToken}` };
      return api(originalRequest);
    } catch (refreshError) {
      processQueue(refreshError, null);
      localStorage.removeItem('authToken');
      localStorage.removeItem('authRefreshToken');
      window.location.href = '/login';
      return Promise.reject(refreshError);
    } finally {
      isRefreshing = false;
    }
  }
);

export const fetchStats = () => api.get('/stats').then(res => res.data);

// Rules API
export const fetchRules = () => api.get('/rules').then(res => res.data);
export const createRule = (rule: any) => api.post('/rules', rule).then(res => res.data);
export const updateRule = (id: string, rule: any) => api.put(`/rules/${id}`, rule).then(res => res.data);
export const deleteRule = (id: string) => api.delete(`/rules/${id}`).then(res => res.data);
export const toggleRule = (id: string) => api.patch(`/rules/${id}/toggle`).then(res => res.data);

// Blocklist API
export const fetchLogs = () => api.get('/logs').then(res => res.data);
export const fetchBlocklist = () => api.get('/blocklist').then(res => res.data);
export const blockIP = (ip: string, reason: string, permanent: boolean = false) =>
  api.post('/blocklist', { ip, reason, permanent }).then(res => res.data);
export const unblockIP = (ip: string) => api.delete(`/blocklist/${ip}`).then(res => res.data);
