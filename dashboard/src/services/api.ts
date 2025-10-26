import axios from 'axios';

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