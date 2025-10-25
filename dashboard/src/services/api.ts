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
export const fetchRules = () => api.get('/rules').then(res => res.data);
export const fetchLogs = () => api.get('/logs').then(res => res.data);
export const fetchBlocklist = () => api.get('/blocklist').then(res => res.data);