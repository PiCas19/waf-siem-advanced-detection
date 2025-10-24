import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
});

export const fetchStats = () => api.get('/stats').then(res => res.data);
export const fetchRules = () => api.get('/rules').then(res => res.data);
export const fetchLogs = () => api.get('/logs').then(res => res.data);
export const fetchBlocklist = () => api.get('/blocklist').then(res => res.data);