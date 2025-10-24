import axios from 'axios';

export const login = (username: string, password: string) =>
  axios.post('/api/auth/login', { username, password });

export const register = (username: string, password: string) =>
  axios.post('/api/auth/register', { username, password });