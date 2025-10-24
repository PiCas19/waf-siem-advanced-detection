export const isValidIP = (ip: string) => {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
};

export const isValidEmail = (email: string) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};