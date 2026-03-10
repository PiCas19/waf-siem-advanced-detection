export const parseJWT = (token: string) => {
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch {
    return null;
  }
};

// Returns true if the token is expired or will expire within 30 seconds.
export const isTokenExpired = (token: string): boolean => {
  const payload = parseJWT(token);
  if (!payload || typeof payload.exp !== 'number') return true;
  return Date.now() / 1000 > payload.exp - 30;
};