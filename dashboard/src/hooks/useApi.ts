export const useApi = <T>(_key: string[], _fn: () => Promise<T>) => {
  // Hook disabled - using WebSocket for real-time updates instead
  return { data: null, isLoading: false, error: null };
};