import { useQuery } from '@tanstack/react-query';

export const useApi = <T>(key: string[], fn: () => Promise<T>) => {
  return useQuery({ queryKey: key, queryFn: fn });
};