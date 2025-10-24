import { useQuery } from '@tanstack/react-query';
import { fetchStats } from '@/services/api';

export default function Stats() {
  const { data: stats = { threats_detected: 0, requests_blocked: 0, total_requests: 0 } } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    refetchInterval: 5000,
  });

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div className="bg-gray-800 p-6 rounded-lg">
        <h2 className="text-lg font-semibold mb-2">Threats Detected</h2>
        <p className="text-3xl font-bold text-red-500">{stats.threats_detected}</p>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg">
        <h2 className="text-lg font-semibold mb-2">Requests Blocked</h2>
        <p className="text-3xl font-bold text-yellow-500">{stats.requests_blocked}</p>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg">
        <h2 className="text-lg font-semibold mb-2">Total Requests</h2>
        <p className="text-3xl font-bold text-green-500">{stats.total_requests}</p>
      </div>
    </div>
  );
}