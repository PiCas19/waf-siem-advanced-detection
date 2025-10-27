import { useQuery } from '@tanstack/react-query';
import { fetchLogs } from '@/services/api';

export default function LogViewer() {
  const { data: logs = [] } = useQuery({
    queryKey: ['logs'],
    queryFn: fetchLogs,
  });

  return (
    <div className="bg-gray-800 p-6 rounded-lg">
      <h2 className="text-xl font-semibold mb-4">Log Viewer</h2>
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {logs.length === 0 ? (
          <p className="text-gray-400">No logs available</p>
        ) : (
          logs.slice(0, 50).map((log: any, i: number) => (
            <div key={i} className="text-xs p-2 bg-gray-700 rounded">
              [{log.timestamp}] {log.threat_type} from {log.client_ip}
            </div>
          ))
        )}
      </div>
    </div>
  );
}