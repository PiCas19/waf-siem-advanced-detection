import { useQuery } from '@tanstack/react-query';
import { fetchBlocklist } from '@/services/api';

export default function BlockedIPs() {
  const { data: ips = [] } = useQuery({
    queryKey: ['blocklist'],
    queryFn: fetchBlocklist,
  });

  return (
    <div className="bg-gray-800 p-6 rounded-lg">
      <h2 className="text-xl font-semibold mb-4">Blocked IPs</h2>
      <div className="space-y-2">
        {ips.length === 0 ? (
          <p className="text-gray-400">No IPs blocked</p>
        ) : (
          ips.map((ip: string) => (
            <div key={ip} className="p-2 bg-red-900 bg-opacity-50 rounded">
              {ip}
            </div>
          ))
        )}
      </div>
    </div>
  );
}