import { useWebSocket } from '@/hooks/useWebSocket';
import { Card } from '@/components/common/Card';

export default function RealtimeAlerts() {
  const { lastEvent } = useWebSocket();

  return (
    <Card title="Realtime Alerts">
      {lastEvent ? (
        <div className="space-y-2">
          <p className="text-red-400 font-semibold">{lastEvent.threat.toUpperCase()}</p>
          <p className="text-sm text-gray-400">IP: {lastEvent.ip}</p>
          <p className="text-xs text-gray-500">{new Date(lastEvent.timestamp).toLocaleString()}</p>
        </div>
      ) : (
        <p className="text-gray-400">No recent alerts</p>
      )}
    </Card>
  );
}