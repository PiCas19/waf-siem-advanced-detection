import Stats from './Stats';
import RealtimeAlerts from './RealtimeAlerts';
import AttackTrends from './AttackTrends';

export default function Dashboard() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Dashboard</h1>
      <Stats />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RealtimeAlerts />
        <AttackTrends />
      </div>
    </div>
  );
}