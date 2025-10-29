import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card } from '@/components/common/Card';

const data = [
  { time: '00:00', threats: 2 },
  { time: '04:00', threats: 1 },
  { time: '08:00', threats: 5 },
  { time: '12:00', threats: 8 },
  { time: '16:00', threats: 3 },
  { time: '20:00', threats: 6 },
];

export default function AttackTrends() {
  return (
    <Card title="Attack Trends (24h)">
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis />
          <Tooltip />
          <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} />
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
}