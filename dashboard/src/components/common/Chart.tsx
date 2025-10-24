import { ResponsiveContainer } from 'recharts';

export default function Chart({ children }: { children: React.ReactNode }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      {children}
    </ResponsiveContainer>
  );
}