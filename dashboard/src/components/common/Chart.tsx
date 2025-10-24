import { ResponsiveContainer } from 'recharts';
import type { ReactElement } from 'react';

interface ChartProps {
  children: ReactElement;
}

export default function Chart({ children }: ChartProps) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      {children}
    </ResponsiveContainer>
  );
}