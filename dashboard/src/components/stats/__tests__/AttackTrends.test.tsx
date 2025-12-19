import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import AttackTrends from '../AttackTrends';

// Mock del componente Card
vi.mock('@/components/common/Card', () => ({
  Card: ({ children, title }: { children: React.ReactNode; title: string }) => (
    <div data-testid="card">
      <h3>{title}</h3>
      {children}
    </div>
  ),
}));

// Mock di Recharts per evitare problemi con il rendering SVG
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children, width, height }: any) => (
    <div data-testid="responsive-container" style={{ width, height }}>
      {children}
    </div>
  ),
  LineChart: ({ children, data }: any) => (
    <div data-testid="line-chart">
      {children}
      <div data-testid="chart-data">{JSON.stringify(data)}</div>
    </div>
  ),
  Line: ({ dataKey, stroke, strokeWidth }: any) => (
    <div data-testid="line" data-key={dataKey} data-stroke={stroke} data-stroke-width={strokeWidth} />
  ),
  XAxis: ({ dataKey }: any) => <div data-testid="x-axis" data-key={dataKey} />,
  YAxis: () => <div data-testid="y-axis" />,
  CartesianGrid: ({ strokeDasharray }: any) => (
    <div data-testid="cartesian-grid" data-dasharray={strokeDasharray} />
  ),
  Tooltip: () => <div data-testid="tooltip" />,
}));

describe('AttackTrends', () => {
  it('renders with correct title', () => {
    render(<AttackTrends />);
    expect(screen.getByText('Attack Trends (24h)')).toBeInTheDocument();
  });

  it('renders chart components', () => {
    render(<AttackTrends />);

    expect(screen.getByTestId('responsive-container')).toBeInTheDocument();
    expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    expect(screen.getByTestId('line')).toBeInTheDocument();
    expect(screen.getByTestId('x-axis')).toBeInTheDocument();
    expect(screen.getByTestId('y-axis')).toBeInTheDocument();
    expect(screen.getByTestId('cartesian-grid')).toBeInTheDocument();
    expect(screen.getByTestId('tooltip')).toBeInTheDocument();
  });

  it('line component has correct props', () => {
    render(<AttackTrends />);
    
    const line = screen.getByTestId('line');
    expect(line.getAttribute('data-key')).toBe('threats');
    expect(line.getAttribute('data-stroke')).toBe('#ef4444');
    expect(line.getAttribute('data-stroke-width')).toBe('2');
  });

  it('cartesian grid has correct props', () => {
    render(<AttackTrends />);
    
    const grid = screen.getByTestId('cartesian-grid');
    expect(grid.getAttribute('data-dasharray')).toBe('3 3');
  });

  it('shows chart data', () => {
    render(<AttackTrends />);
    
    const dataElement = screen.getByTestId('chart-data');
    const data = JSON.parse(dataElement.textContent || '[]');
    
    expect(data).toHaveLength(6);
    expect(data[0]).toEqual({ time: '00:00', threats: 2 });
    expect(data[3]).toEqual({ time: '12:00', threats: 8 });
    expect(data[5]).toEqual({ time: '20:00', threats: 6 });
  });
});