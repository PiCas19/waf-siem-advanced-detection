import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import RealtimeAlerts from '../RealtimeAlerts';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock del hook useWebSocket
vi.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: vi.fn(),
}));

// Mock del componente Card
vi.mock('@/components/common/Card', () => ({
  Card: ({ children, title }: { children: React.ReactNode; title: string }) => (
    <div data-testid="card">
      <h3>{title}</h3>
      {children}
    </div>
  ),
}));

describe('RealtimeAlerts', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders with no recent alerts', () => {
    // Usa el mock importado directamente
    vi.mocked(useWebSocket).mockReturnValue({ lastEvent: null });

    render(<RealtimeAlerts />);

    expect(screen.getByText('Realtime Alerts')).toBeInTheDocument();
    expect(screen.getByText('No recent alerts')).toBeInTheDocument();
  });

  it('renders with recent alert', () => {
    const mockEvent = {
      threat: 'XSS',
      ip: '192.168.1.100',
      timestamp: '2024-01-01T12:00:00Z',
    };

    // Usa el mock importado directamente
    vi.mocked(useWebSocket).mockReturnValue({ lastEvent: mockEvent });

    render(<RealtimeAlerts />);

    expect(screen.getByText('Realtime Alerts')).toBeInTheDocument();
    expect(screen.getByText('XSS')).toBeInTheDocument();
    expect(screen.getByText('IP: 192.168.1.100')).toBeInTheDocument();
    
    // Verifica la formattazione della data
    const dateString = new Date(mockEvent.timestamp).toLocaleString();
    expect(screen.getByText(dateString)).toBeInTheDocument();
  });

  it('renders threat in uppercase', () => {
    const mockEvent = {
      threat: 'sql injection',
      ip: '10.0.0.1',
      timestamp: '2024-01-01T12:00:00Z',
    };

    // Usa el mock importado directamente
    vi.mocked(useWebSocket).mockReturnValue({ lastEvent: mockEvent });

    render(<RealtimeAlerts />);

    expect(screen.getByText('SQL INJECTION')).toBeInTheDocument();
  });
});