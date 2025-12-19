import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import Stats from '../Stats';

// Crea una variabile mock che possiamo modificare nei test
let mockStats = {
  stats: {
    threats_detected: 0,
    requests_blocked: 0,
    total_requests: 0,
  },
  isConnected: false,
};

// Mock con una factory function che ritorna i valori correnti
vi.mock('@/hooks/useWebSocketStats', () => ({
  useWebSocketStats: () => mockStats,
}));

describe('Stats', () => {
  beforeEach(() => {
    // Reset ai valori di default prima di ogni test
    mockStats = {
      stats: {
        threats_detected: 0,
        requests_blocked: 0,
        total_requests: 0,
      },
      isConnected: false,
    };
  });

  it('renders with connected status and stats', () => {
    mockStats = {
      stats: {
        threats_detected: 42,
        requests_blocked: 15,
        total_requests: 1000,
      },
      isConnected: true,
    };

    render(<Stats />);

    expect(screen.getByText('Threats Detected')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('Requests Blocked')).toBeInTheDocument();
    expect(screen.getByText('15')).toBeInTheDocument();
    expect(screen.getByText('Total Requests')).toBeInTheDocument();
    expect(screen.getByText('1000')).toBeInTheDocument();
    expect(screen.getByText('Live')).toBeInTheDocument();
  });

 it('renders with disconnected status', () => {
  mockStats = {
    stats: {
      threats_detected: 0,
      requests_blocked: 0,
      total_requests: 0,
    },
    isConnected: false,
  };

  render(<Stats />);

  expect(screen.getByText('Threats Detected')).toBeInTheDocument();
  
  // Usa querySelector più specifico per ogni valore
  const threatsCard = screen.getByText('Threats Detected').closest('div.bg-gray-800');
  const threatsValue = threatsCard?.querySelector('.text-red-500');
  expect(threatsValue).toHaveTextContent('0');
  
  expect(screen.getByText('Offline')).toBeInTheDocument();
});

  it('applies correct text colors for stats', () => {
    mockStats = {
      stats: {
        threats_detected: 42,
        requests_blocked: 15,
        total_requests: 1000,
      },
      isConnected: true,
    };

    render(<Stats />);

    const threatsElement = screen.getByText('42');
    const blockedElement = screen.getByText('15');
    const totalElement = screen.getByText('1000');

    expect(threatsElement).toHaveClass('text-red-500');
    expect(blockedElement).toHaveClass('text-yellow-500');
    expect(totalElement).toHaveClass('text-green-500');
  });

  it('renders with grid layout', () => {
    mockStats = {
      stats: {
        threats_detected: 42,
        requests_blocked: 15,
        total_requests: 1000,
      },
      isConnected: true,
    };

    const { container } = render(<Stats />);

    const grid = container.firstChild;
    expect(grid).toHaveClass('grid');
    expect(grid).toHaveClass('grid-cols-1');
    expect(grid).toHaveClass('md:grid-cols-3');
    expect(grid).toHaveClass('gap-6');
  });

  it('shows circle icon with correct status when connected', () => {
    mockStats = {
      stats: {
        threats_detected: 42,
        requests_blocked: 15,
        total_requests: 1000,
      },
      isConnected: true,
    };

    render(<Stats />);

    expect(screen.getByText('Live')).toBeInTheDocument();
    
    // Per verificare l'icona, cerca il SVG nel paragrafo
    const liveParagraph = screen.getByText('Live').closest('p');
    const svgElement = liveParagraph?.querySelector('svg');
    expect(svgElement).toBeInTheDocument();
  });

  it('shows circle icon with correct status when disconnected', () => {
    mockStats = {
      stats: {
        threats_detected: 0,
        requests_blocked: 0,
        total_requests: 0,
      },
      isConnected: false,
    };

    render(<Stats />);

    expect(screen.getByText('Offline')).toBeInTheDocument();
    
    const offlineParagraph = screen.getByText('Offline').closest('p');
    const svgElement = offlineParagraph?.querySelector('svg');
    expect(svgElement).toBeInTheDocument();
  });

  it('renders all three stat cards', () => {
    mockStats = {
      stats: {
        threats_detected: 42,
        requests_blocked: 15,
        total_requests: 1000,
      },
      isConnected: true,
    };

    render(<Stats />);

    // Verifica che tutte e tre le card siano presenti
    const headings = screen.getAllByRole('heading', { level: 2 });
    expect(headings).toHaveLength(3);
    expect(headings[0]).toHaveTextContent('Threats Detected');
    expect(headings[1]).toHaveTextContent('Requests Blocked');
    expect(headings[2]).toHaveTextContent('Total Requests');
  });
});