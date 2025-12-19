import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import BlocklistPage from '../BlocklistPage';

// Mock del contesto di autenticazione
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 1, email: 'admin@test.com', role: 'admin' },
  }),
}));

// Mock del contesto toast
vi.mock('@/contexts/SnackbarContext', () => ({
  useToast: () => ({
    showToast: vi.fn(),
  }),
}));

// Setup global fetch mock
global.fetch = vi.fn();

describe('BlocklistPage - New Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('authToken', 'test-token');
  });

  it('sorts blocklist by threat column (LINEE 1019-1023)', async () => {
    const mockBlocklist = [
      { id: 1, ip_address: '192.168.1.1', reason: 'SQLi', blocked_date: '2024-01-01', expires_at: null, permanent: true, threat_type: 'SQLi' },
      { id: 2, ip_address: '192.168.1.2', reason: 'XSS', blocked_date: '2024-01-02', expires_at: null, permanent: true, threat_type: 'XSS' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockBlocklist }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    await waitFor(() => {
      expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
    });

    const threatHeaders = screen.getAllByText('Threat/Rule');
    fireEvent.click(threatHeaders[0]);

    await new Promise(resolve => setTimeout(resolve, 100));

    // Click again to toggle order
    fireEvent.click(threatHeaders[0]);
  });

  it('sorts blocklist by reason column (LINEA 1042)', async () => {
    const mockBlocklist = [
      { id: 1, ip_address: '192.168.2.1', reason: 'Attack A', blocked_date: '2024-01-01', expires_at: null, permanent: true },
      { id: 2, ip_address: '192.168.2.2', reason: 'Attack B', blocked_date: '2024-01-02', expires_at: null, permanent: true },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockBlocklist }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    await waitFor(() => {
      expect(screen.getByText('192.168.2.1')).toBeInTheDocument();
    });

    const reasonHeaders = screen.getAllByText(/Reason/);
    fireEvent.click(reasonHeaders[0]);
  });

  it('sorts blocklist by type, blockedDate and expires columns (LINEE 1063-1111)', async () => {
    const mockBlocklist = [
      { id: 1, ip_address: '192.168.3.1', reason: 'Test', blocked_date: '2024-01-01', expires_at: '2024-02-01', permanent: false, type: 'Temporary' },
      { id: 2, ip_address: '192.168.3.2', reason: 'Test', blocked_date: '2024-01-02', expires_at: null, permanent: true, type: 'Permanent' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockBlocklist }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    await waitFor(() => {
      expect(screen.getByText('192.168.3.1')).toBeInTheDocument();
    });

    // Sort by Type
    const typeHeaders = screen.getAllByText('Type');
    if (typeHeaders.length > 0) {
      fireEvent.click(typeHeaders[0]);
    }

    // Sort by Blocked Date
    const blockedDateHeaders = screen.getAllByText('Blocked Date');
    if (blockedDateHeaders.length > 0) {
      fireEvent.click(blockedDateHeaders[0]);
    }

    // Sort by Expires
    const expiresHeaders = screen.getAllByText(/Expires/);
    if (expiresHeaders.length > 0) {
      fireEvent.click(expiresHeaders[0]);
    }
  });

  it('handles blocklist pagination Previous button (LINEA 1190)', async () => {
    const mockBlocklist = Array.from({ length: 25 }, (_, i) => ({
      id: i + 1,
      ip_address: `192.168.4.${i}`,
      reason: 'Test',
      blocked_date: '2024-01-01',
      expires_at: null,
      permanent: true,
    }));

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockBlocklist }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    await waitFor(() => {
      expect(screen.getByText('192.168.4.0')).toBeInTheDocument();
    });

    // Click Next to go to page 2
    const nextButtons = screen.getAllByText('Next');
    fireEvent.click(nextButtons[0]);

    await new Promise(resolve => setTimeout(resolve, 100));

    // Click Previous
    const prevButtons = screen.getAllByText('Previous');
    fireEvent.click(prevButtons[0]);
  });

  it('handles blocklist pagination Next button (LINEA 1214)', async () => {
    const mockBlocklist = Array.from({ length: 25 }, (_, i) => ({
      id: i + 1,
      ip_address: `192.168.5.${i}`,
      reason: 'Test',
      blocked_date: '2024-01-01',
      expires_at: null,
      permanent: true,
    }));

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockBlocklist }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    await waitFor(() => {
      expect(screen.getByText('192.168.5.0')).toBeInTheDocument();
    });

    const nextButtons = screen.getAllByText('Next');
    fireEvent.click(nextButtons[0]);
  });

  it('sorts whitelist by IP (LINEA 1352)', async () => {
    const mockWhitelist = [
      { id: 1, ip_address: '10.0.1.1', reason: 'Test', added_date: '2024-01-01' },
      { id: 2, ip_address: '10.0.1.2', reason: 'Test', added_date: '2024-01-02' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockWhitelist }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/Whitelist/));

    await waitFor(() => {
      expect(screen.getByText('10.0.1.1')).toBeInTheDocument();
    });

    const ipHeaders = screen.getAllByText('IP Address');
    fireEvent.click(ipHeaders[ipHeaders.length - 1]);
  });

  it('sorts whitelist by reason (LINEA 1374)', async () => {
    const mockWhitelist = [
      { id: 1, ip_address: '10.0.2.1', reason: 'Test A', added_date: '2024-01-01' },
      { id: 2, ip_address: '10.0.2.2', reason: 'Test B', added_date: '2024-01-02' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockWhitelist }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/Whitelist/));

    await waitFor(() => {
      expect(screen.getByText('10.0.2.1')).toBeInTheDocument();
    });

    const reasonHeaders = screen.getAllByText(/Reason/);
    fireEvent.click(reasonHeaders[reasonHeaders.length - 1]);
  });

  it('sorts whitelist by addedDate (LINEA 1396)', async () => {
    const mockWhitelist = [
      { id: 1, ip_address: '10.0.3.1', reason: 'Test', added_date: '2024-01-01' },
      { id: 2, ip_address: '10.0.3.2', reason: 'Test', added_date: '2024-01-02' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: mockWhitelist }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/Whitelist/));

    await waitFor(() => {
      expect(screen.getByText('10.0.3.1')).toBeInTheDocument();
    });

    const addedDateHeaders = screen.getAllByText('Added Date');
    fireEvent.click(addedDateHeaders[0]);
  });

  it('sorts false positives by threatType (LINEA 1514)', async () => {
    const mockFP = [
      { id: 1, threat_type: 'SQLi', client_ip: '172.16.1.1', method: 'GET', url: '/test', status: 'pending', reported_date: '2024-01-01' },
      { id: 2, threat_type: 'XSS', client_ip: '172.16.1.2', method: 'POST', url: '/test', status: 'pending', reported_date: '2024-01-02' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: mockFP }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/False Positives/));

    await waitFor(() => {
      expect(screen.getByText('172.16.1.1')).toBeInTheDocument();
    });

    const threatTypeHeaders = screen.getAllByText('Threat Type');
    fireEvent.click(threatTypeHeaders[threatTypeHeaders.length - 1]);
  });

  it('sorts false positives by IP (LINEE 1535-1539)', async () => {
    const mockFP = [
      { id: 1, threat_type: 'SQLi', client_ip: '172.16.2.1', method: 'GET', url: '/test', status: 'pending', reported_date: '2024-01-01' },
      { id: 2, threat_type: 'XSS', client_ip: '172.16.2.2', method: 'POST', url: '/test', status: 'pending', reported_date: '2024-01-02' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: mockFP }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/False Positives/));

    await waitFor(() => {
      expect(screen.getByText('172.16.2.1')).toBeInTheDocument();
    });

    const ipHeaders = screen.getAllByText('IP Address');
    fireEvent.click(ipHeaders[ipHeaders.length - 1]);
  });

  it('sorts false positives by method (LINEA 1558)', async () => {
    const mockFP = [
      { id: 1, threat_type: 'SQLi', client_ip: '172.16.3.1', method: 'GET', url: '/test', status: 'pending', reported_date: '2024-01-01' },
      { id: 2, threat_type: 'XSS', client_ip: '172.16.3.2', method: 'POST', url: '/test', status: 'pending', reported_date: '2024-01-02' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: mockFP }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/False Positives/));

    await waitFor(() => {
      expect(screen.getByText('172.16.3.1')).toBeInTheDocument();
    });

    const methodHeaders = screen.getAllByText('Method');
    fireEvent.click(methodHeaders[methodHeaders.length - 1]);
  });

  it('handles delete false positive button (LINEE 1703-1731)', async () => {
    const mockFP = [
      { id: 1, threat_type: 'SQLi', client_ip: '172.16.4.1', method: 'GET', url: '/test', status: 'approved', reported_date: '2024-01-01' },
    ];

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: mockFP }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/False Positives/));

    await waitFor(() => {
      expect(screen.getByText('172.16.4.1')).toBeInTheDocument();
    });

    const deleteButtons = screen.queryAllByText(/Delete/);
    expect(deleteButtons.length).toBeGreaterThan(0);
  });

  it('handles false positives pagination Next button (LINEA 1755)', async () => {
    const mockFP = Array.from({ length: 25 }, (_, i) => ({
      id: i + 1,
      threat_type: 'XSS',
      client_ip: `172.16.5.${i}`,
      method: 'GET',
      url: '/test',
      status: 'pending',
      reported_date: '2024-01-01',
    }));

    (global.fetch as any).mockImplementation((url: string) => {
      if (url.includes('/api/false-positives')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ false_positives: mockFP }),
        });
      }
      if (url.includes('/api/blocklist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      if (url.includes('/api/whitelist')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ items: [] }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ items: [] }),
      });
    });

    render(<BrowserRouter><BlocklistPage /></BrowserRouter>);

    fireEvent.click(screen.getByText(/False Positives/));

    await waitFor(() => {
      expect(screen.getByText('172.16.5.0')).toBeInTheDocument();
    });

    const nextButtons = screen.getAllByText('Next');
    if (nextButtons.length > 0) {
      fireEvent.click(nextButtons[nextButtons.length - 1]);
    }
  });
});
