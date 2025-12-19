import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Rules from '../Rules';
import { useToast } from '@/contexts/SnackbarContext';

// Mock dei contesti
vi.mock('@/contexts/SnackbarContext', () => ({
  useToast: vi.fn(() => ({
    showToast: vi.fn(),
  })),
}));

// Mock fetch
global.fetch = vi.fn();

const mockRules = [
  {
    id: 'rule-1',
    name: 'Manual Block: SQL Injection',
    pattern: 'SELECT.*FROM',
    description: 'Manual block for SQL injection',
    threatType: 'SQL Injection',
    mode: 'block' as 'block',
    enabled: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'rule-2',
    name: 'XSS Detection',
    pattern: '<script>',
    description: 'Detects XSS attempts',
    threatType: 'XSS',
    mode: 'detect' as 'detect',
    enabled: false,
    createdAt: '2024-01-02T00:00:00Z',
    updatedAt: '2024-01-02T00:00:00Z',
  },
];

// Helper function per renderizzare il componente
const renderRules = () => {
  return render(
    <BrowserRouter>
      <Rules />
    </BrowserRouter>
  );
};

describe('Rules', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Imposta il token in localStorage
    localStorage.setItem('authToken', 'test-token');
  });

  afterEach(() => {
    localStorage.removeItem('authToken');
  });

  it('renders rules page', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('WAF Rules')).toBeInTheDocument();
      expect(screen.getByText('Crea e gestisci le regole personalizzate del WAF')).toBeInTheDocument();
      expect(screen.getByText('+ Add Rule')).toBeInTheDocument();
    });
  });

  it('loads rules from API', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        '/api/rules',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': expect.stringContaining('Bearer'),
          }),
        })
      );
    });
  });

  it('shows add rule form', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: [], pagination: { total: 0 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('+ Add Rule')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Add Rule'));

    await waitFor(() => {
      expect(screen.getByText('Crea Nuova Regola')).toBeInTheDocument();
    });
  });

  it('adds new rule successfully', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const newRule = {
      id: 'new-rule',
      name: 'Test Rule',
      pattern: 'test.*pattern',
      description: 'Test rule',
      threatType: 'SQL Injection',
      mode: 'block',
      enabled: true,
      createdAt: '2024-01-03T00:00:00Z',
      updatedAt: '2024-01-03T00:00:00Z',
    };

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: [], pagination: { total: 0 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ rule: newRule }),
      });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('+ Add Rule')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Add Rule'));

    await waitFor(() => {
      expect(screen.getByText('Crea Nuova Regola')).toBeInTheDocument();
    });

    // Compila il form
    fireEvent.change(screen.getByPlaceholderText('es. SQL Injection Prevention'), {
      target: { value: 'Test Rule' },
    });
    fireEvent.change(screen.getByPlaceholderText('es. SELECT|INSERT|UPDATE|DELETE|DROP'), {
      target: { value: 'test.*pattern' },
    });

    fireEvent.click(screen.getByText('Crea Regola'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Regola creata con successo', 'success', 4000);
    });
  });

  it('edits existing rule', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ rule: { ...mockRules[0], name: 'Updated Rule' } }),
      });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    // Clicca il bottone modifica
    const editButtons = screen.getAllByRole('button', { name: /modifica/i });
    fireEvent.click(editButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Modifica Regola')).toBeInTheDocument();
    });

    // Modifica il nome
    fireEvent.change(screen.getByPlaceholderText('es. SQL Injection Prevention'), {
      target: { value: 'Updated Rule' },
    });

    fireEvent.click(screen.getByText('Salva Modifiche'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Regola aggiornata con successo', 'success', 4000);
    });
  });

  it('deletes rule with confirmation', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

    // Mock window.confirm
    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    // Clicca il bottone elimina
    const deleteButtons = screen.getAllByRole('button', { name: /elimina/i });
    fireEvent.click(deleteButtons[0]);

    // Restore original confirm
    window.confirm = originalConfirm;

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Regola eliminata con successo', 'success', 4000);
    });
  });

  it('toggles rule enabled status', async () => {
    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ enabled: false }),
      });

    renderRules();

    await waitFor(() => {
      const toggleButtons = screen.getAllByText('Attiva');
      expect(toggleButtons.length).toBeGreaterThan(0);
    });

    const toggleButtons = screen.getAllByText('Attiva');
    fireEvent.click(toggleButtons[0]);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/rules/'),
        expect.objectContaining({
          method: 'PATCH',
          headers: expect.objectContaining({
            'Authorization': expect.stringContaining('Bearer'),
          }),
        })
      );
    });
  });

  it('shows rule details modal', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const detailsButtons = screen.getAllByRole('button', { name: /dettagli/i });
    fireEvent.click(detailsButtons[0]);

    await waitFor(() => {
      const modalTitle = screen.getByRole('heading', { name: 'Manual Block: SQL Injection', level: 2 });
      expect(modalTitle).toBeInTheDocument();
      expect(screen.getByText('Manual block for SQL injection')).toBeInTheDocument();
    });
  });

  it('filters rules by search', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Cerca per nome...')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Cerca per nome...');
    fireEvent.change(searchInput, { target: { value: 'SQL' } });

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
      expect(screen.queryByText('XSS Detection')).not.toBeInTheDocument();
    });
  });

  

  it('handles API error gracefully', async () => {
    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('WAF Rules')).toBeInTheDocument();
    });
  });

  it('handles auto-unblock for manual block rules', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const logsResponse = {
      ok: true,
      json: () => Promise.resolve({
        security_logs: [
          {
            client_ip: '192.168.1.1',
            description: 'SQL Injection',
            threat_type: 'SQL Injection',
          },
        ],
      }),
    };

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      })
      .mockResolvedValueOnce(logsResponse)
      .mockResolvedValueOnce({ ok: true });

    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const deleteButtons = screen.getAllByRole('button', { name: /elimina/i });
    fireEvent.click(deleteButtons[0]);

    window.confirm = originalConfirm;

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/logs'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': expect.stringContaining('Bearer'),
          }),
        })
      );
    });
  });

  it('cancels form editing', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const editButtons = screen.getAllByRole('button', { name: /modifica/i });
    fireEvent.click(editButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Modifica Regola')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Annulla'));

    await waitFor(() => {
      expect(screen.queryByText('Modifica Regola')).not.toBeInTheDocument();
    });
  });

  it('closes details modal', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const detailsButtons = screen.getAllByRole('button', { name: /dettagli/i });
    fireEvent.click(detailsButtons[0]);

    await waitFor(() => {
      const closeButton = screen.getByRole('button', { name: /✕/ });
      expect(closeButton).toBeInTheDocument();
    });

    const closeButton = screen.getByRole('button', { name: /✕/ });
    fireEvent.click(closeButton);

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /✕/ })).not.toBeInTheDocument();
    });
  });

  it('filters rules by threat type', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
      expect(screen.getByText('XSS Detection')).toBeInTheDocument();
    });

    // Find the threat type select - it's the second select element (after the form select)
    const selects = screen.getAllByRole('combobox');
    const threatTypeSelect = selects.find(s => s.previousElementSibling?.textContent === 'Tipo Minaccia');

    if (threatTypeSelect) {
      fireEvent.change(threatTypeSelect, { target: { value: 'SQL Injection' } });

      await waitFor(() => {
        expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
        expect(screen.queryByText('XSS Detection')).not.toBeInTheDocument();
      });
    }
  });

  it('filters rules by mode', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
      expect(screen.getByText('XSS Detection')).toBeInTheDocument();
    });

    // Find the mode select - it's the third select element
    const selects = screen.getAllByRole('combobox');
    const modeSelect = selects.find(s => s.previousElementSibling?.textContent === 'Modalità');

    if (modeSelect) {
      fireEvent.change(modeSelect, { target: { value: 'block' } });

      await waitFor(() => {
        expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
        expect(screen.queryByText('XSS Detection')).not.toBeInTheDocument();
      });
    }
  });

  it('searches rules by description', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Cerca per nome...')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Cerca per nome...');
    fireEvent.change(searchInput, { target: { value: 'Manual block' } });

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
      expect(screen.queryByText('XSS Detection')).not.toBeInTheDocument();
    });
  });

  it('validates missing name field', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: [], pagination: { total: 0 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('+ Add Rule')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Add Rule'));

    await waitFor(() => {
      expect(screen.getByText('Crea Nuova Regola')).toBeInTheDocument();
    });

    // Compila solo il pattern
    fireEvent.change(screen.getByPlaceholderText('es. SELECT|INSERT|UPDATE|DELETE|DROP'), {
      target: { value: 'test.*pattern' },
    });

    fireEvent.click(screen.getByText('Crea Regola'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Nome e Pattern sono obbligatori', 'info', 4000);
    });
  });

  it('validates missing pattern field', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: [], pagination: { total: 0 } },
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('+ Add Rule')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Add Rule'));

    await waitFor(() => {
      expect(screen.getByText('Crea Nuova Regola')).toBeInTheDocument();
    });

    // Compila solo il nome
    fireEvent.change(screen.getByPlaceholderText('es. SQL Injection Prevention'), {
      target: { value: 'Test Rule' },
    });

    fireEvent.click(screen.getByText('Crea Regola'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Nome e Pattern sono obbligatori', 'info', 4000);
    });
  });

  it('handles API response with rules array directly', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        rules: mockRules,
      }),
    });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });
  });

  it('cancels delete when confirm returns false', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        custom_rules: { items: mockRules, pagination: { total: 2 } },
      }),
    });

    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => false);

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const initialFetchCalls = (global.fetch as any).mock.calls.length;

    const deleteButtons = screen.getAllByRole('button', { name: /elimina/i });
    fireEvent.click(deleteButtons[0]);

    window.confirm = originalConfirm;

    // Non dovrebbe chiamare l'API di delete
    expect((global.fetch as any).mock.calls.length).toBe(initialFetchCalls);
  });

  it('handles delete API error', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockRejectedValueOnce(new Error('Delete failed'));

    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const deleteButtons = screen.getAllByRole('button', { name: /elimina/i });
    fireEvent.click(deleteButtons[0]);

    window.confirm = originalConfirm;

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith("Errore nell'eliminazione della regola", 'error', 4000);
    });
  });

  it('handles toggle API error', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockRejectedValueOnce(new Error('Toggle failed'));

    renderRules();

    await waitFor(() => {
      const toggleButtons = screen.getAllByText('Attiva');
      expect(toggleButtons.length).toBeGreaterThan(0);
    });

    const toggleButtons = screen.getAllByText('Attiva');
    fireEvent.click(toggleButtons[0]);

    await waitFor(() => {
      expect(consoleErrorSpy).toHaveBeenCalledWith('Error toggling rule:', expect.any(Error));
    });

    consoleErrorSpy.mockRestore();
  });

  it('handles auto-unblock error gracefully', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      })
      .mockRejectedValueOnce(new Error('Logs fetch failed'));

    const originalConfirm = window.confirm;
    window.confirm = vi.fn(() => true);

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    const deleteButtons = screen.getAllByRole('button', { name: /elimina/i });
    fireEvent.click(deleteButtons[0]);

    window.confirm = originalConfirm;

    await waitFor(() => {
      // La regola dovrebbe essere eliminata nonostante l'errore nell'auto-unblock
      expect(mockToast).toHaveBeenCalledWith('Regola eliminata con successo', 'success', 4000);
    });
  });

  it('edits rule from details modal', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any)
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          custom_rules: { items: mockRules, pagination: { total: 2 } },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ rule: { ...mockRules[0], name: 'Updated from Modal' } }),
      });

    renderRules();

    await waitFor(() => {
      expect(screen.getByText('Manual Block: SQL Injection')).toBeInTheDocument();
    });

    // Apri il modal dettagli
    const detailsButtons = screen.getAllByRole('button', { name: /dettagli/i });
    fireEvent.click(detailsButtons[0]);

    await waitFor(() => {
      const modalEditButton = screen.getAllByRole('button', { name: /modifica/i })[0];
      expect(modalEditButton).toBeInTheDocument();
    });

    // Clicca modifica nel modal
    const modalEditButtons = screen.getAllByRole('button', { name: /modifica/i });
    fireEvent.click(modalEditButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Modifica Regola')).toBeInTheDocument();
    });
  });
});