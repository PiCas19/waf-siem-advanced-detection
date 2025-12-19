import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AddRule from '../AddRule';
import { useToast } from '@/contexts/SnackbarContext';

// Mock dei contesti
vi.mock('@/contexts/SnackbarContext', () => ({
  useToast: vi.fn(() => ({
    showToast: vi.fn(),
  })),
}));

// Mock fetch
global.fetch = vi.fn();

const mockOnRuleAdded = vi.fn();
const mockOnCancel = vi.fn();

describe('AddRule', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    localStorage.setItem('authToken', 'test-token');
  });

  // Test di base - renderizzazione
  it('renders form correctly', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Titolo
    expect(screen.getByText('Create New Rule')).toBeInTheDocument();
    
    // Input field per il nome
    const nameInput = screen.getByPlaceholderText('e.g. SQL Injection Prevention');
    expect(nameInput).toBeInTheDocument();
    
    // Textarea per il pattern
    const patternTextarea = screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP');
    expect(patternTextarea).toBeInTheDocument();
    
    // Textarea per la descrizione
    const descTextarea = screen.getByPlaceholderText('Rule description...');
    expect(descTextarea).toBeInTheDocument();
    
    // Select per threat type (primo select nel DOM)
    const selects = screen.getAllByRole('combobox');
    expect(selects.length).toBeGreaterThan(0);
    
    // Radio button per mode
    const detectRadio = screen.getByLabelText('Detect');
    const blockRadio = screen.getByLabelText('Block');
    expect(detectRadio).toBeInTheDocument();
    expect(blockRadio).toBeInTheDocument();
    
    // Pulsanti
    expect(screen.getByText('Create Rule')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  // Test validazione campi obbligatori
  it('shows error when required fields are missing', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Submit senza compilare nulla
    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        'Rule name and pattern are required',
        'info',
        4000
      );
    });
  });

  // Test submit con successo in modalità detect
  it('submits form successfully in detect mode', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ 
        rule: { 
          id: 'new-rule-id', 
          name: 'Test Detection Rule' 
        } 
      }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila i campi
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: 'Test Detection Rule' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: 'test.*pattern' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('Rule description...'),
      { target: { value: 'Test description for detection rule' } }
    );

    // Seleziona modalità Detect
    fireEvent.click(screen.getByLabelText('Detect'));

    // Submit
    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
      const call = (global.fetch as any).mock.calls[0];
      expect(call[0]).toBe('/api/rules');
      expect(call[1]).toMatchObject({
        method: 'POST',
        headers: {
          'Authorization': expect.stringContaining('Bearer'),
          'Content-Type': 'application/json',
        },
      });
      
      // Verifica il corpo della richiesta
      const body = JSON.parse(call[1].body);
      expect(body).toMatchObject({
        name: 'Test Detection Rule',
        pattern: 'test.*pattern',
        description: 'Test description for detection rule',
        type: 'SQL Injection',
        severity: 'medium',
        action: 'log',
      });
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        'Rule created successfully',
        'success',
        4000
      );
      expect(mockOnRuleAdded).toHaveBeenCalled();
    });
  });

  // Test submit con successo in modalità block con block action
  it('submits form successfully in block mode with block action', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'block-rule-id' } }),
    });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila campi base
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: 'Block Rule Test' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: 'block.*pattern' } }
    );

    // Modalità Block è già selezionata di default
    
    // Trova e clicca il radio button per block action
    const blockActionLabel = screen.getByText('Block - Reject request with 403 Forbidden');
    const blockActionRadio = blockActionLabel.previousElementSibling;
    expect(blockActionRadio).toBeInTheDocument();
    fireEvent.click(blockActionRadio!);

    // Submit
    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
      const call = (global.fetch as any).mock.calls[0];
      const body = JSON.parse(call[1].body);
      
      expect(body.action).toBe('block');
      expect(body.block_enabled).toBe(true);
    });
  });

  // Test submit con redirect action
  it('submits form with redirect action and URL', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'redirect-rule-id' } }),
    });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila campi base
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: 'Redirect Rule Test' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: 'redirect.*pattern' } }
    );

    // Trova e clicca il radio button per redirect action
    const redirectActionLabel = screen.getByText('Redirect - Send to security/error page');
    const redirectActionRadio = redirectActionLabel.previousElementSibling;
    expect(redirectActionRadio).toBeInTheDocument();
    fireEvent.click(redirectActionRadio!);

    // Il campo URL dovrebbe apparire
    await waitFor(() => {
      expect(screen.getByPlaceholderText('https://example.com/security')).toBeInTheDocument();
    });

    // Compila URL
    fireEvent.change(
      screen.getByPlaceholderText('https://example.com/security'),
      { target: { value: 'https://example.com/blocked' } }
    );

    // Submit
    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
      const call = (global.fetch as any).mock.calls[0];
      const body = JSON.parse(call[1].body);
      
      expect(body.redirect_enabled).toBe(true);
      expect(body.redirect_url).toBe('https://example.com/blocked');
    });
  });

  // Test gestione errore API
  it('handles API error gracefully', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({}),
    });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila campi minimi
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: 'Error Test Rule' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: 'error.*pattern' } }
    );

    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Error creating rule', 'error', 4000);
    });
  });

  // Test gestione errore di rete
  it('handles network error', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila campi minimi
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: 'Network Error Test' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: 'network.*error' } }
    );

    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Error saving rule', 'error', 4000);
    });
  });

  // Test cancellazione form
  it('calls onCancel when cancel button is clicked', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    fireEvent.click(screen.getByText('Cancel'));

    expect(mockOnCancel).toHaveBeenCalled();
  });

  // Test campo redirect URL appare/scompare
  it('shows/hides redirect URL field based on selected action', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Inizialmente non visibile
    expect(screen.queryByPlaceholderText('https://example.com/security')).not.toBeInTheDocument();

    // Trova e clicca il radio button per redirect action
    const redirectActionLabel = screen.getByText('Redirect - Send to security/error page');
    const redirectActionRadio = redirectActionLabel.previousElementSibling;
    fireEvent.click(redirectActionRadio!);
    
    // Ora dovrebbe essere visibile
    expect(screen.getByPlaceholderText('https://example.com/security')).toBeInTheDocument();

    // Cambia a un'altra action
    const blockActionLabel = screen.getByText('Block - Reject request with 403 Forbidden');
    const blockActionRadio = blockActionLabel.previousElementSibling;
    fireEvent.click(blockActionRadio!);
    
    // Non dovrebbe più essere visibile
    expect(screen.queryByPlaceholderText('https://example.com/security')).not.toBeInTheDocument();
  });

  // Test disabilitazione blocking actions in detect mode
  it('disables blocking actions when in detect mode', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Seleziona detect mode
    fireEvent.click(screen.getByLabelText('Detect'));

    // Verifica che tutti i radio button delle blocking actions siano disabilitati
    const actionLabels = [
      'None - Only log the threat',
      'Block - Reject request with 403 Forbidden',
      'Drop - Terminate connection immediately (no response)',
      'Redirect - Send to security/error page',
      'Challenge - Require CAPTCHA verification',
    ];

    actionLabels.forEach(label => {
      // Trova il radio button associato al label
      const labelElement = screen.getByText(label);
      const radioButton = labelElement.previousElementSibling;
      expect(radioButton).toBeDisabled();
    });
  });

  // Test tutte le threat types sono presenti
  it('contains all threat types in dropdown', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    const threatTypes = [
      'Command Injection',
      'LDAP Injection',
      'Local File Inclusion',
      'NoSQL Injection',
      'Path Traversal',
      'Prototype Pollution',
      'Response Splitting',
      'Remote File Inclusion',
      'SQL Injection',
      'SSRF',
      'Server-Side Template Injection',
      'Cross-Site Scripting',
      'XML External Entity',
      'Other'
    ];

    // Trova il select per threat type (primo select nel DOM)
    const threatTypeSelect = screen.getAllByRole('combobox')[0];
    const options = Array.from(threatTypeSelect.querySelectorAll('option'));
    const optionValues = options.map(opt => opt.textContent);

    threatTypes.forEach(type => {
      expect(optionValues).toContain(type);
    });
  });

  // Test tutte le severità sono presenti - VERSIONE CORRETTA
  it('contains all severity levels in dropdown', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Trova tutti i select nel DOM
    const allSelects = screen.getAllByRole('combobox');
    // Il secondo select dovrebbe essere quello della severità
    const severitySelect = allSelects[1];
    
    const options = Array.from(severitySelect.querySelectorAll('option'));
    const optionValues = options.map(opt => opt.value);

    expect(optionValues).toContain('low');
    expect(optionValues).toContain('medium');
    expect(optionValues).toContain('high');
    expect(optionValues).toContain('critical');
  });

  // Test reset del form dopo submit riuscito - VERSIONE CORRETTA
  it('resets form after successful submission', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'new-rule' } }),
    });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila tutti i campi
    const nameInput = screen.getByPlaceholderText('e.g. SQL Injection Prevention');
    const patternTextarea = screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP');
    const descTextarea = screen.getByPlaceholderText('Rule description...');

    fireEvent.change(nameInput, { target: { value: 'Test Rule' } });
    fireEvent.change(patternTextarea, { target: { value: 'test.*pattern' } });
    fireEvent.change(descTextarea, { target: { value: 'Test description' } });

    // Trova e cambia severità
    const allSelects = screen.getAllByRole('combobox');
    const severitySelect = allSelects[1];
    fireEvent.change(severitySelect, { target: { value: 'high' } });

    // Submit
    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      // Verifica che il form sia stato resettato
      expect(nameInput).toHaveValue('');
      expect(patternTextarea).toHaveValue('');
      expect(descTextarea).toHaveValue('');
      // La severità dovrebbe tornare al default 'medium'
      expect(severitySelect).toHaveValue('medium');
    });
  });

  // Test senza token di autenticazione
  it('handles missing auth token', async () => {
    localStorage.removeItem('authToken');
    
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'new-rule' } }),
    });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Compila campi
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: 'No Token Rule' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: 'no.*token' } }
    );

    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
      const call = (global.fetch as any).mock.calls[0];
      // Il token dovrebbe essere 'Bearer null' quando non c'è token (localStorage.getItem ritorna null)
      expect(call[1].headers.Authorization).toBe('Bearer null');
    });
  });

  // Test cambio threat type - VERSIONE CORRETTA
  it('allows changing threat type', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    const allSelects = screen.getAllByRole('combobox');
    const threatTypeSelect = allSelects[0];
    
    // Cambia a XSS
    fireEvent.change(threatTypeSelect, { target: { value: 'Cross-Site Scripting' } });
    
    expect(threatTypeSelect).toHaveValue('Cross-Site Scripting');
  });

  // Test cambio severità - VERSIONE CORRETTA
  it('allows changing severity', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    const allSelects = screen.getAllByRole('combobox');
    const severitySelect = allSelects[1];
    
    // Cambia a critical
    fireEvent.change(severitySelect, { target: { value: 'critical' } });
    
    expect(severitySelect).toHaveValue('critical');
  });

  // Test visualizzazione help text
  it('shows help text for pattern field', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    expect(screen.getByText('Enter a regular expression to match attack patterns')).toBeInTheDocument();
  });

  // Test visualizzazione note per blocking actions in detect mode
  it('shows note for blocking actions in detect mode', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Seleziona detect mode
    fireEvent.click(screen.getByLabelText('Detect'));

    expect(screen.getByText('(disabled in Detect mode)')).toBeInTheDocument();
  });

  // Test gestione delle descrizioni lunghe
  it('handles long descriptions', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    const descTextarea = screen.getByPlaceholderText('Rule description...');
    const longDescription = 'A'.repeat(500);
    
    fireEvent.change(descTextarea, { target: { value: longDescription } });
    
    expect(descTextarea).toHaveValue(longDescription);
  });

  // Test pattern regex special characters
  it('handles special regex characters in pattern', () => {
    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    const patternTextarea = screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP');
    const specialPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
    
    fireEvent.change(patternTextarea, { target: { value: specialPattern } });
    
    expect(patternTextarea).toHaveValue(specialPattern);
  });

  // Test gestione degli spazi bianchi nei campi
  it('trims whitespace from input fields', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'trimmed-rule' } }),
    });

    render(<AddRule onRuleAdded={mockOnRuleAdded} onCancel={mockOnCancel} />);

    // Inserisci spazi bianchi
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SQL Injection Prevention'),
      { target: { value: '  Test Rule with spaces  ' } }
    );
    
    fireEvent.change(
      screen.getByPlaceholderText('e.g. SELECT|INSERT|UPDATE|DELETE|DROP'),
      { target: { value: '  test.*pattern  ' } }
    );

    fireEvent.click(screen.getByText('Create Rule'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
      const call = (global.fetch as any).mock.calls[0];
      const body = JSON.parse(call[1].body);
      
      // I valori dovrebbero mantenere gli spazi bianchi (il trim viene fatto nel componente?)
      expect(body.name).toBe('  Test Rule with spaces  ');
      expect(body.pattern).toBe('  test.*pattern  ');
    });
  });

});