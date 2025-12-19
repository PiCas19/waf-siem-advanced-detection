import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import RuleEditor from '../RuleEditor';
import { useToast } from '@/contexts/SnackbarContext';

// Mock dei contesti
vi.mock('@/contexts/SnackbarContext', () => ({
  useToast: vi.fn(() => ({
    showToast: vi.fn(),
  })),
}));

// Mock fetch
global.fetch = vi.fn();

const mockRule = {
  id: 'test-rule',
  name: 'Test Rule',
  pattern: 'test.*pattern',
  description: 'Test rule description',
  threatType: 'SQL Injection',
  type: 'SQL Injection',
  action: 'block',
  mode: 'block' as const,
  enabled: true,
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  block_enabled: true,
  drop_enabled: false,
  redirect_enabled: false,
  challenge_enabled: false,
  redirect_url: '',
};

const mockOnRuleUpdated = vi.fn();
const mockOnCancel = vi.fn();

describe('RuleEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.setItem('authToken', 'test-token');
  });

 it('renders edit form with rule data', () => {
  render(
    <RuleEditor
      rule={mockRule}
      onRuleUpdated={mockOnRuleUpdated}
      onCancel={mockOnCancel}
    />
  );

  expect(screen.getByText('Edit Rule')).toBeInTheDocument();
  expect(screen.getByDisplayValue('Test Rule')).toBeInTheDocument();
  expect(screen.getByDisplayValue('test.*pattern')).toBeInTheDocument();
  expect(screen.getByDisplayValue('Test rule description')).toBeInTheDocument();
  expect(screen.getByDisplayValue('SQL Injection')).toBeInTheDocument();
  
  // Correzione: usa getAllByDisplayValue e controlla quello specifico per mode
  const blockRadioButtons = screen.getAllByDisplayValue('block');
  // Il primo è per "mode", il secondo è per "blockAction"
  expect(blockRadioButtons[0]).toBeChecked();
  expect(screen.getByText('Block - Reject request with 403 Forbidden')).toBeInTheDocument();
});

  it('maps action log to detect mode', () => {
    const ruleWithLogAction = {
      ...mockRule,
      action: 'log',
      mode: 'detect' as const,
    };

    render(
      <RuleEditor
        rule={ruleWithLogAction}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByDisplayValue('detect')).toBeChecked();
  });

  it('maps block_enabled to block action', () => {
    const ruleWithBlockEnabled = {
      ...mockRule,
      block_enabled: true,
      drop_enabled: false,
      redirect_enabled: false,
      challenge_enabled: false,
    };

    render(
      <RuleEditor
        rule={ruleWithBlockEnabled}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByText('Block - Reject request with 403 Forbidden')).toBeInTheDocument();
  });

  it('maps drop_enabled to drop action', () => {
    const ruleWithDropEnabled = {
      ...mockRule,
      block_enabled: false,
      drop_enabled: true,
      redirect_enabled: false,
      challenge_enabled: false,
    };

    render(
      <RuleEditor
        rule={ruleWithDropEnabled}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByText('Drop - Terminate connection immediately (no response)')).toBeInTheDocument();
  });

  it('maps redirect_enabled to redirect action', () => {
    const ruleWithRedirectEnabled = {
      ...mockRule,
      block_enabled: false,
      drop_enabled: false,
      redirect_enabled: true,
      challenge_enabled: false,
      redirect_url: 'https://example.com/blocked',
    };

    render(
      <RuleEditor
        rule={ruleWithRedirectEnabled}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByText('Redirect - Send to security/error page')).toBeInTheDocument();
    expect(screen.getByDisplayValue('https://example.com/blocked')).toBeInTheDocument();
  });

  it('maps challenge_enabled to challenge action', () => {
    const ruleWithChallengeEnabled = {
      ...mockRule,
      block_enabled: false,
      drop_enabled: false,
      redirect_enabled: false,
      challenge_enabled: true,
    };

    render(
      <RuleEditor
        rule={ruleWithChallengeEnabled}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByText('Challenge - Require CAPTCHA verification')).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Cancella il nome - use getByDisplayValue or getByPlaceholderText
    const nameInput = screen.getByDisplayValue('Test Rule');
    fireEvent.change(nameInput, {
      target: { value: '' },
    });

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Nome e Pattern sono obbligatori', 'info', 4000);
    });
  });

  it('updates rule successfully in detect mode', async () => {
  const mockToast = vi.fn();
  (useToast as any).mockReturnValue({ showToast: mockToast });

  const mockResponse = {
    ok: true,
    json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Updated Rule' } }),
  };
  (global.fetch as any).mockResolvedValueOnce(mockResponse);

  render(
    <RuleEditor
      rule={mockRule}
      onRuleUpdated={mockOnRuleUpdated}
      onCancel={mockOnCancel}
    />
  );

  // Correzione: seleziona il radio button per "detect" usando il name corretto
  const detectRadio = screen.getByRole('radio', { name: 'Detect' });
  fireEvent.click(detectRadio);

  // Modifica il nome
  const nameInput = screen.getByDisplayValue('Test Rule');
  fireEvent.change(nameInput, {
    target: { value: 'Updated Rule' },
  });

  fireEvent.click(screen.getByText('Save Changes'));

  // Correzione: usa expect.any(String) per il token che potrebbe essere undefined nel test
  await waitFor(() => {
    expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
      method: 'PUT',
      headers: {
        'Authorization': expect.stringContaining('Bearer'),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Updated Rule',
        pattern: 'test.*pattern',
        description: 'Test rule description',
        type: 'SQL Injection',
        action: 'log',
        block_enabled: false,
        drop_enabled: false,
        redirect_enabled: false,
        challenge_enabled: false,
        redirect_url: '',
      }),
    });
  });

  await waitFor(() => {
    expect(mockToast).toHaveBeenCalledWith('Regola aggiornata con successo', 'success', 4000);
    expect(mockOnRuleUpdated).toHaveBeenCalled();
  });
});

  it('updates rule successfully in block mode with redirect', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Updated Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Seleziona redirect action
    const redirectOption = screen.getByText('Redirect - Send to security/error page');
    fireEvent.click(redirectOption);

    // Inserisci URL - wait for the input to appear
    const urlInput = await screen.findByPlaceholderText('https://example.com/security');
    fireEvent.change(urlInput, {
      target: { value: 'https://example.com/new-blocked' },
    });

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
        method: 'PUT',
        headers: expect.any(Object),
        body: JSON.stringify({
          name: 'Test Rule',
          pattern: 'test.*pattern',
          description: 'Test rule description',
          type: 'SQL Injection',
          action: 'block',
          block_enabled: false,
          drop_enabled: false,
          redirect_enabled: true,
          challenge_enabled: false,
          redirect_url: 'https://example.com/new-blocked',
        }),
      });
    });
  });

  it('handles update error', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({}),
    });

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith("Errore nell'aggiornamento della regola", 'error', 4000);
    });
  });

  it('handles network error', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Errore nel salvataggio della regola', 'error', 4000);
    });
  });

  it('calls onCancel when cancel button is clicked', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    fireEvent.click(screen.getByText('Cancel'));

    expect(mockOnCancel).toHaveBeenCalled();
  });

  it('shows and hides redirect URL field based on action', async () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Seleziona redirect action
    const redirectOption = screen.getByText('Redirect - Send to security/error page');
    fireEvent.click(redirectOption);

    expect(await screen.findByPlaceholderText('https://example.com/security')).toBeInTheDocument();

    // Seleziona un'altra action
    const blockOption = screen.getByText('Block - Reject request with 403 Forbidden');
    fireEvent.click(blockOption);

    // The redirect URL field should not be visible
    await waitFor(() => {
      expect(screen.queryByPlaceholderText('https://example.com/security')).not.toBeInTheDocument();
    });
  });

  it('disables blocking actions in detect mode', () => {
  render(
    <RuleEditor
      rule={mockRule}
      onRuleUpdated={mockOnRuleUpdated}
      onCancel={mockOnCancel}
    />
  );

  // Seleziona detect mode
  const detectRadio = screen.getByRole('radio', { name: 'Detect' });
  fireEvent.click(detectRadio);

  // Le blocking actions dovrebbero essere disabilitate
  // Correzione: trova i radio buttons per blockAction in modo più specifico
  const blockActionRadioButtons = [
    'None - Only log the threat',
    'Block - Reject request with 403 Forbidden',
    'Drop - Terminate connection immediately (no response)',
    'Redirect - Send to security/error page',
    'Challenge - Require CAPTCHA verification',
  ];
  
  blockActionRadioButtons.forEach(labelText => {
    const radio = screen.getByRole('radio', { name: labelText });
    expect(radio).toBeDisabled();
  });
});
  
  it('shows all threat types in dropdown', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

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

    threatTypes.forEach(type => {
      expect(screen.getByText(type)).toBeInTheDocument();
    });
  });

  it('handles rule without threatType', () => {
    const ruleWithoutThreatType = {
      ...mockRule,
      threatType: undefined,
      type: 'SQL Injection',
    };

    render(
      <RuleEditor
        rule={ruleWithoutThreatType}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByDisplayValue('SQL Injection')).toBeInTheDocument();
  });

  it('handles rule without type', () => {
    const ruleWithoutType = {
      ...mockRule,
      type: undefined,
      threatType: 'SQL Injection',
    };

    render(
      <RuleEditor
        rule={ruleWithoutType}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    expect(screen.getByDisplayValue('SQL Injection')).toBeInTheDocument();
  });

  it('validates missing pattern field', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Cancella il pattern
    const patternInput = screen.getByDisplayValue('test.*pattern');
    fireEvent.change(patternInput, {
      target: { value: '' },
    });

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Nome e Pattern sono obbligatori', 'info', 4000);
    });
  });

  it('validates missing both name and pattern', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Cancella nome e pattern
    const nameInput = screen.getByDisplayValue('Test Rule');
    fireEvent.change(nameInput, { target: { value: '' } });

    const patternInput = screen.getByDisplayValue('test.*pattern');
    fireEvent.change(patternInput, { target: { value: '' } });

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Nome e Pattern sono obbligatori', 'info', 4000);
    });
  });

  it('handles description change', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const descriptionInput = screen.getByDisplayValue('Test rule description');
    fireEvent.change(descriptionInput, {
      target: { value: 'Updated description' },
    });

    expect(screen.getByDisplayValue('Updated description')).toBeInTheDocument();
  });

  it('handles pattern change', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const patternInput = screen.getByDisplayValue('test.*pattern');
    fireEvent.change(patternInput, {
      target: { value: 'new.*pattern' },
    });

    expect(screen.getByDisplayValue('new.*pattern')).toBeInTheDocument();
  });

  it('handles threat type change', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const threatTypeSelect = screen.getByDisplayValue('SQL Injection');
    fireEvent.change(threatTypeSelect, {
      target: { value: 'Cross-Site Scripting' },
    });

    expect(screen.getByDisplayValue('Cross-Site Scripting')).toBeInTheDocument();
  });

  it('handles mode change from block to detect', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const detectRadio = screen.getByRole('radio', { name: 'Detect' });
    fireEvent.click(detectRadio);

    expect(detectRadio).toBeChecked();
  });

  it('handles blockAction change to none', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const noneRadio = screen.getByRole('radio', { name: 'None - Only log the threat' });
    fireEvent.click(noneRadio);

    expect(noneRadio).toBeChecked();
  });

  it('handles blockAction change to drop', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const dropRadio = screen.getByRole('radio', { name: 'Drop - Terminate connection immediately (no response)' });
    fireEvent.click(dropRadio);

    expect(dropRadio).toBeChecked();
  });

  it('handles blockAction change to challenge', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const challengeRadio = screen.getByRole('radio', { name: 'Challenge - Require CAPTCHA verification' });
    fireEvent.click(challengeRadio);

    expect(challengeRadio).toBeChecked();
  });

  it('handles redirectUrl change', async () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Seleziona redirect action
    const redirectOption = screen.getByText('Redirect - Send to security/error page');
    fireEvent.click(redirectOption);

    // Cambia l'URL
    const urlInput = await screen.findByPlaceholderText('https://example.com/security');
    fireEvent.change(urlInput, {
      target: { value: 'https://new-url.com' },
    });

    expect(screen.getByDisplayValue('https://new-url.com')).toBeInTheDocument();
  });

  it('submits with blockAction none', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Test Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const noneRadio = screen.getByRole('radio', { name: 'None - Only log the threat' });
    fireEvent.click(noneRadio);

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
        method: 'PUT',
        headers: expect.any(Object),
        body: JSON.stringify({
          name: 'Test Rule',
          pattern: 'test.*pattern',
          description: 'Test rule description',
          type: 'SQL Injection',
          action: 'block',
          block_enabled: false,
          drop_enabled: false,
          redirect_enabled: false,
          challenge_enabled: false,
          redirect_url: '',
        }),
      });
    });
  });

  it('submits with blockAction drop', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Test Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const dropRadio = screen.getByRole('radio', { name: 'Drop - Terminate connection immediately (no response)' });
    fireEvent.click(dropRadio);

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
        method: 'PUT',
        headers: expect.any(Object),
        body: JSON.stringify({
          name: 'Test Rule',
          pattern: 'test.*pattern',
          description: 'Test rule description',
          type: 'SQL Injection',
          action: 'block',
          block_enabled: false,
          drop_enabled: true,
          redirect_enabled: false,
          challenge_enabled: false,
          redirect_url: '',
        }),
      });
    });
  });

  it('submits with blockAction challenge', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Test Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const challengeRadio = screen.getByRole('radio', { name: 'Challenge - Require CAPTCHA verification' });
    fireEvent.click(challengeRadio);

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
        method: 'PUT',
        headers: expect.any(Object),
        body: JSON.stringify({
          name: 'Test Rule',
          pattern: 'test.*pattern',
          description: 'Test rule description',
          type: 'SQL Injection',
          action: 'block',
          block_enabled: false,
          drop_enabled: false,
          redirect_enabled: false,
          challenge_enabled: true,
          redirect_url: '',
        }),
      });
    });
  });

  it('submits with blockAction block', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Test Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
        method: 'PUT',
        headers: expect.any(Object),
        body: JSON.stringify({
          name: 'Test Rule',
          pattern: 'test.*pattern',
          description: 'Test rule description',
          type: 'SQL Injection',
          action: 'block',
          block_enabled: true,
          drop_enabled: false,
          redirect_enabled: false,
          challenge_enabled: false,
          redirect_url: '',
        }),
      });
    });
  });

  it('maps none blockAction when all flags are false', () => {
    const ruleWithNoBlockAction = {
      ...mockRule,
      block_enabled: false,
      drop_enabled: false,
      redirect_enabled: false,
      challenge_enabled: false,
    };

    render(
      <RuleEditor
        rule={ruleWithNoBlockAction}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const noneRadio = screen.getByRole('radio', { name: 'None - Only log the threat' });
    expect(noneRadio).toBeChecked();
  });

  it('does not show redirect URL in detect mode', () => {
    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    const detectRadio = screen.getByRole('radio', { name: 'Detect' });
    fireEvent.click(detectRadio);

    // Seleziona redirect action
    const redirectOption = screen.getByText('Redirect - Send to security/error page');
    fireEvent.click(redirectOption);

    // L'URL input non dovrebbe apparire in detect mode
    expect(screen.queryByPlaceholderText('https://example.com/security')).not.toBeInTheDocument();
  });

  it('clears redirect URL when switching from redirect to other action', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Test Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Seleziona redirect e inserisci URL
    const redirectOption = screen.getByText('Redirect - Send to security/error page');
    fireEvent.click(redirectOption);

    const urlInput = await screen.findByPlaceholderText('https://example.com/security');
    fireEvent.change(urlInput, {
      target: { value: 'https://example.com/blocked' },
    });

    // Cambia a block
    const blockOption = screen.getByText('Block - Reject request with 403 Forbidden');
    fireEvent.click(blockOption);

    // Submit
    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      const callArgs = (global.fetch as any).mock.calls[0];
      const body = JSON.parse(callArgs[1].body);
      expect(body.redirect_url).toBe('');
    });
  });

  it('updates all form fields and submits', async () => {
    const mockToast = vi.fn();
    (useToast as any).mockReturnValue({ showToast: mockToast });

    const mockResponse = {
      ok: true,
      json: () => Promise.resolve({ rule: { id: 'test-rule', name: 'Completely Updated Rule' } }),
    };
    (global.fetch as any).mockResolvedValueOnce(mockResponse);

    render(
      <RuleEditor
        rule={mockRule}
        onRuleUpdated={mockOnRuleUpdated}
        onCancel={mockOnCancel}
      />
    );

    // Aggiorna tutti i campi
    const nameInput = screen.getByDisplayValue('Test Rule');
    fireEvent.change(nameInput, { target: { value: 'Completely Updated Rule' } });

    const patternInput = screen.getByDisplayValue('test.*pattern');
    fireEvent.change(patternInput, { target: { value: 'updated.*pattern' } });

    const descriptionInput = screen.getByDisplayValue('Test rule description');
    fireEvent.change(descriptionInput, { target: { value: 'Updated description' } });

    const threatTypeSelect = screen.getByDisplayValue('SQL Injection');
    fireEvent.change(threatTypeSelect, { target: { value: 'Cross-Site Scripting' } });

    const detectRadio = screen.getByRole('radio', { name: 'Detect' });
    fireEvent.click(detectRadio);

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/rules/test-rule', {
        method: 'PUT',
        headers: expect.any(Object),
        body: JSON.stringify({
          name: 'Completely Updated Rule',
          pattern: 'updated.*pattern',
          description: 'Updated description',
          type: 'Cross-Site Scripting',
          action: 'log',
          block_enabled: false,
          drop_enabled: false,
          redirect_enabled: false,
          challenge_enabled: false,
          redirect_url: '',
        }),
      });
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith('Regola aggiornata con successo', 'success', 4000);
      expect(mockOnRuleUpdated).toHaveBeenCalled();
    });
  });
});