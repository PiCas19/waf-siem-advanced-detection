// Settings.test.tsx - VERSIONE FINALE CORRETTA
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Settings from '../Settings';

// Mock per react-router-dom
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

// Mock per lucide-react
vi.mock('lucide-react', () => ({
  Eye: () => <svg data-testid="eye-icon" />,
  EyeOff: () => <svg data-testid="eyeoff-icon" />,
}));

// Mock per localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};

// Mock per fetch
const mockFetch = vi.fn();

describe('Settings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    
    // Setup global mocks
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true
    });
    
    global.fetch = mockFetch;
    
    // Setup default mock values
    localStorageMock.getItem.mockReturnValue('test-token');
  });

  // Test 1: Renderizzazione base
  it('should render Account Settings title', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    expect(screen.getByText('Account Settings')).toBeInTheDocument();
  });

  // Test 2: Render sezione Change Password
  it('should render Change Password section heading', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    // Usa getAllByText e seleziona l'elemento h3
    const changePasswordHeadings = screen.getAllByText('Change Password');
    const sectionHeading = changePasswordHeadings.find(
      element => element.tagName === 'H3'
    );
    expect(sectionHeading).toBeInTheDocument();
  });

  // Test 3: Render campi password
  it('should render all password fields', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    expect(screen.getByText('Current Password')).toBeInTheDocument();
    expect(screen.getByText('New Password')).toBeInTheDocument();
    expect(screen.getByText('Confirm New Password')).toBeInTheDocument();
  });

  // Test 4: Render bottone Change Password
  it('should render Change Password button', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    // Cerca il bottone per ruolo e testo
    const buttons = screen.getAllByRole('button');
    const changePasswordButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    expect(changePasswordButton).toBeInTheDocument();
  });

  // Test 5: Bottoni toggle visibilità
  it('should have toggle buttons for password visibility', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    // Trova tutti i bottoni di tipo button
    const toggleButtons = screen.getAllByRole('button')
      .filter(button => button.getAttribute('type') === 'button');
    
    // Escludi il bottone "← Back"
    const passwordToggleButtons = toggleButtons.filter(
      button => button.textContent !== '← Back'
    );
    
    // Dovrebbero esserci 3 bottoni toggle (mostra/nascondi password)
    expect(passwordToggleButtons.length).toBe(3);
  });

  // Test 6: Errore campi vuoti
  it('should show error when fields are empty', async () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    // Trova il bottone Change Password
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      expect(screen.getByText('Please fill all password fields')).toBeInTheDocument();
    });
  });

  // Test 7: Errore password non corrispondenti - VERSIONE CORRETTA
  it('should show error when passwords do not match', async () => {
    // Renderizza UNA SOLA VOLTA
    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Imposta valori diversi
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'differentpass' } });

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      expect(screen.getByText('New passwords do not match')).toBeInTheDocument();
    });
  });

  // Test 8: Cambio password riuscito
  it('should successfully change password', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Imposta valori
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    // Verifica chiamata API
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: 'oldpass123',
          new_password: 'newpass123',
        }),
      });
    });

    // Verifica messaggio di successo
    await waitFor(() => {
      expect(screen.getByText('Password updated successfully')).toBeInTheDocument();
    });
  });

  // Test 9: Errore cambio password
  it('should show error when password change fails', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: async () => ({ error: 'Current password is incorrect' }),
    });

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Imposta valori
    fireEvent.change(passwordInputs[0], { target: { value: 'wrongpass' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      expect(screen.getByText('Current password is incorrect')).toBeInTheDocument();
    });
  });

  // Test 10: Stato di loading
  it('should show loading state', async () => {
    // Promise che non si risolve mai
    const neverResolvingPromise = new Promise(() => {});
    mockFetch.mockReturnValue(neverResolvingPromise);

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Imposta valori
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    // Verifica che il testo del bottone cambi
    await waitFor(() => {
      expect(screen.getByText('Updating…')).toBeInTheDocument();
    });
  });

  // Test 11: Navigazione indietro
  it('should navigate back when back button is clicked', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const backButton = screen.getByText('← Back');
    fireEvent.click(backButton);

    expect(mockNavigate).toHaveBeenCalledWith(-1);
  });

  // Test 12: Errore di rete
  it('should show network error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Imposta valori
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  // Test 13: Reset campi dopo successo
  it('should clear fields after successful change', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]') as NodeListOf<HTMLInputElement>;
    
    // Imposta valori
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    // Verifica che i campi abbiano valori
    expect(passwordInputs[0].value).toBe('oldpass123');
    expect(passwordInputs[1].value).toBe('newpass123');
    expect(passwordInputs[2].value).toBe('newpass123');

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      expect(screen.getByText('Password updated successfully')).toBeInTheDocument();
    });

    // Verifica che i campi siano stati resettati
    expect(passwordInputs[0].value).toBe('');
    expect(passwordInputs[1].value).toBe('');
    expect(passwordInputs[2].value).toBe('');
  });

  // Test 14: Bottone disabled durante loading
  it('should disable button during loading', async () => {
    // Promise che non si risolve mai
    const neverResolvingPromise = new Promise(() => {});
    mockFetch.mockReturnValue(neverResolvingPromise);

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Imposta valori
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    // Trova il bottone prima del click
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
      
      // Verifica che il bottone sia disabled
      await waitFor(() => {
        expect(submitButton).toBeDisabled();
      });
    }
  });

  it('should show error when fields are empty', async () => {
  render(
    <BrowserRouter>
      <Settings />
    </BrowserRouter>
  );

  // Trova il bottone Change Password
  const buttons = screen.getAllByRole('button');
  const submitButton = buttons.find(
    button => button.textContent === 'Change Password'
  );
  
  if (submitButton) {
    fireEvent.click(submitButton);
  }

  await waitFor(() => {
    expect(screen.getByText('Please fill all password fields')).toBeInTheDocument();
  });
});
it('should successfully change password', async () => {
  mockFetch.mockResolvedValueOnce({
    ok: true,
    json: async () => ({}),
  });

  const { container } = render(
    <BrowserRouter>
      <Settings />
    </BrowserRouter>
  );

  const passwordInputs = container.querySelectorAll('input[type="password"]');
  
  // Imposta valori
  fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
  fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
  fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

  // Trova e clicca il bottone
  const buttons = screen.getAllByRole('button');
  const submitButton = buttons.find(
    button => button.textContent === 'Change Password'
  );
  
  if (submitButton) {
    fireEvent.click(submitButton);
  }

  // Verifica chiamata API
  await waitFor(() => {
    expect(mockFetch).toHaveBeenCalledWith('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        current_password: 'oldpass123',
        new_password: 'newpass123',
      }),
    });
  });

  // Verifica messaggio di successo
  await waitFor(() => {
    expect(screen.getByText('Password updated successfully')).toBeInTheDocument();
  });
});

  // Test 15: Pulizia messaggi precedenti
  it('should clear previous messages on new submission', async () => {
    // Prima chiamata: errore
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: async () => ({ error: 'First error' }),
    });

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    // Prima chiamata
    fireEvent.change(passwordInputs[0], { target: { value: 'pass1' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'pass2' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'pass2' } });

    // Trova e clicca il bottone
    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      expect(screen.getByText('First error')).toBeInTheDocument();
    });

    // Seconda chiamata: successo
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    // Cambia valori
    fireEvent.change(passwordInputs[0], { target: { value: 'pass3' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'pass4' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'pass4' } });
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    await waitFor(() => {
      // Verifica che l'errore precedente sia sparito
      expect(screen.queryByText('First error')).not.toBeInTheDocument();
      // Verifica che appaia il messaggio di successo
      expect(screen.getByText('Password updated successfully')).toBeInTheDocument();
    });
  });
  
  it('should handle missing auth token', async () => {
    // Mock per localStorage senza token
    localStorageMock.getItem.mockReturnValueOnce(null);

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    // Verifica la chiamata fetch con token null
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer null',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: 'oldpass123',
          new_password: 'newpass123',
        }),
      });
    });
  });
  it('should toggle password visibility for all fields', () => {
    render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    // Trova tutti i bottoni di toggle
    const toggleButtons = screen.getAllByRole('button')
      .filter(button => button.getAttribute('type') === 'button')
      .filter(button => button.textContent !== '← Back');

    // Per ogni bottone di toggle, clicca e verifica che l'icona cambi
    toggleButtons.forEach((button) => {
      // Verifica l'icona iniziale (Eye)
      const icon = button.querySelector('svg');
      expect(icon).toBeInTheDocument();

      // Clicca il bottone
      fireEvent.click(button);

      // Verifica che il titolo sia cambiato
      expect(button).toHaveAttribute('title', expect.stringContaining('Hide password'));
    });

    // Clicca di nuovo per tornare allo stato nascosto
    toggleButtons.forEach((button) => {
      fireEvent.click(button);
      expect(button).toHaveAttribute('title', expect.stringContaining('Show password'));
    });
  });
  it('should handle error without message property', async () => {
    // Mock che lancia un errore senza proprietà message
    mockFetch.mockRejectedValueOnce({});

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    // Verifica l'errore generico
    await waitFor(() => {
      expect(screen.getByText('Error updating password')).toBeInTheDocument();
    });
  });
  it('should reset loading state even when error occurs', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    
    mockFetch.mockRejectedValueOnce(new Error('API Error'));

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    // Verifica che lo stato di loading sia stato resettato
    await waitFor(() => {
      expect(submitButton?.textContent).toBe('Change Password');
      expect(submitButton).not.toBeDisabled();
    });

    consoleSpy.mockRestore();
  });
  it('should handle JSON parse error from API', async () => {
    // Mock di fetch che restituisce una risposta non-JSON
    mockFetch.mockResolvedValueOnce({
      ok: false,
      // Quando json() viene chiamato, lancia un errore
      json: async () => { 
        throw new Error('JSON parse error') 
      },
    });

    const { container } = render(
      <BrowserRouter>
        <Settings />
      </BrowserRouter>
    );

    const passwordInputs = container.querySelectorAll('input[type="password"]');
    
    fireEvent.change(passwordInputs[0], { target: { value: 'oldpass123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'newpass123' } });
    fireEvent.change(passwordInputs[2], { target: { value: 'newpass123' } });

    const buttons = screen.getAllByRole('button');
    const submitButton = buttons.find(
      button => button.textContent === 'Change Password'
    );
    
    if (submitButton) {
      fireEvent.click(submitButton);
    }

    // Modifica: ora dovrebbe mostrare 'Change password failed' invece di 'Error updating password'
    await waitFor(() => {
      expect(screen.getByText('Change password failed')).toBeInTheDocument();
    });
  });
});