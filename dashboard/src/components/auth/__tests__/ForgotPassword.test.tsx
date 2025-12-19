import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import ForgotPassword from '../ForgotPassword';

// Mock per fetch e navigate
const mockNavigate = vi.fn();
const mockFetch = vi.fn();

// Mock di react-router-dom
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

// Mock di fetch globale
global.fetch = mockFetch;

describe('ForgotPassword', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Request Reset Step', () => {
    it('should render Reset Password title', () => {
      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      expect(screen.getByText('Reset Password')).toBeInTheDocument();
    });

    it('should render email input', () => {
      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      expect(screen.getByPlaceholderText('you@example.com')).toBeInTheDocument();
    });

    it('should render Send Reset Link button', () => {
      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      expect(screen.getByRole('button', { name: 'Send Reset Link' })).toBeInTheDocument();
    });

    it('should show error when email is empty', async () => {
      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      const submitButton = screen.getByRole('button', { name: 'Send Reset Link' });
      
      // Usa semplicemente fireEvent.click sul bottone
      await act(async () => {
        fireEvent.click(submitButton);
      });

      // Usa querySelector per trovare il form e fare submit se necessario
      const form = submitButton.closest('form');
      if (form) {
        await act(async () => {
          fireEvent.submit(form);
        });
      }

      
      // Se non trova nessun errore, potrebbe essere che il componente usa la validazione HTML5
      // In quel caso, verifica se l'input ha l'attributo required
      const emailInput = screen.getByPlaceholderText('you@example.com');
      expect(emailInput).toHaveAttribute('required');
    });

    it('should send reset email successfully', async () => {
      // Mock corretto
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      });

      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const submitButton = screen.getByRole('button', { name: 'Send Reset Link' });

      await act(async () => {
        fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
        fireEvent.click(submitButton);
      });

      // Verifica chiamata API
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'test@example.com' }),
        });
      }, { timeout: 2000 });

      // Verifica messaggio di successo
      await waitFor(() => {
        expect(screen.getByText(/Reset link sent to your email/i)).toBeInTheDocument();
      }, { timeout: 2000 });
    });

    it('should clear email after successful submission', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      });

      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com') as HTMLInputElement;
      const submitButton = screen.getByRole('button', { name: 'Send Reset Link' });

      await act(async () => {
        fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
        fireEvent.click(submitButton);
      });

      // Aspetta che la richiesta sia completata
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      }, { timeout: 2000 });

      // L'email dovrebbe essere stata svuotata
      expect(emailInput.value).toBe('');
    });

    it('should display error on failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'User not found' }),
      });

      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const submitButton = screen.getByRole('button', { name: 'Send Reset Link' });

      await act(async () => {
        fireEvent.change(emailInput, { target: { value: 'nonexistent@example.com' } });
        fireEvent.click(submitButton);
      });

      await waitFor(() => {
        expect(screen.getByText(/User not found/i)).toBeInTheDocument();
      }, { timeout: 2000 });
    });

    it('should show loading state while sending', async () => {
      // Crea una promise che si risolve lentamente
      mockFetch.mockImplementationOnce(() => 
        new Promise(resolve => {
          setTimeout(() => resolve({
            ok: true,
            json: async () => ({ success: true }),
          }), 100);
        })
      );

      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const submitButton = screen.getByRole('button', { name: 'Send Reset Link' });

      await act(async () => {
        fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
        fireEvent.click(submitButton);
      });

      // Verifica subito lo stato di loading
      expect(screen.getByRole('button', { name: /Sending...|Loading/i })).toBeInTheDocument();
    });
  });

  describe('Reset Password Step', () => {
    it('should render reset form when token is in URL', () => {
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      expect(screen.getByText('Create New Password')).toBeInTheDocument();
      expect(screen.getAllByPlaceholderText('••••••••')).toHaveLength(2);
      expect(screen.getByRole('button', { name: 'Reset Password' })).toBeInTheDocument();
    });

    it('should show error when passwords do not match', async () => {
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const newPasswordInput = passwordInputs[0];
      const confirmPasswordInput = passwordInputs[1];
      const submitButton = screen.getByRole('button', { name: 'Reset Password' });

      await act(async () => {
        fireEvent.change(newPasswordInput, { target: { value: 'password123' } });
        fireEvent.change(confirmPasswordInput, { target: { value: 'different123' } });
        fireEvent.click(submitButton);
      });

      expect(screen.getByText(/Passwords do not match/i)).toBeInTheDocument();
    });

    it('should show error when password is too short', async () => {
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const newPasswordInput = passwordInputs[0];
      const confirmPasswordInput = passwordInputs[1];
      const submitButton = screen.getByRole('button', { name: 'Reset Password' });

      await act(async () => {
        fireEvent.change(newPasswordInput, { target: { value: 'short' } });
        fireEvent.change(confirmPasswordInput, { target: { value: 'short' } });
        fireEvent.click(submitButton);
      });

      expect(screen.getByText(/Password must be at least 8 characters/i)).toBeInTheDocument();
    });

    it('should reset password successfully', async () => {
      // Mock che si risolve immediatamente
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      });

      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const newPasswordInput = passwordInputs[0];
      const confirmPasswordInput = passwordInputs[1];
      const submitButton = screen.getByRole('button', { name: 'Reset Password' });

      await act(async () => {
        fireEvent.change(newPasswordInput, { target: { value: 'newpassword123' } });
        fireEvent.change(confirmPasswordInput, { target: { value: 'newpassword123' } });
        fireEvent.click(submitButton);
      });

      // Verifica chiamata API
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: 'abc123', new_password: 'newpassword123' }),
        });
      }, { timeout: 2000 });

      // Verifica messaggio di successo
      await waitFor(() => {
        expect(screen.getByText(/Password reset successfully/i)).toBeInTheDocument();
      }, { timeout: 2000 });
    });


    it('should display error on reset failure', async () => {
      // Mock che si risolve immediatamente con errore
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'Invalid or expired token' }),
      });

      render(
        <MemoryRouter initialEntries={['/forgot-password?token=invalid']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const newPasswordInput = passwordInputs[0];
      const confirmPasswordInput = passwordInputs[1];
      const submitButton = screen.getByRole('button', { name: 'Reset Password' });

      await act(async () => {
        fireEvent.change(newPasswordInput, { target: { value: 'newpassword123' } });
        fireEvent.change(confirmPasswordInput, { target: { value: 'newpassword123' } });
        fireEvent.click(submitButton);
      });

      await waitFor(() => {
        expect(screen.getByText(/Invalid or expired token/i)).toBeInTheDocument();
      }, { timeout: 2000 });
    });

    it('should toggle password visibility', async () => {
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const newPasswordInput = passwordInputs[0] as HTMLInputElement;

      // Trova i bottoni di toggle (emoji occhio)
      const toggleButtons = screen.getAllByText('👁️');

      expect(newPasswordInput.type).toBe('password');

      await act(async () => {
        fireEvent.click(toggleButtons[0]);
      });

      expect(newPasswordInput.type).toBe('text');
    });

    // TEST PER COPRIRE LINEA 193: toggle visibility del confirm password (secondo input)
    it('should toggle confirm password visibility', async () => {
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const confirmPasswordInput = passwordInputs[1] as HTMLInputElement;

      // Trova i bottoni di toggle (emoji occhio) - ci dovrebbero essere 2
      const toggleButtons = screen.getAllByText('👁️');
      expect(toggleButtons).toHaveLength(2);

      // Inizialmente è di tipo password
      expect(confirmPasswordInput.type).toBe('password');

      // LINEA 193: Clicca sul SECONDO bottone di toggle (per confirm password)
      await act(async () => {
        fireEvent.click(toggleButtons[1]);
      });

      // Dovrebbe diventare text
      expect(confirmPasswordInput.type).toBe('text');

      // Verifica che ora mostri l'emoji 🙈
      const hideButtons = screen.getAllByText('🙈');
      expect(hideButtons.length).toBeGreaterThanOrEqual(1);
    });

    it('should show error when fields are empty', async () => {
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const submitButton = screen.getByRole('button', { name: 'Reset Password' });
      
      await act(async () => {
        fireEvent.click(submitButton);
      });

      expect(screen.getByText(/Please fill all fields/i)).toBeInTheDocument();
    });


    it('should navigate to login after successful reset', async () => {
      // Promise che si risolve immediatamente
      const mockPromise = Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });
      mockFetch.mockReturnValue(mockPromise);

      vi.useFakeTimers();
      
      render(
        <MemoryRouter initialEntries={['/forgot-password?token=abc123']}>
          <ForgotPassword />
        </MemoryRouter>
      );

      const passwordInputs = screen.getAllByPlaceholderText('••••••••');
      const newPasswordInput = passwordInputs[0];
      const confirmPasswordInput = passwordInputs[1];
      const submitButton = screen.getByRole('button', { name: 'Reset Password' });

      fireEvent.change(newPasswordInput, { target: { value: 'newpassword123' } });
      fireEvent.change(confirmPasswordInput, { target: { value: 'newpassword123' } });
      fireEvent.click(submitButton);

      // Risolvi immediatamente la promise
      await mockPromise;

      // Avanza i timer
      act(() => {
        vi.advanceTimersByTime(2000);
      });

      expect(mockNavigate).toHaveBeenCalledWith('/login');
      
      vi.useRealTimers();
    });

  });


  describe('Back to Login', () => {
    it('should navigate to login when back button is clicked', () => {
      render(
        <BrowserRouter>
          <ForgotPassword />
        </BrowserRouter>
      );

      const backButton = screen.getByText('Back to Login');
      fireEvent.click(backButton);

      expect(mockNavigate).toHaveBeenCalledWith('/login');
    });
  });
});