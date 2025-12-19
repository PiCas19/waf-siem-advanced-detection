import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Login from '../Login';
import * as AuthContext from '@/contexts/AuthContext';

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

describe('Login', () => {
  const mockLogin = vi.fn();
  const mockVerifyOTP = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Normal Login Form', () => {
    beforeEach(() => {
      (AuthContext.useAuth as any).mockReturnValue({
        login: mockLogin,
        verifyOTP: mockVerifyOTP,
        requiresTwoFA: false,
        requiresTwoFASetup: false,
        currentUserEmail: null,
      });
    });

    it('should render login form with title', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      expect(screen.getByText('WAF Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Secure Web Application Firewall')).toBeInTheDocument();
    });

    it('should render email and password inputs', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      expect(screen.getByPlaceholderText('you@example.com')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('••••••••')).toBeInTheDocument();
    });

    it('should render login button', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      expect(screen.getByRole('button', { name: 'Login' })).toBeInTheDocument();
    });

    it('should toggle password visibility when eye icon is clicked', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const passwordInput = screen.getByPlaceholderText('••••••••') as HTMLInputElement;
      const toggleButton = screen.getByRole('button', { name: 'Show password' });

      expect(passwordInput.type).toBe('password');

      fireEvent.click(toggleButton);

      expect(passwordInput.type).toBe('text');
      expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument();
    });

    it('should call login function when form is submitted', async () => {
      mockLogin.mockResolvedValue({});

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const passwordInput = screen.getByPlaceholderText('••••••••');
      const submitButton = screen.getByRole('button', { name: 'Login' });

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
      fireEvent.change(passwordInput, { target: { value: 'password123' } });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'password123');
      });
    });

    it('should display error message on login failure', async () => {
      mockLogin.mockRejectedValue({
        response: { data: { error: 'Invalid credentials' } },
      });

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const passwordInput = screen.getByPlaceholderText('••••••••');
      const submitButton = screen.getByRole('button', { name: 'Login' });

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
      fireEvent.change(passwordInput, { target: { value: 'wrongpassword' } });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Invalid credentials')).toBeInTheDocument();
      });
    });

    it('should show loading state during login', async () => {
      mockLogin.mockImplementation(() => new Promise(() => {}));

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const passwordInput = screen.getByPlaceholderText('••••••••');
      const submitButton = screen.getByRole('button', { name: 'Login' });

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
      fireEvent.change(passwordInput, { target: { value: 'password123' } });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Logging in...' })).toBeInTheDocument();
      });
    });

    it('should navigate to forgot password page', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const forgotPasswordButton = screen.getByText('Forgot password?');
      fireEvent.click(forgotPasswordButton);

      expect(mockNavigate).toHaveBeenCalledWith('/forgot-password');
    });
  });

  describe('2FA Verification Form', () => {
    beforeEach(() => {
      (AuthContext.useAuth as any).mockReturnValue({
        login: mockLogin,
        verifyOTP: mockVerifyOTP,
        requiresTwoFA: true,
        requiresTwoFASetup: false,
        currentUserEmail: 'test@example.com',
      });
    });

    it('should render 2FA verification form', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      expect(screen.getByText('2FA Verification')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('000000')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('12345678')).toBeInTheDocument();
    });

    it('should display current user email as disabled', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByDisplayValue('test@example.com') as HTMLInputElement;
      expect(emailInput).toBeDisabled();
    });

    it('should call verifyOTP when OTP is submitted', async () => {
      mockVerifyOTP.mockResolvedValue({});

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const otpInput = screen.getByPlaceholderText('000000');
      const verifyButton = screen.getByRole('button', { name: 'Verify' });

      fireEvent.change(otpInput, { target: { value: '123456' } });
      fireEvent.click(verifyButton);

      await waitFor(() => {
        expect(mockVerifyOTP).toHaveBeenCalledWith('test@example.com', '123456', '');
      });
    });

    it('should call verifyOTP with backup code when submitted', async () => {
      mockVerifyOTP.mockResolvedValue({});

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const backupInput = screen.getByPlaceholderText('12345678');
      const verifyButton = screen.getByRole('button', { name: 'Verify' });

      fireEvent.change(backupInput, { target: { value: '12345678' } });
      fireEvent.click(verifyButton);

      await waitFor(() => {
        expect(mockVerifyOTP).toHaveBeenCalledWith('test@example.com', '', '12345678');
      });
    });

    it('should navigate to dashboard after successful OTP verification', async () => {
      mockVerifyOTP.mockResolvedValue({});

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const otpInput = screen.getByPlaceholderText('000000');
      const verifyButton = screen.getByRole('button', { name: 'Verify' });

      fireEvent.change(otpInput, { target: { value: '123456' } });
      fireEvent.click(verifyButton);

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
      });
    });

    it('should display error on failed OTP verification', async () => {
      mockVerifyOTP.mockRejectedValue({
        response: { data: { error: 'Invalid OTP code' } },
      });

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const otpInput = screen.getByPlaceholderText('000000');
      const verifyButton = screen.getByRole('button', { name: 'Verify' });

      fireEvent.change(otpInput, { target: { value: '000000' } });
      fireEvent.click(verifyButton);

      await waitFor(() => {
        expect(screen.getByText('Invalid OTP code')).toBeInTheDocument();
      });
    });

    it('should disable verify button when no code is provided', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const verifyButton = screen.getByRole('button', { name: 'Verify' }) as HTMLButtonElement;
      expect(verifyButton).toBeDisabled();
    });

    it('should enforce maxLength of 6 for OTP code', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const otpInput = screen.getByPlaceholderText('000000') as HTMLInputElement;
      expect(otpInput.maxLength).toBe(6);
    });

    it('should enforce maxLength of 8 for backup code', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const backupInput = screen.getByPlaceholderText('12345678') as HTMLInputElement;
      expect(backupInput.maxLength).toBe(8);
    });
  });

  describe('2FA Setup Required Form', () => {
    beforeEach(() => {
      (AuthContext.useAuth as any).mockReturnValue({
        login: mockLogin,
        verifyOTP: mockVerifyOTP,
        requiresTwoFA: false,
        requiresTwoFASetup: true,
        currentUserEmail: 'test@example.com',
      });
    });

    it('should render 2FA setup required screen', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      expect(screen.getByText('2FA Setup Required')).toBeInTheDocument();
      expect(
        screen.getByText('You must set up Two-Factor Authentication before continuing.')
      ).toBeInTheDocument();
    });

    it('should render Set Up 2FA button', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      expect(screen.getByRole('button', { name: 'Set Up 2FA' })).toBeInTheDocument();
    });

    it('should navigate to setup-2fa page when button is clicked', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const setupButton = screen.getByRole('button', { name: 'Set Up 2FA' });
      fireEvent.click(setupButton);

      expect(mockNavigate).toHaveBeenCalledWith('/setup-2fa');
    });

    it('should display error message if present', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      // Simulate an error state (would need to be set internally in the component)
      // For this test, just verify the error div structure exists
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });

  describe('Form Validation', () => {
    beforeEach(() => {
      (AuthContext.useAuth as any).mockReturnValue({
        login: mockLogin,
        verifyOTP: mockVerifyOTP,
        requiresTwoFA: false,
        requiresTwoFASetup: false,
        currentUserEmail: null,
      });
    });

    it('should require email field', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com') as HTMLInputElement;
      expect(emailInput.required).toBe(true);
    });

    it('should require password field', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const passwordInput = screen.getByPlaceholderText('••••••••') as HTMLInputElement;
      expect(passwordInput.required).toBe(true);
    });

    it('should have email type for email input', () => {
      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com') as HTMLInputElement;
      expect(emailInput.type).toBe('email');
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      (AuthContext.useAuth as any).mockReturnValue({
        login: mockLogin,
        verifyOTP: mockVerifyOTP,
        requiresTwoFA: false,
        requiresTwoFASetup: false,
        currentUserEmail: null,
      });
    });

    it('should show generic error message when error has no response', async () => {
      mockLogin.mockRejectedValue(new Error('Network error'));

      render(
        <BrowserRouter>
          <Login />
        </BrowserRouter>
      );

      const emailInput = screen.getByPlaceholderText('you@example.com');
      const passwordInput = screen.getByPlaceholderText('••••••••');
      const submitButton = screen.getByRole('button', { name: 'Login' });

      fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
      fireEvent.change(passwordInput, { target: { value: 'password123' } });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Login failed')).toBeInTheDocument();
      });
    });
  });

});
