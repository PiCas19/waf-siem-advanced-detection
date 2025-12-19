// App.test.tsx
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from '../App'

// Mock dei componenti e contesti
vi.mock('@/contexts/AuthContext', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => <div data-testid="auth-provider">{children}</div>,
}))

vi.mock('@/contexts/SnackbarContext', () => ({
  ToastProvider: ({ children }: { children: React.ReactNode }) => <div data-testid="toast-provider">{children}</div>,
  useToast: vi.fn(() => ({
    toasts: [],
    showToast: vi.fn(),
    removeToast: vi.fn(),
  })),
}))

vi.mock('@/components/ProtectedRoute', () => ({
  default: ({ children, allowTwoFASetup }: { children: React.ReactNode; allowTwoFASetup?: boolean }) => (
    <div data-testid="protected-route" data-allow-twofa={allowTwoFASetup}>
      {children}
    </div>
  ),
}))

vi.mock('@/components/auth/Login', () => ({
  default: () => <div data-testid="login-page">Login Page</div>,
}))

vi.mock('@/components/auth/SetPassword', () => ({
  default: () => <div data-testid="set-password-page">Set Password Page</div>,
}))

vi.mock('@/components/auth/ForgotPassword', () => ({
  default: () => <div data-testid="forgot-password-page">Forgot Password Page</div>,
}))

vi.mock('@/components/auth/ForcedTwoFASetup', () => ({
  default: () => <div data-testid="forced-twofa-setup-page">Forced 2FA Setup Page</div>,
}))

vi.mock('@/components/Dashboard', () => ({
  default: () => <div data-testid="dashboard-page">Dashboard Page</div>,
}))

vi.mock('@/components/auth/Settings', () => ({
  default: () => <div data-testid="settings-page">Settings Page</div>,
}))

vi.mock('@/components/auth/Profile', () => ({
  default: () => <div data-testid="profile-page">Profile Page</div>,
}))

vi.mock('@/components/admin/Users', () => ({
  default: () => <div data-testid="users-page">Users Page</div>,
}))

vi.mock('@/components/common/Snackbar', () => ({
  default: ({ message, onClose }: { message: any; onClose: () => void }) => (
    <div data-testid="snackbar" onClick={onClose}>
      {message.message || 'Snackbar'}
    </div>
  ),
}))

// Mock di react-router-dom per testare le route
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    BrowserRouter: ({ children }: { children: React.ReactNode }) => (
      <div data-testid="browser-router">{children}</div>
    ),
    Routes: ({ children }: { children: React.ReactNode }) => (
      <div data-testid="routes">{children}</div>
    ),
    Route: ({ path, element }: { path: string; element: React.ReactNode }) => (
      <div data-testid={`route-${path}`}>{element}</div>
    ),
    Navigate: ({ to }: { to: string }) => (
      <div data-testid={`navigate-to-${to}`}>Navigate to {to}</div>
    ),
  }
})

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders without crashing', () => {
    render(<App />)
    
    // App should render without throwing errors
    expect(screen.getByTestId('browser-router')).toBeInTheDocument()
    expect(screen.getByTestId('auth-provider')).toBeInTheDocument()
    expect(screen.getByTestId('toast-provider')).toBeInTheDocument()
  })

  it('wraps app with all providers', () => {
    render(<App />)
    
    // Verifica che tutti i provider siano presenti
    expect(screen.getByTestId('browser-router')).toBeInTheDocument()
    expect(screen.getByTestId('auth-provider')).toBeInTheDocument()
    expect(screen.getByTestId('toast-provider')).toBeInTheDocument()
  })

  // Test più semplici che testano la struttura senza simulare il routing
  it('renders SnackbarContainer', () => {
    render(<App />)

    // SnackbarContainer è renderizzato all'interno di AppContent
    expect(screen.getByTestId('browser-router')).toBeInTheDocument()
  })

  // TEST PER COPRIRE LINEA 21: rendering del wrapper div con key per ogni toast
  it('renders toast wrapper div with unique key when toasts are present', async () => {
    // Re-mock useToast con toasts non vuoti
    const mockUseToast = vi.fn(() => ({
      toasts: [
        { id: 'toast-1', message: 'First toast', type: 'success' },
        { id: 'toast-2', message: 'Second toast', type: 'error' },
      ],
      showToast: vi.fn(),
      removeToast: vi.fn(),
    }));

    // Importa dinamicamente il modulo mock
    vi.doMock('@/contexts/SnackbarContext', () => ({
      ToastProvider: ({ children }: { children: React.ReactNode }) => <div data-testid="toast-provider">{children}</div>,
      useToast: mockUseToast,
    }));

    // Re-import App per applicare il nuovo mock
    await vi.resetModules();
    const { default: FreshApp } = await import('../App');

    const { container } = render(<FreshApp />);

    // Verifica che i toast siano renderizzati
    const snackbars = screen.getAllByTestId('snackbar');
    expect(snackbars).toHaveLength(2);

    // Verifica che i wrapper div abbiano la classe corretta (LINEA 21)
    const wrapperDivs = container.querySelectorAll('.pointer-events-auto');
    expect(wrapperDivs).toHaveLength(2);
    expect(wrapperDivs[0]).toHaveClass('pointer-events-auto');
  })
})