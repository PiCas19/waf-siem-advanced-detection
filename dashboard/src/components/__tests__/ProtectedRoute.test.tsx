import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render as rtlRender, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ProtectedRoute from '../ProtectedRoute';
import * as AuthContext from '@/contexts/AuthContext';

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('@/types/rbac', () => ({
  hasPermission: vi.fn((role, permission) => {
    if (role === 'admin') return true;
    if (role === 'user' && permission === 'logs_view') return true;
    return false;
  }),
  UserRole: {},
  RolePermissions: {},
}));

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderWithRouter = (component: React.ReactElement, initialPath = '/') => {
    return rtlRender(
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/login" element={<div>Login Page</div>} />
          <Route path="/setup-2fa" element={<div>Setup 2FA Page</div>} />
          <Route path="/dashboard" element={component} />
          <Route path="/protected" element={component} />
        </Routes>
      </MemoryRouter>
    );
  };

  it('should show loading state while auth is loading', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: true,
      user: null,
      requiresTwoFASetup: false,
    });

    renderWithRouter(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>,
      '/dashboard'
    );

    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('should redirect to login when user is not authenticated', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: null,
      requiresTwoFASetup: false,
    });

    renderWithRouter(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>,
      '/protected'
    );

    expect(screen.getByText('Login Page')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should render children when user is authenticated', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: { id: 1, username: 'testuser', role: 'user' },
      requiresTwoFASetup: false,
    });

    renderWithRouter(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>,
      '/protected'
    );

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('should redirect to 2FA setup when required', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: { id: 1, username: 'testuser', role: 'user' },
      requiresTwoFASetup: true,
    });

    renderWithRouter(
      <ProtectedRoute>
        <div>Protected Content</div>
      </ProtectedRoute>,
      '/dashboard'
    );

    expect(screen.getByText('Setup 2FA Page')).toBeInTheDocument();
  });

  it('should not redirect to 2FA setup when allowTwoFASetup is true', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: { id: 1, username: 'testuser', role: 'user' },
      requiresTwoFASetup: true,
    });

    renderWithRouter(
      <ProtectedRoute allowTwoFASetup={true}>
        <div>2FA Setup Content</div>
      </ProtectedRoute>,
      '/dashboard'
    );

    expect(screen.getByText('2FA Setup Content')).toBeInTheDocument();
  });

  it('should show access denied when user lacks required permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: { id: 2, username: 'user', role: 'user' },
      requiresTwoFASetup: false,
    });

    renderWithRouter(
      <ProtectedRoute requiredPermission="users_delete">
        <div>Admin Content</div>
      </ProtectedRoute>,
      '/protected'
    );

    expect(screen.getByText('Access Denied')).toBeInTheDocument();
    expect(screen.getByText("You don't have permission to access this page.")).toBeInTheDocument();
    expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
  });

  it('should render children when user has required permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: { id: 1, username: 'admin', role: 'admin' },
      requiresTwoFASetup: false,
    });

    renderWithRouter(
      <ProtectedRoute requiredPermission="users_delete">
        <div>Admin Content</div>
      </ProtectedRoute>,
      '/protected'
    );

    expect(screen.getByText('Admin Content')).toBeInTheDocument();
  });

  it('should have link to dashboard on access denied page', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      isLoading: false,
      user: { id: 2, username: 'user', role: 'user' },
      requiresTwoFASetup: false,
    });

    renderWithRouter(
      <ProtectedRoute requiredPermission="users_delete">
        <div>Admin Content</div>
      </ProtectedRoute>,
      '/protected'
    );

    const link = screen.getByText('Return to Dashboard');
    expect(link).toHaveAttribute('href', '/dashboard');
  });
});
