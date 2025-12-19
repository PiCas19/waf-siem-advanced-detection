import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import PermissionGate from '../PermissionGate';
import * as AuthContext from '@/contexts/AuthContext';

// Mock the AuthContext
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

// Mock the rbac module
vi.mock('@/types/rbac', () => ({
  hasPermission: vi.fn((role, permission) => {
    if (role === 'admin') return true;
    if (role === 'user' && permission === 'logs_view') return true;
    return false;
  }),
  UserRole: {},
  RolePermissions: {},
}));

describe('PermissionGate', () => {
  it('should render children when user has permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, username: 'admin', role: 'admin' },
    });

    render(
      <PermissionGate permission="users_delete">
        <button>Delete User</button>
      </PermissionGate>
    );

    expect(screen.getByText('Delete User')).toBeInTheDocument();
  });

  it('should not render children when user does not have permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 2, username: 'user', role: 'user' },
    });

    render(
      <PermissionGate permission="users_delete">
        <button>Delete User</button>
      </PermissionGate>
    );

    expect(screen.queryByText('Delete User')).not.toBeInTheDocument();
  });

  it('should render fallback when user does not have permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 2, username: 'user', role: 'user' },
    });

    render(
      <PermissionGate permission="users_delete" fallback={<div>Access Denied</div>}>
        <button>Delete User</button>
      </PermissionGate>
    );

    expect(screen.queryByText('Delete User')).not.toBeInTheDocument();
    expect(screen.getByText('Access Denied')).toBeInTheDocument();
  });

  it('should render fallback when user is not logged in', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: null,
    });

    render(
      <PermissionGate permission="logs_view" fallback={<div>Please login</div>}>
        <div>Logs Content</div>
      </PermissionGate>
    );

    expect(screen.queryByText('Logs Content')).not.toBeInTheDocument();
    expect(screen.getByText('Please login')).toBeInTheDocument();
  });

  it('should render nothing when no user and no fallback', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: null,
    });

    render(
      <PermissionGate permission="logs_view">
        <div>Protected Content</div>
      </PermissionGate>
    );

    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('should handle user with permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 3, username: 'viewer', role: 'user' },
    });

    render(
      <PermissionGate permission="logs_view">
        <div>View Logs</div>
      </PermissionGate>
    );

    expect(screen.getByText('View Logs')).toBeInTheDocument();
  });
});
