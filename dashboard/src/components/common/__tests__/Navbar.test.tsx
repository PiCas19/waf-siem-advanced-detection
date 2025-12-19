import { describe, it, expect, vi } from 'vitest';
import { render as rtlRender, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Navbar from '../Navbar';
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
}));

vi.mock('../AvatarMenu', () => ({
  default: () => <div>Avatar Menu</div>,
}));

const render = (component: React.ReactElement) => {
  return rtlRender(<BrowserRouter>{component}</BrowserRouter>);
};

describe('Navbar', () => {
  it('should render Statistics link', () => {
    (AuthContext.useAuth as any).mockReturnValue({ user: null });

    render(<Navbar />);

    expect(screen.getByText('Statistics')).toBeInTheDocument();
  });

  it('should show Login link when user is not authenticated', () => {
    (AuthContext.useAuth as any).mockReturnValue({ user: null });

    render(<Navbar />);

    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.queryByText('Avatar Menu')).not.toBeInTheDocument();
  });

  it('should show AvatarMenu when user is authenticated', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, username: 'testuser', role: 'user' },
    });

    render(<Navbar />);

    expect(screen.getByText('Avatar Menu')).toBeInTheDocument();
    expect(screen.queryByText('Login')).not.toBeInTheDocument();
  });

  it('should show Logs link when user has logs_view permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, username: 'user', role: 'user' },
    });

    render(<Navbar />);

    expect(screen.getByText('Logs')).toBeInTheDocument();
  });

  it('should show Users link when user has users_view permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, username: 'admin', role: 'admin' },
    });

    render(<Navbar />);

    expect(screen.getByText('Users')).toBeInTheDocument();
  });

  it('should not show Users link when user lacks users_view permission', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 2, username: 'user', role: 'user' },
    });

    render(<Navbar />);

    expect(screen.queryByText('Users')).not.toBeInTheDocument();
  });
});
