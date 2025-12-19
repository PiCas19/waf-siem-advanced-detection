import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render as rtlRender, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import AvatarMenu from '../AvatarMenu';
import * as AuthContext from '@/contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: vi.fn(),
  };
});

const render = (component: React.ReactElement) => {
  return rtlRender(<BrowserRouter>{component}</BrowserRouter>);
};

describe('AvatarMenu', () => {
  const mockLogout = vi.fn();
  const mockNavigate = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    (useNavigate as any).mockReturnValue(mockNavigate);
  });

  it('should render avatar button', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    const button = screen.getByRole('button', { expanded: false });
    expect(button).toBeInTheDocument();
  });

  it('should show menu when avatar is clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    const avatarButton = screen.getByRole('button', { expanded: false });
    fireEvent.click(avatarButton);

    expect(screen.getByText('Profile')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
    expect(screen.getByText('Logout')).toBeInTheDocument();
  });

  it('should hide menu when clicked outside', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    // Open menu
    const avatarButton = screen.getByRole('button');
    fireEvent.click(avatarButton);
    expect(screen.getByText('Profile')).toBeInTheDocument();

    // Click outside
    fireEvent.click(document.body);

    // Menu should be closed (Profile should not be visible)
    expect(screen.queryByText('Profile')).not.toBeInTheDocument();
  });

  it('should navigate to profile when Profile is clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    // Open menu
    const avatarButton = screen.getByRole('button');
    fireEvent.click(avatarButton);

    // Click Profile
    const profileButton = screen.getByText('Profile');
    fireEvent.click(profileButton);

    expect(mockNavigate).toHaveBeenCalledWith('/profile');
  });

  it('should navigate to settings when Settings is clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    // Open menu
    const avatarButton = screen.getByRole('button');
    fireEvent.click(avatarButton);

    // Click Settings
    const settingsButton = screen.getByText('Settings');
    fireEvent.click(settingsButton);

    expect(mockNavigate).toHaveBeenCalledWith('/settings');
  });

  it('should call logout and navigate when Logout is clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    // Open menu
    const avatarButton = screen.getByRole('button');
    fireEvent.click(avatarButton);

    // Click Logout
    const logoutButton = screen.getByText('Logout');
    fireEvent.click(logoutButton);

    expect(mockLogout).toHaveBeenCalled();
    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });

  it('should generate avatar URL from user email', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'testuser@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    const avatar = screen.getByAltText('avatar');
    const src = avatar.getAttribute('src') || '';
    expect(src).toContain('dicebear.com');
    expect(src).toContain('seed=');
  });

  it('should generate avatar URL from user name if no email', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'John Doe' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    const avatar = screen.getByAltText('avatar');
    const src = avatar.getAttribute('src') || '';
    expect(src).toContain('dicebear.com');
    expect(src).toContain('seed=');
  });

  it('should use "guest" as fallback for avatar seed', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1 },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    const avatar = screen.getByAltText('avatar');
    expect(avatar).toHaveAttribute('src', expect.stringContaining('guest'));
  });

  it('should toggle menu open and closed', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com' },
      logout: mockLogout,
    });

    render(<AvatarMenu />);

    const avatarButton = screen.getByRole('button');

    // Open
    fireEvent.click(avatarButton);
    expect(screen.getByText('Profile')).toBeInTheDocument();

    // Close
    fireEvent.click(avatarButton);
    expect(screen.queryByText('Profile')).not.toBeInTheDocument();

    // Open again
    fireEvent.click(avatarButton);
    expect(screen.getByText('Profile')).toBeInTheDocument();
  });
});
