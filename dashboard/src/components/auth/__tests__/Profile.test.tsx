import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Profile from '../Profile';
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

describe('Profile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render user name', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('John Doe')).toBeInTheDocument();
  });

  it('should render user email', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('test@example.com')).toBeInTheDocument();
  });

  it('should render user role', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'admin' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('admin')).toBeInTheDocument();
  });

  it('should render avatar image', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    const avatar = screen.getByAltText('avatar');
    expect(avatar).toBeInTheDocument();
    expect(avatar.getAttribute('src')).toContain('dicebear.com');
  });

  it('should generate avatar URL from email', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    const avatar = screen.getByAltText('avatar');
    const src = avatar.getAttribute('src') || '';
    expect(src).toContain('dicebear.com');
    expect(src).toContain('seed=');
  });

  it('should generate avatar URL from name if no email', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    const avatar = screen.getByAltText('avatar');
    const src = avatar.getAttribute('src') || '';
    expect(src).toContain('dicebear.com');
    expect(src).toContain('seed=');
  });

  it('should use guest as fallback for avatar', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    const avatar = screen.getByAltText('avatar');
    expect(avatar.getAttribute('src')).toContain('guest');
  });

  it('should display admin permissions', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('manage:all')).toBeInTheDocument();
  });

  it('should display user permissions', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'user@example.com', name: 'User', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('read:logs')).toBeInTheDocument();
    expect(screen.getByText('view:stats')).toBeInTheDocument();
  });

  it('should render Permissions section', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('Permissions')).toBeInTheDocument();
  });

  it('should render back button', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('Back')).toBeInTheDocument();
  });

  it('should navigate back when back button is clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', name: 'John Doe', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    const backButton = screen.getByText('Back');
    fireEvent.click(backButton);

    expect(mockNavigate).toHaveBeenCalledWith(-1);
  });

  it('should display Unknown when user has no name', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, email: 'test@example.com', role: 'user' },
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });

  it('should handle null user gracefully', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: null,
    });

    render(
      <BrowserRouter>
        <Profile />
      </BrowserRouter>
    );

    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('user')).toBeInTheDocument();
  });
});
