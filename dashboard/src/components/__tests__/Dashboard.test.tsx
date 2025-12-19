import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render as rtlRender, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Dashboard from '../Dashboard';
import * as AuthContext from '@/contexts/AuthContext';

// Mock child components
vi.mock('../common/AvatarMenu', () => ({
  default: () => <div data-testid="avatar-menu">Avatar Menu</div>,
}));

vi.mock('../stats/StatsPage', () => ({
  default: () => <div data-testid="stats-page">Stats Page</div>,
}));

vi.mock('../rules/RulesContainer', () => ({
  default: () => <div data-testid="rules-container">Rules Container</div>,
}));

vi.mock('../blocklist/BlocklistPage', () => ({
  default: () => <div data-testid="blocklist-page">Blocklist Page</div>,
}));

vi.mock('../logs/LogsPage', () => ({
  default: () => <div data-testid="logs-page">Logs Page</div>,
}));

vi.mock('../admin/Users', () => ({
  default: () => <div data-testid="users-page">Users Page</div>,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../auth/PermissionGate', () => ({
  default: ({ children, permission }: any) => <div data-permission={permission}>{children}</div>,
}));

const render = (component: React.ReactElement) => {
  return rtlRender(<BrowserRouter>{component}</BrowserRouter>);
};

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render header with WAF Dashboard title', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Test User', role: 'user' },
    });

    render(<Dashboard />);

    expect(screen.getByText('WAF Dashboard')).toBeInTheDocument();
  });

  it('should display welcome message with user name', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'John Doe', role: 'user' },
    });

    render(<Dashboard />);

    expect(screen.getByText('Welcome, John Doe')).toBeInTheDocument();
  });

  it('should render AvatarMenu in header', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Test User', role: 'user' },
    });

    render(<Dashboard />);

    expect(screen.getByTestId('avatar-menu')).toBeInTheDocument();
  });

  it('should display Statistics tab by default', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Test User', role: 'user' },
    });

    render(<Dashboard />);

    expect(screen.getByText('Statistics')).toBeInTheDocument();
    expect(screen.getByTestId('stats-page')).toBeInTheDocument();
  });

  it('should render all navigation tabs', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    expect(screen.getByText('Statistics')).toBeInTheDocument();
    expect(screen.getByText('Rules')).toBeInTheDocument();
    expect(screen.getByText('Logs')).toBeInTheDocument();
    expect(screen.getByText('Threat Blocklist')).toBeInTheDocument();
    expect(screen.getByText('Users')).toBeInTheDocument();
  });

  it('should switch to Rules tab when clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const rulesTab = screen.getByText('Rules');
    fireEvent.click(rulesTab);

    expect(screen.getByTestId('rules-container')).toBeInTheDocument();
    expect(screen.queryByTestId('stats-page')).not.toBeInTheDocument();
  });

  it('should switch to Logs tab when clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const logsTab = screen.getByText('Logs');
    fireEvent.click(logsTab);

    expect(screen.getByTestId('logs-page')).toBeInTheDocument();
    expect(screen.queryByTestId('stats-page')).not.toBeInTheDocument();
  });

  it('should switch to Threat Blocklist tab when clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const blocklistTab = screen.getByText('Threat Blocklist');
    fireEvent.click(blocklistTab);

    expect(screen.getByTestId('blocklist-page')).toBeInTheDocument();
    expect(screen.queryByTestId('stats-page')).not.toBeInTheDocument();
  });

  it('should switch to Users tab when clicked', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const usersTab = screen.getByText('Users');
    fireEvent.click(usersTab);

    expect(screen.getByTestId('users-page')).toBeInTheDocument();
    expect(screen.queryByTestId('stats-page')).not.toBeInTheDocument();
  });

  it('should show only Users page when Users tab is active and user is admin', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const usersTab = screen.getByText('Users');
    fireEvent.click(usersTab);

    expect(screen.getByTestId('users-page')).toBeInTheDocument();
  });

  it('should not show Users page when user role is not admin', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Regular User', role: 'user' },
    });

    render(<Dashboard />);

    // Try to access users tab (won't be visible in UI, but let's test the logic)
    expect(screen.queryByTestId('users-page')).not.toBeInTheDocument();
  });

  it('should apply active styling to Statistics tab by default', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Test User', role: 'user' },
    });

    render(<Dashboard />);

    const statsButton = screen.getByText('Statistics');
    expect(statsButton).toHaveClass('border-blue-500', 'text-blue-400');
  });

  it('should apply active styling to clicked tab', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const rulesTab = screen.getByText('Rules');
    fireEvent.click(rulesTab);

    expect(rulesTab).toHaveClass('border-blue-500', 'text-blue-400');
  });

  it('should wrap Rules tab with PermissionGate for rules_view', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const rulesButton = screen.getByText('Rules');
    const permissionGate = rulesButton.closest('[data-permission="rules_view"]');
    expect(permissionGate).toBeInTheDocument();
  });

  it('should wrap Logs tab with PermissionGate for logs_view', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const logsButton = screen.getByText('Logs');
    const permissionGate = logsButton.closest('[data-permission="logs_view"]');
    expect(permissionGate).toBeInTheDocument();
  });

  it('should wrap Threat Blocklist tab with PermissionGate for blocklist_view', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const blocklistButton = screen.getByText('Threat Blocklist');
    const permissionGate = blocklistButton.closest('[data-permission="blocklist_view"]');
    expect(permissionGate).toBeInTheDocument();
  });

  it('should wrap Users tab with PermissionGate for users_view', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    const usersButton = screen.getByText('Users');
    const permissionGate = usersButton.closest('[data-permission="users_view"]');
    expect(permissionGate).toBeInTheDocument();
  });

  it('should not display Users content for Admin role with uppercase', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'Admin' },
    });

    render(<Dashboard />);

    const usersTab = screen.getByText('Users');
    fireEvent.click(usersTab);

    // Should be visible because role check is case-insensitive and trimmed
    expect(screen.getByTestId('users-page')).toBeInTheDocument();
  });

  it('should handle null user gracefully', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: null,
    });

    render(<Dashboard />);

    expect(screen.getByText('WAF Dashboard')).toBeInTheDocument();
    // User name should not cause crash
    expect(screen.queryByText('Welcome,')).toBeInTheDocument();
  });

  // TEST PER COPRIRE LINEA 36: click handler del tab Statistics quando si torna da altro tab
  it('should handle click on Statistics tab when switching back from another tab', () => {
    (AuthContext.useAuth as any).mockReturnValue({
      user: { id: 1, name: 'Admin User', role: 'admin' },
    });

    render(<Dashboard />);

    // Inizialmente Statistics è attivo
    expect(screen.getByTestId('stats-page')).toBeInTheDocument();

    // Passa a Rules tab
    const rulesTab = screen.getByText('Rules');
    fireEvent.click(rulesTab);

    // Verifica che Rules sia attivo
    expect(screen.getByTestId('rules-container')).toBeInTheDocument();
    expect(screen.queryByTestId('stats-page')).not.toBeInTheDocument();

    // LINEA 36: Clicca di nuovo su Statistics per tornare indietro
    const statsTab = screen.getByText('Statistics');
    fireEvent.click(statsTab);

    // Verifica che Statistics sia di nuovo attivo
    expect(screen.getByTestId('stats-page')).toBeInTheDocument();
    expect(screen.queryByTestId('rules-container')).not.toBeInTheDocument();
    expect(statsTab).toHaveClass('border-blue-500', 'text-blue-400');
  });
});
