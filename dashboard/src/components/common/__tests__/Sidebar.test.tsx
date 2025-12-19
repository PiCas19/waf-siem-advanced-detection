import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import Sidebar from '../Sidebar';

describe('Sidebar', () => {
  it('should render all navigation links', () => {
    render(<Sidebar />);

    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Rules')).toBeInTheDocument();
    expect(screen.getByText('Logs')).toBeInTheDocument();
    expect(screen.getByText('Blocklist')).toBeInTheDocument();
  });

  it('should have correct link destinations', () => {
    render(<Sidebar />);

    const dashboardLink = screen.getByText('Dashboard').closest('a');
    const rulesLink = screen.getByText('Rules').closest('a');
    const logsLink = screen.getByText('Logs').closest('a');
    const blocklistLink = screen.getByText('Blocklist').closest('a');

    expect(dashboardLink).toHaveAttribute('href', '/');
    expect(rulesLink).toHaveAttribute('href', '/rules');
    expect(logsLink).toHaveAttribute('href', '/logs');
    expect(blocklistLink).toHaveAttribute('href', '/blocklist');
  });

  it('should render as aside element', () => {
    const { container } = render(<Sidebar />);

    const aside = container.querySelector('aside');
    expect(aside).toBeInTheDocument();
    expect(aside).toHaveClass('w-64', 'bg-gray-800', 'min-h-screen', 'p-4');
  });

  it('should render navigation within aside', () => {
    const { container } = render(<Sidebar />);

    const nav = container.querySelector('nav');
    expect(nav).toBeInTheDocument();
    expect(nav).toHaveClass('space-y-2');
  });
});
