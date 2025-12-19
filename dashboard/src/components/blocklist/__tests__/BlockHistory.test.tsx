import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import BlockHistory from '../BlockHistory';

describe('BlockHistory Component', () => {
  it('renders Block History heading', () => {
    render(<BlockHistory />);
    expect(screen.getByText('Block History')).toBeInTheDocument();
  });

  it('displays coming soon message', () => {
    render(<BlockHistory />);
    expect(screen.getByText('History coming soon...')).toBeInTheDocument();
  });

  it('has correct container styling', () => {
    const { container } = render(<BlockHistory />);
    expect(container.firstChild).toHaveClass('bg-gray-800');
    expect(container.firstChild).toHaveClass('p-6');
    expect(container.firstChild).toHaveClass('rounded-lg');
  });

  it('has semantic heading level', () => {
    render(<BlockHistory />);
    const heading = screen.getByRole('heading', { level: 2 });
    expect(heading).toHaveTextContent('Block History');
  });

  it('has correct text color for content', () => {
    render(<BlockHistory />);
    const content = screen.getByText('History coming soon...');
    expect(content).toHaveClass('text-gray-400');
  });
});