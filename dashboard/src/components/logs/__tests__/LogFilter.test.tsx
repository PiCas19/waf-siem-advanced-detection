import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import LogFilter from '../LogFilter';

describe('LogFilter Component', () => {
  it('renders Filters heading', () => {
    render(<LogFilter />);
    expect(screen.getByText('Filters')).toBeInTheDocument();
  });

  it('displays coming soon message', () => {
    render(<LogFilter />);
    expect(screen.getByText('Coming soon...')).toBeInTheDocument();
  });

  it('has correct container styling', () => {
    const { container } = render(<LogFilter />);
    expect(container.firstChild).toHaveClass('bg-gray-800');
    expect(container.firstChild).toHaveClass('p-4');
    expect(container.firstChild).toHaveClass('rounded-lg');
  });

  it('heading has correct styling', () => {
    render(<LogFilter />);
    const heading = screen.getByText('Filters');
    expect(heading).toHaveClass('font-semibold', 'mb-2');
  });

  it('coming soon text has correct styling', () => {
    render(<LogFilter />);
    const comingSoonText = screen.getByText('Coming soon...');
    expect(comingSoonText).toHaveClass('text-gray-400');
  });
});