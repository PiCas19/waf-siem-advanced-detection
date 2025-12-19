import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import LogDetails from '../LogDetails';

describe('LogDetails Component', () => {
  it('renders Log Details heading', () => {
    render(<LogDetails />);
    const heading = screen.getByRole('heading', { name: 'Log Details' });
    expect(heading).toBeInTheDocument();
  });

  it('displays correct placeholder message', () => {
    render(<LogDetails />);
    expect(screen.getByText(/Select a log to view details/i)).toBeInTheDocument();
  });

  it('has correct container styling', () => {
    const { container } = render(<LogDetails />);
    const mainContainer = container.firstChild;
    
    expect(mainContainer).toHaveClass('bg-gray-800');
    expect(mainContainer).toHaveClass('p-6');
    expect(mainContainer).toHaveClass('rounded-lg');
  });

  it('heading has proper styling', () => {
    render(<LogDetails />);
    const heading = screen.getByText('Log Details');
    expect(heading).toHaveClass('text-xl', 'font-semibold', 'mb-4');
  });

  it('placeholder text has gray color', () => {
    render(<LogDetails />);
    const placeholder = screen.getByText('Select a log to view details');
    expect(placeholder).toHaveClass('text-gray-400');
  });
});