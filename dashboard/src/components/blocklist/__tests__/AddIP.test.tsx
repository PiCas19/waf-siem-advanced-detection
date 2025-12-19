import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import AddIP from '../AddIP';

describe('AddIP Component', () => {
  it('renders Block IP heading', () => {
    render(<AddIP />);
    expect(screen.getByText('Block IP')).toBeInTheDocument();
  });

  it('displays coming soon message', () => {
    render(<AddIP />);
    expect(screen.getByText('Form coming soon...')).toBeInTheDocument();
  });

  it('has correct styling classes', () => {
    const { container } = render(<AddIP />);
    expect(container.firstChild).toHaveClass('bg-gray-800');
    expect(container.firstChild).toHaveClass('p-6');
    expect(container.firstChild).toHaveClass('rounded-lg');
  });
});
