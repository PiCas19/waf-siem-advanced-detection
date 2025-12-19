import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { Card } from '../Card';

describe('Card', () => {
  it('should render card with title', () => {
    render(<Card title="Test Card">Content</Card>);

    expect(screen.getByText('Test Card')).toBeInTheDocument();
  });

  it('should render children content', () => {
    render(<Card title="Title">Test content inside card</Card>);

    expect(screen.getByText('Test content inside card')).toBeInTheDocument();
  });

  it('should render multiple children', () => {
    render(
      <Card title="Multi-content Card">
        <div>First child</div>
        <div>Second child</div>
        <div>Third child</div>
      </Card>
    );

    expect(screen.getByText('First child')).toBeInTheDocument();
    expect(screen.getByText('Second child')).toBeInTheDocument();
    expect(screen.getByText('Third child')).toBeInTheDocument();
  });

  it('should apply correct CSS classes', () => {
    const { container } = render(<Card title="Styled Card">Content</Card>);

    const cardDiv = container.firstChild;
    expect(cardDiv).toHaveClass('bg-gray-800', 'p-6', 'rounded-lg');
  });

  it('should render title as h3 element', () => {
    render(<Card title="Heading Card">Content</Card>);

    const heading = screen.getByRole('heading', { level: 3 });
    expect(heading).toHaveTextContent('Heading Card');
    expect(heading).toHaveClass('text-lg', 'font-semibold', 'mb-4');
  });

  it('should render with complex children elements', () => {
    render(
      <Card title="Complex Card">
        <button>Click me</button>
        <input type="text" placeholder="Enter text" />
        <p>Description text</p>
      </Card>
    );

    expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter text')).toBeInTheDocument();
    expect(screen.getByText('Description text')).toBeInTheDocument();
  });

  it('should handle empty children', () => {
    render(<Card title="Empty Card">{null}</Card>);

    expect(screen.getByText('Empty Card')).toBeInTheDocument();
  });

  it('should render with different titles', () => {
    const { rerender } = render(<Card title="Title 1">Content</Card>);
    expect(screen.getByText('Title 1')).toBeInTheDocument();

    rerender(<Card title="Title 2">Content</Card>);
    expect(screen.getByText('Title 2')).toBeInTheDocument();
  });
});
