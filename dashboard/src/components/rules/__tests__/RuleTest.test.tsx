// RuleTest.test.tsx
import { describe, it, expect} from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import RuleTest from '../RuleTest';
import { WAFRule } from '../../../types/waf';

// Mock rule data con tipi corretti
const mockRuleWithPattern: WAFRule = {
  id: '1',
  name: 'Test SQL Rule',
  pattern: 'SELECT.*FROM',
  description: 'Test rule for SQL injection',
  type: 'regex',
  severity: 'HIGH',
  enabled: true,
  mode: 'block' as 'block',
  action: 'block' as 'block',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

const mockRuleWithDetectMode: WAFRule = {
  ...mockRuleWithPattern,
  mode: 'detect' as 'detect',
  action: 'detect' as 'detect',
};

const mockRuleWithOnlyActionBlock: WAFRule = {
  ...mockRuleWithPattern,
  mode: undefined,
  action: 'block' as 'block',
};

const mockRuleWithOnlyActionDetect: WAFRule = {
  ...mockRuleWithPattern,
  mode: undefined,
  action: 'detect' as 'detect',
};

const mockRuleWithoutPattern: WAFRule = {
  ...mockRuleWithPattern,
  pattern: undefined,
};

const mockRuleWithInvalidRegex: WAFRule = {
  ...mockRuleWithPattern,
  pattern: 'SELECT[',
};

describe('RuleTest', () => {
  // Test 1: renders without rule
  it('renders without rule', () => {
    render(<RuleTest rule={null} />);
    expect(screen.getByText('Select a rule from the list to test it')).toBeInTheDocument();
  });

  // Test 2: renders with testable rule - CORRETTO
  it('renders with testable rule', () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    // Usa query più specifiche invece di getByText generico
    expect(screen.getByRole('heading', { name: 'Test Rule' })).toBeInTheDocument();
    expect(screen.getByText('Rule under test:')).toBeInTheDocument();
    expect(screen.getByText('Test SQL Rule')).toBeInTheDocument();
    expect(screen.getByText(/Pattern:/)).toBeInTheDocument();
    expect(screen.getByText('SELECT.*FROM')).toBeInTheDocument();
  });

  // Test 3: renders with non-testable rule - CORRETTO
  it('renders with non-testable rule', () => {
    render(<RuleTest rule={mockRuleWithoutPattern} />);
    expect(screen.getByText('Select a rule from the list to test it')).toBeInTheDocument();
  });

  // Test 4: tests rule successfully with match
  it('tests rule successfully with match', async () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' },
    });

    // Usa getByRole per trovare il button specifico
    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('MATCH DETECTED')).toBeInTheDocument();
      expect(screen.getByText(/Pattern found!/)).toBeInTheDocument();
      expect(screen.getByText(/BLOCK.*BLOCK/)).toBeInTheDocument();
    });
  });

  // Test 5: tests rule successfully without match
  it('tests rule successfully without match', async () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'Normal text without SQL' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('NO MATCH')).toBeInTheDocument();
      expect(screen.getByText(/Pattern not found/)).toBeInTheDocument();
    });
  });

  // Test 6: shows error for empty test input
  it('shows error for empty test input', async () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    // Textarea starts empty
    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('Please enter some text to test')).toBeInTheDocument();
    });
  });

  // Test 7: shows error for invalid regex pattern
  it('shows error for invalid regex pattern', async () => {
    render(<RuleTest rule={mockRuleWithInvalidRegex} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'Test input' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText(/Error in regex pattern:/)).toBeInTheDocument();
    });
  });

  // Test 8: clears test input and results
  it('clears test input and results', async () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('MATCH DETECTED')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));

    expect(textarea).toHaveValue('');
    expect(screen.queryByText('MATCH DETECTED')).not.toBeInTheDocument();
  });

  // Test 9: handles detect mode in result message
  it('handles detect mode in result message', async () => {
    render(<RuleTest rule={mockRuleWithDetectMode} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('MATCH DETECTED')).toBeInTheDocument();
      expect(screen.getByText(/Pattern found!/)).toBeInTheDocument();
      expect(screen.getByText(/DETECT.*DETECT/)).toBeInTheDocument();
    });
  });

  // Test 10: handles rule with only action property (block)
  it('handles rule with only action property', async () => {
    render(<RuleTest rule={mockRuleWithOnlyActionBlock} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText(/Pattern found!/)).toBeInTheDocument();
      expect(screen.getByText(/BLOCK.*BLOCK/)).toBeInTheDocument();
    });
  });

  // Test 11: handles rule with only action property (detect)
  it('handles rule with only action property', async () => {
    render(<RuleTest rule={mockRuleWithOnlyActionDetect} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText(/Pattern found!/)).toBeInTheDocument();
      expect(screen.getByText(/DETECT.*DETECT/)).toBeInTheDocument();
    });
  });

  // Test 12: shows different styling for match vs no match
  it('shows different styling for match vs no match', async () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    const textarea = screen.getByRole('textbox');
    
    // Test with match
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      const matchResult = screen.getByText('MATCH DETECTED').closest('div');
      expect(matchResult).toHaveClass('bg-red-500/20');
    });

    // Clear and test without match
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    
    fireEvent.change(textarea, {
      target: { value: 'Normal text' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      const noMatchResult = screen.getByText('NO MATCH').closest('div');
      expect(noMatchResult).toHaveClass('bg-green-500/20');
    });
  });

  // Test 13: handles case-insensitive regex
  it('handles case-insensitive regex', async () => {
    const caseInsensitiveRule: WAFRule = {
      ...mockRuleWithPattern,
      pattern: 'select',
    };
    
    render(<RuleTest rule={caseInsensitiveRule} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users' }, // uppercase in input
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('MATCH DETECTED')).toBeInTheDocument();
    });
  });

  // Test 14: handles multiple matches in input
  it('handles multiple matches in input', async () => {
    render(<RuleTest rule={mockRuleWithPattern} />);
    
    const textarea = screen.getByRole('textbox');
    fireEvent.change(textarea, {
      target: { value: 'SELECT * FROM users; SELECT * FROM orders' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Test Rule' }));

    await waitFor(() => {
      expect(screen.getByText('MATCH DETECTED')).toBeInTheDocument();
    });
  });
});