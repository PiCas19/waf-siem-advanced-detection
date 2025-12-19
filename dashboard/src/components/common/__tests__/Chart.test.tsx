// src/components/common/__tests__/Chart.test.tsx
import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Chart from '../Chart';
import { BarChart, Bar, XAxis, YAxis, LineChart, Line } from 'recharts';
import { useState } from 'react';

// Mock di ResponsiveContainer per evitare problemi con dimensioni
vi.mock('recharts', async () => {
  const actual = await vi.importActual('recharts');
  return {
    ...actual,
    ResponsiveContainer: ({ children, width, height }: { 
      children: React.ReactNode; 
      width?: string; 
      height?: number 
    }) => (
      <div 
        data-testid="responsive-container" 
        data-width={width} 
        data-height={height}
      >
        {children}
      </div>
    ),
    BarChart: ({ children, data }: any) => (
      <div data-testid="bar-chart" data-items={data?.length}>
        {children}
      </div>
    ),
    LineChart: ({ children, data }: any) => (
      <div data-testid="line-chart" data-items={data?.length}>
        {children}
      </div>
    ),
    XAxis: () => <div data-testid="x-axis">XAxis</div>,
    YAxis: () => <div data-testid="y-axis">YAxis</div>,
    Bar: ({ dataKey, fill }: any) => (
      <div data-testid="bar" data-key={dataKey} data-fill={fill}>
        Bar
      </div>
    ),
    Line: ({ dataKey, stroke }: any) => (
      <div data-testid="line" data-key={dataKey} data-stroke={stroke}>
        Line
      </div>
    ),
  };
});

describe('Chart', () => {
  it('should render ResponsiveContainer with correct props', () => {
    render(
      <Chart>
        <div>Test Child</div>
      </Chart>
    );

    const container = screen.getByTestId('responsive-container');
    expect(container).toBeInTheDocument();
    expect(container).toHaveAttribute('data-width', '100%');
    expect(container).toHaveAttribute('data-height', '300');
  });

  it('should render children inside ResponsiveContainer', () => {
    render(
      <Chart>
        <div data-testid="test-child">Chart Content</div>
      </Chart>
    );

    expect(screen.getByTestId('test-child')).toBeInTheDocument();
    expect(screen.getByText('Chart Content')).toBeInTheDocument();
  });

  it('should render Recharts components as children', () => {
    const testData = [
      { name: 'A', value: 10 },
      { name: 'B', value: 20 },
      { name: 'C', value: 30 },
    ];

    render(
      <Chart>
        <BarChart data={testData}>
          <XAxis dataKey="name" />
          <YAxis />
          <Bar dataKey="value" fill="#8884d8" />
        </BarChart>
      </Chart>
    );

    expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    expect(screen.getByTestId('bar-chart')).toHaveAttribute('data-items', '3');
    expect(screen.getByTestId('x-axis')).toBeInTheDocument();
    expect(screen.getByTestId('y-axis')).toBeInTheDocument();
    expect(screen.getByTestId('bar')).toBeInTheDocument();
    expect(screen.getByTestId('bar')).toHaveAttribute('data-key', 'value');
    expect(screen.getByTestId('bar')).toHaveAttribute('data-fill', '#8884d8');
  });

  it('should accept any React element as children', () => {
    const CustomComponent = () => <div data-testid="custom-component">Custom</div>;

    render(
      <Chart>
        <CustomComponent />
      </Chart>
    );

    expect(screen.getByTestId('custom-component')).toBeInTheDocument();
    expect(screen.getByText('Custom')).toBeInTheDocument();
  });

  it('should handle complex nested children', () => {
    render(
      <Chart>
        <div>
          <h3>Chart Title</h3>
          <svg data-testid="test-svg" width="100" height="100">
            <circle cx="50" cy="50" r="40" fill="blue" />
          </svg>
          <p>Description</p>
        </div>
      </Chart>
    );

    expect(screen.getByText('Chart Title')).toBeInTheDocument();
    expect(screen.getByText('Description')).toBeInTheDocument();
    expect(screen.getByTestId('test-svg')).toBeInTheDocument();
  });

  it('should maintain 100% width and 300px height', () => {
    render(
      <Chart>
        <div>Test</div>
      </Chart>
    );

    const responsiveContainer = screen.getByTestId('responsive-container');
    expect(responsiveContainer).toHaveAttribute('data-width', '100%');
    expect(responsiveContainer).toHaveAttribute('data-height', '300');
  });

  it('should work with fragment as children', () => {
    render(
      <Chart>
        <>
          <span>Part 1</span>
          <span>Part 2</span>
        </>
      </Chart>
    );

    expect(screen.getByText('Part 1')).toBeInTheDocument();
    expect(screen.getByText('Part 2')).toBeInTheDocument();
  });

  it('should preserve children props and state', () => {
    const ButtonWithState = () => {
      const [clicked, setClicked] = useState(false);
      
      return (
        <button 
          data-testid="state-button" 
          onClick={() => setClicked(true)}
        >
          {clicked ? 'Clicked' : 'Click me'}
        </button>
      );
    };

    render(
      <Chart>
        <ButtonWithState />
      </Chart>
    );

    const button = screen.getByTestId('state-button');
    expect(button).toHaveTextContent('Click me');
    
    fireEvent.click(button);
    expect(button).toHaveTextContent('Clicked');
  });

  it('should render multiple chart types', () => {
    const lineData = [
      { x: 1, y: 10 },
      { x: 2, y: 20 },
      { x: 3, y: 15 },
    ];

    render(
      <Chart>
        <LineChart data={lineData}>
          <XAxis dataKey="x" />
          <YAxis />
          <Line dataKey="y" stroke="#ff7300" />
        </LineChart>
      </Chart>
    );

    expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    expect(screen.getByTestId('line-chart')).toHaveAttribute('data-items', '3');
    expect(screen.getByTestId('line')).toHaveAttribute('data-key', 'y');
    expect(screen.getByTestId('line')).toHaveAttribute('data-stroke', '#ff7300');
  });

  it('should render with conditional children using valid ReactElement', () => {
    const shouldShow = true;
    const content = shouldShow ? <div data-testid="conditional">Conditional Content</div> : <div>Fallback</div>;
    
    render(
      <Chart>
        {content}
      </Chart>
    );

    expect(screen.getByTestId('conditional')).toBeInTheDocument();
    expect(screen.getByText('Conditional Content')).toBeInTheDocument();
  });

  it('should work with valid React fragment containing single element', () => {
    // Fragment con singolo elemento è valido
    render(
      <Chart>
        <>
          <div data-testid="single-in-fragment">Single in Fragment</div>
        </>
      </Chart>
    );

    expect(screen.getByTestId('single-in-fragment')).toBeInTheDocument();
  });

  it('should accept valid JSX element types', () => {
    // Test con diversi tipi validi di JSX
    const tests = [
      { element: <span>Span element</span>, testId: 'span-test' },
      { element: <button>Button</button>, testId: 'button-test' },
      { element: <input type="text" placeholder="Input" />, testId: 'input-test' },
    ];

    tests.forEach(({ element, testId }) => {
      const { unmount } = render(
        <Chart>
          {React.cloneElement(element, { 'data-testid': testId })}
        </Chart>
      );

      expect(screen.getByTestId(testId)).toBeInTheDocument();
      unmount();
    });
  });

  it('should handle component with props correctly', () => {
    const ComponentWithProps = ({ text, count }: { text: string; count: number }) => (
      <div data-testid="with-props">
        {text} - {count}
      </div>
    );

    render(
      <Chart>
        <ComponentWithProps text="Test" count={42} />
      </Chart>
    );

    expect(screen.getByTestId('with-props')).toBeInTheDocument();
    expect(screen.getByText('Test - 42')).toBeInTheDocument();
  });
});