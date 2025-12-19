import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Register from '../Register';

describe('Register', () => {
  it('should render Registration Disabled title', () => {
    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>
    );

    expect(screen.getByText('Registration Disabled')).toBeInTheDocument();
  });

  it('should render explanation message', () => {
    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>
    );

    expect(
      screen.getByText(
        /Account creation is restricted to administrators. If you need an account, please contact your administrator./
      )
    ).toBeInTheDocument();
  });

  it('should render link to login page', () => {
    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>
    );

    const loginLink = screen.getByText('Go to Login');
    expect(loginLink).toBeInTheDocument();
    expect(loginLink).toHaveAttribute('href', '/login');
  });

  it('should have proper styling for disabled registration', () => {
    render(
      <BrowserRouter>
        <Register />
      </BrowserRouter>
    );

    const container = screen.getByText('Registration Disabled').closest('div');
    expect(container).toHaveClass('bg-gray-800');
  });
});
