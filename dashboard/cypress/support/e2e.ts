// Import commands.ts using ES2015 syntax:
import './commands';

// Suppress specific uncaught exceptions that should not fail tests
Cypress.on('uncaught:exception', (err) => {
  // ResizeObserver errors are benign browser implementation details
  if (err.message.includes('ResizeObserver')) {
    return false;
  }
  // Suppress navigation-related errors from the 401 interceptor logout redirect
  if (err.message.includes('No refresh token available')) {
    return false;
  }
  return true;
});
