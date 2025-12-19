/// <reference types="cypress" />

// Custom command to login
Cypress.Commands.add('login', (email: string, password: string) => {
  cy.visit('/login');
  cy.get('input[placeholder="you@example.com"]').type(email);
  cy.get('input[placeholder="••••••••"]').type(password);
  cy.contains('button', 'Login').click();
});

// Custom command to clear localStorage and sessionStorage
Cypress.Commands.add('clearStorage', () => {
  cy.clearLocalStorage();
  cy.clearCookies();
  cy.window().then((win) => {
    win.sessionStorage.clear();
  });
});

// Custom command to set auth token (corrected key: authToken)
Cypress.Commands.add('setAuthToken', (token: string) => {
  // Get the current location or visit about:blank if needed
  cy.document({ log: false }).then((doc) => {
    // We have a document, so we can set localStorage
    doc.defaultView?.localStorage.setItem('authToken', token);
    doc.defaultView?.localStorage.setItem('authUser', JSON.stringify({
      id: 1,
      email: 'test@example.com',
      name: 'Test User',
      role: 'admin',
      two_fa_enabled: false
    }));
  });
});

// Custom command to intercept common API calls
Cypress.Commands.add('mockDashboardAPIs', () => {
  cy.intercept('GET', '/api/stats', {
    statusCode: 200,
    body: {
      threats_detected: 250,
      requests_blocked: 150,
      total_requests: 5000,
      xss_attempts: 50,
      sqli_attempts: 80,
      lfi_attempts: 20,
    },
  }).as('getStats');

  cy.intercept('GET', '/api/logs*', {
    statusCode: 200,
    body: {
      security_logs: [],
      audit_logs: [],
    },
  }).as('getLogs');

  cy.intercept('GET', '/api/rules', {
    statusCode: 200,
    body: {
      default_rules: [],
      custom_rules: {
        items: [],
      },
    },
  }).as('getRules');

  cy.intercept('GET', '/api/blocklist*', {
    statusCode: 200,
    body: { items: [] },
  }).as('getBlocklist');

  cy.intercept('GET', '/api/whitelist*', {
    statusCode: 200,
    body: { items: [] },
  }).as('getWhitelist');

  cy.intercept('GET', '/api/false-positives*', {
    statusCode: 200,
    body: { false_positives: [] },
  }).as('getFalsePositives');

  cy.intercept('GET', '/api/admin/users*', {
    statusCode: 200,
    body: { data: [] },
  }).as('getUsers');
});

// Custom command to visit dashboard with auth already set
Cypress.Commands.add('visitDashboardAuthenticated', (options?: {
  token?: string;
  role?: string;
  email?: string;
  name?: string;
}) => {
  const token = options?.token || 'test-token';
  const role = options?.role || 'admin';
  const email = options?.email || 'admin@test.com';
  const name = options?.name || 'Admin User';

  cy.mockDashboardAPIs();
  cy.visit('/dashboard', {
    onBeforeLoad: (win) => {
      win.localStorage.setItem('authToken', token);
      win.localStorage.setItem('authUser', JSON.stringify({
        id: 1,
        email,
        name,
        role,
        two_fa_enabled: false
      }));
    }
  });
});

// Declare custom commands for TypeScript
declare global {
  namespace Cypress {
    interface Chainable {
      login(email: string, password: string): Chainable<void>;
      clearStorage(): Chainable<void>;
      setAuthToken(token: string): Chainable<void>;
      mockDashboardAPIs(): Chainable<void>;
      visitDashboardAuthenticated(options?: { token?: string; role?: string; email?: string; name?: string }): Chainable<void>;
    }
  }
}

export {};
