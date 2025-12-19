describe('Authentication', () => {
  beforeEach(() => {
    cy.clearStorage();
  });

  describe('Login Page', () => {
    it('should display login form', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').should('be.visible');
      cy.get('input[placeholder="••••••••"]').should('be.visible');
      cy.contains('button', 'Login').should('be.visible');
    });

    it('should show validation errors for empty fields', () => {
      cy.visit('/login');
      cy.contains('button', 'Login').click();
      // HTML5 validation dovrebbe impedire il submit
      cy.get('input[placeholder="you@example.com"]:invalid').should('exist');
    });

    it('should login with valid credentials', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').type('admin@test.com');
      cy.get('input[placeholder="••••••••"]').type('password123');

      // Intercept login API call
      cy.intercept('POST', '/api/auth/login', {
        statusCode: 200,
        body: {
          token: 'fake-jwt-token',
          user: {
            id: 1,
            email: 'admin@test.com',
            name: 'Admin User',
            role: 'admin',
            two_fa_enabled: false
          },
        },
      }).as('loginRequest');

      cy.contains('button', 'Login').click();

      // Wait for API call
      cy.wait('@loginRequest');

      // Should redirect to dashboard
      cy.url().should('include', '/dashboard');
      cy.contains('WAF Dashboard').should('be.visible');
    });

    it('should show error message for invalid credentials', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').type('wronguser@test.com');
      cy.get('input[placeholder="••••••••"]').type('wrongpass');

      // Intercept failed login
      cy.intercept('POST', '/api/auth/login', {
        statusCode: 401,
        body: { error: 'Invalid credentials' },
      }).as('loginRequest');

      cy.contains('button', 'Login').click();

      cy.wait('@loginRequest');

      // Should show error message in red div
      cy.get('.bg-red-500').contains(/invalid|error|failed/i).should('be.visible');
    });

    it('should navigate to forgot password page', () => {
      cy.visit('/login');
      cy.contains('Forgot password?').click();
      cy.url().should('include', '/forgot-password');
    });

    it('should toggle password visibility', () => {
      cy.visit('/login');

      // Password should be hidden initially
      cy.get('input[placeholder="••••••••"]').should('have.attr', 'type', 'password');

      // Click eye icon to show password
      cy.get('button').find('svg').first().click();

      // Password should now be visible
      cy.get('input[placeholder="••••••••"]').should('have.attr', 'type', 'text');
    });
  });

  describe('2FA Verification Flow', () => {
    it('should show 2FA input after initial login when 2FA is enabled', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').type('user@test.com');
      cy.get('input[placeholder="••••••••"]').type('password123');

      // Mock login response that requires 2FA
      cy.intercept('POST', '/api/auth/login', {
        statusCode: 200,
        body: {
          requires_2fa: true,
          temp_token: 'temp-token-123',
        },
      }).as('loginWith2FA');

      cy.contains('button', 'Login').click();
      cy.wait('@loginWith2FA');

      // Should show 2FA verification screen
      cy.contains('2FA Verification').should('be.visible');
      cy.get('input[placeholder="000000"]').should('be.visible');
      cy.get('input[placeholder="12345678"]').should('be.visible');
      cy.contains('button', 'Verify').should('be.visible');
    });

    it('should verify 2FA code successfully', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').type('user@test.com');
      cy.get('input[placeholder="••••••••"]').type('password123');

      cy.intercept('POST', '/api/auth/login', {
        statusCode: 200,
        body: {
          requires_2fa: true,
          temp_token: 'temp-token-123',
        },
      }).as('loginWith2FA');

      cy.contains('button', 'Login').click();
      cy.wait('@loginWith2FA');

      // Enter 2FA code (6 digits)
      cy.get('input[placeholder="000000"]').type('123456');

      cy.intercept('POST', '/api/auth/verify-otp', {
        statusCode: 200,
        body: {
          token: 'final-auth-token',
          user: {
            id: 1,
            email: 'user@test.com',
            name: 'User',
            role: 'analyst',
            two_fa_enabled: true
          },
        },
      }).as('verify2FA');

      cy.contains('button', 'Verify').click();
      cy.wait('@verify2FA');

      // Should redirect to dashboard
      cy.url().should('include', '/dashboard');
      cy.contains('WAF Dashboard').should('be.visible');
    });

    it('should verify using backup code', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').type('user@test.com');
      cy.get('input[placeholder="••••••••"]').type('password123');

      cy.intercept('POST', '/api/auth/login', {
        statusCode: 200,
        body: {
          requires_2fa: true,
          temp_token: 'temp-token-123',
        },
      }).as('loginWith2FA');

      cy.contains('button', 'Login').click();
      cy.wait('@loginWith2FA');

      // Enter backup code (8 digits)
      cy.get('input[placeholder="12345678"]').type('87654321');

      cy.intercept('POST', '/api/auth/verify-otp', {
        statusCode: 200,
        body: {
          token: 'final-auth-token',
          user: { id: 1, email: 'user@test.com', name: 'User', role: 'analyst' },
        },
      }).as('verify2FA');

      cy.contains('button', 'Verify').click();
      cy.wait('@verify2FA');

      cy.url().should('include', '/dashboard');
    });
  });

  describe('2FA Setup Required Flow', () => {
    it('should redirect to 2FA setup when required', () => {
      cy.visit('/login');
      cy.get('input[placeholder="you@example.com"]').type('newuser@test.com');
      cy.get('input[placeholder="••••••••"]').type('password123');

      cy.intercept('POST', '/api/auth/login', {
        statusCode: 200,
        body: {
          requires_2fa_setup: true,
          token: 'temp-token',
          user: { id: 1, email: 'newuser@test.com', name: 'New User', role: 'user' }
        },
      }).as('loginRequires2FASetup');

      cy.contains('button', 'Login').click();
      cy.wait('@loginRequires2FASetup');

      // Should show 2FA setup required message
      cy.contains('2FA Setup Required').should('be.visible');
      cy.contains('You must set up Two-Factor Authentication before continuing').should('be.visible');
      cy.contains('button', 'Set Up 2FA').should('be.visible');
    });
  });

  describe('Forgot Password Page', () => {
    it('should display forgot password form', () => {
      cy.visit('/forgot-password');
      cy.contains(/forgot password|reset/i).should('be.visible');
      cy.get('input[type="email"]').should('be.visible');
    });
  });

  describe('Set Password Page', () => {
    it('should display set password form with token', () => {
      cy.visit('/set-password?token=test-token-123');
      cy.contains(/set password|create password/i).should('be.visible');
      cy.get('input[type="password"]').should('have.length.at.least', 2);
    });

    it('should set password successfully', () => {
      cy.visit('/set-password?token=test-token-123');

      cy.get('input[type="password"]').eq(0).type('NewSecurePass123!');
      cy.get('input[type="password"]').eq(1).type('NewSecurePass123!');

      cy.intercept('POST', '/api/auth/set-password', {
        statusCode: 200,
        body: {
          token: 'new-auth-token',
          user: { id: 1, email: 'user@test.com', name: 'User', role: 'user', two_fa_enabled: false },
          requires_2fa_setup: true
        },
      }).as('setPassword');

      cy.contains('button', 'Set password').click();
      cy.wait('@setPassword');

      // Should redirect to 2FA setup (not dashboard)
      cy.url({ timeout: 10000 }).should('include', '/setup-2fa');
    });
  });

  describe('Logout', () => {
    it('should logout user and redirect to login', () => {
      // Mock dashboard APIs
      cy.mockDashboardAPIs();

      // Visit dashboard with auth token set before load
      cy.visit('/dashboard', {
        onBeforeLoad: (win) => {
          win.localStorage.setItem('authToken', 'fake-token');
          win.localStorage.setItem('authUser', JSON.stringify({
            id: 1,
            email: 'admin@test.com',
            name: 'Admin User',
            role: 'admin',
            two_fa_enabled: false
          }));
        }
      });
      cy.wait('@getStats');

      // Click avatar menu button (opens dropdown)
      cy.get('button[aria-haspopup="true"]').click();

      // Click logout from dropdown
      cy.contains('Logout').click();

      // Should redirect to login page
      cy.url().should('include', '/login');

      // Token should be removed
      cy.window().then((win) => {
        expect(win.localStorage.getItem('authToken')).to.be.null;
      });
    });
  });

  describe('Protected Routes', () => {
    it('should redirect to login when accessing protected route without auth', () => {
      cy.visit('/dashboard');
      cy.url().should('include', '/login');
    });

    it('should allow access to protected route with valid token', () => {
      cy.mockDashboardAPIs();

      cy.visit('/dashboard', {
        onBeforeLoad: (win) => {
          win.localStorage.setItem('authToken', 'valid-token');
          win.localStorage.setItem('authUser', JSON.stringify({
            id: 1,
            email: 'user@test.com',
            name: 'Test User',
            role: 'analyst',
            two_fa_enabled: false
          }));
        }
      });
      cy.wait('@getStats');

      cy.url().should('include', '/dashboard');
      cy.contains('WAF Dashboard').should('be.visible');
    });
  });
});
