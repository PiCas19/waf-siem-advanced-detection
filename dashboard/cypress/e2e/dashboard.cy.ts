describe('Dashboard Navigation and Features', () => {
  beforeEach(() => {
    cy.clearStorage();
  });

  describe('Main Dashboard', () => {
    it('should display dashboard after login', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');
      cy.url().should('include', '/dashboard');
      cy.contains('WAF Dashboard').should('be.visible');
    });

    it('should show welcome message with user name', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');
      cy.contains(/welcome/i).should('be.visible');
    });

    it('should display all navigation tabs', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      // Check all tabs are visible
      cy.contains('button', 'Statistics').should('be.visible');
      cy.contains('button', 'Rules').should('be.visible');
      cy.contains('button', 'Logs').should('be.visible');
      cy.contains('button', 'Threat Blocklist').should('be.visible');
      cy.contains('button', 'Users').should('be.visible');
    });

    it('should have Statistics tab active by default', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      // Statistics tab should have active styling
      cy.contains('button', 'Statistics')
        .should('have.class', 'border-blue-500')
        .and('have.class', 'text-blue-400');
    });
  });

  describe('Statistics Tab', () => {
    it('should show statistics cards', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      // Check for numbers from mock (250, 150, 5000)
      cy.contains(/250|150|5000/i).should('be.visible');
    });

    it('should display charts', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      // Recharts uses SVG
      cy.get('svg', { timeout: 10000 }).should('exist');
    });
  });

  describe('Rules Tab', () => {
    it('should navigate to rules tab', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('button', 'Rules').click();

      // Tab should be active
      cy.contains('button', 'Rules')
        .should('have.class', 'border-blue-500');
    });

    it('should open add rule form', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Rules').click();
      cy.wait('@getRules');

      cy.contains('button', 'Add Rule').click();

      // Form should be visible
      cy.get('input').should('be.visible');
    });
  });

  describe('Logs Tab', () => {
    it('should navigate to logs tab', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('button', 'Logs').click();

      // Tab should be active
      cy.contains('button', 'Logs')
        .should('have.class', 'border-blue-500');
    });

    it('should display security logs sub-tab', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Logs').click();
      cy.wait('@getLogs');

      // Should show Security Logs sub-tab
      cy.contains('Security Logs').should('be.visible');
      cy.contains('Audit Logs').should('be.visible');
    });

    it('should have export buttons', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Logs').click();
      cy.wait('@getLogs');

      cy.contains('button', 'Export CSV').should('be.visible');
      cy.contains('button', 'Export JSON').should('be.visible');
      cy.contains('button', 'Export PDF').should('be.visible');
    });
  });

  describe('Threat Blocklist Tab', () => {
    it('should navigate to blocklist tab', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('button', 'Threat Blocklist').click();

      // Tab should be active
      cy.contains('button', 'Threat Blocklist')
        .should('have.class', 'border-blue-500');
    });

    it('should display three sub-tabs', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Threat Blocklist').click();
      cy.wait('@getBlocklist');

      // Check for all three sub-tabs
      cy.contains('Blocklist').should('be.visible');
      cy.contains('Whitelist').should('be.visible');
      cy.contains('False Positives').should('be.visible');
    });

    it('should switch to whitelist tab', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Threat Blocklist').click();
      cy.wait('@getBlocklist');

      cy.contains('button', 'Whitelist').click();

      // Whitelist tab should be active
      cy.contains('button', 'Whitelist')
        .should('have.class', 'border-green-500');
    });

    it('should switch to false positives tab', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Threat Blocklist').click();
      cy.wait('@getBlocklist');

      cy.contains('button', 'False Positives').click();

      // False Positives tab should be active
      cy.contains('button', 'False Positives')
        .should('have.class', 'border-blue-500');
    });
  });

  describe('Users Tab (Admin)', () => {
    it('should navigate to users tab', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('button', 'Users').click();

      // Tab should be active
      cy.contains('button', 'Users')
        .should('have.class', 'border-blue-500');
    });

    it('should have add user button', () => {
      cy.visitDashboardAuthenticated();
      cy.contains('button', 'Users').click();
      cy.wait('@getUsers');

      cy.contains('button', /add user|\+ user/i).should('be.visible');
    });
  });

  describe('Tab Navigation Persistence', () => {
    it('should remember active tab when switching', () => {
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      // Switch to Rules
      cy.contains('button', 'Rules').click();
      cy.contains('button', 'Rules').should('have.class', 'border-blue-500');

      // Switch to Logs
      cy.contains('button', 'Logs').click();
      cy.contains('button', 'Logs').should('have.class', 'border-blue-500');
      cy.contains('button', 'Rules').should('have.class', 'border-transparent');

      // Switch back to Statistics
      cy.contains('button', 'Statistics').click();
      cy.contains('button', 'Statistics').should('have.class', 'border-blue-500');
      cy.contains('button', 'Logs').should('have.class', 'border-transparent');
    });
  });

  describe('Responsive Design', () => {
    it('should work on desktop viewport', () => {
      cy.viewport(1920, 1080);
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('WAF Dashboard').should('be.visible');
      cy.contains('button', 'Statistics').should('be.visible');
    });

    it('should work on tablet viewport', () => {
      cy.viewport('ipad-2');
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('Statistics').should('be.visible');
    });

    it('should work on mobile viewport', () => {
      cy.viewport('iphone-x');
      cy.visitDashboardAuthenticated();
      cy.wait('@getStats');

      cy.contains('WAF Dashboard').should('be.visible');
    });
  });
});
