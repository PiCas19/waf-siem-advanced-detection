import { describe, it, expect } from 'vitest';
import {
  UserRole,
  RolePermissions,
  ROLE_PERMISSIONS,
  getPermissionsForRole,
  hasPermission
} from '@/types/rbac';

describe('RBAC Types', () => {
  describe('Type Definitions', () => {
    describe('UserRole type', () => {
      it('should accept valid user roles', () => {
        const adminRole: UserRole = 'admin';
        const operatorRole: UserRole = 'operator';
        const analystRole: UserRole = 'analyst';
        const userRole: UserRole = 'user';

        expect(adminRole).toBe('admin');
        expect(operatorRole).toBe('operator');
        expect(analystRole).toBe('analyst');
        expect(userRole).toBe('user');
      });

      it('should reject invalid roles', () => {
        // TypeScript dovrebbe segnalare un errore per i ruoli non validi
        // Questo è testato dal compilatore TypeScript, non dal runtime
        // const invalidRole: UserRole = 'superadmin'; // Questo darebbe errore TypeScript
      });
    });

    describe('RolePermissions interface', () => {
      it('should have all required permissions fields', () => {
        const permissions: RolePermissions = {
          dashboard: true,
          rules_view: true,
          rules_create: true,
          rules_edit: true,
          rules_delete: true,
          logs_view: true,
          logs_export: true,
          logs_delete: true,
          blocklist_view: true,
          blocklist_add: true,
          blocklist_remove: true,
          whitelist_view: true,
          whitelist_add: true,
          whitelist_remove: true,
          false_positives_view: true,
          false_positives_report: true,
          false_positives_resolve: true,
          false_positives_delete: true,
          threats_block: true,
          threats_unblock: true,
          users_view: true,
          users_create: true,
          users_edit: true,
          users_delete: true,
          users_change_role: true,
          access_control: true,
          settings: true,
        };

        expect(typeof permissions.dashboard).toBe('boolean');
        expect(typeof permissions.rules_view).toBe('boolean');
        expect(typeof permissions.users_view).toBe('boolean');
        expect(typeof permissions.settings).toBe('boolean');
      });

      it('should accept partial permissions (all booleans)', () => {
        const partialPermissions: Partial<RolePermissions> = {
          dashboard: true,
          rules_view: false,
          logs_view: true,
        };

        expect(partialPermissions.dashboard).toBe(true);
        expect(partialPermissions.rules_view).toBe(false);
        expect(partialPermissions.logs_view).toBe(true);
      });
    });
  });

  describe('ROLE_PERMISSIONS constant', () => {
    describe('Admin permissions', () => {
      it('should have full access for admin role', () => {
        const adminPermissions = ROLE_PERMISSIONS.admin;

        // Verifica che l'admin abbia accesso completo
        expect(adminPermissions.dashboard).toBe(true);
        expect(adminPermissions.rules_view).toBe(true);
        expect(adminPermissions.rules_create).toBe(true);
        expect(adminPermissions.rules_edit).toBe(true);
        expect(adminPermissions.rules_delete).toBe(true);
        expect(adminPermissions.logs_view).toBe(true);
        expect(adminPermissions.logs_export).toBe(true);
        expect(adminPermissions.logs_delete).toBe(true);
        expect(adminPermissions.blocklist_view).toBe(true);
        expect(adminPermissions.blocklist_add).toBe(true);
        expect(adminPermissions.blocklist_remove).toBe(true);
        expect(adminPermissions.whitelist_view).toBe(true);
        expect(adminPermissions.whitelist_add).toBe(true);
        expect(adminPermissions.whitelist_remove).toBe(true);
        expect(adminPermissions.false_positives_view).toBe(true);
        expect(adminPermissions.false_positives_report).toBe(true);
        expect(adminPermissions.false_positives_resolve).toBe(true);
        expect(adminPermissions.false_positives_delete).toBe(true);
        expect(adminPermissions.threats_block).toBe(true);
        expect(adminPermissions.threats_unblock).toBe(true);
        expect(adminPermissions.users_view).toBe(true);
        expect(adminPermissions.users_create).toBe(true);
        expect(adminPermissions.users_edit).toBe(true);
        expect(adminPermissions.users_delete).toBe(true);
        expect(adminPermissions.users_change_role).toBe(true);
        expect(adminPermissions.access_control).toBe(true);
        expect(adminPermissions.settings).toBe(true);
      });
    });

    describe('Operator permissions', () => {
      it('should have appropriate permissions for operator role', () => {
        const operatorPermissions = ROLE_PERMISSIONS.operator;

        // Operator può vedere dashboard
        expect(operatorPermissions.dashboard).toBe(true);

        // Operator può gestire regole (tranne delete)
        expect(operatorPermissions.rules_view).toBe(true);
        expect(operatorPermissions.rules_create).toBe(true);
        expect(operatorPermissions.rules_edit).toBe(true);
        expect(operatorPermissions.rules_delete).toBe(false);

        // Operator può vedere ed esportare log (tranne delete)
        expect(operatorPermissions.logs_view).toBe(true);
        expect(operatorPermissions.logs_export).toBe(true);
        expect(operatorPermissions.logs_delete).toBe(false);

        // Operator può gestire liste
        expect(operatorPermissions.blocklist_view).toBe(true);
        expect(operatorPermissions.blocklist_add).toBe(true);
        expect(operatorPermissions.blocklist_remove).toBe(true);
        expect(operatorPermissions.whitelist_view).toBe(true);
        expect(operatorPermissions.whitelist_add).toBe(true);
        expect(operatorPermissions.whitelist_remove).toBe(true);

        // Operator può gestire false positives
        expect(operatorPermissions.false_positives_view).toBe(true);
        expect(operatorPermissions.false_positives_report).toBe(true);
        expect(operatorPermissions.false_positives_resolve).toBe(true);
        expect(operatorPermissions.false_positives_delete).toBe(true);

        // Operator può bloccare/sbloccare minacce
        expect(operatorPermissions.threats_block).toBe(true);
        expect(operatorPermissions.threats_unblock).toBe(true);

        // Operator NON può gestire utenti
        expect(operatorPermissions.users_view).toBe(false);
        expect(operatorPermissions.users_create).toBe(false);
        expect(operatorPermissions.users_edit).toBe(false);
        expect(operatorPermissions.users_delete).toBe(false);
        expect(operatorPermissions.users_change_role).toBe(false);

        // Operator può gestire access control ma non settings generali
        expect(operatorPermissions.access_control).toBe(true);
        expect(operatorPermissions.settings).toBe(false);
      });
    });

    describe('Analyst permissions', () => {
      it('should have read-only permissions for analyst role', () => {
        const analystPermissions = ROLE_PERMISSIONS.analyst;

        // Analyst può vedere solo dashboard e log
        expect(analystPermissions.dashboard).toBe(true);
        expect(analystPermissions.logs_view).toBe(true);

        // Analyst NON può esportare o eliminare log
        expect(analystPermissions.logs_export).toBe(false);
        expect(analystPermissions.logs_delete).toBe(false);

        // Analyst NON può gestire regole
        expect(analystPermissions.rules_view).toBe(false);
        expect(analystPermissions.rules_create).toBe(false);
        expect(analystPermissions.rules_edit).toBe(false);
        expect(analystPermissions.rules_delete).toBe(false);

        // Analyst NON può gestire liste
        expect(analystPermissions.blocklist_view).toBe(false);
        expect(analystPermissions.blocklist_add).toBe(false);
        expect(analystPermissions.blocklist_remove).toBe(false);
        expect(analystPermissions.whitelist_view).toBe(false);
        expect(analystPermissions.whitelist_add).toBe(false);
        expect(analystPermissions.whitelist_remove).toBe(false);

        // Analyst NON può gestire false positives
        expect(analystPermissions.false_positives_view).toBe(false);
        expect(analystPermissions.false_positives_report).toBe(false);
        expect(analystPermissions.false_positives_resolve).toBe(false);
        expect(analystPermissions.false_positives_delete).toBe(false);

        // Analyst NON può bloccare/sbloccare minacce
        expect(analystPermissions.threats_block).toBe(false);
        expect(analystPermissions.threats_unblock).toBe(false);

        // Analyst NON può gestire utenti
        expect(analystPermissions.users_view).toBe(false);
        expect(analystPermissions.users_create).toBe(false);
        expect(analystPermissions.users_edit).toBe(false);
        expect(analystPermissions.users_delete).toBe(false);
        expect(analystPermissions.users_change_role).toBe(false);

        // Analyst NON può gestire access control o settings
        expect(analystPermissions.access_control).toBe(false);
        expect(analystPermissions.settings).toBe(false);
      });
    });

    describe('User permissions', () => {
      it('should have minimal permissions for regular user role', () => {
        const userPermissions = ROLE_PERMISSIONS.user;

        // User può vedere solo dashboard
        expect(userPermissions.dashboard).toBe(true);

        // Tutte le altre permissions devono essere false
        expect(userPermissions.rules_view).toBe(false);
        expect(userPermissions.rules_create).toBe(false);
        expect(userPermissions.rules_edit).toBe(false);
        expect(userPermissions.rules_delete).toBe(false);
        expect(userPermissions.logs_view).toBe(false);
        expect(userPermissions.logs_export).toBe(false);
        expect(userPermissions.logs_delete).toBe(false);
        expect(userPermissions.blocklist_view).toBe(false);
        expect(userPermissions.blocklist_add).toBe(false);
        expect(userPermissions.blocklist_remove).toBe(false);
        expect(userPermissions.whitelist_view).toBe(false);
        expect(userPermissions.whitelist_add).toBe(false);
        expect(userPermissions.whitelist_remove).toBe(false);
        expect(userPermissions.false_positives_view).toBe(false);
        expect(userPermissions.false_positives_report).toBe(false);
        expect(userPermissions.false_positives_resolve).toBe(false);
        expect(userPermissions.false_positives_delete).toBe(false);
        expect(userPermissions.threats_block).toBe(false);
        expect(userPermissions.threats_unblock).toBe(false);
        expect(userPermissions.users_view).toBe(false);
        expect(userPermissions.users_create).toBe(false);
        expect(userPermissions.users_edit).toBe(false);
        expect(userPermissions.users_delete).toBe(false);
        expect(userPermissions.users_change_role).toBe(false);
        expect(userPermissions.access_control).toBe(false);
        expect(userPermissions.settings).toBe(false);
      });
    });
  });

  describe('Helper Functions', () => {
    describe('getPermissionsForRole', () => {
      it('should return admin permissions for admin role', () => {
        const permissions = getPermissionsForRole('admin');
        expect(permissions.dashboard).toBe(true);
        expect(permissions.rules_delete).toBe(true);
        expect(permissions.users_view).toBe(true);
      });

      it('should return operator permissions for operator role', () => {
        const permissions = getPermissionsForRole('operator');
        expect(permissions.dashboard).toBe(true);
        expect(permissions.rules_delete).toBe(false);
        expect(permissions.users_view).toBe(false);
        expect(permissions.access_control).toBe(true);
      });

      it('should return analyst permissions for analyst role', () => {
        const permissions = getPermissionsForRole('analyst');
        expect(permissions.dashboard).toBe(true);
        expect(permissions.logs_view).toBe(true);
        expect(permissions.logs_export).toBe(false);
        expect(permissions.rules_view).toBe(false);
      });

      it('should return user permissions for user role', () => {
        const permissions = getPermissionsForRole('user');
        expect(permissions.dashboard).toBe(true);
        expect(permissions.logs_view).toBe(false);
        expect(permissions.rules_view).toBe(false);
        expect(permissions.users_view).toBe(false);
      });

      it('should default to user permissions for unknown role', () => {
        // Usiamo 'any' per testare un ruolo non valido
        const invalidRole = 'invalid' as UserRole;
        const permissions = getPermissionsForRole(invalidRole);
        
        // Dovrebbe tornare le permissions di default (user)
        expect(permissions.dashboard).toBe(true);
        expect(permissions.logs_view).toBe(false);
        expect(permissions.rules_view).toBe(false);
      });

      it('should return the same reference as ROLE_PERMISSIONS', () => {
        const adminPermissions1 = getPermissionsForRole('admin');
        const adminPermissions2 = ROLE_PERMISSIONS.admin;
        
        // Dovrebbero essere lo stesso oggetto (stesso riferimento)
        expect(adminPermissions1).toBe(adminPermissions2);
      });
    });

    describe('hasPermission', () => {
      it('should return true when admin has permission', () => {
        expect(hasPermission('admin', 'dashboard')).toBe(true);
        expect(hasPermission('admin', 'rules_delete')).toBe(true);
        expect(hasPermission('admin', 'users_create')).toBe(true);
        expect(hasPermission('admin', 'settings')).toBe(true);
      });

      it('should return false when admin does not have permission (all true for admin)', () => {
        // Admin ha tutte le permissions a true, quindi questo test è per completezza
        // Se aggiungessimo una permission che admin non ha, qui verrebbe testata
      });

      it('should correctly check operator permissions', () => {
        // Operator ha alcune permissions
        expect(hasPermission('operator', 'dashboard')).toBe(true);
        expect(hasPermission('operator', 'rules_edit')).toBe(true);
        expect(hasPermission('operator', 'access_control')).toBe(true);
        
        // Operator non ha altre permissions
        expect(hasPermission('operator', 'rules_delete')).toBe(false);
        expect(hasPermission('operator', 'users_view')).toBe(false);
        expect(hasPermission('operator', 'settings')).toBe(false);
      });

      it('should correctly check analyst permissions', () => {
        // Analyst ha poche permissions
        expect(hasPermission('analyst', 'dashboard')).toBe(true);
        expect(hasPermission('analyst', 'logs_view')).toBe(true);
        
        // Analyst non ha altre permissions
        expect(hasPermission('analyst', 'logs_export')).toBe(false);
        expect(hasPermission('analyst', 'rules_view')).toBe(false);
        expect(hasPermission('analyst', 'threats_block')).toBe(false);
      });

      it('should correctly check user permissions', () => {
        // User ha solo dashboard
        expect(hasPermission('user', 'dashboard')).toBe(true);
        
        // User non ha altre permissions
        expect(hasPermission('user', 'logs_view')).toBe(false);
        expect(hasPermission('user', 'rules_view')).toBe(false);
        expect(hasPermission('user', 'blocklist_view')).toBe(false);
        expect(hasPermission('user', 'access_control')).toBe(false);
      });

      it('should handle invalid role by defaulting to user permissions', () => {
        const invalidRole = 'invalid' as UserRole;
        
        // Per un ruolo non valido, dovrebbe tornare le permissions di default (user)
        expect(hasPermission(invalidRole, 'dashboard')).toBe(true);
        expect(hasPermission(invalidRole, 'logs_view')).toBe(false);
        expect(hasPermission(invalidRole, 'rules_view')).toBe(false);
      });

      it('should work with all permission keys', () => {
        // Testa alcune permission chiave per ogni ruolo
        const testPermissions: Array<keyof RolePermissions> = [
          'dashboard',
          'rules_view',
          'logs_view',
          'blocklist_add',
          'false_positives_report',
          'threats_block',
          'users_view',
          'access_control',
          'settings'
        ];

        testPermissions.forEach(permission => {
          // Admin dovrebbe avere tutte le permissions
          expect(hasPermission('admin', permission)).toBe(true);
          
          // Controlla che la funzione non lanci errori
          expect(() => hasPermission('operator', permission)).not.toThrow();
          expect(() => hasPermission('analyst', permission)).not.toThrow();
          expect(() => hasPermission('user', permission)).not.toThrow();
        });
      });
    });
  });

  describe('Integration Tests', () => {
    it('should maintain permission hierarchy correctly', () => {

      
      // Conta il numero di permissions true per ogni ruolo
      const countPermissions = (role: UserRole): number => {
        const permissions = ROLE_PERMISSIONS[role];
        return Object.values(permissions).filter(Boolean).length;
      };
      
      const adminCount = countPermissions('admin');
      const operatorCount = countPermissions('operator');
      const analystCount = countPermissions('analyst');
      const userCount = countPermissions('user');
      
      // Admin dovrebbe avere più permissions
      expect(adminCount).toBeGreaterThan(operatorCount);
      expect(operatorCount).toBeGreaterThan(analystCount);
      expect(analystCount).toBeGreaterThan(userCount);
      
      // User dovrebbe avere solo dashboard
      expect(userCount).toBe(1); // solo dashboard
      
      // Analyst dovrebbe avere almeno 2 permissions (dashboard + logs_view)
      expect(analystCount).toBeGreaterThanOrEqual(2);
    });

    it('should provide consistent permission structure', () => {
      // Verifica che tutte le chiavi di permissions siano presenti in ogni ruolo
      const permissionKeys = Object.keys(ROLE_PERMISSIONS.admin) as Array<keyof RolePermissions>;
      
      Object.values(ROLE_PERMISSIONS).forEach(permissions => {
        // Ogni ruolo dovrebbe avere tutte le chiavi
        permissionKeys.forEach(key => {
          expect(permissions).toHaveProperty(key);
          expect(typeof permissions[key]).toBe('boolean');
        });
        
        // Il numero totale di chiavi dovrebbe essere consistente
        expect(Object.keys(permissions).length).toBe(permissionKeys.length);
      });
    });

    it('should work with real-world permission scenarios', () => {
      // Scenario 1: Admin può fare tutto
      expect(hasPermission('admin', 'users_create')).toBe(true);
      expect(hasPermission('admin', 'rules_delete')).toBe(true);
      expect(hasPermission('admin', 'logs_delete')).toBe(true);
      expect(hasPermission('admin', 'settings')).toBe(true);

      // Scenario 2: Operator può gestire regole ma non eliminare utenti
      expect(hasPermission('operator', 'rules_create')).toBe(true);
      expect(hasPermission('operator', 'rules_edit')).toBe(true);
      expect(hasPermission('operator', 'rules_delete')).toBe(false);
      expect(hasPermission('operator', 'users_delete')).toBe(false);

      // Scenario 3: Analyst può solo visualizzare
      expect(hasPermission('analyst', 'logs_view')).toBe(true);
      expect(hasPermission('analyst', 'logs_export')).toBe(false);
      expect(hasPermission('analyst', 'threats_block')).toBe(false);

      // Scenario 4: User ha accesso minimo
      expect(hasPermission('user', 'dashboard')).toBe(true);
      expect(hasPermission('user', 'rules_view')).toBe(false);
      expect(hasPermission('user', 'blocklist_view')).toBe(false);
    });
  });
});