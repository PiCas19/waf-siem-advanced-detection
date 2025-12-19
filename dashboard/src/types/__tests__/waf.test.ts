import { describe, it, expect } from 'vitest';
import { 
  WAFRule, 
  isTestableRule, 
  getCreatedDate, 
  getUpdatedDate, 
  DefaultRule, 
  CustomRule, 
  CustomRulesNested, 
  RulesResponse, 
  RuleTestResult 
} from '@/types/waf';

describe('WAF Types', () => {
  describe('Type Guards and Helpers', () => {
    describe('isTestableRule', () => {
      it('should return true for a rule with pattern', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          pattern: 'test-pattern',
          description: 'Test description',
          enabled: true
        };
        
        expect(isTestableRule(rule)).toBe(true);
      });

      it('should return false for a rule without pattern', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test description',
          enabled: true
        };
        
        expect(isTestableRule(rule)).toBe(false);
      });

      it('should return false for null', () => {
        expect(isTestableRule(null)).toBe(false);
      });

      it('should return false for undefined', () => {
        expect(isTestableRule(undefined)).toBe(false);
      });

      it('should return false for an empty object', () => {
        expect(isTestableRule({} as WAFRule)).toBe(false);
      });

      it('should type guard correctly when pattern is present', () => {
        const rule: WAFRule | null = {
          id: '1',
          name: 'Test Rule',
          pattern: 'test-pattern',
          description: 'Test description',
          enabled: true
        };

        if (isTestableRule(rule)) {
          // TypeScript dovrebbe sapere che rule.pattern esiste qui
          expect(rule.pattern).toBe('test-pattern');
        }
      });
    });

    describe('getCreatedDate', () => {
      it('should return formatted date from createdAt (camelCase)', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true,
          createdAt: '2024-01-15T10:30:00Z'
        };

        const result = getCreatedDate(rule);
        expect(result).toBe('15/01/2024, 11:30:00'); // UTC+1 in Italia
      });

      it('should return formatted date from created_at (snake_case)', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true,
          created_at: '2024-01-15T10:30:00Z'
        };

        const result = getCreatedDate(rule);
        expect(result).toBe('15/01/2024, 11:30:00');
      });

      it('should return "Data sconosciuta" when no date is present', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true
        };

        const result = getCreatedDate(rule);
        expect(result).toBe('Data sconosciuta');
      });

      it('should prefer createdAt over created_at when both are present', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true,
          createdAt: '2024-01-15T10:30:00Z',
          created_at: '2023-12-01T10:30:00Z'
        };

        const result = getCreatedDate(rule);
        expect(result).toBe('15/01/2024, 11:30:00'); // Prende createdAt
      });
    });

    describe('getUpdatedDate', () => {
      it('should return formatted date from updatedAt (camelCase)', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true,
          updatedAt: '2024-01-20T14:45:00Z'
        };

        const result = getUpdatedDate(rule);
        expect(result).toBe('20/01/2024, 15:45:00');
      });

      it('should return formatted date from updated_at (snake_case)', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true,
          updated_at: '2024-01-20T14:45:00Z'
        };

        const result = getUpdatedDate(rule);
        expect(result).toBe('20/01/2024, 15:45:00');
      });

      it('should return "Data sconosciuta" when no date is present', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true
        };

        const result = getUpdatedDate(rule);
        expect(result).toBe('Data sconosciuta');
      });

      it('should prefer updatedAt over updated_at when both are present', () => {
        const rule: WAFRule = {
          id: '1',
          name: 'Test Rule',
          description: 'Test',
          enabled: true,
          updatedAt: '2024-01-20T14:45:00Z',
          updated_at: '2023-12-01T10:30:00Z'
        };

        const result = getUpdatedDate(rule);
        expect(result).toBe('20/01/2024, 15:45:00'); // Prende updatedAt
      });
    });
  });

  describe('Type Definitions', () => {
    describe('WAFRule interface', () => {
      it('should accept minimal WAFRule object', () => {
        const minimalRule: WAFRule = {
          id: '1',
          name: 'Minimal Rule',
          description: 'Minimal description',
          enabled: true
        };

        expect(minimalRule.id).toBe('1');
        expect(minimalRule.name).toBe('Minimal Rule');
        expect(minimalRule.enabled).toBe(true);
      });

      it('should accept full WAFRule object', () => {
        const fullRule: WAFRule = {
          id: '2',
          name: 'Full Rule',
          pattern: 'test-pattern',
          description: 'Full description',
          threatType: 'SQL Injection',
          type: 'regex',
          mode: 'block',
          action: 'block',
          enabled: true,
          createdAt: '2024-01-01T00:00:00Z',
          created_at: '2024-01-01T00:00:00Z',
          updatedAt: '2024-01-02T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
          severity: 'high',
          examples: ['example1', 'example2'],
          is_default: true,
          isDefault: true
        };

        expect(fullRule.id).toBe('2');
        expect(fullRule.pattern).toBe('test-pattern');
        expect(fullRule.mode).toBe('block');
        expect(fullRule.is_default).toBe(true);
        expect(fullRule.isDefault).toBe(true);
      });

      it('should support both camelCase and snake_case fields', () => {
        const rule: WAFRule = {
          id: '3',
          name: 'Mixed Case Rule',
          description: 'Test',
          enabled: true,
          createdAt: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
          is_default: true
        };

        expect(rule.createdAt).toBeDefined();
        expect(rule.updated_at).toBeDefined();
        expect(rule.is_default).toBe(true);
      });
    });

    describe('DefaultRule interface', () => {
      it('should require type, severity, examples and is_default', () => {
        const defaultRule: DefaultRule = {
          id: 'default-1',
          name: 'Default SQL Injection Rule',
          description: 'Detects SQL injection attempts',
          enabled: true,
          type: 'sql-injection',
          severity: 'high',
          examples: ['SELECT * FROM users', 'DROP TABLE users'],
          is_default: true
        };

        expect(defaultRule.type).toBe('sql-injection');
        expect(defaultRule.severity).toBe('high');
        expect(defaultRule.examples).toHaveLength(2);
        expect(defaultRule.is_default).toBe(true);
      });

      it('should extend WAFRule interface', () => {
        const defaultRule: DefaultRule = {
          id: 'default-2',
          name: 'Default Rule',
          description: 'Description',
          enabled: true,
          type: 'xss',
          severity: 'medium',
          examples: ['example'],
          is_default: true,
          pattern: '.*', // Campo opzionale da WAFRule
          mode: 'detect' // Campo opzionale da WAFRule
        };

        expect(defaultRule.pattern).toBe('.*');
        expect(defaultRule.mode).toBe('detect');
      });
    });

    describe('CustomRule interface', () => {
      it('should require specific fields', () => {
        const customRule: CustomRule = {
          id: 'custom-1',
          name: 'My Custom Rule',
          pattern: 'my-pattern',
          description: 'Custom description',
          type: 'custom',
          action: 'block',
          created_at: '2024-01-15T10:30:00Z',
          updated_at: '2024-01-20T14:45:00Z',
          enabled: true
        };

        expect(customRule.id).toBe('custom-1');
        expect(customRule.pattern).toBe('my-pattern');
        expect(customRule.action).toBe('block');
        expect(customRule.created_at).toBeDefined();
        expect(customRule.updated_at).toBeDefined();
      });

      it('should allow action to be either block or log', () => {
        const blockRule: CustomRule = {
          id: '1',
          name: 'Block Rule',
          pattern: 'pattern',
          description: 'Test',
          type: 'custom',
          action: 'block',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
          enabled: true
        };

        const logRule: CustomRule = {
          id: '2',
          name: 'Log Rule',
          pattern: 'pattern',
          description: 'Test',
          type: 'custom',
          action: 'log',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
          enabled: true
        };

        expect(blockRule.action).toBe('block');
        expect(logRule.action).toBe('log');
      });
    });

    describe('CustomRulesNested interface', () => {
      it('should support nested structure with items and pagination', () => {
        const nested: CustomRulesNested = {
          items: [
            {
              id: '1',
              name: 'Custom Rule 1',
              pattern: 'pattern1',
              description: 'Description 1',
              type: 'custom',
              action: 'block',
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-02T00:00:00Z',
              enabled: true
            }
          ],
          pagination: {
            total: 1,
            limit: 10,
            offset: 0
          }
        };

        expect(nested.items).toHaveLength(1);
        expect(nested.pagination?.total).toBe(1);
        expect(nested.pagination?.limit).toBe(10);
      });

      // RIMOSSO: Questo test non è corretto perché CustomRulesNested non è un array
      // it('should support array of CustomRule directly', () => {
      //   const directArray: CustomRule[] = [
      //     {
      //       id: '1',
      //       name: 'Custom Rule 1',
      //       pattern: 'pattern1',
      //       description: 'Description 1',
      //       type: 'custom',
      //       action: 'block',
      //       created_at: '2024-01-01T00:00:00Z',
      //       updated_at: '2024-01-02T00:00:00Z',
      //       enabled: true
      //     }
      //   ];
      // 
      //   const nestedWithArray: CustomRulesNested = directArray;
      //   expect(Array.isArray(nestedWithArray)).toBe(true);
      // });
    });

    describe('RulesResponse interface', () => {
      it('should support various response structures', () => {
        const response: RulesResponse = {
          default_rules: [
            {
              id: 'default-1',
              name: 'Default Rule',
              description: 'Default description',
              enabled: true,
              type: 'sql-injection',
              severity: 'high',
              examples: ['example'],
              is_default: true
            }
          ],
          custom_rules: {
            items: [
              {
                id: 'custom-1',
                name: 'Custom Rule',
                pattern: 'pattern',
                description: 'Custom description',
                type: 'custom',
                action: 'block',
                created_at: '2024-01-01T00:00:00Z',
                updated_at: '2024-01-02T00:00:00Z',
                enabled: true
              }
            ],
            pagination: {
              total: 1,
              limit: 10,
              offset: 0
            }
          },
          total_rules: 2,
          total_default_rules: 1,
          total_custom_rules: 1
        };

        expect(response.default_rules).toHaveLength(1);
        expect(response.custom_rules).toHaveProperty('items');
        expect(response.total_rules).toBe(2);
      });

      it('should support camelCase fields', () => {
        const response: RulesResponse = {
          defaultRules: [
            {
              id: 'default-1',
              name: 'Default Rule',
              description: 'Description',
              enabled: true,
              type: 'type',
              severity: 'high',
              examples: ['example'],
              is_default: true
            }
          ],
          customRules: [
            {
              id: 'custom-1',
              name: 'Custom Rule',
              pattern: 'pattern',
              description: 'Description',
              type: 'custom',
              action: 'block',
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-02T00:00:00Z',
              enabled: true
            }
          ],
          totalRules: 2
        };

        expect(response.defaultRules).toBeDefined();
        expect(response.customRules).toBeDefined();
        expect(response.totalRules).toBe(2);
      });

      it('should support flat rules array', () => {
        const response: RulesResponse = {
          rules: [
            {
              id: '1',
              name: 'Rule 1',
              pattern: 'pattern1',
              description: 'Description 1',
              type: 'custom',
              action: 'block',
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-02T00:00:00Z',
              enabled: true
            }
          ],
          total_rules: 1
        };

        expect(response.rules).toHaveLength(1);
        expect(response.total_rules).toBe(1);
      });
    });

    describe('RuleTestResult interface', () => {
      it('should require matched and message fields', () => {
        const result: RuleTestResult = {
          matched: true,
          message: 'Pattern matched successfully'
        };

        expect(result.matched).toBe(true);
        expect(result.message).toBe('Pattern matched successfully');
      });

      it('should support both true and false for matched', () => {
        const trueResult: RuleTestResult = {
          matched: true,
          message: 'Matched'
        };

        const falseResult: RuleTestResult = {
          matched: false,
          message: 'Not matched'
        };

        expect(trueResult.matched).toBe(true);
        expect(falseResult.matched).toBe(false);
      });
    });
  });

  describe('Integration Tests', () => {
    it('should handle test results', () => {
      const testResults: RuleTestResult[] = [
        { matched: true, message: 'Pattern matched' },
        { matched: false, message: 'No match found' }
      ];

      expect(testResults[0].matched).toBe(true);
      expect(testResults[1].matched).toBe(false);
      expect(testResults[0].message).toContain('Pattern');
    });
  });
});