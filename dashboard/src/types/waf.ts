/**
 * Unified WAF Types
 * Shared type definitions for WAF rules and related components
 */

export interface WAFRule {
  id: string;
  name: string;
  pattern?: string;
  description: string;
  threatType?: string;
  type?: string;
  mode?: 'block' | 'detect';
  action?: string;
  enabled: boolean;
  createdAt?: string;
  created_at?: string;
  updatedAt?: string;
  updated_at?: string;
  severity?: string;
  examples?: string[];
  is_default?: boolean;
  isDefault?: boolean;
}

// Type guard per verificare se una regola ha i campi richiesti per il test
export function isTestableRule(rule: WAFRule | null | undefined): rule is WAFRule & { pattern: string } {
  // Considera testabile se ha un pattern; la modalità può essere derivata da mode o action
  return Boolean(rule && rule.pattern);
}

// Helper per ottenere la data di creazione (supporta sia camelCase che snake_case)
export function getCreatedDate(rule: WAFRule): string {
  const date = rule.createdAt || rule.created_at;
  if (!date) return 'Data sconosciuta';
  return new Date(date).toLocaleString('it-IT');
}

// Helper per ottenere la data di aggiornamento (supporta sia camelCase che snake_case)
export function getUpdatedDate(rule: WAFRule): string {
  const date = rule.updatedAt || rule.updated_at;
  if (!date) return 'Data sconosciuta';
  return new Date(date).toLocaleString('it-IT');
}

export interface DefaultRule extends WAFRule {
  type: string;
  severity: string;
  examples: string[];
  is_default: true;
}

export interface CustomRule extends WAFRule {
  id: string;
  name: string;
  pattern: string;
  type: string;
  action: 'block' | 'log';
  created_at: string;
  updated_at: string;
}

export interface CustomRulesNested {
  items?: CustomRule[];
  pagination?: {
    total: number;
    limit: number;
    offset: number;
  };
}

export interface RulesResponse {
  // API returns nested structure: custom_rules: { items: [...], pagination: {...} }
  default_rules?: DefaultRule[];
  defaultRules?: DefaultRule[];
  custom_rules?: CustomRulesNested | CustomRule[];
  customRules?: CustomRule[];
  rules?: CustomRule[];
  total_rules?: number;
  totalRules?: number;
  total_default_rules?: number;
  total_custom_rules?: number;
}

export interface RuleTestResult {
  matched: boolean;
  message: string;
}
