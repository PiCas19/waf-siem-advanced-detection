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
export function isTestableRule(rule: WAFRule | null | undefined): rule is WAFRule & { pattern: string; mode: 'block' | 'detect' } {
  return Boolean(rule && rule.pattern && rule.mode);
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

export interface RulesResponse {
  default_rules?: DefaultRule[];
  defaultRules?: DefaultRule[];
  custom_rules?: CustomRule[];
  customRules?: CustomRule[];
  rules?: CustomRule[];
  total_rules?: number;
  totalRules?: number;
}

export interface RuleTestResult {
  matched: boolean;
  message: string;
}
