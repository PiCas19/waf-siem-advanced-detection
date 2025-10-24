export interface Rule {
  id: string;
  name: string;
  severity: string;
  patterns: string[];
  enabled: boolean;
}