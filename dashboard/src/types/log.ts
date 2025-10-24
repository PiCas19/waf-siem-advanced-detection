export interface LogEntry {
  timestamp: string;
  threat_type: string;
  client_ip: string;
  payload: string;
}