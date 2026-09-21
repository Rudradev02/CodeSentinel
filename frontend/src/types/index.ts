/**
 * CodeSentinel frontend type exports.
 */

export * from './api';

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  uptime_seconds: number;
  timestamp: string;
  components: Record<string, string>;
}
