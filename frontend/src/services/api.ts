/**
 * API client service for CodeSentinel Backend communication.
 */

import { HealthResponse } from '../types';

const API_BASE_URL = '';

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Health check failed with HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

export async function fetchV1Health(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`v1 Health check failed with HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}
