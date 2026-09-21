/**
 * Typed API Client for communicating with the CodeSentinel Backend.
 */

import {
  AnalysisResultDTO,
  APIErrorResponse,
  CompareRequest,
  ComparisonResponseDTO,
  HealthResponse,
  RuleListResponse,
  RuleMetadataDTO,
} from '../types';

export class CodeSentinelAPIError extends Error {
  code: string;
  details?: Record<string, unknown> | null;
  status: number;

  constructor(status: number, errorData: APIErrorResponse) {
    super(errorData.message || `API Error ${status}`);
    this.name = 'CodeSentinelAPIError';
    this.status = status;
    this.code = errorData.code || 'UNKNOWN_ERROR';
    this.details = errorData.details;
  }
}

const DEFAULT_TIMEOUT_MS = 60000;

async function request<T>(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      let errorPayload: APIErrorResponse;
      try {
        errorPayload = await response.json();
      } catch {
        errorPayload = {
          code: `HTTP_${response.status}`,
          message: response.statusText || 'An unexpected HTTP error occurred.',
        };
      }
      throw new CodeSentinelAPIError(response.status, errorPayload);
    }

    return await response.json();
  } catch (err) {
    if (err instanceof CodeSentinelAPIError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new CodeSentinelAPIError(408, {
        code: 'TIMEOUT',
        message: `Request timed out after ${timeoutMs / 1000} seconds.`,
      });
    }
    throw new CodeSentinelAPIError(500, {
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'Network communication failed.',
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Execute static codebase analysis synchronously.
 */
export async function analyzeRepository(
  path: string,
  options: {
    fail_on?: string;
    max_component_depth?: number;
    enabled_rules?: string[];
    disabled_rules?: string[];
  } = {}
): Promise<AnalysisResultDTO> {
  return request<AnalysisResultDTO>('/api/v1/analyze', {
    method: 'POST',
    body: JSON.stringify({
      path: path.trim(),
      ...options,
    }),
  });
}

/**
 * Retrieve list of all registered security and architecture rules.
 */
export async function fetchRules(): Promise<RuleListResponse> {
  return request<RuleListResponse>('/api/v1/rules', {
    method: 'GET',
  });
}

/**
 * Retrieve metadata for a specific rule by ID.
 */
export async function fetchRule(ruleId: string): Promise<RuleMetadataDTO> {
  return request<RuleMetadataDTO>(`/api/v1/rules/${encodeURIComponent(ruleId)}`, {
    method: 'GET',
  });
}

/**
 * Check backend health status.
 */
export async function fetchBackendHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/api/v1/health', {
    method: 'GET',
  });
}

/**
 * Compare current codebase analysis against a baseline run (Phase 9).
 */
export async function compareAnalyses(
  requestPayload: CompareRequest
): Promise<ComparisonResponseDTO> {
  return request<ComparisonResponseDTO>('/api/v1/compare', {
    method: 'POST',
    body: JSON.stringify(requestPayload),
  });
}

