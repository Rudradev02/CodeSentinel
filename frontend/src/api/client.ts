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

// ==============================================================================
// Phase 10: Persistent Analysis Storage & Repository Catalog APIs
// ==============================================================================

import {
  AnalysisHistoryDTO,
  AnalysisJobDTO,
  JobListDTO,
  RepositoryDTO,
  RepositoryListDTO,
  SSEProgressEvent,
} from '../types';

/**
 * List all registered repositories.
 */
export async function listRepositories(
  skip: number = 0,
  limit: number = 50
): Promise<RepositoryListDTO> {
  return request<RepositoryListDTO>(`/api/v1/repositories?skip=${skip}&limit=${limit}`, {
    method: 'GET',
  });
}

/**
 * Register a local codebase repository.
 */
export async function registerRepository(
  path: string,
  name?: string
): Promise<RepositoryDTO> {
  return request<RepositoryDTO>('/api/v1/repositories', {
    method: 'POST',
    body: JSON.stringify({ path, name }),
  });
}

/**
 * Fetch a single repository by UUID.
 */
export async function getRepository(repositoryId: string): Promise<RepositoryDTO> {
  return request<RepositoryDTO>(`/api/v1/repositories/${encodeURIComponent(repositoryId)}`, {
    method: 'GET',
  });
}

/**
 * Delete a repository and its cascaded historical analyses.
 */
export async function deleteRepository(repositoryId: string): Promise<void> {
  return request<void>(`/api/v1/repositories/${encodeURIComponent(repositoryId)}`, {
    method: 'DELETE',
  });
}

/**
 * Queue asynchronous analysis on a registered repository (202 Accepted).
 */
export async function runRepositoryAnalysis(
  repositoryId: string,
  options: {
    fail_on?: string;
    max_component_depth?: number;
    enabled_rules?: string[];
    disabled_rules?: string[];
  } = {}
): Promise<AnalysisJobDTO> {
  return request<AnalysisJobDTO>(`/api/v1/repositories/${encodeURIComponent(repositoryId)}/analyses`, {
    method: 'POST',
    body: JSON.stringify(options),
  });
}

/**
 * Fetch status of an analysis job.
 */
export async function getJob(jobId: string): Promise<AnalysisJobDTO> {
  return request<AnalysisJobDTO>(`/api/v1/jobs/${encodeURIComponent(jobId)}`, {
    method: 'GET',
  });
}

/**
 * Request cooperative cancellation of an analysis job.
 */
export async function cancelJob(jobId: string): Promise<AnalysisJobDTO> {
  return request<AnalysisJobDTO>(`/api/v1/jobs/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST',
  });
}

/**
 * Fetch paginated list of jobs for a repository.
 */
export async function listRepositoryJobs(
  repositoryId: string,
  skip: number = 0,
  limit: number = 20
): Promise<JobListDTO> {
  return request<JobListDTO>(
    `/api/v1/repositories/${encodeURIComponent(repositoryId)}/jobs?skip=${skip}&limit=${limit}`,
    {
      method: 'GET',
    }
  );
}

/**
 * Subscribe to real-time progress events for an analysis job via Server-Sent Events (SSE).
 * Returns an unsubscribe / cleanup function.
 */
export function subscribeToJobProgress(
  jobId: string,
  onEvent: (event: SSEProgressEvent) => void,
  onError?: (err: Event) => void
): () => void {
  const url = `/api/v1/jobs/${encodeURIComponent(jobId)}/stream`;
  const eventSource = new EventSource(url);

  const handleMessage = (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data) as SSEProgressEvent;
      onEvent(data);
    } catch {
      // Ignore unparseable frames
    }
  };

  eventSource.addEventListener('progress', handleMessage);
  eventSource.addEventListener('completed', (e: MessageEvent) => {
    handleMessage(e);
    eventSource.close();
  });
  eventSource.addEventListener('failed', (e: MessageEvent) => {
    handleMessage(e);
    eventSource.close();
  });
  eventSource.addEventListener('cancelled', (e: MessageEvent) => {
    handleMessage(e);
    eventSource.close();
  });

  if (onError) {
    eventSource.onerror = (err) => {
      onError(err);
    };
  }

  return () => {
    eventSource.close();
  };
}

/**
 * Fetch historical analysis snapshots for a repository.
 */
export async function listRepositoryAnalyses(
  repositoryId: string,
  skip: number = 0,
  limit: number = 20
): Promise<AnalysisHistoryDTO> {
  return request<AnalysisHistoryDTO>(
    `/api/v1/repositories/${encodeURIComponent(repositoryId)}/analyses?skip=${skip}&limit=${limit}`,
    {
      method: 'GET',
    }
  );
}

/**
 * Fetch a specific historical analysis snapshot reconstructed from database.
 */
export async function getHistoricalAnalysis(
  repositoryId: string,
  analysisId: string
): Promise<AnalysisResultDTO> {
  return request<AnalysisResultDTO>(
    `/api/v1/repositories/${encodeURIComponent(repositoryId)}/analyses/${encodeURIComponent(analysisId)}`,
    {
      method: 'GET',
    }
  );
}

