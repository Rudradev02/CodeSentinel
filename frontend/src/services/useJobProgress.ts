/**
 * Custom React hook for tracking real-time analysis progress via Server-Sent Events (SSE).
 */

import { useCallback, useEffect, useState } from 'react';
import { cancelJob, subscribeToJobProgress } from '../api/client';
import { SSEProgressEvent } from '../types';

export interface UseJobProgressReturn {
  status: string;
  progressPercent: number;
  progressStage: string | null;
  progressMessage: string | null;
  snapshotId: string | null;
  errorMessage: string | null;
  isTerminal: boolean;
  cancel: () => Promise<void>;
  reset: () => void;
}

export function useJobProgress(
  jobId: string | null,
  callbacks?: {
    onCompleted?: (snapshotId: string) => void;
    onFailed?: (error: string) => void;
    onCancelled?: () => void;
  }
): UseJobProgressReturn {
  const [status, setStatus] = useState<string>('IDLE');
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [progressStage, setProgressStage] = useState<string | null>(null);
  const [progressMessage, setProgressMessage] = useState<string | null>(null);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const reset = useCallback(() => {
    setStatus('IDLE');
    setProgressPercent(0);
    setProgressStage(null);
    setProgressMessage(null);
    setSnapshotId(null);
    setErrorMessage(null);
  }, []);

  const cancel = useCallback(async () => {
    if (!jobId) return;
    try {
      await cancelJob(jobId);
      setStatus('CANCELLED');
      setProgressMessage('Cancellation requested...');
    } catch (err) {
      console.error('Failed to cancel job:', err);
    }
  }, [jobId]);

  useEffect(() => {
    if (!jobId) {
      reset();
      return;
    }

    setStatus('QUEUED');
    setProgressPercent(0);
    setProgressMessage('Connecting to analysis worker stream...');

    const unsubscribe = subscribeToJobProgress(
      jobId,
      (event: SSEProgressEvent) => {
        setStatus(event.status);
        setProgressPercent(event.progress_percent ?? 0);
        if (event.progress_stage) setProgressStage(event.progress_stage);
        if (event.progress_message) setProgressMessage(event.progress_message);
        if (event.snapshot_id) setSnapshotId(event.snapshot_id);
        if (event.error_message) setErrorMessage(event.error_message);

        if (event.status === 'COMPLETED' && event.snapshot_id) {
          callbacks?.onCompleted?.(event.snapshot_id);
        } else if (event.status === 'FAILED') {
          callbacks?.onFailed?.(event.error_message || 'Analysis task failed');
        } else if (event.status === 'CANCELLED') {
          callbacks?.onCancelled?.();
        }
      },
      (err: Event) => {
        console.warn('SSE stream error or disconnect for job', jobId, err);
      }
    );

    return () => {
      unsubscribe();
    };
  }, [jobId, callbacks, reset]);

  const isTerminal = ['COMPLETED', 'FAILED', 'CANCELLED'].includes(status);

  return {
    status,
    progressPercent,
    progressStage,
    progressMessage,
    snapshotId,
    errorMessage,
    isTerminal,
    cancel,
    reset,
  };
}
