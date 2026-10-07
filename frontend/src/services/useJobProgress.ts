/**
 * Custom React hook for tracking real-time analysis progress via Server-Sent Events (SSE).
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { cancelJob, getJob, subscribeToJobProgress } from '../api/client';
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
    onCompleted?: (snapshotId: string, repositoryId?: string) => void;
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

  const callbacksRef = useRef(callbacks);
  useEffect(() => {
    callbacksRef.current = callbacks;
  }, [callbacks]);

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

    let isDone = false;
    let pollInterval: ReturnType<typeof setInterval> | null = null;

    const handleTerminalState = async (
      terminalStatus: string,
      snapshot?: string | null,
      error?: string | null,
      repositoryId?: string,
    ) => {
      if (isDone) return;
      isDone = true;
      if (pollInterval) clearInterval(pollInterval);
      setStatus(terminalStatus);
      if (terminalStatus === 'COMPLETED' && snapshot) {
        setSnapshotId(snapshot);
        setProgressPercent(100);
        setProgressStage('COMPLETED');
        setProgressMessage('Analysis completed successfully');
        let finalRepoId = repositoryId;
        if (!finalRepoId && jobId) {
          try {
            const j = await getJob(jobId);
            if (j.repository_id) finalRepoId = j.repository_id;
          } catch {
            // ignore
          }
        }
        callbacksRef.current?.onCompleted?.(snapshot, finalRepoId);
      } else if (terminalStatus === 'FAILED') {
        setErrorMessage(error || 'Analysis task failed');
        callbacksRef.current?.onFailed?.(error || 'Analysis task failed');
      } else if (terminalStatus === 'CANCELLED') {
        callbacksRef.current?.onCancelled?.();
      }
    };

    const unsubscribe = subscribeToJobProgress(
      jobId,
      (event: SSEProgressEvent) => {
        if (isDone) return;
        setStatus(event.status);
        if (event.progress_percent !== undefined) setProgressPercent(event.progress_percent);
        if (event.progress_stage) setProgressStage(event.progress_stage);
        if (event.progress_message) setProgressMessage(event.progress_message);
        if (event.snapshot_id) setSnapshotId(event.snapshot_id);
        if (event.error_message) setErrorMessage(event.error_message);

        if (event.status === 'COMPLETED' && event.snapshot_id) {
          handleTerminalState('COMPLETED', event.snapshot_id, null, event.repository_id ?? undefined);
        } else if (event.status === 'FAILED') {
          handleTerminalState('FAILED', null, event.error_message);
        } else if (event.status === 'CANCELLED') {
          handleTerminalState('CANCELLED');
        }
      },
      (err: Event) => {
        console.warn('SSE stream notice for job', jobId, err);
      }
    );

    // Complementary fast poll to guarantee completion detection even if SSE drops
    const checkJobStatus = async () => {
      if (isDone) return;
      try {
        const job = await getJob(jobId);
        if (isDone) return;
        setStatus(job.status);
        if (job.progress_percent !== undefined) setProgressPercent(job.progress_percent);
        if (job.progress_stage) setProgressStage(job.progress_stage);
        if (job.progress_message) setProgressMessage(job.progress_message);
        if (job.snapshot_id) setSnapshotId(job.snapshot_id);
        if (job.error_message) setErrorMessage(job.error_message);

        if (job.status === 'COMPLETED' && job.snapshot_id) {
          handleTerminalState('COMPLETED', job.snapshot_id, null, job.repository_id);
        } else if (job.status === 'FAILED') {
          handleTerminalState('FAILED', null, job.error_message);
        } else if (job.status === 'CANCELLED') {
          handleTerminalState('CANCELLED');
        }
      } catch {
        // Polling retry on next interval
      }
    };

    // Initial check immediately and every 1.5s
    checkJobStatus();
    pollInterval = setInterval(checkJobStatus, 1500);

    return () => {
      isDone = true;
      if (pollInterval) clearInterval(pollInterval);
      unsubscribe();
    };
  }, [jobId, reset]);

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
