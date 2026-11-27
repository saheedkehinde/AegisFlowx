'use client';

import { useEffect, useCallback, useSyncExternalStore } from 'react';
import { useAuth } from '@/hooks/use-auth';
import type { QuotaErrorCode, QuotaSnapshot } from '@/lib/quota-types';

interface SharedQuotaState {
  quota: QuotaSnapshot | null;
  loading: boolean;
  error: string | null;
  errorCode: QuotaErrorCode | null;
  requiresVerification: boolean;
}

let globalQuotaState: SharedQuotaState = {
  quota: null,
  loading: true,
  error: null,
  errorCode: null,
  requiresVerification: false,
};

const listeners = new Set<() => void>();
let inFlightFetch: Promise<void> | null = null;
let lastAuthSignature: string | null = null;

function notify() {
  listeners.forEach((listener) => {
    try {
      listener();
    } catch {
      // Ignore subscriber errors
    }
  });
}

function setGlobalQuotaState(partial: Partial<SharedQuotaState>) {
  globalQuotaState = { ...globalQuotaState, ...partial };
  notify();
}

export function updateQuotaSnapshot(snapshot: QuotaSnapshot | null | undefined) {
  if (!snapshot) return;
  setGlobalQuotaState({
    quota: snapshot,
    loading: false,
    error: null,
    errorCode: null,
    requiresVerification: false,
  });
}

const QUOTA_FETCH_TIMEOUT_MS = 10000;
const QUOTA_RETRY_DELAY_MS = 700;
const QUOTA_MAX_ATTEMPTS = 2;

function isTransientQuotaFetchFailure(status: number | null, errorCode?: string | null): boolean {
  if (errorCode === 'invalid_guest_token' || errorCode === 'email_verification_required') {
    return false;
  }
  if (status === null) return true; // Network/timeout error
  return status >= 500 || status === 429;
}

export async function refreshQuota(): Promise<void> {
  if (typeof window === 'undefined') return;
  if (inFlightFetch) {
    return inFlightFetch;
  }

  setGlobalQuotaState({ loading: true, error: null });

  inFlightFetch = (async () => {
    try {
      for (let attempt = 1; attempt <= QUOTA_MAX_ATTEMPTS; attempt++) {
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timeoutId = controller
          ? window.setTimeout(() => controller.abort(), QUOTA_FETCH_TIMEOUT_MS)
          : undefined;

        try {
          const res = await fetch('/api/quota', {
            method: 'GET',
            cache: 'no-store',
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
            signal: controller?.signal,
          });

          const data = await res.json().catch(() => null);

          if (res.ok && data?.quota) {
            setGlobalQuotaState({
              quota: data.quota as QuotaSnapshot,
              loading: false,
              error: null,
              errorCode: null,
              requiresVerification: false,
            });
            return;
          }

          const errorCode =
            (data?.errorCode as QuotaErrorCode | undefined) || 'quota_service_unavailable';
          const canRetry =
            attempt < QUOTA_MAX_ATTEMPTS && isTransientQuotaFetchFailure(res.status, errorCode);

          if (canRetry) {
            await new Promise((resolve) => window.setTimeout(resolve, QUOTA_RETRY_DELAY_MS));
            continue;
          }

          setGlobalQuotaState({
            quota: null,
            loading: false,
            error: data?.error || 'Unable to verify remaining investigation credits.',
            errorCode,
            requiresVerification: Boolean(data?.requiresVerification),
          });
          return;
        } catch (err: unknown) {
          const canRetry = attempt < QUOTA_MAX_ATTEMPTS;
          if (canRetry) {
            await new Promise((resolve) => window.setTimeout(resolve, QUOTA_RETRY_DELAY_MS));
            continue;
          }

          const timedOut =
            err instanceof Error && (err.name === 'AbortError' || err.name === 'TimeoutError');
          setGlobalQuotaState({
            quota: null,
            loading: false,
            error: timedOut
              ? 'Investigation credit check timed out. Please retry.'
              : 'Unable to reach investigation quota service.',
            errorCode: 'quota_service_unavailable',
            requiresVerification: false,
          });
          return;
        } finally {
          if (timeoutId !== undefined) {
            window.clearTimeout(timeoutId);
          }
        }
      }
    } finally {
      inFlightFetch = null;
    }
  })();

  return inFlightFetch;
}

function subscribe(callback: () => void) {
  listeners.add(callback);
  return () => {
    listeners.delete(callback);
  };
}

function getSnapshot(): SharedQuotaState {
  return globalQuotaState;
}

export function useQuota() {
  const { authState, user } = useAuth();
  const state = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  useEffect(() => {
    if (authState === 'loading') return;
    const signature = `${authState}:${user?.id || 'guest'}`;
    if (lastAuthSignature !== signature) {
      lastAuthSignature = signature;
      refreshQuota();
    }
  }, [authState, user?.id]);

  const stableRefresh = useCallback(() => refreshQuota(), []);
  const stableUpdate = useCallback(
    (snapshot: QuotaSnapshot | null | undefined) => updateQuotaSnapshot(snapshot),
    []
  );

  return {
    quota: state.quota,
    loading: state.loading,
    error: state.error,
    errorCode: state.errorCode,
    requiresVerification: state.requiresVerification,
    refreshQuota: stableRefresh,
    updateQuotaSnapshot: stableUpdate,
  };
}
