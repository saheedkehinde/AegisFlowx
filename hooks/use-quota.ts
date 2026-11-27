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

export async function refreshQuota(): Promise<void> {
  if (typeof window === 'undefined') return;
  if (inFlightFetch) {
    return inFlightFetch;
  }

  setGlobalQuotaState({ loading: globalQuotaState.quota === null });

  inFlightFetch = (async () => {
    try {
      const res = await fetch('/api/quota', {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
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
      } else {
        setGlobalQuotaState({
          quota: data?.quota || null,
          loading: false,
          error: data?.error || 'Unable to verify remaining investigation credits.',
          errorCode: (data?.errorCode as QuotaErrorCode) || 'quota_service_unavailable',
          requiresVerification: Boolean(data?.requiresVerification),
        });
      }
    } catch {
      setGlobalQuotaState({
        loading: false,
        error: 'Unable to reach investigation quota service.',
        errorCode: 'quota_service_unavailable',
        requiresVerification: false,
      });
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
