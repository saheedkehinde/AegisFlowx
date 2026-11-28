import { randomUUID } from 'node:crypto';
import { redactSecrets } from '@/lib/model-config';

export type SafeQuotaOutcome =
  | 'none'
  | 'initialized'
  | 'reserved'
  | 'committed'
  | 'refunded'
  | 'blocked';

export interface SafeRouteDiagnosticEvent {
  correlationId: string;
  endpoint: string;
  stage: string;
  httpStatus: number;
  detail?: string;
  errorCategory?: string;
  providerCategory?:
    | 'primary_ai'
    | 'fallback_ai'
    | 'quota'
    | 'rate_limit'
    | 'validation'
    | 'auth'
    | 'transport'
    | 'none';
  fallbackAttempted?: boolean;
  quotaOutcome?: SafeQuotaOutcome;
  middlewareOutcome?: string;
  durationMs?: number;
}

/**
 * Extracts or mints a sanitized request correlation ID without reading sensitive headers or bodies.
 */
export function getOrCreateCorrelationId(req?: Request): string {
  try {
    const candidate =
      req?.headers?.get?.('x-aegis-correlation-id') ||
      req?.headers?.get?.('x-request-id') ||
      req?.headers?.get?.('x-vercel-id') ||
      '';
    const cleaned = candidate.trim().replace(/[^A-Za-z0-9._:-]/g, '');
    if (cleaned.length >= 6 && cleaned.length <= 64) {
      return cleaned;
    }
  } catch {
    // Ignore synthetic request header errors
  }

  try {
    return `aegis-${randomUUID().slice(0, 12)}`;
  } catch {
    return `aegis-${Date.now().toString(36)}`;
  }
}

/**
 * Emits a compact, strictly sanitized structured diagnostic record to server logs.
 * Never logs tokens, secrets, cookies, raw IPs, user IDs, message bodies, or file contents,
 * and never throws or interrupts request handling.
 */
export function logSafeRouteEvent(event: SafeRouteDiagnosticEvent): void {
  try {
    const httpStatus = Number(event.httpStatus || 500);
    const isErrorStatus = httpStatus >= 400;
    const rawDetail = event.detail || (!isErrorStatus ? event.errorCategory : undefined);

    const payload = {
      ts: new Date().toISOString(),
      correlationId: redactSecrets(String(event.correlationId || 'unknown')).slice(0, 64),
      endpoint: String(event.endpoint || 'unknown').slice(0, 64),
      stage: String(event.stage || 'unknown').slice(0, 64),
      httpStatus,
      detail: rawDetail ? redactSecrets(String(rawDetail)).slice(0, 64) : undefined,
      errorCategory:
        isErrorStatus && event.errorCategory
          ? redactSecrets(String(event.errorCategory)).slice(0, 64)
          : undefined,
      providerCategory: event.providerCategory || 'none',
      fallbackAttempted: Boolean(event.fallbackAttempted),
      quotaOutcome: event.quotaOutcome || 'none',
      middlewareOutcome: event.middlewareOutcome
        ? redactSecrets(String(event.middlewareOutcome).replace(/[^A-Za-z0-9._:-]/g, '_')).slice(
            0,
            48
          )
        : undefined,
      durationMs:
        typeof event.durationMs === 'number' && Number.isFinite(event.durationMs)
          ? Math.max(0, Math.round(event.durationMs))
          : undefined,
    };

    const line = `[AegisDiag] ${JSON.stringify(payload)}`;
    if (payload.httpStatus >= 500) {
      console.warn(line);
    } else {
      console.info(line);
    }
  } catch {
    // Logging must never affect request outcome
  }
}
