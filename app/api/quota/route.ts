import { NextRequest, NextResponse } from 'next/server';
import { attachGuestCookie, getOrInitializeQuotaSnapshot } from '@/lib/quota';
import { redactSecrets } from '@/lib/model-config';
import { getOrCreateCorrelationId, logSafeRouteEvent } from '@/lib/diagnostics-log';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const correlationId = getOrCreateCorrelationId(req);
  const startMs = Date.now();

  try {
    const outcome = await getOrInitializeQuotaSnapshot(req);

    if (!outcome.ok || !outcome.snapshot) {
      const errorCode = outcome.errorCode || 'quota_service_unavailable';
      logSafeRouteEvent({
        correlationId,
        endpoint: '/api/quota',
        stage: outcome.status >= 500 ? 'quota_unavailable' : 'quota_blocked',
        httpStatus: outcome.status,
        errorCategory: errorCode,
        providerCategory: 'quota',
        quotaOutcome: 'blocked',
        durationMs: Date.now() - startMs,
      });

      const errRes = NextResponse.json(
        {
          error: redactSecrets(
            outcome.error || 'Unable to retrieve investigation quota balance.'
          ),
          errorCode,
          requiresVerification: outcome.requiresVerification ?? false,
        },
        {
          status: outcome.status,
          headers: {
            'Cache-Control': 'no-store, max-age=0',
            Vary: 'Cookie',
            'X-Aegis-Correlation-Id': correlationId,
          },
        }
      );

      return attachGuestCookie(errRes, outcome.cookieToSet);
    }

    logSafeRouteEvent({
      correlationId,
      endpoint: '/api/quota',
      stage: 'init_success',
      httpStatus: 200,
      providerCategory: 'quota',
      quotaOutcome: 'initialized',
      durationMs: Date.now() - startMs,
    });

    const response = NextResponse.json(
      {
        quota: outcome.snapshot,
      },
      {
        status: 200,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
          Vary: 'Cookie',
          'X-Aegis-Correlation-Id': correlationId,
        },
      }
    );

    return attachGuestCookie(response, outcome.cookieToSet);
  } catch (err: unknown) {
    logSafeRouteEvent({
      correlationId,
      endpoint: '/api/quota',
      stage: 'unhandled_exception',
      httpStatus: 503,
      errorCategory: 'quota_service_unavailable',
      providerCategory: 'quota',
      quotaOutcome: 'blocked',
      durationMs: Date.now() - startMs,
    });

    console.error(
      'Unhandled error in GET /api/quota:',
      redactSecrets(err instanceof Error ? err.message : 'unknown_error')
    );

    return NextResponse.json(
      {
        error: 'Usage quota protection service is temporarily unavailable.',
        errorCode: 'quota_service_unavailable',
      },
      {
        status: 503,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
          Vary: 'Cookie',
          'X-Aegis-Correlation-Id': correlationId,
        },
      }
    );
  }
}
