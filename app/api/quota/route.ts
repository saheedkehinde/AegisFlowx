import { NextRequest, NextResponse } from 'next/server';
import { attachGuestCookie, getOrInitializeQuotaSnapshot } from '@/lib/quota';
import { redactSecrets } from '@/lib/model-config';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const outcome = await getOrInitializeQuotaSnapshot(req);

    if (!outcome.ok || !outcome.snapshot) {
      return NextResponse.json(
        {
          error: redactSecrets(
            outcome.error || 'Unable to retrieve investigation quota balance.'
          ),
          errorCode: outcome.errorCode || 'quota_service_unavailable',
          requiresVerification: outcome.requiresVerification ?? false,
        },
        {
          status: outcome.status,
          headers: {
            'Cache-Control': 'no-store, max-age=0',
          },
        }
      );
    }

    const response = NextResponse.json(
      {
        quota: outcome.snapshot,
      },
      {
        status: 200,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
        },
      }
    );

    return attachGuestCookie(response, outcome.cookieToSet);
  } catch (err: unknown) {
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
        },
      }
    );
  }
}
