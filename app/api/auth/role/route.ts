import { NextRequest, NextResponse } from 'next/server';
import { verifyAdminUser } from '@/lib/admin-auth';

export const dynamic = 'force-dynamic';

/**
 * Server-verified read-only role inspection endpoint for UI presentation only.
 * Protected endpoints MUST still independently call verifyAdminUser().
 */
export async function GET(req: NextRequest) {
  const authResult = await verifyAdminUser(req, { allowApiKeyHeader: false });

  if (!authResult.user) {
    return NextResponse.json(
      {
        authenticated: false,
        isAdmin: false,
        role: 'guest',
      },
      {
        headers: {
          'Cache-Control': 'no-store, max-age=0',
        },
      }
    );
  }

  return NextResponse.json(
    {
      authenticated: true,
      isAdmin: authResult.isAdmin,
      role: authResult.user.role,
    },
    {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      },
    }
  );
}
