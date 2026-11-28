import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

const MIDDLEWARE_AUTH_TIMEOUT_MS = 2500;

function nextWithOutcome(request: NextRequest, outcome: string): NextResponse {
  try {
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-aegis-middleware-outcome', outcome);
    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
  } catch {
    return NextResponse.next({ request });
  }
}

export async function updateSession(request: NextRequest) {
  const pathname = request.nextUrl?.pathname || '';
  const isApiRequest = pathname.startsWith('/api/');

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !key || url === 'YOUR_SUPABASE_URL' || key === 'YOUR_SUPABASE_PUBLISHABLE_KEY') {
    return nextWithOutcome(request, 'auth_unconfigured');
  }

  const hasSupabaseCookie =
    typeof request.cookies?.getAll === 'function'
      ? request.cookies.getAll().some((c) => c.name.startsWith('sb-'))
      : false;

  // Never stall anonymous/guest /api/* requests with an unnecessary Edge auth roundtrip
  if (isApiRequest && !hasSupabaseCookie) {
    return nextWithOutcome(request, 'guest_passthrough');
  }

  let supabaseResponse = nextWithOutcome(request, 'session_checked');
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    const supabase = createServerClient(url, key, {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          supabaseResponse = nextWithOutcome(request, 'session_refreshed');
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    });

    // IMPORTANT: Use getUser() to verify session with Supabase Auth server, avoiding unverified cookie trust
    const authResult = await Promise.race([
      supabase.auth.getUser().then(
        () => 'ok' as const,
        () => 'auth_error' as const
      ),
      new Promise<'timeout'>((resolve) => {
        timer = setTimeout(() => resolve('timeout'), MIDDLEWARE_AUTH_TIMEOUT_MS);
      }),
    ]);

    if (authResult === 'timeout') {
      return nextWithOutcome(request, 'session_timeout_passthrough');
    }
    if (authResult === 'auth_error') {
      return nextWithOutcome(request, 'session_error_passthrough');
    }
  } catch {
    return nextWithOutcome(request, 'middleware_error_passthrough');
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }

  return supabaseResponse;
}
