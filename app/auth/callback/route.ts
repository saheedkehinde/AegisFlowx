import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import type { EmailOtpType } from '@supabase/supabase-js';

// Safe destination validator to prevent open redirect vulnerabilities
function getSafeRedirectPath(rawNext: string | null, defaultPath: string): string {
  if (!rawNext) return defaultPath;
  const trimmed = rawNext.trim();
  // Ensure path is strictly relative, does not start with protocol-relative '//', and has no backslashes
  if (
    trimmed.startsWith('/') &&
    !trimmed.startsWith('//') &&
    !trimmed.includes('\\') &&
    !trimmed.includes(':')
  ) {
    return trimmed;
  }
  return defaultPath;
}

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const token_hash = searchParams.get('token_hash');
  const type = searchParams.get('type') as EmailOtpType | null;
  const rawNext = searchParams.get('next');

  // Supabase error parameters (e.g. otp_expired, access_denied)
  const incomingError = searchParams.get('error');
  const incomingErrorDesc = searchParams.get('error_description');

  // Handle reverse-proxy forwarded hosts on Vercel
  const forwardedHost = request.headers.get('x-forwarded-host');
  const isLocalEnv = process.env.NODE_ENV === 'development';
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/+$/, '');
  const redirectBase =
    siteUrl ||
    (!isLocalEnv && forwardedHost ? `https://${forwardedHost}` : origin);

  // If Supabase redirected directly with an error
  if (incomingError) {
    const errorMsg = incomingErrorDesc || incomingError;
    console.warn('Auth callback received error from Supabase:', incomingError, incomingErrorDesc);
    return NextResponse.redirect(
      `${redirectBase}/auth/login?error=${encodeURIComponent(
        `Authentication error: ${errorMsg}. Please try signing in or request a new activation link.`
      )}`
    );
  }

  // Determine appropriate default destination based on flow type
  const defaultDestination = type === 'recovery' ? '/auth/reset-password' : '/investigations';
  const targetPath = getSafeRedirectPath(rawNext, defaultDestination);

  const supabase = await createClient();
  if (!supabase) {
    return NextResponse.redirect(
      `${redirectBase}/auth/login?error=Authentication+service+is+not+configured.`
    );
  }

  // 1. Support PKCE authorization code exchange
  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(`${redirectBase}${targetPath}`);
    }
    console.warn('Auth code exchange failure:', error.message);
    return NextResponse.redirect(
      `${redirectBase}/auth/login?error=${encodeURIComponent(
        `Confirmation failed: ${error.message}. Please try signing in or request a new link.`
      )}`
    );
  }

  // 2. Support Token Hash OTP verification (Supabase email template verifyOtp)
  if (token_hash && type) {
    const { error } = await supabase.auth.verifyOtp({
      token_hash,
      type,
    });
    if (!error) {
      return NextResponse.redirect(`${redirectBase}${targetPath}`);
    }
    console.warn('Auth token_hash verification failure:', error.message);
    return NextResponse.redirect(
      `${redirectBase}/auth/login?error=${encodeURIComponent(
        `Verification failed: ${error.message}. The verification link may have expired or already been used.`
      )}`
    );
  }

  // If neither code nor token_hash is present
  return NextResponse.redirect(
    `${redirectBase}/auth/login?error=Invalid+or+missing+verification+token.+Please+request+a+new+link.`
  );
}
