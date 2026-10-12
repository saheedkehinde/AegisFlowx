/**
 * Helper to determine the canonical base URL for authentication callbacks and redirects.
 * Prioritizes explicitly configured production site URL, then Vercel production URL,
 * then browser origin, with default fallback to https://aegisflowx.vercel.app.
 */
export function getSiteUrl(): string {
  // 1. Explicitly configured canonical site URL (e.g. https://aegisflowx.vercel.app)
  const envUrl = process.env.NEXT_PUBLIC_SITE_URL || process.env.NEXT_PUBLIC_APP_URL;
  if (envUrl && envUrl.trim() !== '') {
    return envUrl.trim().replace(/\/+$/, '');
  }

  // 2. Client-side browser execution: always match the current active origin (works for previews & custom domains)
  if (typeof window !== 'undefined' && window.location?.origin) {
    return window.location.origin.replace(/\/+$/, '');
  }

  // 3. Vercel system environment variable
  if (process.env.NEXT_PUBLIC_VERCEL_URL) {
    return `https://${process.env.NEXT_PUBLIC_VERCEL_URL}`.replace(/\/+$/, '');
  }

  // 4. Default intended production domain
  return 'https://aegisflowx.vercel.app';
}

export function getCallbackUrl(nextPath: string = '/investigations'): string {
  const base = getSiteUrl();
  const safeNext = nextPath.startsWith('/') ? nextPath : `/${nextPath}`;
  return `${base}/auth/callback?next=${encodeURIComponent(safeNext)}`;
}
