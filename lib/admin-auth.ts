import { createClient } from '@/lib/supabase/server';

export interface AdminAuthResult {
  isAdmin: boolean;
  user: {
    id: string;
    email?: string;
    role?: string;
  } | null;
  reason?: string;
}

/**
 * Server-side administrator verification.
 * Enforces authorization without introducing database schema changes or migrations:
 * 1. Checks Supabase session app_metadata.role / user_metadata.role === 'admin'
 * 2. Checks app_metadata.is_admin / user_metadata.is_admin === true
 * 3. Checks user.email against ADMIN_EMAILS / ADMIN_EMAIL environment variable
 * 4. Checks x-aegis-admin-key header against ADMIN_API_KEY environment variable (if configured)
 */
export async function verifyAdminUser(req?: Request): Promise<AdminAuthResult> {
  // 1. Check optional admin API key header for programmatic administration
  const adminApiKey = process.env.ADMIN_API_KEY;
  if (req && adminApiKey && adminApiKey.trim().length > 16) {
    const headerKey = req.headers.get('x-aegis-admin-key');
    if (headerKey && headerKey.trim() === adminApiKey.trim()) {
      return {
        isAdmin: true,
        user: { id: 'service-admin', email: 'service@aegisflow.internal', role: 'admin' },
      };
    }
  }

  // 2. Check Supabase authenticated session
  const supabase = await createClient();
  if (!supabase) {
    // Supabase not configured in current environment; check if dev admin bypass is allowed
    const isDev = process.env.NODE_ENV !== 'production';
    if (isDev && process.env.ENABLE_DEV_ADMIN_DIAGNOSTICS === 'true') {
      return {
        isAdmin: true,
        user: { id: 'dev-admin', email: 'developer@local.test', role: 'admin' },
      };
    }
    return { isAdmin: false, user: null, reason: 'Authentication client unavailable' };
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return { isAdmin: false, user: null, reason: 'No active authenticated session' };
  }

  const appRole = (user.app_metadata?.role as string) || '';
  const userRole = (user.user_metadata?.role as string) || '';
  const isAdminFlag = Boolean(user.app_metadata?.is_admin || user.user_metadata?.is_admin);

  const configuredAdminEmails = (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || '')
    .toLowerCase()
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);

  const isEmailAdmin = Boolean(
    user.email && configuredAdminEmails.includes(user.email.toLowerCase())
  );

  if (appRole === 'admin' || userRole === 'admin' || isAdminFlag || isEmailAdmin) {
    return {
      isAdmin: true,
      user: {
        id: user.id,
        email: user.email,
        role: appRole || userRole || 'admin',
      },
    };
  }

  return {
    isAdmin: false,
    user: {
      id: user.id,
      email: user.email,
      role: appRole || userRole || 'user',
    },
    reason: 'User lacks administrator privileges',
  };
}
