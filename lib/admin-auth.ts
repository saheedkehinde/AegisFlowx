import { createHash, timingSafeEqual } from 'node:crypto';
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';

export type AuthoritativeAdminRole = 'admin' | 'super_admin';
export type UserRoleName = AuthoritativeAdminRole | 'analyst' | 'user' | 'guest';
export type AdminAuthSource =
  | 'api_key'
  | 'user_roles'
  | 'app_metadata'
  | 'admin_emails_bootstrap'
  | 'dev_bypass'
  | 'none';
export type UserRolesTableStatus =
  | 'verified'
  | 'migration_missing'
  | 'unconfigured'
  | 'error';

export interface AdminAuthResult {
  isAdmin: boolean;
  user: {
    id: string;
    email?: string;
    role: UserRoleName;
  } | null;
  authSource: AdminAuthSource;
  userRolesTableStatus: UserRolesTableStatus;
  reason?: string;
}

export interface VerifiableUser {
  id: string;
  email?: string;
  email_confirmed_at?: string | null;
  confirmed_at?: string | null;
  app_metadata?: Record<string, unknown>;
  user_metadata?: Record<string, unknown>;
}

export interface VerifyAdminOptions {
  allowApiKeyHeader?: boolean;
}

export interface VerifyAdminDependencies {
  createServerClient?: typeof createServerSupabaseClient;
  lookupUserRole?: (
    userId: string,
    sessionClient: unknown
  ) => Promise<{ role: string | null; tableStatus: UserRolesTableStatus }>;
  env?: NodeJS.ProcessEnv;
}

const AUTHORITATIVE_ADMIN_ROLES = new Set<string>(['admin', 'super_admin']);
const MIN_ADMIN_KEY_LENGTH = 17; // Requires strictly > 16 characters

/**
 * Performs a constant-time comparison between a caller-provided key and the
 * configured server ADMIN_API_KEY using SHA-256 fixed-length digests and timingSafeEqual.
 * Prevents length-oracle timing leaks and rejects missing, empty, or placeholder keys.
 */
export function verifyAdminApiKey(
  providedKey: string | null | undefined,
  configuredKey: string | null | undefined
): boolean {
  if (typeof providedKey !== 'string' || typeof configuredKey !== 'string') {
    return false;
  }

  const trimmedConfigured = configuredKey.trim();
  const trimmedProvided = providedKey.trim();

  if (
    trimmedConfigured.length < MIN_ADMIN_KEY_LENGTH ||
    trimmedProvided.length === 0 ||
    trimmedConfigured === 'YOUR_ADMIN_API_KEY'
  ) {
    return false;
  }

  const expectedDigest = createHash('sha256').update(trimmedConfigured, 'utf8').digest();
  const providedDigest = createHash('sha256').update(trimmedProvided, 'utf8').digest();

  return timingSafeEqual(expectedDigest, providedDigest);
}

function getServiceRoleClient(env: NodeJS.ProcessEnv = process.env) {
  const url = env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;

  if (
    !url ||
    !serviceRoleKey ||
    url === 'YOUR_SUPABASE_URL' ||
    serviceRoleKey === 'YOUR_SUPABASE_SERVICE_ROLE_KEY' ||
    serviceRoleKey.trim().length < 20
  ) {
    return null;
  }

  return createSupabaseClient(url, serviceRoleKey.trim(), {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

function isMissingRelationError(error: { code?: string; message?: string } | null | undefined): boolean {
  if (!error) return false;
  const code = error.code || '';
  const msg = (error.message || '').toLowerCase();
  return (
    code === '42P01' ||
    code === 'PGRST205' ||
    msg.includes('could not find the table') ||
    msg.includes('schema cache') ||
    (msg.includes('relation') && msg.includes('does not exist'))
  );
}

/**
 * Looks up the authoritative role for an already-verified Supabase user ID from
 * `public.user_roles`. Uses the privileged service-role client when configured,
 * falling back to the verified SSR session client (permitted by RLS SELECT policy
 * `"Users can view their own role"` in 0002_administrative_roles.sql).
 */
export async function lookupAuthoritativeUserRole(
  userId: string,
  sessionClient: any,
  env: NodeJS.ProcessEnv = process.env
): Promise<{ role: string | null; tableStatus: UserRolesTableStatus }> {
  const queryClient = getServiceRoleClient(env) || sessionClient;
  if (!queryClient || typeof queryClient.from !== 'function') {
    return { role: null, tableStatus: 'unconfigured' };
  }

  try {
    const { data, error } = await queryClient
      .from('user_roles')
      .select('role')
      .eq('user_id', userId)
      .maybeSingle();

    if (error) {
      if (isMissingRelationError(error)) {
        return { role: null, tableStatus: 'migration_missing' };
      }
      return { role: null, tableStatus: 'error' };
    }

    return {
      role: typeof data?.role === 'string' ? data.role : null,
      tableStatus: 'verified',
    };
  } catch {
    return { role: null, tableStatus: 'error' };
  }
}

function parseConfiguredAdminEmails(env: NodeJS.ProcessEnv): string[] {
  return (env.ADMIN_EMAILS || env.ADMIN_EMAIL || '')
    .toLowerCase()
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
}

function normalizeAppMetadataRole(appMetadata?: Record<string, unknown>): AuthoritativeAdminRole | null {
  if (!appMetadata || typeof appMetadata !== 'object') return null;

  const rawRole = typeof appMetadata.role === 'string' ? appMetadata.role.trim() : '';
  if (rawRole === 'super_admin') return 'super_admin';
  if (rawRole === 'admin') return 'admin';
  if (appMetadata.is_admin === true) return 'admin';

  return null;
}

/**
 * Pure server-side authorization evaluator.
 * INVARIANT: `user.user_metadata` is NEVER inspected or trusted for privilege decisions.
 */
export function evaluateAdminAuthorization(params: {
  user: VerifiableUser;
  dbRole: string | null;
  userRolesTableStatus: UserRolesTableStatus;
  env?: NodeJS.ProcessEnv;
}): AdminAuthResult {
  const { user, dbRole, userRolesTableStatus, env = process.env } = params;

  // 1. Authoritative database role from public.user_roles
  if (dbRole && AUTHORITATIVE_ADMIN_ROLES.has(dbRole)) {
    return {
      isAdmin: true,
      user: {
        id: user.id,
        email: user.email,
        role: dbRole as AuthoritativeAdminRole,
      },
      authSource: 'user_roles',
      userRolesTableStatus,
    };
  }

  // 2. Trusted server-signed Supabase app_metadata (unwritable by end users)
  const appMetadataRole = normalizeAppMetadataRole(user.app_metadata);
  if (appMetadataRole) {
    return {
      isAdmin: true,
      user: {
        id: user.id,
        email: user.email,
        role: appMetadataRole,
      },
      authSource: 'app_metadata',
      userRolesTableStatus,
    };
  }

  // 3. Server-side ADMIN_EMAILS bootstrap mechanism (requires confirmed email)
  const configuredAdminEmails = parseConfiguredAdminEmails(env);
  const isConfirmed = Boolean(user.email_confirmed_at || user.confirmed_at);
  const isEmailBootstrapped = Boolean(
    user.email &&
      isConfirmed &&
      configuredAdminEmails.includes(user.email.toLowerCase())
  );

  if (isEmailBootstrapped) {
    return {
      isAdmin: true,
      user: {
        id: user.id,
        email: user.email,
        role: 'admin',
      },
      authSource: 'admin_emails_bootstrap',
      userRolesTableStatus,
    };
  }

  // Non-admin fallback role (never reads user_metadata)
  const nonAdminRole: UserRoleName =
    dbRole === 'analyst' || user.app_metadata?.role === 'analyst' ? 'analyst' : 'user';

  return {
    isAdmin: false,
    user: {
      id: user.id,
      email: user.email,
      role: nonAdminRole,
    },
    authSource: 'none',
    userRolesTableStatus,
    reason: 'User lacks administrator privileges',
  };
}

/**
 * Authoritative server-side administrator verification.
 * Sources accepted:
 * 1. Constant-time validated `x-aegis-admin-key` header (when allowApiKeyHeader !== false)
 * 2. Verified Supabase session (`supabase.auth.getUser()`) with:
 *    a) `public.user_roles` (`admin` / `super_admin`)
 *    b) Server-signed `app_metadata` (`role: 'admin' | 'super_admin'` or `is_admin === true`)
 *    c) Server env `ADMIN_EMAILS` / `ADMIN_EMAIL` bootstrap (for verified email accounts)
 *
 * Strictly rejects `user_metadata` and all client-supplied role claims.
 */
export async function verifyAdminUser(
  req?: Request,
  options: VerifyAdminOptions = {},
  deps: VerifyAdminDependencies = {}
): Promise<AdminAuthResult> {
  const env = deps.env || process.env;
  const allowApiKeyHeader = options.allowApiKeyHeader !== false;

  // 1. Optional service-to-service API key header (constant-time comparison)
  if (allowApiKeyHeader && req) {
    const headerKey = req.headers.get('x-aegis-admin-key');
    if (verifyAdminApiKey(headerKey, env.ADMIN_API_KEY)) {
      return {
        isAdmin: true,
        user: { id: 'service-admin', email: 'service@aegisflow.internal', role: 'admin' },
        authSource: 'api_key',
        userRolesTableStatus: getServiceRoleClient(env) ? 'verified' : 'unconfigured',
      };
    }
  }

  // 2. Authenticate session with Supabase Auth server (never trusts raw cookies or client claims)
  const createClientFn = deps.createServerClient || createServerSupabaseClient;
  const supabase = await createClientFn();

  if (!supabase) {
    const isDev = env.NODE_ENV !== 'production';
    if (isDev && env.ENABLE_DEV_ADMIN_DIAGNOSTICS === 'true') {
      return {
        isAdmin: true,
        user: { id: 'dev-admin', email: 'developer@local.test', role: 'admin' },
        authSource: 'dev_bypass',
        userRolesTableStatus: 'unconfigured',
      };
    }
    return {
      isAdmin: false,
      user: null,
      authSource: 'none',
      userRolesTableStatus: 'unconfigured',
      reason: 'Authentication client unavailable',
    };
  }

  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();

  if (userError || !user) {
    return {
      isAdmin: false,
      user: null,
      authSource: 'none',
      userRolesTableStatus: 'unconfigured',
      reason: 'No active authenticated session',
    };
  }

  // 3. Authoritative role lookup in public.user_roles
  const lookupFn =
    deps.lookupUserRole ||
    ((uid: string, client: unknown) => lookupAuthoritativeUserRole(uid, client, env));

  const { role: dbRole, tableStatus: userRolesTableStatus } = await lookupFn(user.id, supabase);

  return evaluateAdminAuthorization({
    user: user as VerifiableUser,
    dbRole,
    userRolesTableStatus,
    env,
  });
}
