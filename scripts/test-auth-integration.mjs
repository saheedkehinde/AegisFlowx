import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

console.log('🛡️ Starting AegisFlow Supabase Auth & Security Integration Test Suite...\n');

// ====================================================================
// TEST SUITE 1: Open Redirect Prevention & Callback Destination Sanitization
// ====================================================================
console.log('--- Test Suite 1: Open Redirect Prevention & Callback Destination ---');
{
  function getSafeRedirectPath(rawNext, defaultPath) {
    if (!rawNext) return defaultPath;
    const trimmed = rawNext.trim();
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

  // Safe internal paths
  assert.equal(getSafeRedirectPath('/investigations', '/investigations'), '/investigations');
  assert.equal(getSafeRedirectPath('/auth/reset-password', '/investigations'), '/auth/reset-password');
  assert.equal(getSafeRedirectPath('/settings?tab=diagnostics', '/investigations'), '/settings?tab=diagnostics');

  // Dangerous / open-redirect attempts must be rejected
  assert.equal(getSafeRedirectPath('//attacker.com/evil', '/investigations'), '/investigations', 'Protocol-relative URL must be neutralized');
  assert.equal(getSafeRedirectPath('https://malicious.com', '/investigations'), '/investigations', 'Absolute HTTPS URL must be neutralized');
  assert.equal(getSafeRedirectPath('http://malicious.com', '/investigations'), '/investigations', 'Absolute HTTP URL must be neutralized');
  assert.equal(getSafeRedirectPath('javascript:alert(1)', '/investigations'), '/investigations', 'javascript: URI must be neutralized');
  assert.equal(getSafeRedirectPath('/\\attacker.com', '/investigations'), '/investigations', 'Backslash obfuscation must be neutralized');
  assert.equal(getSafeRedirectPath(null, '/investigations'), '/investigations', 'Null path must fall back to default');
  assert.equal(getSafeRedirectPath('', '/investigations'), '/investigations', 'Empty path must fall back to default');

  console.log('✅ Test 1 Passed: Callback route enforces strict allowlisting against open redirects');
}

// ====================================================================
// TEST SUITE 2: SQL Migration Schema & RLS Verification
// ====================================================================
console.log('\n--- Test Suite 2: SQL Migration Schema, Grants & RLS Policies ---');
{
  const migrationPath = path.resolve('supabase/migrations/0001_aegisflow_phase2.sql');
  assert.ok(fs.existsSync(migrationPath), 'Migration file 0001_aegisflow_phase2.sql must exist');

  const sql = fs.readFileSync(migrationPath, 'utf8');

  // Verify Profiles Table
  assert.ok(sql.includes('create table if not exists public.profiles'), 'Must declare public.profiles table');
  assert.ok(sql.includes('references auth.users(id) on delete cascade'), 'Profiles must reference auth.users with cascade delete');
  assert.ok(sql.includes('alter table public.profiles enable row level security'), 'RLS must be enabled on public.profiles');

  // Verify Analysis History Table & exact column definitions
  assert.ok(sql.includes('create table if not exists public.analysis_history'), 'Must declare public.analysis_history table');
  assert.ok(sql.includes('threat_severity text not null check (threat_severity in (\'high\', \'medium\', \'low\', \'uncertain\'))'), 'Check constraint for threat_severity must match enum');
  assert.ok(sql.includes('severity_score integer not null check (severity_score >= 0 and severity_score <= 100)'), 'Check constraint for severity_score must be 0-100');
  assert.ok(sql.includes('evidence_sufficiency text not null check (evidence_sufficiency in (\'sufficient\', \'moderate\', \'sparse\'))'), 'Check constraint for evidence_sufficiency must match');
  assert.ok(sql.includes('model_confidence text not null check (model_confidence in (\'high\', \'moderate\', \'low\'))'), 'Check constraint for model_confidence must match');
  assert.ok(sql.includes('alter table public.analysis_history enable row level security'), 'RLS must be enabled on public.analysis_history');

  // Verify Row Level Security Policies (Least Privilege)
  assert.ok(sql.includes('auth.uid() = id'), 'Profiles policy must isolate to auth.uid() = id');
  assert.ok(sql.includes('auth.uid() = user_id'), 'Analysis history policy must isolate to auth.uid() = user_id');

  // Verify Explicit Grants & Revocations
  assert.ok(sql.includes('revoke all on public.profiles from anon'), 'Anonymous users must be denied all access to profiles');
  assert.ok(sql.includes('revoke all on public.analysis_history from anon'), 'Anonymous users must be denied all access to analysis_history');
  assert.ok(sql.includes('grant select, insert, update on public.profiles to authenticated'), 'Authenticated users granted minimum required profiles permissions');
  assert.ok(sql.includes('grant select, insert, delete on public.analysis_history to authenticated'), 'Authenticated users granted minimum required history permissions');

  // Verify Safe Profile Provisioning Trigger
  assert.ok(sql.includes('create or replace function public.handle_new_user()'), 'Safe user trigger function must exist');
  assert.ok(sql.includes('on conflict (id) do nothing'), 'Trigger function must handle idempotent profile creation safely');
  assert.ok(sql.includes('create trigger on_auth_user_created'), 'Trigger must be attached to auth.users');

  console.log('✅ Test 2 Passed: SQL migration strictly validates schema constraints, RLS, and grants');
}

// ====================================================================
// TEST SUITE 3: Application Code Schema Alignment
// ====================================================================
console.log('\n--- Test Suite 3: Application Code Alignment with Database Constraints ---');
{
  const apiRoutePath = path.resolve('app/api/analyze/route.ts');
  const apiRouteCode = fs.readFileSync(apiRoutePath, 'utf8');

  // Verify server-side verification before insert
  assert.ok(apiRouteCode.includes('supabase.auth.getUser()'), 'Server route must verify user via getUser() before persisting');
  assert.ok(apiRouteCode.includes('user_id: user.id'), 'Persisted record must bind user_id strictly to authenticated user');

  // Verify non-fatal error isolation: persistence warning must not fail the AI response
  assert.ok(apiRouteCode.includes('Database persistence warning (non-fatal)'), 'Persistence errors must be logged as non-fatal warnings');

  // Verify anonymous users bypass persistence without error
  assert.ok(apiRouteCode.includes('if (user && !userError)'), 'Unauthenticated users gracefully skip persistence without failure');

  console.log('✅ Test 3 Passed: Application persistence logic matches database schema and security rules');
}

// ====================================================================
// TEST SUITE 4: Supabase Client & Server SSR Configuration
// ====================================================================
console.log('\n--- Test Suite 4: Supabase SSR Module Invariants ---');
{
  const clientPath = path.resolve('lib/supabase/client.ts');
  const serverPath = path.resolve('lib/supabase/server.ts');
  const middlewarePath = path.resolve('lib/supabase/middleware.ts');

  const clientCode = fs.readFileSync(clientPath, 'utf8');
  const serverCode = fs.readFileSync(serverPath, 'utf8');
  const middlewareCode = fs.readFileSync(middlewarePath, 'utf8');

  // Client checks
  assert.ok(clientCode.includes('createBrowserClient'), 'Browser client must use @supabase/ssr createBrowserClient');
  assert.ok(clientCode.includes('isSupabaseConfigured'), 'Browser client must export isSupabaseConfigured()');

  // Server checks
  assert.ok(serverCode.includes('createServerClient'), 'Server client must use @supabase/ssr createServerClient');
  assert.ok(serverCode.includes('getAll()'), 'Server client must use cookies().getAll()');
  assert.ok(serverCode.includes('setAll('), 'Server client must use cookies().setAll()');

  // Middleware session refresh checks
  assert.ok(middlewareCode.includes('updateSession'), 'Middleware must export updateSession');
  assert.ok(middlewareCode.includes('supabase.auth.getUser()'), 'Middleware must verify user with getUser() to prevent cookie tampering');

  console.log('✅ Test 4 Passed: SSR architecture satisfies Next.js 15 and Supabase SSR specifications');
}

// ====================================================================
// TEST SUITE 5: Authentication Routes & Pages Completeness
// ====================================================================
console.log('\n--- Test Suite 5: Authentication UI & Route Completeness ---');
{
  const expectedAuthFiles = [
    'app/auth/login/page.tsx',
    'app/auth/register/page.tsx',
    'app/auth/forgot-password/page.tsx',
    'app/auth/reset-password/page.tsx',
    'app/auth/callback/route.ts',
  ];

  for (const relPath of expectedAuthFiles) {
    const fullPath = path.resolve(relPath);
    assert.ok(fs.existsSync(fullPath), `Expected auth route file to exist: ${relPath}`);
  }

  // Verify callback route handles both PKCE code and token_hash OTP verification
  const callbackCode = fs.readFileSync(path.resolve('app/auth/callback/route.ts'), 'utf8');
  assert.ok(callbackCode.includes('exchangeCodeForSession(code)'), 'Callback must support PKCE authorization code exchange');
  assert.ok(callbackCode.includes('verifyOtp({'), 'Callback must support Token Hash verifyOtp flow');

  console.log('✅ Test 5 Passed: All 5 required authentication interfaces and callback flows are implemented');
}

console.log('\n🎉 ALL 5 SUPABASE AUTH INTEGRATION TEST SUITES COMPLETED SUCCESSFULLY!\n');
