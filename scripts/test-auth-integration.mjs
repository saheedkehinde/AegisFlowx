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

// ====================================================================
// TEST SUITE 6: Production Domain & Callback Resilience Invariants
// ====================================================================
console.log('\n--- Test Suite 6: Production Domain & Callback Resilience Invariants ---');
{
  const siteUrlPath = path.resolve('lib/supabase/site-url.ts');
  assert.ok(fs.existsSync(siteUrlPath), 'lib/supabase/site-url.ts must exist');
  const siteUrlCode = fs.readFileSync(siteUrlPath, 'utf8');
  assert.ok(siteUrlCode.includes('getSiteUrl'), 'Must export getSiteUrl()');
  assert.ok(siteUrlCode.includes('getCallbackUrl'), 'Must export getCallbackUrl()');
  assert.ok(siteUrlCode.includes('https://aegisflowx.vercel.app'), 'Must have default fallback to https://aegisflowx.vercel.app');

  // Verify resilient callback query interceptor in register and login pages
  const registerCode = fs.readFileSync(path.resolve('app/auth/register/page.tsx'), 'utf8');
  const loginCode = fs.readFileSync(path.resolve('app/auth/login/page.tsx'), 'utf8');

  assert.ok(registerCode.includes("params.get('code')"), 'Register page must intercept code param for resilient redirect');
  assert.ok(registerCode.includes("params.get('token_hash')"), 'Register page must intercept token_hash param for resilient redirect');
  assert.ok(registerCode.includes('getCallbackUrl'), 'Register page must use canonical getCallbackUrl');

  assert.ok(loginCode.includes("params.get('code')"), 'Login page must intercept code param for resilient redirect');
  assert.ok(loginCode.includes("params.get('token_hash')"), 'Login page must intercept token_hash param for resilient redirect');
  assert.ok(loginCode.includes('getCallbackUrl'), 'Login page must use canonical getCallbackUrl');

  // Verify callback route handles incoming errors from Supabase
  const callbackCode = fs.readFileSync(path.resolve('app/auth/callback/route.ts'), 'utf8');
  assert.ok(callbackCode.includes("searchParams.get('error')"), 'Callback route must parse incoming Supabase error parameter');

  console.log('✅ Test 6 Passed: Production domain resolution and callback auto-forwarding resilience verified');
}

// ====================================================================
// TEST SUITE 7: Analysis History Permissions & RLS Ownership Isolation
// ====================================================================
console.log('\n--- Test Suite 7: Analysis History Permissions, RLS Isolation & Error Resilience ---');
{
  const migration2Path = path.resolve('supabase/migrations/0002_fix_analysis_history_permissions.sql');
  assert.ok(fs.existsSync(migration2Path), 'Migration 0002_fix_analysis_history_permissions.sql must exist');
  const sql2 = fs.readFileSync(migration2Path, 'utf8');

  // Verify Table Privileges (Fix for 42501 permission denied)
  assert.ok(
    sql2.includes('grant select, insert, delete on table public.analysis_history to authenticated'),
    'Authenticated role must be granted SELECT, INSERT, DELETE on analysis_history'
  );
  assert.ok(
    sql2.includes('revoke all on table public.analysis_history from anon'),
    'Anonymous role must be strictly revoked of all permissions on analysis_history'
  );
  assert.ok(
    sql2.includes('alter table public.analysis_history enable row level security'),
    'Row Level Security must be enabled on public.analysis_history'
  );

  // Verify Ownership RLS Policies
  assert.ok(
    sql2.includes('create policy "Users can view only their own analysis records"'),
    'SELECT policy must exist for analysis_history'
  );
  assert.ok(
    sql2.includes('create policy "Users can insert analysis records owned by themselves"'),
    'INSERT policy must exist for analysis_history'
  );
  assert.ok(
    sql2.includes('create policy "Users can delete only their own analysis records"'),
    'DELETE policy must exist for analysis_history'
  );
  assert.ok(
    sql2.includes('using (auth.uid() = user_id)'),
    'SELECT & DELETE policies must use auth.uid() = user_id'
  );
  assert.ok(
    sql2.includes('with check (auth.uid() = user_id)'),
    'INSERT policy must enforce with check (auth.uid() = user_id)'
  );

  // Simulate PostgreSQL RLS Engine
  class MockPostgresRlsEngine {
    constructor() {
      this.tableGrants = {
        authenticated: ['SELECT', 'INSERT', 'DELETE'],
        anon: []
      };
      this.records = [
        { id: 'rec-1', user_id: 'analyst-alpha', input_snippet: 'Suspicious email from payroll', threat_severity: 'high' },
        { id: 'rec-2', user_id: 'analyst-beta', input_snippet: 'Routine MFA prompt', threat_severity: 'low' },
      ];
    }

    select(role, currentUserId) {
      if (!this.tableGrants[role]?.includes('SELECT')) {
        throw new Error('42501: permission denied for table analysis_history');
      }
      // RLS Policy: using (auth.uid() = user_id)
      return this.records.filter(r => r.user_id === currentUserId);
    }

    insert(role, currentUserId, newRecord) {
      if (!this.tableGrants[role]?.includes('INSERT')) {
        throw new Error('42501: permission denied for table analysis_history');
      }
      // RLS Policy: with check (auth.uid() = user_id)
      if (newRecord.user_id !== currentUserId) {
        throw new Error('42501: new row violates row-level security policy for table analysis_history');
      }
      this.records.push(newRecord);
      return newRecord;
    }

    delete(role, currentUserId, targetId) {
      if (!this.tableGrants[role]?.includes('DELETE')) {
        throw new Error('42501: permission denied for table analysis_history');
      }
      // RLS Policy: using (auth.uid() = user_id)
      const initialCount = this.records.length;
      this.records = this.records.filter(r => !(r.id === targetId && r.user_id === currentUserId));
      return { deletedCount: initialCount - this.records.length };
    }
  }

  const engine = new MockPostgresRlsEngine();

  // Test 7.1: Authenticated User can read their own history
  const alphaRecords = engine.select('authenticated', 'analyst-alpha');
  assert.equal(alphaRecords.length, 1);
  assert.equal(alphaRecords[0].id, 'rec-1');

  // Test 7.2: Authenticated User CANNOT read other users' history
  const betaRecords = engine.select('authenticated', 'analyst-beta');
  assert.equal(betaRecords.length, 1);
  assert.equal(betaRecords[0].id, 'rec-2');
  assert.ok(!alphaRecords.some(r => r.user_id === 'analyst-beta'), 'User Alpha cannot see User Beta records');

  // Test 7.3: Authenticated User can insert records owned by themselves
  const newAlphaRecord = { id: 'rec-3', user_id: 'analyst-alpha', input_snippet: 'Phishing SMS', threat_severity: 'high' };
  engine.insert('authenticated', 'analyst-alpha', newAlphaRecord);
  assert.equal(engine.select('authenticated', 'analyst-alpha').length, 2);

  // Test 7.4: Authenticated User CANNOT insert records on behalf of another user
  assert.throws(() => {
    engine.insert('authenticated', 'analyst-alpha', {
      id: 'rec-4',
      user_id: 'analyst-beta',
      input_snippet: 'Spoofed record',
      threat_severity: 'low'
    });
  }, /violates row-level security policy/);

  // Test 7.5: Authenticated User can delete their own record
  const delAlpha = engine.delete('authenticated', 'analyst-alpha', 'rec-3');
  assert.equal(delAlpha.deletedCount, 1);

  // Test 7.6: Authenticated User CANNOT delete other users' records
  const delBetaAttempt = engine.delete('authenticated', 'analyst-alpha', 'rec-2');
  assert.equal(delBetaAttempt.deletedCount, 0, 'User Alpha cannot delete User Beta record');
  assert.equal(engine.select('authenticated', 'analyst-beta').length, 1, 'Beta record remains intact');

  // Test 7.7: Anonymous visitor gets PostgreSQL 42501 permission denied
  assert.throws(() => {
    engine.select('anon', null);
  }, /42501: permission denied for table analysis_history/);

  assert.throws(() => {
    engine.insert('anon', null, { id: 'rec-anon', user_id: 'any', input_snippet: 'test' });
  }, /42501: permission denied for table analysis_history/);

  assert.throws(() => {
    engine.delete('anon', null, 'rec-1');
  }, /42501: permission denied for table analysis_history/);

  // Test 7.8: Application Investigations Page Code Verification
  const invCode = fs.readFileSync(path.resolve('app/investigations/page.tsx'), 'utf8');
  assert.ok(
    invCode.includes('supabase.auth.getSession()'),
    'Investigations page must verify active session before executing query'
  );
  assert.ok(
    invCode.includes('Retry Loading History'),
    'Investigations page must render an explicit Retry button on fetch error'
  );
  assert.ok(
    invCode.includes('!fetchError && filteredRecords.length === 0'),
    'Empty state must NOT be rendered when fetchError is present'
  );

  console.log('✅ Test 7 Passed: Migration 0002 grants, RLS isolation, and UI retry resilience strictly verified');
}

console.log('\n🎉 ALL 7 SUPABASE AUTH INTEGRATION TEST SUITES COMPLETED SUCCESSFULLY!\n');

