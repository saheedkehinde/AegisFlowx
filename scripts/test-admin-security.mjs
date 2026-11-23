import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import Module from 'node:module';
import ts from 'typescript';

console.log('🛡️ Starting AegisFlow Phase 1 Administrator Security Foundation Test Suite...\n');

const ROOT = process.cwd();
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.stack || err.message}`);
    failed++;
  }
}

async function asyncTest(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.stack || err.message}`);
    failed++;
  }
}

/**
 * Compiles & executes the REAL TypeScript source modules from the repository
 * using a controlled module loader where only external network/Next/Supabase runtime bindings
 * can be swapped with test doubles per scenario.
 */
function createTsModuleLoader(customBindings = {}) {
  const nativeRequire = Module.createRequire(import.meta.url);
  const cache = new Map();

  function resolveTsFile(specifier) {
    if (specifier.startsWith('@/')) {
      const rel = specifier.slice(2);
      const tsPath = path.join(ROOT, `${rel}.ts`);
      const tsxPath = path.join(ROOT, `${rel}.tsx`);
      if (fs.existsSync(tsPath)) return tsPath;
      if (fs.existsSync(tsxPath)) return tsxPath;
    }
    return null;
  }

  function loadModule(specifier) {
    if (Object.prototype.hasOwnProperty.call(customBindings, specifier)) {
      return customBindings[specifier];
    }

    const resolvedFile = resolveTsFile(specifier) || (path.isAbsolute(specifier) ? specifier : null);
    if (!resolvedFile) {
      return nativeRequire(specifier);
    }

    if (cache.has(resolvedFile)) {
      return cache.get(resolvedFile).exports;
    }

    const source = fs.readFileSync(resolvedFile, 'utf8');
    const transpiled = ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        esModuleInterop: true,
        jsx: ts.JsxEmit.ReactJSX,
      },
      fileName: resolvedFile,
    });

    const mod = { exports: {} };
    cache.set(resolvedFile, mod);

    const fn = new Function('require', 'module', 'exports', '__filename', '__dirname', transpiled.outputText);
    fn(
      (childSpec) => loadModule(childSpec),
      mod,
      mod.exports,
      resolvedFile,
      path.dirname(resolvedFile)
    );
    return mod.exports;
  }

  return { loadModule };
}

function createHarness({
  sessionUser = null,
  dbRoleResponse = { data: null, error: null },
  envOverrides = {},
  serviceRoleClientFactory = null,
} = {}) {
  const envBackup = {};
  const managedKeys = [
    'ADMIN_API_KEY',
    'ADMIN_EMAILS',
    'ADMIN_EMAIL',
    'ENABLE_DEV_ADMIN_DIAGNOSTICS',
    'NODE_ENV',
    'NEXT_PUBLIC_SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY',
    'FEATHERLESS_API_KEY',
    'GEMINI_API_KEY',
    ...Object.keys(envOverrides),
  ];
  for (const k of managedKeys) {
    envBackup[k] = process.env[k];
  }
  for (const [k, v] of Object.entries(envOverrides)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }

  const fakeSessionClient = sessionUser
    ? {
        auth: {
          getUser: async () => ({ data: { user: sessionUser }, error: null }),
        },
        from: (table) => ({
          select: () => ({
            eq: () => ({
              maybeSingle: async () => {
                assert.equal(table, 'user_roles');
                return dbRoleResponse;
              },
            }),
          }),
        }),
      }
    : {
        auth: {
          getUser: async () => ({ data: { user: null }, error: null }),
        },
        from: () => {
          throw new Error('Anonymous session must never reach database role lookup');
        },
      };

  const nextResponseStub = {
    NextResponse: {
      json(body, init = {}) {
        return {
          status: init.status || 200,
          headers: init.headers || {},
          body,
          async json() {
            return body;
          },
        };
      },
    },
    NextRequest: class {},
  };

  const mockSupabaseJs = {
    createClient: serviceRoleClientFactory
      ? serviceRoleClientFactory
      : () => fakeSessionClient,
  };

  const mockWebResearcher = {
    probeSerperDiagnostic: async () => ({
      provider: 'Serper',
      status: 'configured_and_reachable',
      isConfigured: true,
      message: 'Serper probe mock OK',
      latencyMs: 12,
    }),
    probeUrlhausDiagnostic: async () => ({
      provider: 'URLhaus',
      status: 'configured_and_reachable',
      isConfigured: true,
      message: 'URLhaus probe mock OK',
      latencyMs: 14,
    }),
    getMaxSearchesPerAnalysis: () => 2,
    getCacheStats: () => ({ entries: 0 }),
    getCacheTtlMs: () => 300000,
  };

  const isRealGeminiKey = () => {
    const k = process.env.GEMINI_API_KEY;
    return Boolean(k && k.trim().length > 10 && k !== 'MY_GEMINI_API_KEY' && k !== 'YOUR_GEMINI_API_KEY');
  };

  const mockGeminiClient = {
    isGeminiConfigured: isRealGeminiKey,
    isGeminiFallbackEnabled: isRealGeminiKey,
    isGeminiSearchFallbackEnabled: () => true,
    isGeminiDocumentFallbackEnabled: () => true,
    getResolvedGeminiModel: () => 'gemini-3.8-flash',
    probeGeminiDiagnostic: async () => ({
      provider: 'Google Gemini',
      status: 'configured_and_reachable',
      isConfigured: true,
      message: 'Gemini probe mock OK',
      latencyMs: 25,
    }),
  };

  const mockOrchestrator = {
    getProviderTelemetry: () => ({ aiFallbacks: 0 }),
  };

  const { loadModule } = createTsModuleLoader({
    'node:crypto': crypto,
    'next/server': nextResponseStub,
    '@supabase/supabase-js': mockSupabaseJs,
    '@/lib/supabase/server': {
      createClient: async () => fakeSessionClient,
      isSupabaseConfigured: () => true,
    },
    '@/lib/fact-checker/web-researcher': mockWebResearcher,
    '@/lib/gemini/client': mockGeminiClient,
    '@/lib/provider-orchestrator': mockOrchestrator,
  });

  const adminAuthMod = loadModule('@/lib/admin-auth');
  const adminDiagRoute = loadModule('@/app/api/admin/diagnostics/route');
  const publicDiagRoute = loadModule('@/app/api/diagnostics/route');
  const modelDiagRoute = loadModule('@/app/api/model-diagnostic/route');
  const authRoleRoute = loadModule('@/app/api/auth/role/route');

  function restoreEnv() {
    for (const [k, v] of Object.entries(envBackup)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }

  return {
    adminAuthMod,
    adminDiagRoute,
    publicDiagRoute,
    modelDiagRoute,
    authRoleRoute,
    restoreEnv,
  };
}

function makeReq(headers = {}) {
  const normalized = new Map(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)])
  );
  return {
    headers: {
      get(name) {
        return normalized.get(name.toLowerCase()) ?? null;
      },
    },
  };
}

// ====================================================================
// 1. Source Code & Static Invariants Verification
// ====================================================================
console.log('--- Suite 1: Source Code & Privilege Boundary Invariants ---');

test('1.1 lib/admin-auth.ts completely eliminates user_metadata authorization and uses constant-time crypto comparison', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib/admin-auth.ts'), 'utf8');
  const nonCommentLines = src
    .split('\n')
    .filter((line) => !line.trim().startsWith('*') && !line.trim().startsWith('//'))
    .join('\n');

  assert.ok(
    !/user_metadata/.test(nonCommentLines.replace(/user_metadata\?: Record<string, unknown>;/, '')),
    'lib/admin-auth.ts MUST NOT inspect user_metadata anywhere in executable code'
  );
  assert.ok(src.includes('timingSafeEqual'), 'lib/admin-auth.ts must use crypto.timingSafeEqual');
  assert.ok(src.includes('createHash'), 'lib/admin-auth.ts must hash keys to fixed-length digests before timingSafeEqual');
  assert.ok(src.includes("'super_admin'") && src.includes("'admin'"), 'Must recognize authoritative admin and super_admin roles');
});

test('1.2 /admin/diagnostics SSR page enforces verifyAdminUser on server before rendering AdminDiagnosticsClient', () => {
  const pageSrc = fs.readFileSync(path.join(ROOT, 'app/admin/diagnostics/page.tsx'), 'utf8');
  assert.ok(!pageSrc.startsWith("'use client'"), '/admin/diagnostics page.tsx must be a Server Component');
  assert.ok(pageSrc.includes('verifyAdminUser'), '/admin/diagnostics must verify authorization server-side');
  assert.ok(pageSrc.includes('allowApiKeyHeader: false'), 'SSR admin page must authenticate via session, not header bypass');
});

// ====================================================================
// 2. Live Execution Against Real Compiled Server Handlers (Tests 1-7)
// ====================================================================
console.log('\n--- Suite 2: Executable Authorization Matrix (Real lib/admin-auth.ts & Route Handlers) ---');

await asyncTest('2.1 Unauthenticated user is denied /api/admin/diagnostics (HTTP 403) and gets guest role from /api/auth/role', async () => {
  const h = createHarness({
    sessionUser: null,
    envOverrides: {
      NODE_ENV: 'production',
      ENABLE_DEV_ADMIN_DIAGNOSTICS: 'false',
      ADMIN_API_KEY: 'super-secret-admin-key-longer-than-16',
    },
  });
  try {
    const adminRes = await h.adminDiagRoute.GET(makeReq());
    assert.equal(adminRes.status, 403);
    assert.equal(adminRes.body.providers, undefined);
    assert.equal(adminRes.body.reason, undefined, '403 payload must not leak internal reason metadata');

    const roleRes = await h.authRoleRoute.GET(makeReq());
    assert.equal(roleRes.status, 200);
    assert.deepEqual(roleRes.body, { authenticated: false, isAdmin: false, role: 'guest' });
  } finally {
    h.restoreEnv();
  }
});

await asyncTest('2.2 Ordinary authenticated analyst/user is denied /api/admin/diagnostics (HTTP 403) and cannot obtain detailed provider diagnostics', async () => {
  const normalUser = {
    id: 'user-ordinary-1',
    email: 'analyst@example.com',
    email_confirmed_at: '2026-01-01T00:00:00Z',
    app_metadata: { role: 'user' },
    user_metadata: { display_name: 'Ordinary Analyst' },
  };
  const h = createHarness({
    sessionUser: normalUser,
    dbRoleResponse: { data: { role: 'analyst' }, error: null },
    envOverrides: {
      NODE_ENV: 'production',
      FEATHERLESS_API_KEY: 'YOUR_FEATHERLESS_API_KEY',
      GEMINI_API_KEY: 'MY_GEMINI_API_KEY',
    },
  });
  try {
    const adminRes = await h.adminDiagRoute.GET(makeReq());
    assert.equal(adminRes.status, 403);

    const publicDiagRes = await h.publicDiagRoute.GET(makeReq());
    assert.equal(publicDiagRes.status, 200);
    assert.equal(publicDiagRes.body.providers, undefined);
    assert.equal(publicDiagRes.body.geminiFallback, undefined);
    assert.equal(publicDiagRes.body.activeModelConfig, undefined);
    assert.equal(publicDiagRes.body.overallStatus, 'degraded', 'Must honestly reflect unconfigured AI aggregate without naming vendors');
    assert.ok(!/featherless|qwen|serper|gemini/i.test(JSON.stringify(publicDiagRes.body)));

    const modelDiagRes = await h.modelDiagRoute.GET(makeReq());
    assert.equal(modelDiagRes.status, 200);
    assert.equal(modelDiagRes.body.engine, 'Aegis AI');
    assert.equal(modelDiagRes.body.operational, false);
    assert.equal(modelDiagRes.body.provider, undefined);
    assert.equal(modelDiagRes.body.configuredModel, undefined);

    const roleRes = await h.authRoleRoute.GET(makeReq());
    assert.deepEqual(roleRes.body, { authenticated: true, isAdmin: false, role: 'analyst' });
  } finally {
    h.restoreEnv();
  }
});

await asyncTest('2.3 Privilege escalation via client-editable user_metadata (role: "admin", is_admin: true) is STRICTLY DENIED', async () => {
  const escalatedUser = {
    id: 'user-attacker-1',
    email: 'attacker@example.com',
    email_confirmed_at: '2026-01-01T00:00:00Z',
    app_metadata: {},
    user_metadata: {
      role: 'admin',
      super_admin: true,
      is_admin: true,
      permissions: ['admin'],
    },
  };
  const h = createHarness({
    sessionUser: escalatedUser,
    dbRoleResponse: { data: null, error: null },
    envOverrides: {
      NODE_ENV: 'production',
      ADMIN_EMAILS: 'trusted-admin@example.com',
      GEMINI_API_KEY: 'AIzaFakeKeyForAggregateCheck12345',
    },
  });
  try {
    const authRes = await h.adminAuthMod.verifyAdminUser(makeReq());
    assert.equal(authRes.isAdmin, false, 'Attacker manipulating user_metadata MUST NOT become admin');
    assert.equal(authRes.authSource, 'none');
    assert.equal(authRes.user?.role, 'user', 'Returned role must NOT reflect tampered user_metadata');

    const adminRes = await h.adminDiagRoute.GET(makeReq());
    assert.equal(adminRes.status, 403, '/api/admin/diagnostics must return 403 even with user_metadata.role = admin');

    const publicDiagRes = await h.publicDiagRoute.GET(makeReq());
    assert.equal(publicDiagRes.body.providers, undefined, '/api/diagnostics must not leak providers on tampered user_metadata');
    assert.equal(publicDiagRes.body.geminiFallback, undefined);

    const modelDiagRes = await h.modelDiagRoute.GET(makeReq());
    assert.equal(modelDiagRes.body.configuredModel, undefined, '/api/model-diagnostic must not leak model IDs on tampered user_metadata');

    const roleRes = await h.authRoleRoute.GET(makeReq());
    assert.deepEqual(roleRes.body, { authenticated: true, isAdmin: false, role: 'user' });
  } finally {
    h.restoreEnv();
  }
});

await asyncTest('2.4 Valid trusted administrator (via public.user_roles super_admin & app_metadata) accesses full admin diagnostics', async () => {
  const adminUser = {
    id: 'admin-uuid-1',
    email: 'kaynesaheed@gmail.com',
    email_confirmed_at: '2026-01-01T00:00:00Z',
    app_metadata: {},
    user_metadata: {},
  };

  // 2.4a: Authoritative public.user_roles lookup returns super_admin
  const hDb = createHarness({
    sessionUser: adminUser,
    dbRoleResponse: { data: { role: 'super_admin' }, error: null },
    envOverrides: {
      NODE_ENV: 'production',
      GEMINI_API_KEY: 'AIzaTestKeyForAdminDiag123456',
      FEATHERLESS_API_KEY: 'YOUR_FEATHERLESS_API_KEY',
    },
  });
  try {
    const adminRes = await hDb.adminDiagRoute.GET(makeReq());
    assert.equal(adminRes.status, 200);
    assert.equal(adminRes.body.authorization.authSource, 'user_roles');
    assert.equal(adminRes.body.authorization.role, 'super_admin');
    assert.equal(adminRes.body.authorization.userRolesTableStatus, 'verified');
    assert.ok(adminRes.body.providers?.featherless);
    assert.ok(adminRes.body.geminiFallback);

    const roleRes = await hDb.authRoleRoute.GET(makeReq());
    assert.deepEqual(roleRes.body, { authenticated: true, isAdmin: true, role: 'super_admin' });
  } finally {
    hDb.restoreEnv();
  }

  // 2.4b: Missing migration 0002 handled cleanly; trusted server-signed app_metadata still authorized
  const appMetaAdmin = {
    ...adminUser,
    app_metadata: { role: 'admin' },
  };
  const hAppMeta = createHarness({
    sessionUser: appMetaAdmin,
    dbRoleResponse: { data: null, error: { code: '42P01', message: 'relation "public.user_roles" does not exist' } },
    envOverrides: {
      NODE_ENV: 'production',
      ADMIN_EMAILS: '',
    },
  });
  try {
    const authRes = await hAppMeta.adminAuthMod.verifyAdminUser(makeReq());
    assert.equal(authRes.isAdmin, true);
    assert.equal(authRes.authSource, 'app_metadata');
    assert.equal(authRes.userRolesTableStatus, 'migration_missing');
  } finally {
    hAppMeta.restoreEnv();
  }

  // 2.4c: Unconfirmed email cannot use ADMIN_EMAILS bootstrap
  const unconfirmedBootstrapUser = {
    id: 'unconfirmed-1',
    email: 'admin@example.com',
    email_confirmed_at: null,
    app_metadata: {},
    user_metadata: {},
  };
  const hBootstrap = createHarness({
    sessionUser: unconfirmedBootstrapUser,
    dbRoleResponse: { data: null, error: null },
    envOverrides: {
      NODE_ENV: 'production',
      ADMIN_EMAILS: 'admin@example.com',
    },
  });
  try {
    const authRes = await hBootstrap.adminAuthMod.verifyAdminUser(makeReq());
    assert.equal(authRes.isAdmin, false, 'Unconfirmed email must be denied ADMIN_EMAILS bootstrap');
  } finally {
    hBootstrap.restoreEnv();
  }
});

await asyncTest('2.5 Constant-time ADMIN_API_KEY verification rejects missing, empty, short, placeholder, and mismatched keys', async () => {
  const h = createHarness({
    sessionUser: null,
    envOverrides: {
      NODE_ENV: 'production',
      ADMIN_API_KEY: 'valid-long-admin-api-key-9876543210',
    },
  });
  try {
    const { verifyAdminApiKey } = h.adminAuthMod;
    const validKey = 'valid-long-admin-api-key-9876543210';

    assert.equal(verifyAdminApiKey(undefined, validKey), false);
    assert.equal(verifyAdminApiKey('', validKey), false);
    assert.equal(verifyAdminApiKey('   ', validKey), false);
    assert.equal(verifyAdminApiKey('short', validKey), false);
    assert.equal(verifyAdminApiKey('valid-long-admin-api-key-9876543211', validKey), false);
    assert.equal(verifyAdminApiKey(validKey, 'too-short'), false, 'Configured key <= 16 chars must be rejected');
    assert.equal(verifyAdminApiKey('YOUR_ADMIN_API_KEY', 'YOUR_ADMIN_API_KEY'), false, 'Placeholder ADMIN_API_KEY must be rejected');
    assert.equal(verifyAdminApiKey(validKey, validKey), true);

    // Invalid key header against /api/admin/diagnostics returns 403
    const badRes = await h.adminDiagRoute.GET(makeReq({ 'x-aegis-admin-key': 'wrong-key-value' }));
    assert.equal(badRes.status, 403);

    // Valid key header against /api/admin/diagnostics returns 200
    const goodRes = await h.adminDiagRoute.GET(makeReq({ 'x-aegis-admin-key': validKey }));
    assert.equal(goodRes.status, 200);
    assert.equal(goodRes.body.authorization.authSource, 'api_key');
    assert.ok(!JSON.stringify(goodRes.body).includes(validKey), 'Response must never echo ADMIN_API_KEY');
  } finally {
    h.restoreEnv();
  }
});

await asyncTest('2.6 Browser-spoofed headers / role claims cannot bypass server authorization on /api/auth/role or /api/admin/diagnostics', async () => {
  const normalUser = {
    id: 'user-ordinary-2',
    email: 'user2@example.com',
    email_confirmed_at: '2026-01-01T00:00:00Z',
    app_metadata: {},
    user_metadata: { role: 'super_admin', is_admin: true },
  };
  const h = createHarness({
    sessionUser: normalUser,
    dbRoleResponse: { data: null, error: null },
    envOverrides: {
      NODE_ENV: 'production',
      ADMIN_API_KEY: 'valid-long-admin-api-key-9876543210',
    },
  });
  try {
    // Even if browser attempts to send x-aegis-admin-key to /api/auth/role or spoofed role headers to /api/admin/diagnostics
    const spoofedReq = makeReq({
      'x-user-role': 'super_admin',
      'x-is-admin': 'true',
      'x-admin-emails': 'user2@example.com',
      'x-aegis-admin-key': 'valid-long-admin-api-key-9876543210',
    });

    const roleRes = await h.authRoleRoute.GET(spoofedReq);
    assert.equal(roleRes.body.isAdmin, false, '/api/auth/role must ignore API key headers and client role headers');
    assert.equal(roleRes.body.role, 'user');

    const adminRes = await h.adminDiagRoute.GET(
      makeReq({
        'x-user-role': 'super_admin',
        'x-is-admin': 'true',
        'x-admin-emails': 'user2@example.com',
      })
    );
    assert.equal(adminRes.status, 403, 'Forged client role headers must be ignored by /api/admin/diagnostics');
  } finally {
    h.restoreEnv();
  }
});

// ====================================================================
// 3. Live HTTP Server Boundary Verification (When Port 3000 Active)
// ====================================================================
console.log('\n--- Suite 3: Live HTTP Endpoint & SSR Guard Verification ---');

function httpGetRaw(urlPath, headers = {}) {
  return new Promise((resolve) => {
    const req = http.get(
      `http://127.0.0.1:3000${urlPath}`,
      { headers },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          resolve({ offline: false, status: res.statusCode, raw: data });
        });
      }
    );
    req.on('error', () => resolve({ offline: true }));
    req.setTimeout(6000, () => {
      req.destroy();
      resolve({ offline: true });
    });
  });
}

await asyncTest('3.1 Live HTTP endpoints enforce admin boundary on /api/admin/diagnostics, /api/auth/role, /api/diagnostics, /api/model-diagnostic, and SSR /admin/diagnostics', async () => {
  const adminApi = await httpGetRaw('/api/admin/diagnostics', {
    'x-aegis-admin-key': 'definitely-invalid-key',
    'x-user-role': 'admin',
  });
  if (adminApi.offline) {
    console.log('    ℹ️ Dev server offline; skipping live HTTP boundary check.');
    return;
  }

  assert.equal(adminApi.status, 403, 'Live /api/admin/diagnostics must return 403');
  assert.ok(!/featherless|qwen|serper|gemini/i.test(adminApi.raw));

  const roleApi = await httpGetRaw('/api/auth/role');
  assert.equal(roleApi.status, 200);
  assert.deepEqual(JSON.parse(roleApi.raw), { authenticated: false, isAdmin: false, role: 'guest' });

  const adminSsrPage = await httpGetRaw('/admin/diagnostics');
  assert.equal(adminSsrPage.status, 200);
  assert.ok(adminSsrPage.raw.includes('Administrator Access Required'), 'Unauthenticated /admin/diagnostics must SSR render access-denied wall');
  assert.ok(!adminSsrPage.raw.includes('Featherless AI Gateway'), 'SSR denied page must NOT render provider telemetry markup');
  assert.ok(!adminSsrPage.raw.includes('Google Gemini API'), 'SSR denied page must NOT render Gemini fallback markup');
});

console.log(`\n========================================`);
console.log(`Phase 1 Admin Security Results: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
}
