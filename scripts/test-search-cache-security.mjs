import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Module from 'node:module';
import ts from 'typescript';

console.log('🛡️ Starting AegisFlow Phase 1B Search Cache Security Hardening Test Suite...\n');

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

function resolveFileCandidate(basePath) {
  const candidates = [
    basePath,
    `${basePath}.ts`,
    `${basePath}.tsx`,
    `${basePath}.js`,
    path.join(basePath, 'index.ts'),
    path.join(basePath, 'index.tsx'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) {
      return c;
    }
  }
  return null;
}

/**
 * Compiles & executes the REAL TypeScript source modules from the repository
 * with controlled dependency bindings for Supabase & external network calls.
 */
function createTsModuleLoader(customBindings = {}) {
  const nativeRequire = Module.createRequire(import.meta.url);
  const cache = new Map();

  function loadModule(specifier, fromDir = ROOT) {
    if (Object.prototype.hasOwnProperty.call(customBindings, specifier)) {
      return customBindings[specifier];
    }

    let resolvedFile = null;
    if (specifier.startsWith('@/')) {
      resolvedFile = resolveFileCandidate(path.join(ROOT, specifier.slice(2)));
    } else if (specifier.startsWith('./') || specifier.startsWith('../')) {
      resolvedFile = resolveFileCandidate(path.resolve(fromDir, specifier));
    } else if (path.isAbsolute(specifier)) {
      resolvedFile = resolveFileCandidate(specifier);
    }

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
    const modDir = path.dirname(resolvedFile);

    const fn = new Function('require', 'module', 'exports', '__filename', '__dirname', transpiled.outputText);
    fn(
      (childSpec) => loadModule(childSpec, modDir),
      mod,
      mod.exports,
      resolvedFile,
      modDir
    );
    return mod.exports;
  }

  return { loadModule };
}

/**
 * In-memory Postgres `public.search_cache` simulator enforcing privileges & RLS
 * modeled directly after 0003_search_cache.sql + 0004_harden_search_cache_permissions.sql.
 */
function createSimulatedSearchCacheDb(migration0004Sql) {
  const rows = new Map();

  const revokedAnon = /revoke\s+all\s+on\s+table\s+public\.search_cache\s+from\s+anon\b/i.test(migration0004Sql);
  const revokedAuth = /revoke\s+all\s+on\s+table\s+public\.search_cache\s+from\s+authenticated\b/i.test(migration0004Sql);
  const revokedPublic = /revoke\s+all\s+on\s+table\s+public\.search_cache\s+from\s+public\b/i.test(migration0004Sql);
  const droppedInsertPolicy = /drop\s+policy\s+if\s+exists\s+"Allow inserting search cache"\s+on\s+public\.search_cache/i.test(
    migration0004Sql
  );
  const droppedUpdatePolicy = /drop\s+policy\s+if\s+exists\s+"Allow updating search cache"\s+on\s+public\.search_cache/i.test(
    migration0004Sql
  );
  const droppedSelectPolicy = /drop\s+policy\s+if\s+exists\s+"Allow reading unexpired cache"\s+on\s+public\.search_cache/i.test(
    migration0004Sql
  );
  const grantedServiceRole = /grant\s+select,\s*insert,\s*update,\s*delete\s+on\s+table\s+public\.search_cache\s+to\s+service_role/i.test(
    migration0004Sql
  );

  function checkPrivilege(role, operation) {
    if (role === 'service_role') {
      return grantedServiceRole;
    }
    if (role === 'anon') {
      if (revokedAnon || revokedPublic) return false;
      if (operation === 'SELECT') return !droppedSelectPolicy;
      if (operation === 'INSERT') return !droppedInsertPolicy;
      if (operation === 'UPDATE') return !droppedUpdatePolicy;
      return false;
    }
    if (role === 'authenticated') {
      if (revokedAuth || revokedPublic) return false;
      if (operation === 'SELECT') return !droppedSelectPolicy;
      if (operation === 'INSERT') return !droppedInsertPolicy;
      if (operation === 'UPDATE') return !droppedUpdatePolicy;
      return false;
    }
    return false;
  }

  function clientForRole(role) {
    return {
      from(table) {
        assert.equal(table, 'search_cache', 'Only search_cache table is modeled here');

        return {
          select() {
            const filters = { cache_key: null, provider: null, gtExpiresAt: null };
            const queryBuilder = {
              eq(col, val) {
                filters[col] = val;
                return queryBuilder;
              },
              gt(col, val) {
                if (col === 'expires_at') filters.gtExpiresAt = Date.parse(val);
                return queryBuilder;
              },
              async maybeSingle() {
                if (!checkPrivilege(role, 'SELECT')) {
                  return {
                    data: null,
                    error: { code: '42501', message: `permission denied for table search_cache (role=${role})` },
                  };
                }
                const row = filters.cache_key ? rows.get(filters.cache_key) : null;
                if (!row) return { data: null, error: null };
                if (filters.provider && row.provider !== filters.provider) return { data: null, error: null };
                if (filters.gtExpiresAt !== null && Date.parse(row.expires_at) <= filters.gtExpiresAt) {
                  return { data: null, error: null };
                }
                return { data: { ...row }, error: null };
              },
            };
            return queryBuilder;
          },

          async insert(payload) {
            if (!checkPrivilege(role, 'INSERT')) {
              return {
                data: null,
                error: { code: '42501', message: `permission denied for table search_cache (role=${role})` },
              };
            }
            rows.set(payload.cache_key, { ...payload });
            return { data: payload, error: null };
          },

          update(payload) {
            return {
              async eq(col, val) {
                if (!checkPrivilege(role, 'UPDATE')) {
                  return {
                    data: null,
                    error: { code: '42501', message: `permission denied for table search_cache (role=${role})` },
                  };
                }
                if (col === 'cache_key' && rows.has(val)) {
                  rows.set(val, { ...rows.get(val), ...payload });
                }
                return { data: null, error: null };
              },
            };
          },

          async upsert(payload, options) {
            const exists = rows.has(payload.cache_key);
            if (!checkPrivilege(role, 'INSERT') || (exists && !checkPrivilege(role, 'UPDATE'))) {
              return {
                data: null,
                error: { code: '42501', message: `permission denied for table search_cache (role=${role})` },
              };
            }
            assert.equal(options?.onConflict, 'cache_key');
            rows.set(payload.cache_key, { ...payload });
            return { data: payload, error: null };
          },

          delete() {
            return {
              async eq(col, val) {
                if (!checkPrivilege(role, 'DELETE')) {
                  return {
                    data: null,
                    error: { code: '42501', message: `permission denied for table search_cache (role=${role})` },
                  };
                }
                if (col === 'cache_key') {
                  rows.delete(val);
                }
                return { data: null, error: null };
              },
            };
          },
        };
      },
    };
  }

  return { rows, clientForRole };
}

// ====================================================================
// Suite 1: Migration Audit & Preserved Schema Invariants
// ====================================================================
console.log('--- Suite 1: SQL Migration & Schema Preservation Audit ---');

const migration0003Path = path.join(ROOT, 'supabase/migrations/0003_search_cache.sql');
const migration0004Path = path.join(ROOT, 'supabase/migrations/0004_harden_search_cache_permissions.sql');

test('1.1 Migration 0004 exists and 0003 original migration remains untouched', () => {
  assert.ok(fs.existsSync(migration0004Path), '0004_harden_search_cache_permissions.sql must exist');
  assert.ok(fs.existsSync(migration0003Path), '0003_search_cache.sql must be preserved');
  const sql0003 = fs.readFileSync(migration0003Path, 'utf8');
  assert.ok(sql0003.includes('create table if not exists public.search_cache'), '0003 schema intact');
});

test('1.2 Migration 0004 preserves schema/data, enables RLS, revokes anon/authenticated, and drops permissive policies', () => {
  const sql0004 = fs.readFileSync(migration0004Path, 'utf8');

  // Strip SQL line comments before scanning executable SQL statements
  const executableSql0004 = sql0004
    .split('\n')
    .map((line) => line.replace(/--.*$/, ''))
    .join('\n');

  // Must not drop or recreate the table
  assert.ok(!/drop\s+table/i.test(executableSql0004), 'Must not DROP TABLE public.search_cache');
  assert.ok(!/create\s+table/i.test(executableSql0004), 'Must not recreate public.search_cache');

  // Must keep RLS enabled
  assert.ok(
    /alter\s+table\s+public\.search_cache\s+enable\s+row\s+level\s+security\s*;/i.test(executableSql0004),
    'Must keep RLS enabled on public.search_cache'
  );

  // Must drop permissive policies from 0003
  assert.ok(executableSql0004.includes('drop policy if exists "Allow inserting search cache" on public.search_cache;'));
  assert.ok(executableSql0004.includes('drop policy if exists "Allow updating search cache" on public.search_cache;'));
  assert.ok(executableSql0004.includes('drop policy if exists "Allow reading unexpired cache" on public.search_cache;'));

  // Must contain zero permissive write grants/policies
  assert.ok(!/with\s+check\s*\(\s*true\s*\)/i.test(executableSql0004), 'Must not introduce WITH CHECK (true)');
  assert.ok(!/using\s*\(\s*true\s*\)/i.test(executableSql0004), 'Must not introduce USING (true)');
  assert.ok(!/grant\s+[^;]*\bto\s+[^;]*(anon|authenticated)/i.test(executableSql0004), 'Must not grant to anon or authenticated');

  // Must revoke all on public.search_cache from public, anon, authenticated & grant to service_role
  assert.ok(/revoke\s+all\s+on\s+table\s+public\.search_cache\s+from\s+public\s*;/i.test(sql0004));
  assert.ok(/revoke\s+all\s+on\s+table\s+public\.search_cache\s+from\s+anon\s*;/i.test(sql0004));
  assert.ok(/revoke\s+all\s+on\s+table\s+public\.search_cache\s+from\s+authenticated\s*;/i.test(sql0004));
  assert.ok(
    /grant\s+select,\s*insert,\s*update,\s*delete\s+on\s+table\s+public\.search_cache\s+to\s+service_role\s*;/i.test(
      sql0004
    )
  );
});

// ====================================================================
// Suite 2: Database Privilege & Poisoning Resistance Simulation
// ====================================================================
console.log('\n--- Suite 2: PostgREST Privilege & Cache Poisoning Prevention ---');

const sql0004 = fs.readFileSync(migration0004Path, 'utf8');

await asyncTest('2.1 Anonymous (anon) callers cannot read, insert, update, or delete search_cache rows', async () => {
  const db = createSimulatedSearchCacheDb(sql0004);
  const anon = db.clientForRole('anon');

  const ins = await anon.from('search_cache').insert({ cache_key: 'poison', provider: 'serper' });
  assert.equal(ins.error?.code, '42501', 'anon INSERT must fail with insufficient_privilege');

  const upd = await anon.from('search_cache').update({ response_payload: { evil: true } }).eq('cache_key', 'k1');
  assert.equal(upd.error?.code, '42501', 'anon UPDATE must fail with insufficient_privilege');

  const del = await anon.from('search_cache').delete().eq('cache_key', 'k1');
  assert.equal(del.error?.code, '42501', 'anon DELETE must fail with insufficient_privilege');

  const sel = await anon.from('search_cache').select('*').eq('cache_key', 'k1').maybeSingle();
  assert.equal(sel.error?.code, '42501', 'anon direct SELECT must fail with insufficient_privilege');
});

await asyncTest('2.2 Ordinary authenticated callers cannot poison, overwrite, or delete cache rows', async () => {
  const db = createSimulatedSearchCacheDb(sql0004);
  const service = db.clientForRole('service_role');
  const authUser = db.clientForRole('authenticated');

  await service.from('search_cache').upsert(
    {
      cache_key: 'legit-key',
      provider: 'serper',
      query_normalized: 'cbn advisory',
      response_payload: { sources: [{ title: 'Official CBN Notice' }] },
      cached_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    },
    { onConflict: 'cache_key' }
  );

  const ins = await authUser.from('search_cache').insert({ cache_key: 'user-poison', provider: 'serper' });
  assert.equal(ins.error?.code, '42501', 'authenticated INSERT must be rejected');

  const upd = await authUser
    .from('search_cache')
    .update({ response_payload: { sources: [{ title: 'Spoofed Link' }] } })
    .eq('cache_key', 'legit-key');
  assert.equal(upd.error?.code, '42501', 'authenticated UPDATE poisoning attempt must be rejected');

  const del = await authUser.from('search_cache').delete().eq('cache_key', 'legit-key');
  assert.equal(del.error?.code, '42501', 'authenticated DELETE must be rejected');

  const verify = await service.from('search_cache').select('*').eq('cache_key', 'legit-key').maybeSingle();
  assert.equal(verify.data?.response_payload?.sources?.[0]?.title, 'Official CBN Notice', 'Trusted entry remains uncorrupted');
});

// ====================================================================
// Suite 3: Server-Only Service Client, Key Hashing & Secret Safety
// ====================================================================
console.log('\n--- Suite 3: Server-Only Cache Helper & Secret Hygiene ---');

await asyncTest('3.1 Server-only cache client uses persistSession: false and fails closed in browser or missing env', async () => {
  const createdClients = [];
  const db = createSimulatedSearchCacheDb(sql0004);

  const { loadModule } = createTsModuleLoader({
    '@supabase/supabase-js': {
      createClient(url, key, options) {
        createdClients.push({ url, key, options });
        return db.clientForRole('service_role');
      },
    },
  });

  const searchCache = loadModule('@/lib/fact-checker/search-cache');

  // Missing / placeholder env returns null cleanly
  assert.equal(searchCache.getSearchCacheServiceClient({}), null);
  assert.equal(
    searchCache.getSearchCacheServiceClient({
      NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
      SUPABASE_SERVICE_ROLE_KEY: 'YOUR_SUPABASE_SERVICE_ROLE_KEY',
    }),
    null
  );

  // Browser window guard fails closed even with env present
  globalThis.window = {};
  try {
    assert.equal(
      searchCache.getSearchCacheServiceClient({
        NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
        SUPABASE_SERVICE_ROLE_KEY: 'service-role-secret-value-at-least-20-chars',
      }),
      null,
      'Must refuse client instantiation if window is defined'
    );
  } finally {
    delete globalThis.window;
  }

  // Valid server config creates client with persistSession: false & autoRefreshToken: false
  const client = searchCache.getSearchCacheServiceClient({
    NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_SERVICE_ROLE_KEY: 'service-role-secret-value-at-least-20-chars',
  });
  assert.ok(client, 'Valid server environment must return service-role client');
  assert.equal(createdClients.length, 1);
  assert.equal(createdClients[0].options?.auth?.persistSession, false);
  assert.equal(createdClients[0].options?.auth?.autoRefreshToken, false);

  // SHA-256 cache_key derivation & secret redaction on write
  const expectedKey = crypto.createHash('sha256').update('serper:serper:cbn fee:4:cbn', 'utf8').digest('hex');
  assert.equal(searchCache.deriveSearchCacheKey('serper', 'serper:cbn fee:4:cbn'), expectedKey);

  const secretToken = 'rc_1111222233334444555566667777888899990000';
  const wrote = await searchCache.writePersistentSearchCache(
    'serper',
    'serper:cbn fee:4:cbn',
    'cbn fee',
    { sources: [{ snippet: `debug leaked ${secretToken}` }] },
    60_000,
    client
  );
  assert.equal(wrote, true);

  const stored = db.rows.get(expectedKey);
  assert.ok(stored, 'Row must be stored under SHA-256 key');
  assert.ok(!JSON.stringify(stored.response_payload).includes(secretToken), 'Secret tokens must be redacted before DB storage');

  const hit = await searchCache.readPersistentSearchCache('serper', 'serper:cbn fee:4:cbn', client);
  assert.ok(hit, 'Unexpired entry must be returned by service-role reader');
});

await asyncTest('3.2 Expired cache rows are strictly treated as misses', async () => {
  const db = createSimulatedSearchCacheDb(sql0004);
  const service = db.clientForRole('service_role');
  const { loadModule } = createTsModuleLoader({
    '@supabase/supabase-js': {
      createClient: () => service,
    },
  });
  const searchCache = loadModule('@/lib/fact-checker/search-cache');

  const rawKey = 'serper:expired query:4:none';
  const hashedKey = searchCache.deriveSearchCacheKey('serper', rawKey);

  db.rows.set(hashedKey, {
    cache_key: hashedKey,
    provider: 'serper',
    query_normalized: 'expired query',
    response_payload: { sources: [{ title: 'Stale Result', url: 'https://stale.example' }] },
    cached_at: new Date(Date.now() - 3600_000).toISOString(),
    expires_at: new Date(Date.now() - 1000).toISOString(),
  });

  const expiredHit = await searchCache.readPersistentSearchCache('serper', rawKey, service);
  assert.equal(expiredHit, null, 'Expired search_cache row must yield a cache miss');
});

test('3.3 Client bundles/components never import server cache modules or reference SUPABASE_SERVICE_ROLE_KEY', () => {
  const scanDirs = [
    path.join(ROOT, 'components'),
    path.join(ROOT, 'hooks'),
  ];
  const appFiles = [];
  function walk(dir, excludeNames = new Set()) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!excludeNames.has(entry.name)) walk(full, excludeNames);
      } else if (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) {
        appFiles.push(full);
      }
    }
  }
  walk(path.join(ROOT, 'app'), new Set(['api', 'admin']));
  for (const d of scanDirs) walk(d);

  const leaks = [];
  for (const f of appFiles) {
    const content = fs.readFileSync(f, 'utf8');
    if (
      content.includes('SUPABASE_SERVICE_ROLE_KEY') ||
      content.includes('search-cache') ||
      content.includes('web-researcher')
    ) {
      leaks.push(path.relative(ROOT, f));
    }
  }
  assert.deepEqual(leaks, [], `Client files must never reference service-role key or server cache: ${leaks.join(', ')}`);
});

// ====================================================================
// Suite 4: Web Researcher End-to-End Cache Preservation & Fallback
// ====================================================================
console.log('\n--- Suite 4: Web Researcher Cache Integration & Failure Safety ---');

await asyncTest('4.1 searchSerper writes fresh results to service-role cache, serves unexpired hits without fetch, and bypasses expired rows', async () => {
  const db = createSimulatedSearchCacheDb(sql0004);
  const service = db.clientForRole('service_role');

  const envBackup = {
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  };
  const originalFetch = globalThis.fetch;

  process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'service-role-secret-value-at-least-20-chars';

  let fetchCalls = 0;
  try {
    const { loadModule } = createTsModuleLoader({
      '@supabase/supabase-js': {
        createClient: () => service,
      },
      '@/lib/gemini/client': {
        isGeminiSearchFallbackEnabled: () => false,
      },
      '@/lib/gemini/search-grounding': {
        searchGeminiGoogleSearch: async () => ({ sources: [] }),
      },
      '@/lib/provider-orchestrator': {
        recordProviderMetric: () => {},
      },
    });

    const researcher = loadModule('@/lib/fact-checker/web-researcher');
    researcher.clearSerperCache();

    globalThis.fetch = async (url) => {
      fetchCalls++;
      assert.equal(url, 'https://google.serper.dev/search');
      return new Response(
        JSON.stringify({
          organic: [
            {
              title: 'Official Security Advisory',
              link: 'https://cisa.gov/advisory-1',
              snippet: 'Verified federal security advisory details.',
            },
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    };

    // 1. Cold miss -> calls Serper once and writes persistent cache
    const first = await researcher.searchSerper('cisa advisory test', 'serper_test_key_12345', 4);
    assert.equal(fetchCalls, 1);
    assert.equal(first.fromCache, false);
    assert.equal(first.sources.length, 1);
    assert.equal(db.rows.size, 1, 'Fresh result must persist to search_cache');

    // 2. Clear in-memory Map -> persistent cache hit avoids outbound fetch
    researcher.clearSerperCache();
    const second = await researcher.searchSerper('cisa advisory test', 'serper_test_key_12345', 4);
    assert.equal(fetchCalls, 1, 'Unexpired persistent search_cache hit must avoid outbound API call');
    assert.equal(second.fromCache, true);
    assert.equal(second.sources[0].provenance, 'cached_evidence');

    // 3. Expire persistent row + clear in-memory Map -> triggers fresh fetch
    researcher.clearSerperCache();
    for (const [k, row] of db.rows.entries()) {
      db.rows.set(k, { ...row, expires_at: new Date(Date.now() - 5000).toISOString() });
    }
    const third = await researcher.searchSerper('cisa advisory test', 'serper_test_key_12345', 4);
    assert.equal(fetchCalls, 2, 'Expired search_cache entry must trigger fresh search');
    assert.equal(third.fromCache, false);
  } finally {
    globalThis.fetch = originalFetch;
    if (envBackup.NEXT_PUBLIC_SUPABASE_URL === undefined) delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    else process.env.NEXT_PUBLIC_SUPABASE_URL = envBackup.NEXT_PUBLIC_SUPABASE_URL;
    if (envBackup.SUPABASE_SERVICE_ROLE_KEY === undefined) delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    else process.env.SUPABASE_SERVICE_ROLE_KEY = envBackup.SUPABASE_SERVICE_ROLE_KEY;
  }
});

await asyncTest('4.2 Provider failures (rate limit/HTTP error) and unconfigured URLhaus never poison cache', async () => {
  const db = createSimulatedSearchCacheDb(sql0004);
  const service = db.clientForRole('service_role');

  const envBackup = {
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
    URLHAUS_AUTH_KEY: process.env.URLHAUS_AUTH_KEY,
  };
  const originalFetch = globalThis.fetch;

  process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'service-role-secret-value-at-least-20-chars';
  process.env.URLHAUS_AUTH_KEY = 'urlhaus_test_auth_key_12345';

  try {
    const { loadModule } = createTsModuleLoader({
      '@supabase/supabase-js': {
        createClient: () => service,
      },
      '@/lib/gemini/client': {
        isGeminiSearchFallbackEnabled: () => false,
      },
      '@/lib/gemini/search-grounding': {
        searchGeminiGoogleSearch: async () => ({ sources: [] }),
      },
      '@/lib/provider-orchestrator': {
        recordProviderMetric: () => {},
      },
    });

    const researcher = loadModule('@/lib/fact-checker/web-researcher');
    researcher.clearSerperCache();
    researcher.clearUrlhausCache();

    globalThis.fetch = async () =>
      new Response(JSON.stringify({ message: 'too many requests' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' },
      });

    const failedSerper = await researcher.searchSerper('failing query', 'serper_test_key_12345', 4);
    assert.equal(failedSerper.rateLimited, true);
    assert.equal(db.rows.size, 0, 'Rate-limited Serper failure must NOT write to search_cache');

    globalThis.fetch = async () =>
      new Response(JSON.stringify({ message: 'monthly quota exceeded' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' },
      });
    const quotaSerper = await researcher.searchSerper('quota query', 'serper_test_key_12345', 4);
    assert.equal(quotaSerper.quotaExhausted, true);
    assert.equal(db.rows.size, 0, 'Quota-exhausted Serper failure must NOT write to search_cache');

    const failedUrlhaus = await researcher.checkUrlhausThreatIntel('evil-example.test', 'domain');
    assert.equal(failedUrlhaus.status, 'unreachable');
    assert.equal(db.rows.size, 0, 'Rate-limited URLhaus lookup must NOT write to search_cache');
  } finally {
    globalThis.fetch = originalFetch;
    if (envBackup.NEXT_PUBLIC_SUPABASE_URL === undefined) delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    else process.env.NEXT_PUBLIC_SUPABASE_URL = envBackup.NEXT_PUBLIC_SUPABASE_URL;
    if (envBackup.SUPABASE_SERVICE_ROLE_KEY === undefined) delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    else process.env.SUPABASE_SERVICE_ROLE_KEY = envBackup.SUPABASE_SERVICE_ROLE_KEY;
    if (envBackup.URLHAUS_AUTH_KEY === undefined) delete process.env.URLHAUS_AUTH_KEY;
    else process.env.URLHAUS_AUTH_KEY = envBackup.URLHAUS_AUTH_KEY;
  }
});

console.log(`\n========================================`);
console.log(`Phase 1B Search Cache Security Results: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
}
