import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import Module from 'node:module';
import ts from 'typescript';

console.log('🛡️ Starting AegisFlow /api/analyze Transport & Edge Reliability Test Suite...\n');

const ROOT = process.cwd();
const nativeRequire = Module.createRequire(import.meta.url);

let totalTests = 0;
let passedTests = 0;

async function asyncTest(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err?.stack || err?.message || err}`);
    process.exitCode = 1;
  }
}

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err?.stack || err?.message || err}`);
    process.exitCode = 1;
  }
}

function loadTs(relPath, mocks = {}) {
  const full = path.join(ROOT, relPath);
  const src = fs.readFileSync(full, 'utf8');
  const out = ts.transpileModule(src, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
  });
  const mod = { exports: {} };
  const fn = new Function('require', 'module', 'exports', '__filename', '__dirname', out.outputText);
  fn(
    (spec) => {
      if (Object.prototype.hasOwnProperty.call(mocks, spec)) return mocks[spec];
      if (spec.startsWith('./') || spec.startsWith('../')) {
        const siblingKey =
          '@/' + path.posix.normalize(path.posix.join(path.posix.dirname(relPath.replace(/\\/g, '/')), spec));
        if (Object.prototype.hasOwnProperty.call(mocks, siblingKey)) return mocks[siblingKey];
      }
      return nativeRequire(spec);
    },
    mod,
    mod.exports,
    full,
    path.dirname(full)
  );
  return mod.exports;
}

class MockHeaders extends Map {
  constructor(initial = {}) {
    super();
    for (const [k, v] of Object.entries(initial)) {
      this.set(k, v);
    }
  }
  get(k) {
    return super.get(String(k).toLowerCase()) ?? null;
  }
  set(k, v) {
    return super.set(String(k).toLowerCase(), String(v));
  }
  has(k) {
    return super.has(String(k).toLowerCase());
  }
}

function createMockNextServer() {
  const NextResponse = {
    json(body, init = {}) {
      const headers = new MockHeaders({ 'content-type': 'application/json' });
      if (init.headers) {
        if (init.headers instanceof Map || typeof init.headers.forEach === 'function') {
          init.headers.forEach((v, k) => headers.set(k, v));
        } else {
          for (const [k, v] of Object.entries(init.headers)) {
            headers.set(k, v);
          }
        }
      }
      return {
        status: init.status ?? 200,
        ok: (init.status ?? 200) < 300,
        headers,
        body,
        cookies: {
          setCalls: [],
          set(name, value, options) {
            this.setCalls.push({ name, value, options });
          },
        },
        async json() {
          return body;
        },
      };
    },
    next(init = {}) {
      const headers = new MockHeaders();
      return {
        status: 200,
        ok: true,
        isNext: true,
        requestHeaders: init?.request?.headers || null,
        headers,
        cookies: {
          setCalls: [],
          set(name, value, options) {
            this.setCalls.push({ name, value, options });
          },
        },
      };
    },
    redirect() {
      throw new Error('Unexpected NextResponse.redirect() call!');
    },
  };
  return { NextResponse };
}

const modelConfig = loadTs('lib/model-config.ts', {});
const realScamAnalyzer = loadTs('lib/scam-analyzer.ts', {});
const transportHelper = loadTs('lib/analyze-transport.ts', {});

function setupRouteHarness(overrides = {}) {
  const mockNextServer = createMockNextServer();
  const loggedEvents = [];
  const rawDiagnostics = loadTs('lib/diagnostics-log.ts', { '@/lib/model-config': modelConfig });
  const diagnosticsMock = {
    getOrCreateCorrelationId: rawDiagnostics.getOrCreateCorrelationId,
    logSafeRouteEvent: (evt) => {
      loggedEvents.push(evt);
    },
  };

  let quotaState = { reserves: 0, commits: 0, refunds: 0 };
  let vaultState = { existingIds: [], inserts: 0 };
  let geminiCalls = 0;
  let geminiCapturedTimeout = 0;
  let rateLimitCalls = 0;
  let authLookupCalls = 0;

  let geminiMode = overrides.geminiMode || 'valid';
  let quotaOutcomeMode = overrides.quotaOutcomeMode || 'allow';
  let rateLimitAllow = overrides.rateLimitAllow !== undefined ? overrides.rateLimitAllow : true;
  let bearerBehavior = overrides.bearerBehavior || 'valid';
  let supabaseAuthUser = overrides.supabaseAuthUser !== undefined ? overrides.supabaseAuthUser : { id: 'user-test-123' };

  const realMessageAnalyzer = loadTs('lib/gemini/message-analyzer.ts', {
    '@/lib/gemini/client': {
      getGeminiClient: () => ({
        models: {
          generateContent: async () => {
            geminiCalls++;
            if (geminiMode === 'fail') {
              throw new Error('Gemini 503 failure with secret AIzaSyFakeKey1234567890123456789012345');
            }
            if (geminiMode === 'slow') {
              await new Promise((r) => setTimeout(r, 250));
            }
            return {
              text: JSON.stringify({
                riskLevel: 'high',
                summary: 'Urgent banking lure with suspicious verification link.',
                indicators: [{ name: 'Suspicious Link', evidence: 'https://bit.ly/wf-sec', reason: 'Phishing' }],
                recommendedActions: ['Verify through official banking app directly.'],
                limitations: ['Text triage only.'],
              }),
            };
          },
        },
      }),
      getResolvedGeminiModel: () => 'gemini-3.8-flash',
      isGeminiFallbackEnabled: () => true,
      sanitizeGeminiError: (e) => modelConfig.redactSecrets(String(e?.message || e)),
    },
    '@/lib/scam-analyzer': realScamAnalyzer,
  });

  const analyzeRoute = loadTs('app/api/analyze/route.ts', {
    'next/server': mockNextServer,
    '@/lib/scam-analyzer': realScamAnalyzer,
    '@/lib/supabase/server': {
      createClient: async () => ({
        auth: {
          getUser: async (token) => {
            authLookupCalls++;
            if (token) {
              if (bearerBehavior === 'reject') {
                return { data: { user: null }, error: { message: 'Invalid JWT token' } };
              }
              if (bearerBehavior === 'throw') {
                throw new Error('Auth service down');
              }
              return { data: { user: { id: 'bearer-user-1' } }, error: null };
            }
            return { data: { user: supabaseAuthUser }, error: null };
          },
        },
        from: (table) => {
          assert.equal(table, 'analysis_history');
          return {
            select: () => ({
              eq: () => ({
                eq: () => ({
                  gte: () => ({
                    limit: async () => ({ data: vaultState.existingIds.map((id) => ({ id })), error: null }),
                  }),
                }),
              }),
            }),
            insert: async () => {
              vaultState.inserts++;
              return { error: null };
            },
          };
        },
      }),
    },
    '@/lib/model-config': modelConfig,
    '@/lib/gemini/client': {
      isGeminiFallbackEnabled: () => overrides.geminiEnabled !== false,
    },
    '@/lib/gemini/message-analyzer': {
      analyzeMessageWithGemini: async (msg, timeoutMs, signal) => {
        geminiCapturedTimeout = timeoutMs;
        return realMessageAnalyzer.analyzeMessageWithGemini(msg, timeoutMs, signal);
      },
    },
    '@/lib/provider-orchestrator': {
      classifyHttpError: (status, bodySnippet = '') => {
        const lower = (bodySnippet || '').toLowerCase();
        if (status === 401 || status === 403) return 'auth_failure';
        if (status === 429) return 'rate_limited';
        if (status === 408 || status === 504 || lower.includes('timeout')) return 'timeout';
        if (status === 502 || status === 503 || status === 500) return 'unavailable';
        if (status >= 400 && status < 500) return 'bad_request';
        return 'unknown';
      },
      isEligibleForFallback: (code) =>
        code === 'rate_limited' || code === 'quota_exhausted' || code === 'timeout' || code === 'unavailable',
      recordProviderMetric() {},
    },
    '@/lib/rate-limit': {
      enforceApiRateLimit: async () => {
        rateLimitCalls++;
        if (!rateLimitAllow) {
          return {
            allowed: false,
            status: 429,
            limit: 12,
            remaining: 0,
            retryAfterSeconds: 30,
            resetAt: new Date(Date.now() + 30000).toISOString(),
            scope: 'guest',
            mode: 'distributed_supabase',
            unavailable: false,
            error: 'Request limit reached. Please wait 30 second(s).',
            errorCode: 'rate_limit_exceeded',
          };
        }
        return {
          allowed: true,
          status: 200,
          limit: 12,
          remaining: 11,
          retryAfterSeconds: 0,
          resetAt: new Date(Date.now() + 60000).toISOString(),
          scope: 'guest',
          mode: 'distributed_supabase',
        };
      },
      buildRateLimitErrorResponse: (o) =>
        mockNextServer.NextResponse.json(
          { error: o.error, errorCode: o.errorCode, retryAfterSeconds: o.retryAfterSeconds },
          { status: o.status }
        ),
      attachRateLimitHeaders: (res) => res,
    },
    '@/lib/quota': {
      reserveInvestigationQuota: async () => {
        if (quotaOutcomeMode === 'email_unverified') {
          return {
            allowed: false,
            status: 403,
            capability: 'message_analysis',
            errorCode: 'email_verification_required',
            requiresVerification: true,
            error: 'Please verify your email address before running investigations.',
          };
        }
        if (quotaOutcomeMode === 'exhausted') {
          return {
            allowed: false,
            status: 403,
            capability: 'message_analysis',
            errorCode: 'quota_exhausted',
            requiresRegistration: true,
            error: 'Guest credits exhausted.',
          };
        }
        if (quotaOutcomeMode === 'invalid_guest_token') {
          return {
            allowed: false,
            status: 403,
            capability: 'message_analysis',
            errorCode: 'invalid_guest_token',
            error: 'Guest token rejected.',
          };
        }
        quotaState.reserves++;
        return {
          allowed: true,
          status: 200,
          reservation: { reservationId: `res-${quotaState.reserves}`, snapshot: { totalRemaining: 11 } },
        };
      },
      commitQuotaReservation: async () => {
        quotaState.commits++;
        return { totalRemaining: 11 };
      },
      refundQuotaReservation: async () => {
        quotaState.refunds++;
        return { totalRemaining: 12 };
      },
      buildQuotaErrorResponse: (o) =>
        mockNextServer.NextResponse.json(
          { error: o.error, errorCode: o.errorCode, capability: o.capability },
          { status: o.status, headers: { 'Cache-Control': 'no-store, max-age=0', Vary: 'Cookie' } }
        ),
      attachGuestCookie: (r) => r,
    },
    '@/lib/diagnostics-log': diagnosticsMock,
  });

  return {
    analyzeRoute,
    loggedEvents,
    getState: () => ({
      quotaState: { ...quotaState },
      vaultState: { ...vaultState },
      geminiCalls,
      geminiCapturedTimeout,
      rateLimitCalls,
      authLookupCalls,
    }),
    setGeminiMode: (m) => {
      geminiMode = m;
    },
  };
}

function makePostRequest(message, opts = {}) {
  const headers = new MockHeaders(opts.headers || {});
  return {
    method: 'POST',
    headers,
    signal: opts.signal,
    async json() {
      return { message };
    },
  };
}

// ====================================================================
// Scenarios 1–6 & 10–15: Server Route, Auth/Authz, Headers, Diagnostics, Fallback, Quota, Vault
// ====================================================================
console.log('--- Scenarios 1–6 & 10–15: Server Route, Auth/Authz, Middleware, Diagnostics & Orchestration ---');

await asyncTest('Scenario 1: /api/analyze returns strict JSON success, force-dynamic, no-store, correlation ID & sanitized lifecycle stages', async () => {
  const harness = setupRouteHarness();
  assert.equal(harness.analyzeRoute.dynamic, 'force-dynamic');
  assert.equal(harness.analyzeRoute.maxDuration, 60);

  // GET /api/analyze returns strict JSON 405 without HTML
  const getRes = await harness.analyzeRoute.GET({ headers: new MockHeaders() });
  assert.equal(getRes.status, 405);
  assert.equal(getRes.headers.get('content-type'), 'application/json');
  assert.equal(getRes.headers.get('cache-control'), 'no-store, max-age=0');
  assert.ok(getRes.headers.get('x-aegis-correlation-id'));
  assert.equal(getRes.body.errorCode, 'method_not_allowed');

  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  try {
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({
          choices: [{ message: { content: '{"riskLevel":"low","summary":"Routine team lunch reminder.","indicators":[],"recommendedActions":["No action required."],"limitations":["Text triage only."]}' } }],
        });
      },
    });

    const req = makePostRequest('Hey Alex, lunch is still on for noon tomorrow at Osteria.', {
      headers: {
        'x-aegis-correlation-id': 'cli-scenario-01',
        'x-aegis-middleware-outcome': 'guest_passthrough',
      },
    });
    const res = await harness.analyzeRoute.POST(req);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.equal(res.headers.get('cache-control'), 'no-store, max-age=0');
    assert.equal(res.headers.get('x-aegis-correlation-id'), 'cli-scenario-01');
    assert.equal(res.body.riskLevel, 'low');

    const stages = harness.loggedEvents.map((e) => e.stage);
    for (const requiredStage of [
      'request_received',
      'middleware_or_session_outcome',
      'authentication_checked',
      'validation_completed',
      'quota_reserved',
      'primary_started',
      'primary_outcome',
      'analysis_validated',
      'vault_persisted',
      'quota_committed',
      'response_sent',
    ]) {
      assert.ok(stages.includes(requiredStage), `Missing required diagnostic stage: ${requiredStage}`);
    }

    const serializedLogs = JSON.stringify(harness.loggedEvents);
    assert.ok(!serializedLogs.includes('Osteria'), 'Diagnostics must never log raw message text');
    assert.ok(!serializedLogs.includes('rc_aaaa'), 'Diagnostics must never log API keys');
    assert.ok(
      harness.loggedEvents.every((evt) => evt.httpStatus >= 400 || !evt.errorCategory),
      'Healthy HTTP 200 diagnostic events must use detail instead of errorCategory'
    );

    const rawDiagMod = loadTs('lib/diagnostics-log.ts', { '@/lib/model-config': modelConfig });
    const capturedInfo = [];
    const origInfo = console.info;
    console.info = (...args) => capturedInfo.push(args.join(' '));
    try {
      rawDiagMod.logSafeRouteEvent({
        correlationId: 'cli-test-200',
        endpoint: '/api/analyze',
        stage: 'authentication_checked',
        httpStatus: 200,
        detail: 'session_or_guest_cookie',
        providerCategory: 'auth',
      });
    } finally {
      console.info = origInfo;
    }
    assert.equal(capturedInfo.length, 1);
    assert.ok(!capturedInfo[0].includes('errorCategory'), '200 OK diagnostic line must not serialize errorCategory');
    assert.ok(capturedInfo[0].includes('"detail":"session_or_guest_cookie"'));
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

await asyncTest('Scenario 2: /api/analyze returns sanitized JSON 401 when Bearer authentication fails (after rate limit, no redirect/HTML)', async () => {
  const harness = setupRouteHarness({ bearerBehavior: 'reject' });

  const malformedReq = makePostRequest('Test message for auth check', {
    headers: { authorization: 'Basic bad-token-xyz' },
  });
  const res1 = await harness.analyzeRoute.POST(malformedReq);
  assert.equal(res1.status, 401);
  assert.equal(res1.headers.get('content-type'), 'application/json');
  assert.equal(res1.headers.get('cache-control'), 'no-store, max-age=0');
  assert.equal(res1.body.errorCode, 'authentication_failed');
  assert.ok(!JSON.stringify(res1.body).includes('bad-token-xyz'));
  assert.equal(harness.getState().rateLimitCalls, 1, 'Rate limiting must execute before auth rejection');

  const invalidJwtReq = makePostRequest('Test message for auth check', {
    headers: { authorization: 'Bearer invalid.jwt.secret_token_value' },
  });
  const res2 = await harness.analyzeRoute.POST(invalidJwtReq);
  assert.equal(res2.status, 401);
  assert.equal(res2.headers.get('content-type'), 'application/json');
  assert.equal(res2.body.errorCode, 'authentication_failed');
  assert.ok(!JSON.stringify(res2.body).includes('secret_token_value'));
  assert.equal(harness.getState().quotaState.reserves, 0, '401 must never consume quota');
});

await asyncTest('Scenario 3: /api/analyze returns sanitized JSON 403 when authorization or quota fails', async () => {
  for (const mode of ['email_unverified', 'exhausted', 'invalid_guest_token']) {
    const harness = setupRouteHarness({ quotaOutcomeMode: mode });
    const res = await harness.analyzeRoute.POST(makePostRequest('Verify this urgent banking notice'));
    assert.equal(res.status, 403);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.equal(res.headers.get('cache-control'), 'no-store, max-age=0');
    assert.ok(res.headers.get('x-aegis-correlation-id'));
    assert.ok(res.body.errorCode);
    assert.equal(res.headers.get('location'), null);
  }
});

await asyncTest('Scenario 4: /api/analyze does NOT redirect unauthenticated guest analysis requests to HTML pages', async () => {
  const harness = setupRouteHarness({ supabaseAuthUser: null });
  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  try {
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({
          choices: [{ message: { content: '{"riskLevel":"low","summary":"Routine hello message.","indicators":[]}' } }],
        });
      },
    });
    const res = await harness.analyzeRoute.POST(makePostRequest('Hello, how are you doing today?'));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.equal(res.headers.get('location'), null);
    assert.equal(harness.getState().vaultState.inserts, 0, 'Guest request skips Vault insert cleanly');
    assert.deepEqual(harness.getState().quotaState, { reserves: 1, commits: 1, refunds: 0 });
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

await asyncTest('Scenario 5: Edge middleware handles /api/analyze without redirect/HTML, preserves cookies, skips guest Edge auth, and survives stalled getUser()', async () => {
  const mockNextServer = createMockNextServer();
  const prevUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const prevKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://example.supabase.co';
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = 'anon-public-test-key';

  let getUserCalls = 0;
  let mode = 'refresh';

  const mwModule = loadTs('lib/supabase/middleware.ts', {
    'next/server': mockNextServer,
    '@supabase/ssr': {
      createServerClient: (_url, _key, cfg) => ({
        auth: {
          getUser: async () => {
            getUserCalls++;
            if (mode === 'refresh') {
              cfg.cookies.setAll([{ name: 'sb-access-token', value: 'refreshed-jwt', options: { path: '/' } }]);
              return { data: { user: { id: 'u-1' } }, error: null };
            }
            if (mode === 'throw') {
              throw new Error('Edge network error');
            }
            if (mode === 'hang') {
              return new Promise(() => {});
            }
            return { data: { user: null }, error: null };
          },
        },
      }),
    },
  });

  try {
    // 5a: Guest /api/analyze request skips Edge getUser() roundtrip completely
    const guestReq = {
      nextUrl: { pathname: '/api/analyze' },
      headers: new MockHeaders(),
      cookies: {
        getAll: () => [{ name: 'aegis_guest_token', value: 'guest.sig' }],
        set() {},
      },
    };
    const guestRes = await mwModule.updateSession(guestReq);
    assert.equal(guestRes.status, 200);
    assert.equal(guestRes.isNext, true);
    assert.equal(getUserCalls, 0, 'Guest /api/* requests must bypass Edge Supabase getUser()');
    assert.equal(guestRes.requestHeaders.get('x-aegis-middleware-outcome'), 'guest_passthrough');

    // 5b: Authenticated /api/analyze request refreshes SSR cookies without redirecting
    mode = 'refresh';
    const cookieJar = [{ name: 'sb-project-auth-token', value: 'old-token' }];
    const authReq = {
      nextUrl: { pathname: '/api/analyze' },
      headers: new MockHeaders(),
      cookies: {
        getAll: () => cookieJar,
        set(name, value) {
          cookieJar.push({ name, value });
        },
      },
    };
    const authRes = await mwModule.updateSession(authReq);
    assert.equal(authRes.status, 200);
    assert.equal(authRes.isNext, true);
    assert.equal(getUserCalls, 1);
    assert.equal(authRes.requestHeaders.get('x-aegis-middleware-outcome'), 'session_refreshed');
    assert.equal(authRes.cookies.setCalls[0].name, 'sb-access-token');

    // 5c: Stalled or throwing getUser() degrades cleanly to passthrough without HTML or 500
    mode = 'throw';
    const errRes = await mwModule.updateSession(authReq);
    assert.equal(errRes.status, 200);
    assert.equal(errRes.isNext, true);
    assert.equal(errRes.requestHeaders.get('x-aegis-middleware-outcome'), 'session_error_passthrough');

    mode = 'hang';
    const startMs = Date.now();
    const timeoutRes = await mwModule.updateSession(authReq);
    const elapsedMs = Date.now() - startMs;
    assert.equal(timeoutRes.status, 200);
    assert.equal(timeoutRes.isNext, true);
    assert.equal(timeoutRes.requestHeaders.get('x-aegis-middleware-outcome'), 'session_timeout_passthrough');
    assert.ok(elapsedMs < 3500, `Expected bounded middleware timeout < 3500ms, took ${elapsedMs}ms`);
  } finally {
    if (prevUrl === undefined) delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    else process.env.NEXT_PUBLIC_SUPABASE_URL = prevUrl;
    if (prevKey === undefined) delete process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
    else process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = prevKey;
  }
});

await asyncTest('Scenarios 6 & 14: Dual-provider failure returns sanitized JSON without secrets and refunds exactly once', async () => {
  const harness = setupRouteHarness({ geminiMode: 'fail' });
  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  try {
    globalThis.fetch = async () => ({
      ok: false,
      status: 503,
      async text() {
        return 'Upstream gateway error rc_' + 'z'.repeat(40);
      },
    });
    const res = await harness.analyzeRoute.POST(makePostRequest('Urgent account unlock required'));
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.equal(res.headers.get('cache-control'), 'no-store, max-age=0');
    assert.ok(res.headers.get('x-aegis-correlation-id'));
    const bodyStr = JSON.stringify(res.body);
    assert.ok(!bodyStr.includes('rc_'));
    assert.ok(!bodyStr.includes('AIzaSy'));
    assert.deepEqual(harness.getState().quotaState, { reserves: 1, commits: 0, refunds: 1 });
    assert.equal(harness.getState().vaultState.inserts, 0);
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

await asyncTest('Scenario 10: Client abort returns JSON 499 and refunds exactly once (no duplicate refunds)', async () => {
  const harness = setupRouteHarness({ geminiMode: 'slow' });
  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  try {
    const controller = new AbortController();
    globalThis.fetch = async () => ({ ok: false, status: 503, async text() { return 'Down'; } });
    setTimeout(() => controller.abort(), 30);
    const res = await harness.analyzeRoute.POST(
      makePostRequest('Suspicious wire instructions request', { signal: controller.signal })
    );
    assert.equal(res.status, 499);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.equal(res.body.errorCode, 'client_aborted');
    assert.deepEqual(harness.getState().quotaState, { reserves: 1, commits: 0, refunds: 1 });
    assert.equal(harness.getState().vaultState.inserts, 0);
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

await asyncTest('Scenarios 11 & 15: Valid Featherless skips Gemini, persists once to Vault, and commits quota once', async () => {
  const harness = setupRouteHarness();
  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  try {
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({
          choices: [{ message: { content: '{"riskLevel":"low","summary":"Ordinary note.","indicators":[]}' } }],
        });
      },
    });
    const res = await harness.analyzeRoute.POST(makePostRequest('See you at the sprint review at 2 PM.'));
    assert.equal(res.status, 200);
    assert.equal(harness.getState().geminiCalls, 0);
    assert.equal(harness.getState().vaultState.inserts, 1);
    assert.deepEqual(harness.getState().quotaState, { reserves: 1, commits: 1, refunds: 0 });
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

await asyncTest('Scenario 12: Featherless HTTP 429 triggers Gemini directly without repeated retries', async () => {
  const harness = setupRouteHarness();
  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  let fetchCalls = 0;
  try {
    globalThis.fetch = async () => {
      fetchCalls++;
      return { ok: false, status: 429, async text() { return 'rate limit exceeded'; } };
    };
    const res = await harness.analyzeRoute.POST(makePostRequest('Click here to unlock account'));
    assert.equal(res.status, 200);
    assert.equal(fetchCalls, 1);
    assert.equal(harness.getState().geminiCalls, 1);
    assert.deepEqual(harness.getState().quotaState, { reserves: 1, commits: 1, refunds: 0 });
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

await asyncTest('Scenario 13: Featherless TimeoutError triggers Gemini within remaining budget (>= 15000ms)', async () => {
  const harness = setupRouteHarness();
  const origKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);
  let fetchCalls = 0;
  try {
    globalThis.fetch = async () => {
      fetchCalls++;
      const err = new Error('Timed out');
      err.name = 'TimeoutError';
      throw err;
    };
    const res = await harness.analyzeRoute.POST(makePostRequest('Urgent payroll verification link'));
    assert.equal(res.status, 200);
    assert.equal(fetchCalls, 1);
    assert.equal(harness.getState().geminiCalls, 1);
    assert.ok(harness.getState().geminiCapturedTimeout >= 15000);
    assert.deepEqual(harness.getState().quotaState, { reserves: 1, commits: 1, refunds: 0 });
  } finally {
    globalThis.fetch = origFetch;
    if (origKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origKey;
  }
});

// ====================================================================
// Scenarios 7–9: Client Transport Handling & Sanitized Client Telemetry
// ====================================================================
console.log('\n--- Scenarios 7–9: Client Transport Classification & Safe Diagnostics ---');

test('Scenario 7: Client transport handles HTML HTTP 200 & opaqueredirect safely without leaking raw HTML, and MessageAnalyzer refreshes quota', () => {
  const html200 = transportHelper.classifyHttpTransportAnomaly({
    status: 200,
    type: 'basic',
    redirected: false,
    contentType: 'text/html; charset=utf-8',
    hasCorrelationId: false,
    bodyText: '<!DOCTYPE html><html><head><title>Login</title></head><body>Secret Portal Token XYZ</body></html>',
    url: 'https://aegisflowx.vercel.app/auth/login?token=secret-query-param',
  });
  assert.equal(html200.anomaly, true);
  assert.equal(html200.category, 'html_response');
  assert.equal(html200.errorCode, 'unexpected_html_response');
  assert.ok(!html200.message.includes('Secret Portal Token'));
  assert.ok(!html200.message.includes('<!DOCTYPE'));

  const opaqueRedirect = transportHelper.classifyHttpTransportAnomaly({
    status: 0,
    type: 'opaqueredirect',
    redirected: false,
    contentType: '',
    hasCorrelationId: false,
    bodyText: '',
  });
  assert.equal(opaqueRedirect.anomaly, true);
  assert.equal(opaqueRedirect.category, 'transport');
  assert.equal(opaqueRedirect.errorCode, 'unexpected_redirect');

  const gateway504 = transportHelper.classifyHttpTransportAnomaly({
    status: 504,
    contentType: 'text/html',
    bodyText: '<html>504 Gateway Time-out</html>',
  });
  assert.equal(gateway504.anomaly, true);
  assert.equal(gateway504.category, 'timeout');
  assert.equal(gateway504.errorCode, 'gateway_timeout_html');

  // Verify MessageAnalyzer.tsx source integrates redirect: 'manual', correlation header, and refreshQuota
  const analyzerSrc = fs.readFileSync(path.join(ROOT, 'components/MessageAnalyzer.tsx'), 'utf8');
  assert.ok(analyzerSrc.includes("redirect: 'manual'"), 'MessageAnalyzer must send redirect: manual');
  assert.ok(analyzerSrc.includes("'x-aegis-correlation-id'"), 'MessageAnalyzer must send x-aegis-correlation-id');
  assert.ok(analyzerSrc.includes('classifyHttpTransportAnomaly('), 'MessageAnalyzer must use classifyHttpTransportAnomaly');
  assert.ok(analyzerSrc.includes('refreshQuota()'), 'MessageAnalyzer must refresh quota on transport failures');
});

test('Scenario 8: Client transport handles TypeError Failed to fetch / offline & strips query params in safe logs', () => {
  const networkErr = transportHelper.classifyFetchException({
    err: new TypeError('Failed to fetch'),
    didClientTimeout: false,
    didUserCancel: false,
    isOnline: true,
  });
  assert.equal(networkErr.category, 'transport');
  assert.equal(networkErr.errorCode, 'network_fetch_failed');

  const offlineErr = transportHelper.classifyFetchException({
    err: new TypeError('Failed to fetch'),
    didClientTimeout: false,
    didUserCancel: false,
    isOnline: false,
  });
  assert.equal(offlineErr.category, 'transport');
  assert.equal(offlineErr.errorCode, 'offline_network_error');

  // Check URL sanitization and safe client transport log
  assert.equal(
    transportHelper.sanitizeUrlPathOnly('https://aegisflowx.vercel.app/api/analyze?token=abc#hash'),
    'https://aegisflowx.vercel.app/api/analyze'
  );

  const capturedLogs = [];
  const origWarn = console.warn;
  console.warn = (...args) => capturedLogs.push(args.join(' '));
  try {
    transportHelper.emitSafeClientTransportLog({
      correlationId: 'cli-test-log',
      status: 200,
      contentType: 'text/html; charset=utf-8',
      hasCorrelationId: false,
      redirected: true,
      url: 'https://aegisflowx.vercel.app/auth/login?secret=should_not_appear',
      durationMs: 123,
      category: 'html_response',
      errorCode: 'unexpected_html_response',
    });
  } finally {
    console.warn = origWarn;
  }
  assert.equal(capturedLogs.length, 1);
  assert.ok(!capturedLogs[0].includes('should_not_appear'));
  assert.ok(capturedLogs[0].includes('cli-test-log'));
});

test('Scenario 9: Client timeout is strictly distinguished from user cancellation and server JSON errors', () => {
  const abortErr = new Error('The user aborted a request.');
  abortErr.name = 'AbortError';

  const timeoutClassified = transportHelper.classifyFetchException({
    err: abortErr,
    didClientTimeout: true,
    didUserCancel: false,
  });
  assert.equal(timeoutClassified.category, 'timeout');
  assert.equal(timeoutClassified.errorCode, 'client_timeout');

  const cancelClassified = transportHelper.classifyFetchException({
    err: abortErr,
    didClientTimeout: false,
    didUserCancel: true,
  });
  assert.equal(cancelClassified.category, 'cancelled');
  assert.equal(cancelClassified.errorCode, 'user_cancelled');

  const badJson = transportHelper.parseAnalyzeJsonBody('{broken json', 'application/json', 200);
  assert.equal(badJson.ok, false);
  assert.equal(badJson.errorCode, 'invalid_json_response');
});

console.log(`\n========================================`);
console.log(`Results: ${passedTests} passed, ${totalTests - passedTests} failed`);
console.log(`========================================\n`);

if (totalTests - passedTests > 0) {
  process.exit(1);
}
