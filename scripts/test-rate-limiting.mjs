import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';

const require = createRequire(import.meta.url);

console.log('🧪 Starting AegisFlow Phase 2D — Distributed Rate Limiting & Abuse Protection Test Suite...\n');

let passedTests = 0;
let totalTests = 0;

async function test(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.stack || err.message}`);
  }
}

const repoRoot = process.cwd();

function compileTsModule(relativePath, extraRequire = {}) {
  const fullPath = path.join(repoRoot, relativePath);
  const source = fs.readFileSync(fullPath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
    },
    fileName: fullPath,
  });

  const mod = { exports: {} };
  const fn = new vm.Script(
    `(function(exports, require, module, __filename, __dirname) {\n${transpiled.outputText}\n})`,
    { filename: fullPath }
  ).runInThisContext();

  const localRequire = (specifier) => {
    if (specifier in extraRequire) return extraRequire[specifier];
    if (
      specifier === 'node:crypto' ||
      specifier === 'node:net' ||
      specifier === 'crypto' ||
      specifier === 'net'
    ) {
      return require(specifier);
    }
    throw new Error(`Unexpected require("${specifier}") in ${relativePath}`);
  };

  fn(mod.exports, localRequire, mod, fullPath, path.dirname(fullPath));
  return mod.exports;
}

// Compile shared dependencies
const modelConfig = compileTsModule('lib/model-config.ts');

// Mock next/server with mutable Headers support
function createNextServerMock() {
  class MockHeaders extends Map {
    get(key) {
      return super.get(String(key).toLowerCase()) ?? null;
    }
    set(key, value) {
      return super.set(String(key).toLowerCase(), String(value));
    }
    has(key) {
      return super.has(String(key).toLowerCase());
    }
  }

  return {
    NextResponse: {
      json(body, init = {}) {
        const headers = new MockHeaders();
        if (init.headers) {
          for (const [k, v] of Object.entries(init.headers)) {
            headers.set(k, v);
          }
        }
        return {
          status: init.status ?? 200,
          ok: (init.status ?? 200) >= 200 && (init.status ?? 200) < 300,
          headers,
          body,
          async json() {
            return body;
          },
        };
      },
    },
  };
}

const mockNextServer = createNextServerMock();

const routeHarness = {
  currentUserId: null,
  supabaseInserts: [],
  bodyReadCalls: 0,
  formReadCalls: 0,
  aiCalls: 0,
  factCheckCalls: 0,
  urlValidateCalls: 0,
  ssrfCalls: 0,
  urlInvestigateCalls: 0,
  pdfValidateCalls: 0,
  rateLimitBehavior: null,
};

function resetHarness() {
  routeHarness.currentUserId = null;
  routeHarness.supabaseInserts = [];
  routeHarness.bodyReadCalls = 0;
  routeHarness.formReadCalls = 0;
  routeHarness.aiCalls = 0;
  routeHarness.factCheckCalls = 0;
  routeHarness.urlValidateCalls = 0;
  routeHarness.ssrfCalls = 0;
  routeHarness.urlInvestigateCalls = 0;
  routeHarness.pdfValidateCalls = 0;
  routeHarness.rateLimitBehavior = null;
}

const mockSupabaseServer = {
  async createClient() {
    if (!routeHarness.currentUserId) return null;
    const uid = routeHarness.currentUserId;
    return {
      auth: {
        async getUser() {
          return { data: { user: { id: uid } }, error: null };
        },
      },
      from(table) {
        return {
          select() {
            const chain = {
              eq() {
                return chain;
              },
              gte() {
                return chain;
              },
              async limit() {
                return { data: [] };
              },
            };
            return chain;
          },
          async insert(payload) {
            routeHarness.supabaseInserts.push({ table, payload });
            return { error: null };
          },
        };
      },
    };
  },
};

const mockSupabaseJs = {
  createClient() {
    throw new Error('createClient from @supabase/supabase-js should be injected in unit tests');
  },
};

const rateLimitMod = compileTsModule('lib/rate-limit.ts', {
  '@supabase/supabase-js': mockSupabaseJs,
  'next/server': mockNextServer,
  '@/lib/supabase/server': mockSupabaseServer,
  '@/lib/model-config': modelConfig,
});

// Create an in-memory local store shared across route tests via wrapper around rateLimitMod
const sharedRouteTestStore = new Map();
const routeEnvOverride = {
  NODE_ENV: 'test',
  RATE_LIMIT_ANALYZE_GUEST_MAX: '3',
  RATE_LIMIT_ANALYZE_AUTH_MAX: '6',
  RATE_LIMIT_SCAN_DOCUMENT_GUEST_MAX: '2',
  RATE_LIMIT_SCAN_DOCUMENT_AUTH_MAX: '5',
  RATE_LIMIT_FACT_CHECK_GUEST_MAX: '2',
  RATE_LIMIT_FACT_CHECK_AUTH_MAX: '5',
  RATE_LIMIT_URL_INVESTIGATION_GUEST_MAX: '3',
  RATE_LIMIT_URL_INVESTIGATION_AUTH_MAX: '6',
  RATE_LIMIT_WINDOW_SECONDS: '60',
  RATE_LIMIT_HASH_SALT: 'phase2d-test-salt',
};

const rateLimitWrapperForRoutes = {
  async enforceApiRateLimit(req, endpoint) {
    if (routeHarness.rateLimitBehavior) {
      return routeHarness.rateLimitBehavior(req, endpoint);
    }
    return rateLimitMod.enforceApiRateLimit(req, endpoint, {
      env: routeEnvOverride,
      localStore: sharedRouteTestStore,
      getAuthenticatedUserId: async () => routeHarness.currentUserId,
    });
  },
  buildRateLimitErrorResponse: rateLimitMod.buildRateLimitErrorResponse,
  attachRateLimitHeaders: rateLimitMod.attachRateLimitHeaders,
};

// Route dependency mocks to verify zero expensive execution or DB inserts on rate-limit rejection
const mockScamAnalyzer = {
  extractIOCsFromMessage() {
    return {};
  },
  validateAnalysisPayload() {
    return { valid: true };
  },
};

const mockGeminiClient = {
  isGeminiFallbackEnabled() {
    return true;
  },
  isGeminiDocumentFallbackEnabled() {
    return true;
  },
};

const mockMessageAnalyzer = {
  async analyzeMessageWithGemini() {
    routeHarness.aiCalls++;
    return {
      modelUsed: 'gemini-mock',
      result: {
        riskLevel: 'low',
        severityScore: 15,
        summary: 'Benign test message.',
        indicators: [],
        recommendedActions: ['No urgent threat indicators found.'],
        limitations: [],
        evidenceSufficiency: 'sufficient',
        confidence: 0.9,
        confidenceRationale: 'Mock response',
        iocs: {},
        model: 'gemini-mock',
      },
    };
  },
};

const mockProviderOrchestrator = {
  classifyHttpError() {
    return 'unavailable';
  },
  isEligibleForFallback() {
    return true;
  },
  recordProviderMetric() {},
};

const mockDocumentScanner = {
  validateUploadedFileBuffer() {
    routeHarness.pdfValidateCalls++;
    return { valid: false, error: 'Mock invalid file', errorCode: 'INVALID_FILE' };
  },
  async extractTextFromPdf() {
    routeHarness.aiCalls++;
    return { text: '', pageCount: 0, isScannedOrEmpty: true };
  },
  validateDocumentScanPayload() {
    return { valid: true };
  },
};

const mockGeminiDocAnalyzer = {
  async analyzeDocumentWithGemini() {
    routeHarness.aiCalls++;
    throw new Error('Should not run when rejected');
  },
  GeminiDocumentFallbackError: class GeminiDocumentFallbackError extends Error {},
  classifyGeminiError() {
    return 'unknown';
  },
};

const mockFactChecker = {
  async generateFactCheckReport(text) {
    routeHarness.factCheckCalls++;
    return {
      executiveSummary: 'Mock verified claim.',
      threatSeverity: 'low',
      severityScore: 10,
      suspiciousIndicators: [],
      confidenceLevel: 'high',
      confidenceRationale: 'Mock check',
      evidenceSufficiency: 'sufficient',
      extractedClaims: [{ claimText: text, verdict: 'verified', rationale: 'Mock check' }],
      recommendations: { forIndividuals: ['Continue exercising standard caution.'] },
      sources: [],
      researchLimitations: [],
      searchProviderStatus: { researchStatus: 'not_required' },
    };
  },
};

const mockUrlInvestigator = {
  validateAndNormalizeUrl(rawUrl) {
    routeHarness.urlValidateCalls++;
    try {
      const parsedUrl = new URL(rawUrl);
      return { isValid: true, parsedUrl };
    } catch {
      return { isValid: false, error: 'Invalid URL' };
    }
  },
  async screenUrlForSsrf() {
    routeHarness.ssrfCalls++;
    return { safe: true };
  },
  async investigateUrl(rawUrl) {
    routeHarness.urlInvestigateCalls++;
    return {
      urlComponents: {
        rawUrl,
        normalizedUrl: rawUrl,
        displayUrl: rawUrl,
        hostname: 'example.org',
        domain: 'example.org',
      },
      overallSeverity: 'low',
      severityScore: 10,
      executiveSummary: 'Mock URL report.',
      indicators: [],
      recommendedActions: { forIndividuals: [], forSecurityTeams: [], forOrganizations: [] },
      evidenceLimitations: [],
      webEvidence: [],
      threatIntel: [],
      domainIntelligence: {},
      confidenceLevel: 'high',
      confidenceRationale: 'Mock check',
      modelUsed: 'mock-url',
    };
  },
};

const mockVaultNorm = {
  normalizeIndicators(ind) {
    return Array.isArray(ind) ? ind : [];
  },
};

// Compile all 4 real API routes
const analyzeRoute = compileTsModule('app/api/analyze/route.ts', {
  'next/server': mockNextServer,
  '@/lib/scam-analyzer': mockScamAnalyzer,
  '@/lib/supabase/server': mockSupabaseServer,
  '@/lib/model-config': modelConfig,
  '@/lib/gemini/client': mockGeminiClient,
  '@/lib/gemini/message-analyzer': mockMessageAnalyzer,
  '@/lib/provider-orchestrator': mockProviderOrchestrator,
  '@/lib/rate-limit': rateLimitWrapperForRoutes,
});

const scanDocRoute = compileTsModule('app/api/scan-document/route.ts', {
  'next/server': mockNextServer,
  '@/lib/document-scanner': mockDocumentScanner,
  '@/lib/scam-analyzer': mockScamAnalyzer,
  '@/lib/supabase/server': mockSupabaseServer,
  '@/lib/model-config': modelConfig,
  '@/lib/gemini/client': mockGeminiClient,
  '@/lib/gemini/document-analyzer': mockGeminiDocAnalyzer,
  '@/lib/provider-orchestrator': mockProviderOrchestrator,
  '@/lib/rate-limit': rateLimitWrapperForRoutes,
});

const factCheckRoute = compileTsModule('app/api/fact-check/route.ts', {
  'next/server': mockNextServer,
  '@/lib/fact-checker/fact-checker': mockFactChecker,
  '@/lib/supabase/server': mockSupabaseServer,
  '@/lib/model-config': modelConfig,
  '@/lib/rate-limit': rateLimitWrapperForRoutes,
});

const urlInvestigationRoute = compileTsModule('app/api/url-investigation/route.ts', {
  'next/server': mockNextServer,
  '@/lib/url-investigation/investigator': mockUrlInvestigator,
  '@/lib/supabase/server': mockSupabaseServer,
  '@/lib/model-config': modelConfig,
  '@/lib/vault-normalization': mockVaultNorm,
  '@/lib/rate-limit': rateLimitWrapperForRoutes,
});

function createMockRequest({
  headers = {},
  jsonBody = {},
  formDataError = false,
  ip = undefined,
} = {}) {
  const normalized = new Map();
  for (const [k, v] of Object.entries(headers)) {
    normalized.set(k.toLowerCase(), v);
  }
  return {
    ip,
    headers: {
      get(name) {
        return normalized.get(String(name).toLowerCase()) ?? null;
      },
    },
    async json() {
      routeHarness.bodyReadCalls++;
      return jsonBody;
    },
    async formData() {
      routeHarness.formReadCalls++;
      if (formDataError) throw new Error('Should not parse formData');
      return {
        get() {
          return null;
        },
      };
    },
  };
}

/**
 * Simulated atomic PostgreSQL RPC store matching supabase/migrations/0005_rate_limiting.sql semantics.
 */
function createSimulatedDistributedSupabaseClient({ shouldFail = false, throwException = false } = {}) {
  const rows = new Map();
  const rpcCalls = [];

  const client = {
    rows,
    rpcCalls,
    async rpc(fnName, params) {
      rpcCalls.push({ fnName, params });
      if (throwException) {
        throw new Error('connect ECONNREFUSED postgresql://service_role_secret@db.internal:5432');
      }
      if (shouldFail) {
        return { data: null, error: { message: 'relation "public.api_rate_limits" does not exist' } };
      }
      assert.equal(fnName, 'consume_rate_limit');
      const now = Date.now();
      const { p_rate_key, p_endpoint, p_scope, p_max_requests, p_window_seconds } = params;
      const limit = Math.max(1, Number(p_max_requests));
      const windowEndMs = now + Math.max(1, Number(p_window_seconds)) * 1000;

      const existing = rows.get(p_rate_key);
      let row;
      if (!existing || now >= existing.windowEndMs) {
        row = {
          rate_key: p_rate_key,
          endpoint: p_endpoint,
          scope: p_scope,
          request_count: 1,
          windowEndMs,
        };
      } else {
        row = {
          ...existing,
          request_count: Math.min(existing.request_count + 1, limit + 1),
        };
      }
      rows.set(p_rate_key, row);

      const allowed = row.request_count <= limit;
      const currentCount = Math.min(row.request_count, limit);
      const remaining = Math.max(0, limit - currentCount);
      const retryAfterSeconds = allowed
        ? 0
        : Math.max(1, Math.ceil((row.windowEndMs - now) / 1000));

      return {
        data: [
          {
            allowed,
            current_count: currentCount,
            remaining,
            retry_after_seconds: retryAfterSeconds,
            reset_at: new Date(row.windowEndMs).toISOString(),
          },
        ],
        error: null,
      };
    },
  };

  return client;
}

// =========================================================================
// TEST 1: Requests below limit succeed + attach rate-limit headers
// =========================================================================
await test('1. Requests below configured limits succeed and decrement X-RateLimit-Remaining', async () => {
  sharedRouteTestStore.clear();
  resetHarness();

  const req1 = createMockRequest({
    headers: { 'x-vercel-forwarded-for': '198.51.100.10' },
    jsonBody: { text: 'Please confirm this claim is verifiable.', context: '' },
  });
  const res1 = await factCheckRoute.POST(req1);
  assert.equal(res1.status, 200);
  assert.equal(res1.headers.get('X-RateLimit-Limit'), '2');
  assert.equal(res1.headers.get('X-RateLimit-Remaining'), '1');
  assert.equal(res1.headers.get('X-RateLimit-Scope'), 'guest');
  assert.equal(routeHarness.factCheckCalls, 1);

  const req2 = createMockRequest({
    headers: { 'x-vercel-forwarded-for': '198.51.100.10' },
    jsonBody: { text: 'Second claim under guest quota.', context: '' },
  });
  const res2 = await factCheckRoute.POST(req2);
  assert.equal(res2.status, 200);
  assert.equal(res2.headers.get('X-RateLimit-Remaining'), '0');
  assert.equal(routeHarness.factCheckCalls, 2);
});

// =========================================================================
// TEST 2: Exceeding limits returns 429 on ALL 4 public endpoints before expensive work
// =========================================================================
await test('2. Exceeding limit returns HTTP 429 on all 4 endpoints BEFORE body parsing, PDF OCR, SSRF, or AI calls', async () => {
  sharedRouteTestStore.clear();
  resetHarness();

  const guestHeaders = { 'x-vercel-forwarded-for': '198.51.100.22' };

  // /api/analyze (guestMax = 3)
  for (let i = 0; i < 3; i++) {
    const res = await analyzeRoute.POST(
      createMockRequest({ headers: guestHeaders, jsonBody: { message: 'Check this message' } })
    );
    assert.equal(res.status, 200);
  }
  const callsBeforeAnalyzeReject = { body: routeHarness.bodyReadCalls, ai: routeHarness.aiCalls };
  const blockedAnalyze = await analyzeRoute.POST(
    createMockRequest({ headers: guestHeaders, jsonBody: { message: '4th request should be blocked' } })
  );
  assert.equal(blockedAnalyze.status, 429);
  assert.equal(routeHarness.bodyReadCalls, callsBeforeAnalyzeReject.body, 'Must reject before reading JSON body');
  assert.equal(routeHarness.aiCalls, callsBeforeAnalyzeReject.ai, 'Must reject before calling AI provider');

  // /api/scan-document (guestMax = 2)
  for (let i = 0; i < 2; i++) {
    await scanDocRoute.POST(createMockRequest({ headers: guestHeaders }));
  }
  const callsBeforeScanReject = { form: routeHarness.formReadCalls, pdf: routeHarness.pdfValidateCalls, ai: routeHarness.aiCalls };
  const blockedScan = await scanDocRoute.POST(createMockRequest({ headers: guestHeaders, formDataError: true }));
  assert.equal(blockedScan.status, 429);
  assert.equal(routeHarness.formReadCalls, callsBeforeScanReject.form, 'Must reject before reading multipart formData');
  assert.equal(routeHarness.pdfValidateCalls, callsBeforeScanReject.pdf, 'Must reject before validating PDF buffer');
  assert.equal(routeHarness.aiCalls, callsBeforeScanReject.ai, 'Must reject before vision/document AI call');

  // /api/fact-check (guestMax = 2)
  for (let i = 0; i < 2; i++) {
    const res = await factCheckRoute.POST(
      createMockRequest({ headers: guestHeaders, jsonBody: { text: 'Valid claim' } })
    );
    assert.equal(res.status, 200);
  }
  const fcBefore = routeHarness.factCheckCalls;
  const blockedFc = await factCheckRoute.POST(
    createMockRequest({ headers: guestHeaders, jsonBody: { text: '3rd claim' } })
  );
  assert.equal(blockedFc.status, 429);
  assert.equal(routeHarness.factCheckCalls, fcBefore, 'Must reject before calling generateFactCheckReport');

  // /api/url-investigation (guestMax = 3)
  for (let i = 0; i < 3; i++) {
    const res = await urlInvestigationRoute.POST(
      createMockRequest({ headers: guestHeaders, jsonBody: { url: 'https://example.com' } })
    );
    assert.equal(res.status, 200);
  }
  const urlBefore = { val: routeHarness.urlValidateCalls, ssrf: routeHarness.ssrfCalls, inv: routeHarness.urlInvestigateCalls };
  const blockedUrl = await urlInvestigationRoute.POST(
    createMockRequest({ headers: guestHeaders, jsonBody: { url: 'https://example.com/4th' } })
  );
  assert.equal(blockedUrl.status, 429);
  assert.equal(routeHarness.urlValidateCalls, urlBefore.val, 'Must reject before URL validation');
  assert.equal(routeHarness.ssrfCalls, urlBefore.ssrf, 'Must reject before SSRF DNS checks');
  assert.equal(routeHarness.urlInvestigateCalls, urlBefore.inv, 'Must reject before URL investigation');
});

// =========================================================================
// TEST 3: Retry-After header, X-RateLimit headers & sanitized 429 payload
// =========================================================================
await test('3. 429 responses include valid Retry-After integer, rate-limit headers, and zero sensitive details', async () => {
  sharedRouteTestStore.clear();
  resetHarness();

  const sensitiveIp = '203.0.113.77';
  const sensitiveUserUuid = '11111111-2222-3333-4444-555555555555';
  routeHarness.currentUserId = sensitiveUserUuid;

  for (let i = 0; i < 5; i++) {
    const okRes = await factCheckRoute.POST(
      createMockRequest({
        headers: { 'x-vercel-forwarded-for': sensitiveIp },
        jsonBody: { text: 'Authenticated quota check' },
      })
    );
    assert.equal(okRes.status, 200);
  }

  const blocked = await factCheckRoute.POST(
    createMockRequest({
      headers: { 'x-vercel-forwarded-for': sensitiveIp },
      jsonBody: { text: 'SECRET_PAYLOAD_SHOULD_NEVER_ECHO' },
    })
  );
  assert.equal(blocked.status, 429);
  const retryAfter = Number.parseInt(blocked.headers.get('Retry-After'), 10);
  assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60, `Invalid Retry-After: ${retryAfter}`);
  assert.equal(blocked.headers.get('X-RateLimit-Remaining'), '0');
  assert.equal(blocked.headers.get('X-RateLimit-Scope'), 'user');

  const body = await blocked.json();
  const serialized = JSON.stringify(body);
  assert.equal(body.errorCode, 'rate_limit_exceeded');
  assert.equal(body.retryAfterSeconds, retryAfter);
  assert.ok(!serialized.includes(sensitiveIp), '429 body must not expose client IP');
  assert.ok(!serialized.includes(sensitiveUserUuid), '429 body must not expose user UUID');
  assert.ok(!serialized.includes('SECRET_PAYLOAD_SHOULD_NEVER_ECHO'), '429 body must not echo input content');
  assert.ok(!serialized.includes('SUPABASE_SERVICE_ROLE_KEY'), '429 body must not expose secret references');
});

// =========================================================================
// TEST 4: Authenticated user isolation vs guest and other authenticated users
// =========================================================================
await test('4. Authenticated users get isolated per-user higher limits unaffected by shared IPs or spoofed headers', async () => {
  const localStore = new Map();
  const sharedIp = '198.51.100.88';
  const env = {
    NODE_ENV: 'test',
    RATE_LIMIT_ANALYZE_GUEST_MAX: '2',
    RATE_LIMIT_ANALYZE_AUTH_MAX: '4',
    RATE_LIMIT_WINDOW_SECONDS: '60',
  };

  // Exhaust guest bucket at sharedIp
  for (let i = 0; i < 2; i++) {
    const out = await rateLimitMod.enforceApiRateLimit(
      createMockRequest({ headers: { 'x-vercel-forwarded-for': sharedIp } }),
      'analyze',
      { env, localStore, getAuthenticatedUserId: async () => null }
    );
    assert.equal(out.allowed, true);
  }
  const blockedGuest = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': sharedIp } }),
    'analyze',
    { env, localStore, getAuthenticatedUserId: async () => null }
  );
  assert.equal(blockedGuest.allowed, false);
  assert.equal(blockedGuest.scope, 'guest');

  // Authenticated User A behind the SAME IP still has full auth quota (4 requests), even if IP header changes
  for (let i = 0; i < 4; i++) {
    const outA = await rateLimitMod.enforceApiRateLimit(
      createMockRequest({ headers: { 'x-vercel-forwarded-for': i % 2 === 0 ? sharedIp : '203.0.113.99' } }),
      'analyze',
      { env, localStore, getAuthenticatedUserId: async () => 'user-alice-001' }
    );
    assert.equal(outA.allowed, true);
    assert.equal(outA.scope, 'authenticated');
    assert.equal(outA.limit, 4);
  }
  const blockedAlice = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '203.0.113.199' } }),
    'analyze',
    { env, localStore, getAuthenticatedUserId: async () => 'user-alice-001' }
  );
  assert.equal(blockedAlice.allowed, false);

  // Authenticated User B remains completely unaffected by Alice's exhaustion
  const userBOut = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': sharedIp } }),
    'analyze',
    { env, localStore, getAuthenticatedUserId: async () => 'user-bob-002' }
  );
  assert.equal(userBOut.allowed, true);
  assert.equal(userBOut.remaining, 3);
});

// =========================================================================
// TEST 5: Header spoofing & guest IP hardening
// =========================================================================
await test('5. Spoofed leftmost x-forwarded-for, x-client-ip, true-client-ip, and User-Agent cannot bypass guest quotas', async () => {
  const localStore = new Map();
  const env = {
    NODE_ENV: 'test',
    RATE_LIMIT_URL_INVESTIGATION_GUEST_MAX: '2',
    RATE_LIMIT_WINDOW_SECONDS: '60',
  };

  // Scenario A: Edge sets x-vercel-forwarded-for; attacker rotates spoofed x-forwarded-for & x-client-ip & UA
  const attackerVectors = [
    {
      'x-vercel-forwarded-for': '198.51.100.42',
      'x-forwarded-for': '10.0.0.1',
      'x-client-ip': '172.16.0.5',
      'true-client-ip': '1.2.3.4',
      'user-agent': 'Bot/1.0',
    },
    {
      'x-vercel-forwarded-for': '198.51.100.42',
      'x-forwarded-for': '9.9.9.9, 8.8.8.8',
      'x-client-ip': '172.16.0.6',
      'true-client-ip': '5.6.7.8',
      'user-agent': 'Bot/2.0',
    },
    {
      'x-vercel-forwarded-for': '198.51.100.42',
      'x-forwarded-for': 'invalid-spoofed-value',
      'x-client-ip': '172.16.0.7',
      'true-client-ip': '9.9.9.9',
      'user-agent': 'Bot/3.0',
    },
  ];

  const r1 = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: attackerVectors[0] }),
    'url_investigation',
    { env, localStore, getAuthenticatedUserId: async () => null }
  );
  const r2 = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: attackerVectors[1] }),
    'url_investigation',
    { env, localStore, getAuthenticatedUserId: async () => null }
  );
  const r3 = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: attackerVectors[2] }),
    'url_investigation',
    { env, localStore, getAuthenticatedUserId: async () => null }
  );

  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.equal(r3.allowed, false, 'Attacker rotating spoofed headers behind edge IP must still hit 429');
  assert.equal(r1.rateKey, r3.rateKey);

  // Scenario B: Multi-hop x-forwarded-for uses RIGHTMOST valid IP (outer proxy), ignoring leftmost spoof
  const rightMostId = rateLimitMod.extractTrustedClientNetworkId(
    createMockRequest({ headers: { 'x-forwarded-for': '1.1.1.1, garbage, 203.0.113.55' } })
  );
  assert.equal(rightMostId, 'ip:203.0.113.55');

  // Scenario C: Missing or malformed IPs collapse to single deterministic fallback token
  const malformedId1 = rateLimitMod.extractTrustedClientNetworkId(
    createMockRequest({ headers: { 'x-forwarded-for': 'spoofed-text-value' } })
  );
  const malformedId2 = rateLimitMod.extractTrustedClientNetworkId(createMockRequest({ headers: {} }));
  assert.equal(malformedId1, 'ip:untrusted-or-loopback');
  assert.equal(malformedId2, 'ip:untrusted-or-loopback');
});

// =========================================================================
// TEST 6: Concurrent requests burst test (atomic enforcement without race overruns)
// =========================================================================
await test('6. Concurrent request burst enforces exact limit without race-condition bypass', async () => {
  const localStore = new Map();
  const distributedClient = createSimulatedDistributedSupabaseClient();
  const env = {
    NODE_ENV: 'production',
    RATE_LIMIT_SCAN_DOCUMENT_GUEST_MAX: '5',
    RATE_LIMIT_WINDOW_SECONDS: '60',
  };

  // Burst 20 concurrent requests through simulated distributed atomic PostgreSQL RPC
  const burstPromises = Array.from({ length: 20 }, () =>
    rateLimitMod.enforceApiRateLimit(
      createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.77' } }),
      'scan_document',
      {
        env,
        localStore,
        serviceClient: distributedClient,
        getAuthenticatedUserId: async () => null,
      }
    )
  );

  const outcomes = await Promise.all(burstPromises);
  const allowedCount = outcomes.filter((o) => o.allowed).length;
  const blockedCount = outcomes.filter((o) => !o.allowed && o.status === 429).length;

  assert.equal(allowedCount, 5, 'Exactly guestMax=5 requests must be allowed in burst');
  assert.equal(blockedCount, 15, 'Remaining 15 concurrent requests must return 429');
});

// =========================================================================
// TEST 7: Distributed Supabase RPC multi-instance test + SQL migration security assertions
// =========================================================================
await test('7. Distributed Supabase RPC shares quotas across separate serverless instances and SQL migration enforces strict RLS', async () => {
  // Verify SQL migration invariants
  const sql = fs.readFileSync(path.join(repoRoot, 'supabase/migrations/0005_rate_limiting.sql'), 'utf8').toLowerCase();
  assert.ok(sql.includes('create table if not exists public.api_rate_limits'));
  assert.ok(sql.includes('alter table public.api_rate_limits enable row level security'));
  assert.ok(sql.includes('revoke all on table public.api_rate_limits from anon'));
  assert.ok(sql.includes('revoke all on table public.api_rate_limits from authenticated'));
  assert.ok(sql.includes('grant select, insert, update, delete on table public.api_rate_limits to service_role'));
  assert.ok(sql.includes('revoke all on function public.consume_rate_limit'));
  assert.ok(sql.includes('grant execute on function public.consume_rate_limit'));
  assert.ok(sql.includes('to service_role'));
  assert.ok(sql.includes('security definer'));
  assert.ok(sql.includes('set search_path = public'));
  assert.ok(sql.includes('least(rl.request_count + 1, v_limit + 1)'));

  // Two isolated serverless instances (different in-memory Maps) sharing one Supabase RPC backend
  const instanceAStore = new Map();
  const instanceBStore = new Map();
  const distributedClient = createSimulatedDistributedSupabaseClient();
  const env = {
    NODE_ENV: 'production',
    RATE_LIMIT_ANALYZE_GUEST_MAX: '3',
    RATE_LIMIT_WINDOW_SECONDS: '60',
  };
  const clientReq = () => createMockRequest({ headers: { 'x-vercel-forwarded-for': '203.0.113.150' } });

  const instA1 = await rateLimitMod.enforceApiRateLimit(clientReq(), 'analyze', {
    env,
    localStore: instanceAStore,
    serviceClient: distributedClient,
    getAuthenticatedUserId: async () => null,
  });
  const instB2 = await rateLimitMod.enforceApiRateLimit(clientReq(), 'analyze', {
    env,
    localStore: instanceBStore,
    serviceClient: distributedClient,
    getAuthenticatedUserId: async () => null,
  });
  const instA3 = await rateLimitMod.enforceApiRateLimit(clientReq(), 'analyze', {
    env,
    localStore: instanceAStore,
    serviceClient: distributedClient,
    getAuthenticatedUserId: async () => null,
  });
  const instB4 = await rateLimitMod.enforceApiRateLimit(clientReq(), 'analyze', {
    env,
    localStore: instanceBStore,
    serviceClient: distributedClient,
    getAuthenticatedUserId: async () => null,
  });

  assert.equal(instA1.allowed, true);
  assert.equal(instA1.mode, 'distributed_supabase');
  assert.equal(instA1.remaining, 2);
  assert.equal(instB2.allowed, true);
  assert.equal(instB2.remaining, 1);
  assert.equal(instA3.allowed, true);
  assert.equal(instA3.remaining, 0);
  assert.equal(instB4.allowed, false);
  assert.equal(instB4.status, 429);
  assert.equal(instB4.mode, 'distributed_supabase');
});

// =========================================================================
// TEST 8: Distributed limiter unavailability behavior (fail_closed default & degraded_local explicit)
// =========================================================================
await test('8. Limiter unavailability fails closed (503) by default in production and enforces halved cap under explicit degraded_local', async () => {
  resetHarness();

  // Case A: Default fail_closed when RPC fails in production
  const failingClient = createSimulatedDistributedSupabaseClient({ shouldFail: true });
  const failClosedOutcome = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.123' } }),
    'fact_check',
    {
      env: { NODE_ENV: 'production', RATE_LIMIT_FACT_CHECK_GUEST_MAX: '10' },
      localStore: new Map(),
      serviceClient: failingClient,
      getAuthenticatedUserId: async () => null,
    }
  );
  assert.equal(failClosedOutcome.allowed, false, 'Must NEVER silently allow unprotected expensive requests');
  assert.equal(failClosedOutcome.status, 503);
  assert.equal(failClosedOutcome.mode, 'fail_closed');
  assert.equal(failClosedOutcome.unavailable, true);
  assert.equal(failClosedOutcome.errorCode, 'rate_limiter_unavailable');

  // Route-level check when limiter returns fail_closed 503 -> returns 503 + Retry-After, zero AI/DB side effects
  routeHarness.rateLimitBehavior = async () => failClosedOutcome;
  const routeRes = await analyzeRoute.POST(
    createMockRequest({ jsonBody: { message: 'Should fail closed before AI' } })
  );
  assert.equal(routeRes.status, 503);
  assert.ok(Number.parseInt(routeRes.headers.get('Retry-After'), 10) >= 1);
  assert.equal(routeHarness.aiCalls, 0);
  assert.equal(routeHarness.bodyReadCalls, 0);
  assert.equal(routeHarness.supabaseInserts.length, 0);

  // Case B: RPC throws exception containing DB URI -> must be caught, redacted, and fail closed
  const throwingClient = createSimulatedDistributedSupabaseClient({ throwException: true });
  const thrownOutcome = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.124' } }),
    'analyze',
    {
      env: { NODE_ENV: 'production' },
      localStore: new Map(),
      serviceClient: throwingClient,
      getAuthenticatedUserId: async () => null,
    }
  );
  assert.equal(thrownOutcome.allowed, false);
  assert.equal(thrownOutcome.status, 503);
  const errRes = rateLimitMod.buildRateLimitErrorResponse(thrownOutcome);
  const errJson = await errRes.json();
  assert.ok(!JSON.stringify(errJson).includes('service_role_secret'));

  // Case C: Explicit RATE_LIMIT_FAILURE_POLICY=degraded_local enforces halved local cap (floor(10/2) = 5)
  const degradedStore = new Map();
  const degradedEnv = {
    NODE_ENV: 'production',
    RATE_LIMIT_FACT_CHECK_GUEST_MAX: '10',
    RATE_LIMIT_FAILURE_POLICY: 'degraded_local',
  };
  for (let i = 0; i < 5; i++) {
    const okDegraded = await rateLimitMod.enforceApiRateLimit(
      createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.200' } }),
      'fact_check',
      {
        env: degradedEnv,
        localStore: degradedStore,
        serviceClient: failingClient,
        getAuthenticatedUserId: async () => null,
      }
    );
    assert.equal(okDegraded.allowed, true);
    assert.equal(okDegraded.mode, 'degraded_local');
    assert.equal(okDegraded.limit, 5);
  }
  const cappedDegraded = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.200' } }),
    'fact_check',
    {
      env: degradedEnv,
      localStore: degradedStore,
      serviceClient: failingClient,
      getAuthenticatedUserId: async () => null,
    }
  );
  assert.equal(cappedDegraded.allowed, false);
  assert.equal(cappedDegraded.status, 429);
  assert.equal(cappedDegraded.mode, 'degraded_local');
});

// =========================================================================
// TEST 9: Privacy & investigation history non-pollution
// =========================================================================
await test('9. Rate keys are SHA-256 hashes (no raw IPs/UUIDs stored) and rejected requests never pollute analysis_history', async () => {
  sharedRouteTestStore.clear();
  resetHarness();

  const rawIp = '203.0.113.211';
  const rawUid = '99999999-8888-7777-6666-555555555555';
  const distributedClient = createSimulatedDistributedSupabaseClient();

  const guestOut = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': rawIp } }),
    'analyze',
    {
      env: { NODE_ENV: 'production', RATE_LIMIT_HASH_SALT: 'privacy-salt' },
      localStore: new Map(),
      serviceClient: distributedClient,
      getAuthenticatedUserId: async () => null,
    }
  );
  const userOut = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': rawIp } }),
    'analyze',
    {
      env: { NODE_ENV: 'production', RATE_LIMIT_HASH_SALT: 'privacy-salt' },
      localStore: new Map(),
      serviceClient: distributedClient,
      getAuthenticatedUserId: async () => rawUid,
    }
  );

  assert.ok(!guestOut.rateKey.includes(rawIp), 'Guest rate_key must never store raw IP');
  assert.ok(!userOut.rateKey.includes(rawUid), 'Auth rate_key must never store raw user UUID');
  assert.match(guestOut.rateKey, /^analyze:guest:[a-f0-9]{64}$/);
  assert.match(userOut.rateKey, /^analyze:authenticated:[a-f0-9]{64}$/);

  const storedKeys = Array.from(distributedClient.rows.keys());
  assert.equal(storedKeys.length, 2);
  for (const key of storedKeys) {
    assert.ok(!key.includes(rawIp) && !key.includes(rawUid));
  }

  // Rejected authenticated requests must never write to analysis_history
  routeHarness.currentUserId = rawUid;
  for (let i = 0; i < 6; i++) {
    const res = await analyzeRoute.POST(
      createMockRequest({
        headers: { 'x-vercel-forwarded-for': rawIp },
        jsonBody: { message: `Allowed message #${i + 1}` },
      })
    );
    assert.equal(res.status, 200);
  }
  const insertsAfterAllowed = routeHarness.supabaseInserts.length;
  assert.equal(insertsAfterAllowed, 6);

  const rejectedRes = await analyzeRoute.POST(
    createMockRequest({
      headers: { 'x-vercel-forwarded-for': rawIp },
      jsonBody: { message: '7th message must NOT pollute analysis_history' },
    })
  );
  assert.equal(rejectedRes.status, 429);
  assert.equal(
    routeHarness.supabaseInserts.length,
    insertsAfterAllowed,
    'Rejected 429 requests must never insert into analysis_history'
  );
});

// =========================================================================
// TEST 10: Independent per-endpoint buckets & clean existing response shapes
// =========================================================================
await test('10. Quotas are isolated per endpoint so exhausting one does not block unrelated tools', async () => {
  sharedRouteTestStore.clear();
  resetHarness();

  const headers = { 'x-vercel-forwarded-for': '198.51.100.250' };

  // Exhaust fact-check quota (guestMax=2)
  await factCheckRoute.POST(createMockRequest({ headers, jsonBody: { text: 'Claim 1' } }));
  await factCheckRoute.POST(createMockRequest({ headers, jsonBody: { text: 'Claim 2' } }));
  const blockedFc = await factCheckRoute.POST(createMockRequest({ headers, jsonBody: { text: 'Claim 3' } }));
  assert.equal(blockedFc.status, 429);

  // /api/analyze and /api/url-investigation remain available for the same guest
  const analyzeOk = await analyzeRoute.POST(createMockRequest({ headers, jsonBody: { message: 'Urgent bank message' } }));
  assert.equal(analyzeOk.status, 200);
  const analyzeBody = await analyzeOk.json();
  assert.equal(analyzeBody.riskLevel, 'low');

  const urlOk = await urlInvestigationRoute.POST(createMockRequest({ headers, jsonBody: { url: 'https://example.org' } }));
  assert.equal(urlOk.status, 200);
  const urlBody = await urlOk.json();
  assert.equal(urlBody.report.urlComponents.normalizedUrl, 'https://example.org');
});

// =========================================================================
// TEST 11: Bounded timeout + transient-only retry + fail-fast on config/migration errors
// =========================================================================
await test('11. RPC timeout & transient error use bounded retry (max 2 attempts), while missing migration fails fast in 1 attempt', async () => {
  // Case A: Non-retryable missing migration (42P01) -> fails fast in 1 attempt without retrying
  let nonRetryableCalls = 0;
  const missingMigrationClient = {
    async rpc() {
      nonRetryableCalls++;
      return {
        data: null,
        error: { code: '42P01', message: 'relation "public.api_rate_limits" does not exist' },
      };
    },
  };
  const outMissing = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.31' } }),
    'analyze',
    {
      env: { NODE_ENV: 'production' },
      serviceClient: missingMigrationClient,
      getAuthenticatedUserId: async () => null,
      sleep: async () => {},
    }
  );
  assert.equal(outMissing.status, 503);
  assert.equal(outMissing.errorCode, 'rate_limiter_unavailable');
  assert.equal(nonRetryableCalls, 1, 'Missing migration/table error must NOT trigger retry loop');

  // Case B: Transient error on attempt 1 -> single bounded retry succeeds on attempt 2
  let transientCalls = 0;
  const recoveringClient = {
    async rpc() {
      transientCalls++;
      if (transientCalls === 1) {
        throw new Error('connect ECONNRESET');
      }
      return {
        data: [{ allowed: true, current_count: 1, remaining: 11, retry_after_seconds: 0, reset_at: new Date(Date.now() + 60000).toISOString() }],
        error: null,
      };
    },
  };
  const outRecovered = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.32' } }),
    'analyze',
    {
      env: { NODE_ENV: 'production' },
      serviceClient: recoveringClient,
      getAuthenticatedUserId: async () => null,
      sleep: async () => {},
    }
  );
  assert.equal(outRecovered.allowed, true);
  assert.equal(outRecovered.status, 200);
  assert.equal(outRecovered.mode, 'distributed_supabase');
  assert.equal(transientCalls, 2, 'Transient failure should retry exactly once and recover');

  // Case C: Hanging RPC times out cleanly -> bounded retries exhausted -> fail_closed 503
  let timeoutCalls = 0;
  const hangingClient = {
    rpc() {
      timeoutCalls++;
      return new Promise(() => {});
    },
  };
  const outTimedOut = await rateLimitMod.enforceApiRateLimit(
    createMockRequest({ headers: { 'x-vercel-forwarded-for': '198.51.100.33' } }),
    'analyze',
    {
      env: { NODE_ENV: 'production' },
      serviceClient: hangingClient,
      getAuthenticatedUserId: async () => null,
      rpcTimeoutMs: 60,
      maxRpcAttempts: 2,
      sleep: async () => {},
    }
  );
  assert.equal(outTimedOut.allowed, false);
  assert.equal(outTimedOut.status, 503);
  assert.equal(outTimedOut.errorCode, 'rate_limiter_unavailable');
  assert.equal(timeoutCalls, 2, 'Hanging RPC must respect bounded maxRpcAttempts=2 and fail closed');
});

// =========================================================================
// TEST 12: Health probe & DocumentScanner rate-limit vs AI error distinction
// =========================================================================
await test('12. Admin rate-limiter probe classifies config/migration/operational states and UI distinguishes rate-limiter vs AI errors', async () => {
  const missingCfg = await rateLimitMod.probeRateLimiterHealth({ NODE_ENV: 'production' }, null);
  assert.equal(missingCfg.status, 'missing_configuration');
  assert.equal(missingCfg.configured, false);

  const missingMigClient = {
    from() {
      return {
        select: async () => ({ error: { code: '42P01', message: 'relation "public.api_rate_limits" does not exist' } }),
      };
    },
  };
  const missingMig = await rateLimitMod.probeRateLimiterHealth({ NODE_ENV: 'production' }, missingMigClient);
  assert.equal(missingMig.status, 'missing_migration');

  const okClient = {
    from() {
      return {
        select: async () => ({ error: null }),
      };
    },
  };
  const operational = await rateLimitMod.probeRateLimiterHealth({ NODE_ENV: 'production' }, okClient);
  assert.equal(operational.status, 'operational');
  assert.equal(operational.mode, 'distributed_supabase');

  // Verify DocumentScanner error formatter distinguishes rate_limiter_unavailable & rate_limit_exceeded from AI engines
  const realScamAnalyzer = compileTsModule('lib/scam-analyzer.ts', {});
  const realDocScanner = compileTsModule('lib/document-scanner.ts', {
    path,
    '@/lib/scam-analyzer': realScamAnalyzer,
  });
  const rlUnavailableNotice = realDocScanner.formatDocumentScanErrorNotice(
    'rate_limiter_unavailable',
    'Rate-limiting protection service is temporarily unavailable.',
    503
  );
  assert.equal(rlUnavailableNotice.categoryTitle, 'Rate-Limit Protection Unavailable');
  assert.ok(!/AI Analysis Engines/i.test(rlUnavailableNotice.categoryTitle));

  const rlExceededNotice = realDocScanner.formatDocumentScanErrorNotice(
    'rate_limit_exceeded',
    'Request limit reached.',
    429
  );
  assert.equal(rlExceededNotice.categoryTitle, 'Request Quota Reached');
});

console.log(`\n📊 Phase 2D Rate Limiting Results: ${passedTests}/${totalTests} passed`);
if (passedTests !== totalTests) {
  process.exit(1);
}
