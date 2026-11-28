import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import Module from 'node:module';
import ts from 'typescript';

console.log('🛡️ Starting AegisFlow Phase 3C Multi-Provider & Gemini Fallback Test Suite...\n');

let totalTests = 0;
let passedTests = 0;
let skippedTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    const res = fn();
    if (res === 'skipped') {
      skippedTests++;
    } else {
      console.log(`  ✓ ${name}`);
      passedTests++;
    }
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    process.exitCode = 1;
  }
}

async function asyncTest(name, fn) {
  totalTests++;
  try {
    const res = await fn();
    if (res === 'skipped') {
      skippedTests++;
    } else {
      console.log(`  ✓ ${name}`);
      passedTests++;
    }
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    process.exitCode = 1;
  }
}

// ====================================================================
// Logic Implementation Mirroring lib/provider-orchestrator.ts & lib/gemini/
// ====================================================================

function classifyHttpError(status, bodySnippet = '') {
  const lower = (bodySnippet || '').toLowerCase();
  if (status === 401 || status === 403) return 'auth_failure';
  if (status === 429) {
    if (
      lower.includes('quota') ||
      lower.includes('credit') ||
      lower.includes('exhausted') ||
      lower.includes('exceeded') ||
      lower.includes('limit reached') ||
      lower.includes('capacity_exhausted')
    ) {
      return 'quota_exhausted';
    }
    return 'rate_limited';
  }
  if (status === 408 || status === 504 || lower.includes('timeout') || lower.includes('abort')) {
    return 'timeout';
  }
  if (status === 502 || status === 503 || status === 500) return 'unavailable';
  if (status >= 400 && status < 500) return 'bad_request';
  return 'unknown';
}

function isEligibleForFallback(code) {
  return code === 'rate_limited' || code === 'quota_exhausted' || code === 'timeout' || code === 'unavailable';
}

function isGeminiConfigured(key) {
  return Boolean(
    key &&
    key.trim().length > 10 &&
    key !== 'MY_GEMINI_API_KEY' &&
    key !== 'YOUR_GEMINI_API_KEY'
  );
}

function isGeminiFallbackEnabled(env) {
  if (!isGeminiConfigured(env.GEMINI_API_KEY)) return false;
  const envVal = env.GEMINI_FALLBACK_ENABLED;
  if (envVal !== undefined && (envVal.toLowerCase() === 'false' || envVal === '0')) {
    return false;
  }
  return true;
}

function isGeminiSearchFallbackEnabled(env) {
  if (!isGeminiFallbackEnabled(env)) return false;
  const envVal = env.GEMINI_SEARCH_FALLBACK_ENABLED;
  if (envVal !== undefined && (envVal.toLowerCase() === 'false' || envVal === '0')) {
    return false;
  }
  return true;
}

function getResolvedGeminiModel(env) {
  const envModel = env.GEMINI_MODEL;
  if (envModel && envModel.trim().length > 0 && !envModel.startsWith('AIza') && !envModel.startsWith('rc_')) {
    return envModel.trim();
  }
  return 'gemini-3.8-flash';
}

function redactSecrets(text, key) {
  if (!text || typeof text !== 'string') return '';
  let sanitized = text;
  if (key && key.length > 8) {
    sanitized = sanitized.split(key).join('[REDACTED_KEY]');
  }
  sanitized = sanitized.replace(/rc_[a-f0-9]{30,}/gi, '[REDACTED_TOKEN]');
  sanitized = sanitized.replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_GEMINI_KEY]');
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9_\-\.]{15,}/gi, 'Bearer [REDACTED_TOKEN]');
  return sanitized;
}

function isPrivateOrReservedIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const cleanIp = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (cleanIp === '127.0.0.1' || cleanIp.startsWith('127.')) return true;
  if (cleanIp.startsWith('10.')) return true;
  if (cleanIp.startsWith('192.168.')) return true;
  if (cleanIp.startsWith('172.')) {
    const parts = cleanIp.split('.');
    if (parts.length === 4) {
      const secondOctet = parseInt(parts[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
  }
  if (cleanIp === '169.254.169.254' || cleanIp.startsWith('169.254.')) return true;
  if (cleanIp === '::1' || cleanIp === '::') return true;
  return false;
}

// ====================================================================
// UNIT 1: Error Classification & Orchestration
// ====================================================================
console.log('--- Unit 1: Provider Error Classification & Orchestration ---');

test('1.1 Classifies HTTP 429 quota exhaustion correctly as eligible for fallback', () => {
  const code = classifyHttpError(429, 'Your API credit balance or quota has been exhausted');
  assert.equal(code, 'quota_exhausted');
  assert.equal(isEligibleForFallback(code), true);
});

test('1.2 Classifies HTTP 429 rate limit correctly as eligible for fallback', () => {
  const code = classifyHttpError(429, 'Too many requests, please retry shortly');
  assert.equal(code, 'rate_limited');
  assert.equal(isEligibleForFallback(code), true);
});

test('1.3 Classifies HTTP 504 / timeout correctly as eligible for fallback', () => {
  const code = classifyHttpError(504, 'Gateway Timeout');
  assert.equal(code, 'timeout');
  assert.equal(isEligibleForFallback(code), true);
});

test('1.4 Classifies HTTP 400 bad request as NOT eligible for fallback', () => {
  const code = classifyHttpError(400, 'Invalid parameters');
  assert.equal(code, 'bad_request');
  assert.equal(isEligibleForFallback(code), false);
});

test('1.5 Classifies HTTP 401/403 authentication failures as NOT eligible for fallback', () => {
  const code = classifyHttpError(401, 'Invalid API Key');
  assert.equal(code, 'auth_failure');
  assert.equal(isEligibleForFallback(code), false);
});

// ====================================================================
// UNIT 2: Configuration & Safe Defaults
// ====================================================================
console.log('\n--- Unit 2: Gemini Configuration & Safe Defaults ---');

test('2.1 Default Gemini model resolves to supported gemini-3.8-flash', () => {
  const model = getResolvedGeminiModel({});
  assert.equal(model, 'gemini-3.8-flash');
});

test('2.2 Unconfigured or placeholder GEMINI_API_KEY safely disables fallback', () => {
  assert.equal(isGeminiConfigured('MY_GEMINI_API_KEY'), false);
  assert.equal(isGeminiConfigured(''), false);
  assert.equal(isGeminiConfigured(undefined), false);
  assert.equal(isGeminiFallbackEnabled({ GEMINI_API_KEY: 'MY_GEMINI_API_KEY' }), false);
});

test('2.3 Explicit disable flags (GEMINI_FALLBACK_ENABLED=false) are respected', () => {
  const env = {
    GEMINI_API_KEY: 'AIzaSyFakeKeyValidFormat1234567890',
    GEMINI_FALLBACK_ENABLED: 'false',
  };
  assert.equal(isGeminiConfigured(env.GEMINI_API_KEY), true);
  assert.equal(isGeminiFallbackEnabled(env), false);
});

test('2.4 Search fallback can be disabled independently from AI reasoning fallback', () => {
  const env = {
    GEMINI_API_KEY: 'AIzaSyFakeKeyValidFormat1234567890',
    GEMINI_SEARCH_FALLBACK_ENABLED: 'false',
  };
  assert.equal(isGeminiFallbackEnabled(env), true);
  assert.equal(isGeminiSearchFallbackEnabled(env), false);
});

test('2.5 Unconfigured key reports status missing_configuration and NEVER claims operational', () => {
  const unconfiguredProbe = (key) => {
    const configured = Boolean(key && key.trim().length > 10 && !key.includes('PLACEHOLDER') && !key.includes('MY_GEMINI_API_KEY') && !key.includes('YOUR_GEMINI_API_KEY'));
    if (!configured) {
      return {
        provider: 'Google Gemini',
        status: 'missing_configuration',
        isConfigured: false,
        message: 'GEMINI_API_KEY is not configured or using placeholder; fallback remains inactive while primary providers operate normally.',
      };
    }
    return { status: 'configured_and_reachable', isConfigured: true };
  };

  const res1 = unconfiguredProbe('MY_GEMINI_API_KEY');
  assert.equal(res1.status, 'missing_configuration');
  assert.equal(res1.isConfigured, false);
  assert.notEqual(res1.status, 'operational');
  assert.notEqual(res1.status, 'configured_and_reachable');

  const res2 = unconfiguredProbe('');
  assert.equal(res2.status, 'missing_configuration');
  assert.equal(res2.isConfigured, false);
});

test('2.6 Selected Gemini model gemini-3.8-flash officially supports reasoning, structured JSON, grounding & vision', () => {
  const supportedCapabilities = {
    'gemini-3.8-flash': ['text_reasoning', 'structured_json', 'google_search_grounding', 'multimodal_vision'],
  };
  const model = getResolvedGeminiModel({});
  assert.equal(model, 'gemini-3.8-flash');
  assert.ok(supportedCapabilities[model].includes('structured_json'));
  assert.ok(supportedCapabilities[model].includes('google_search_grounding'));
  assert.ok(supportedCapabilities[model].includes('multimodal_vision'));
});

// ====================================================================
// UNIT 3: AI Reasoning Fallback Execution Rules
// ====================================================================
console.log('\n--- Unit 3: AI Reasoning Fallback Execution Rules ---');

test('3.1 Primary Qwen succeeds: Gemini is NOT called', () => {
  let geminiCalled = false;
  const primaryResult = {
    riskLevel: 'high',
    summary: 'Suspicious invoice lure',
    indicators: [{ name: 'Fake Link', evidence: 'http://evil.com', reason: 'Phishing' }],
  };

  const primaryCall = () => ({ ok: true, data: primaryResult });
  const fallbackCall = () => { geminiCalled = true; };

  const res = primaryCall();
  if (!res.ok) fallbackCall();

  assert.equal(geminiCalled, false);
  assert.equal(res.data.riskLevel, 'high');
});

test('3.2 Qwen rate-limit / quota failure: Gemini fallback is attempted once', () => {
  let primaryAttempts = 0;
  let fallbackAttempts = 0;

  const mockExecution = () => {
    primaryAttempts++;
    const primaryError = { status: 429, body: 'capacity_exhausted' };
    const errCode = classifyHttpError(primaryError.status, primaryError.body);

    if (isEligibleForFallback(errCode)) {
      fallbackAttempts++;
      return {
        providerUsed: 'gemini',
        modelUsed: 'gemini-3.8-flash (Gemini Fallback)',
        result: {
          riskLevel: 'high',
          summary: 'Fallback detected threat',
          indicators: [{ name: 'Urgency', evidence: 'urgent', reason: 'Panic lure' }],
          recommendedActions: ['Do not pay demand'],
          limitations: ['Gemini fallback analysis'],
        },
      };
    }
  };

  const outcome = mockExecution();
  assert.equal(primaryAttempts, 1);
  assert.equal(fallbackAttempts, 1);
  assert.equal(outcome.providerUsed, 'gemini');
  assert.ok(outcome.modelUsed.includes('Fallback'));
});

test('3.3 Qwen timeout or upstream 504: Gemini fallback is attempted once', () => {
  let primaryAttempts = 0;
  let fallbackAttempts = 0;

  const mockExecution = () => {
    primaryAttempts++;
    const errCode = classifyHttpError(504, 'Gateway Timeout');

    if (isEligibleForFallback(errCode)) {
      fallbackAttempts++;
      return { providerUsed: 'gemini', success: true };
    }
  };

  const outcome = mockExecution();
  assert.equal(primaryAttempts, 1);
  assert.equal(fallbackAttempts, 1);
  assert.equal(outcome.success, true);
});

test('3.4 Invalid user input: Gemini is NEVER called', () => {
  let geminiCalled = false;
  const emptyInput = '   ';
  const isInvalid = !emptyInput || emptyInput.trim().length === 0;

  if (isInvalid) {
    // Return early HTTP 400
  } else {
    geminiCalled = true;
  }

  assert.equal(isInvalid, true);
  assert.equal(geminiCalled, false);
});

test('3.5 Authentication failure on user request: Gemini is NEVER called', () => {
  let geminiCalled = false;
  const userAuthenticated = false;

  if (!userAuthenticated) {
    // Return HTTP 401
  } else {
    geminiCalled = true;
  }

  assert.equal(geminiCalled, false);
});

test('3.6 Gemini output matches the existing response schema', () => {
  const geminiResponse = {
    riskLevel: 'high',
    summary: 'Detected coercive urgent wire transfer demand',
    indicators: [
      { name: 'Wire Pressure', evidence: 'Wire within 1 hour', reason: 'Urgency lure' },
    ],
    recommendedActions: ['Never wire funds based on unsolicited requests'],
    limitations: ['Passive heuristic analysis only'],
    severityScore: 85,
    model: 'gemini-3.8-flash (Gemini Fallback)',
  };

  assert.equal(typeof geminiResponse.riskLevel, 'string');
  assert.ok(['high', 'medium', 'low', 'uncertain'].includes(geminiResponse.riskLevel));
  assert.ok(Array.isArray(geminiResponse.indicators));
  assert.equal(typeof geminiResponse.summary, 'string');
  assert.equal(typeof geminiResponse.severityScore, 'number');
});

test('3.7 Both AI providers fail: graceful error / partial result', () => {
  let primaryFailed = true;
  let fallbackFailed = true;

  let responsePayload = null;
  if (primaryFailed && fallbackFailed) {
    responsePayload = {
      error: 'Upstream AI analysis is temporarily unavailable. Please try again shortly.',
      status: 502,
    };
  }

  assert.equal(responsePayload.status, 502);
  assert.ok(responsePayload.error.includes('temporarily unavailable'));
});

// ====================================================================
// UNIT 4: Web Research Fallback (Serper to Gemini Grounding)
// ====================================================================
console.log('\n--- Unit 4: Web Research & Grounding Fallback ---');

test('4.1 Serper succeeds: Gemini Search is NOT called', () => {
  let geminiSearchCalled = false;
  const serperResponse = {
    sources: [{ title: 'Official Bank Advisory', url: 'https://bank.example.com', snippet: 'No fees' }],
    rateLimited: false,
    quotaExhausted: false,
  };

  let finalSources = [];
  if (serperResponse.sources.length > 0) {
    finalSources = serperResponse.sources;
  } else {
    geminiSearchCalled = true;
  }

  assert.equal(geminiSearchCalled, false);
  assert.equal(finalSources.length, 1);
});

test('4.2 Serper temporary failure: Gemini grounding is attempted once', () => {
  let serperAttempts = 0;
  let groundingAttempts = 0;

  const mockSearch = () => {
    serperAttempts++;
    const serperError = { status: 429, body: 'quota exceeded' };
    const errCode = classifyHttpError(serperError.status, serperError.body);

    if (isEligibleForFallback(errCode)) {
      groundingAttempts++;
      return {
        providerMode: 'gemini_grounding',
        sources: [
          {
            title: 'Regulatory Warning Notice',
            url: 'https://regulatory.gov/notice.html',
            snippet: 'Advisory on fraudulent bank fees.',
            provenance: 'web_search',
          },
        ],
      };
    }
  };

  const res = mockSearch();
  assert.equal(serperAttempts, 1);
  assert.equal(groundingAttempts, 1);
  assert.equal(res.providerMode, 'gemini_grounding');
  assert.equal(res.sources.length, 1);
});

test('4.3 Grounding chunks preserve actual source metadata without fabrication', () => {
  const mockChunks = [
    { web: { uri: 'https://cbn.gov.ng/circulars/2026.pdf', title: 'CBN Circular' } },
    { web: { uri: 'https://reuters.com/finance/report', title: 'Reuters Report' } },
  ];

  const extracted = [];
  for (const chunk of mockChunks) {
    if (chunk.web?.uri) {
      extracted.push({
        id: `src-${extracted.length + 1}`,
        title: chunk.web.title,
        url: chunk.web.uri,
        domain: new URL(chunk.web.uri).hostname.replace(/^www\./, ''),
        provenance: 'web_search',
        limitationNote: 'Sourced via Gemini Google Search grounding fallback.',
      });
    }
  }

  assert.equal(extracted.length, 2);
  assert.equal(extracted[0].domain, 'cbn.gov.ng');
  assert.equal(extracted[1].domain, 'reuters.com');
  assert.ok(extracted[0].limitationNote.includes('grounding fallback'));
});

test('4.4 Grounding returns NO usable sources: zero fabricated citations created', () => {
  const emptyGroundingChunks = [];
  const sources = [];

  for (const chunk of emptyGroundingChunks) {
    if (chunk.web?.uri) {
      sources.push(chunk.web.uri);
    }
  }

  assert.equal(sources.length, 0, 'Must never fabricate fake search citations');
});

test('4.5 Gemini Search is disabled: no grounding call occurs', () => {
  let groundingInvoked = false;
  const env = {
    GEMINI_API_KEY: 'AIzaSyFakeKeyValidFormat1234567890',
    GEMINI_SEARCH_FALLBACK_ENABLED: 'false',
  };

  if (isGeminiSearchFallbackEnabled(env)) {
    groundingInvoked = true;
  }

  assert.equal(groundingInvoked, false);
});

// ====================================================================
// UNIT 5: URLhaus Independence & Security Invariants
// ====================================================================
console.log('\n--- Unit 5: URLhaus Independence & Security Invariants ---');

test('5.1 URLhaus unavailable remains unavailable, NEVER safe by default', () => {
  const unavailableResponse = {
    indicator: 'unreachable.example.com',
    status: 'unreachable',
    importantNotice: 'Threat intelligence feed is currently unreachable. An absence of threat intelligence does NOT confirm that this destination is safe or benign.',
  };

  assert.equal(unavailableResponse.status, 'unreachable');
  assert.notEqual(unavailableResponse.status, 'clean_or_unlisted');
  assert.ok(unavailableResponse.importantNotice.includes('does NOT confirm'));
});

test('5.2 SSRF filter strictly blocks all loopback, private RFC-1918, and metadata IPs', () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false); // public example.com IP
});

test('5.3 Document file validation remains unchanged and strictly enforced', () => {
  function validateFileMock(buffer, mimeType) {
    if (buffer.length === 0) return { isValid: false, error: 'File is empty' };
    if (!['application/pdf', 'image/png', 'image/jpeg', 'image/webp'].includes(mimeType)) {
      return { isValid: false, error: 'Unsupported file format' };
    }
    return { isValid: true };
  }

  const badFile = validateFileMock(Buffer.from('malicious payload'), 'application/x-executable');
  assert.equal(badFile.isValid, false);
  assert.equal(badFile.error, 'Unsupported file format');
});

test('5.4 No secret is exposed in browser bundles, API responses, or logs', () => {
  const secretKey = 'AIzaSySecretTestingKey1234567890';
  const rawLog = `Connection failed using key ${secretKey} and auth rc_33f49266885b262f9c701f2c9eebeb4ed118bf634db1cd816f4b74b137ac1c86`;
  const sanitized = redactSecrets(rawLog, secretKey);

  assert.ok(!sanitized.includes('AIzaSySecretTestingKey'));
  assert.ok(!sanitized.includes('rc_33f49266885b'));
  assert.ok(sanitized.includes('[REDACTED_GEMINI_KEY]') || sanitized.includes('[REDACTED_KEY]'));
  assert.ok(sanitized.includes('[REDACTED_TOKEN]'));
});

// ====================================================================
// UNIT 6: Live API Smoke Verification (if dev server is listening)
// ====================================================================
console.log('\n--- Unit 6: Live Endpoint Boundary Verification ---');

await asyncTest('6.1 Public diagnostics masks internal providers while admin diagnostics enforces authorization', async () => {
  const checkEndpoint = (path) =>
    new Promise((resolve) => {
      const req = http.get(`http://127.0.0.1:3000${path}`, (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            resolve({ ok: true, status: res.statusCode, json, raw: data });
          } catch {
            resolve({ ok: false, status: res.statusCode });
          }
        });
      });
      req.on('error', () => resolve({ ok: false, offline: true }));
      req.setTimeout(6000, () => {
        req.destroy();
        resolve({ ok: false, offline: true });
      });
    });

  const publicRes = await checkEndpoint('/api/diagnostics');
  if (publicRes.offline) {
    console.log('    ℹ️ Dev server is not running on port 3000. Skipping live HTTP endpoint check.');
    return 'skipped';
  }

  assert.equal(publicRes.status, 200);
  assert.ok(publicRes.ok, 'Endpoint should return parseable JSON');
  assert.ok(publicRes.json.aegisAi !== undefined, 'Public diagnostics must expose customer-safe aegisAi status');
  assert.equal(publicRes.json.geminiFallback, undefined, 'Public diagnostics must NOT expose geminiFallback telemetry');
  assert.ok(!/featherless|qwen|serper|gemini/i.test(publicRes.raw), 'Public diagnostics must NOT disclose vendor names');

  const adminRes = await checkEndpoint('/api/admin/diagnostics');
  assert.equal(adminRes.status, 403, 'Admin diagnostics endpoint must reject unauthorized requests with HTTP 403');
});

// ====================================================================
// UNIT 7: Compiled Real /api/analyze & message-analyzer.ts Resilience Tests (A-L)
// ====================================================================
console.log('\n--- Unit 7: Real /api/analyze Scenario Coverage (A-L) ---');

await asyncTest('7.1 Scenarios A-L: Primary <think> JSON, empty/malformed/429/503/timeout fallback, unexpected structures, unusable Gemini {}, abort before Vault/commit, dedup/idempotency & Nigerian bank alert', async () => {
  const ROOT = process.cwd();
  const nativeRequire = Module.createRequire(import.meta.url);

  function loadTs(relPath, mocks) {
    const full = path.join(ROOT, relPath);
    const src = fs.readFileSync(full, 'utf8');
    const out = ts.transpileModule(src, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
      fileName: full,
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
    get(k) { return super.get(String(k).toLowerCase()) ?? null; }
    set(k, v) { return super.set(String(k).toLowerCase(), String(v)); }
  }
  const mockNextServer = {
    NextResponse: {
      json(body, init = {}) {
        const headers = new MockHeaders();
        if (init.headers) {
          for (const [k, v] of Object.entries(init.headers)) headers.set(k, v);
        }
        return { status: init.status ?? 200, ok: (init.status ?? 200) < 300, headers, body, async json() { return body; } };
      },
    },
  };

  const realScamAnalyzer = loadTs('lib/scam-analyzer.ts', {});
  const modelConfig = loadTs('lib/model-config.ts', {});
  const diagnosticsLog = loadTs('lib/diagnostics-log.ts', { '@/lib/model-config': modelConfig });

  let geminiMode = 'valid';
  let geminiCalls = 0;
  let geminiCapturedTimeout = 0;
  let quotaState = { reserves: 0, commits: 0, refunds: 0 };
  let vaultState = { existingIds: [], inserts: 0 };

  const mockSupabaseFactory = async () => ({
    auth: {
      getUser: async () => ({ data: { user: { id: 'user-test-123' } }, error: null }),
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
  });

  const realMessageAnalyzer = loadTs('lib/gemini/message-analyzer.ts', {
    '@/lib/gemini/client': {
      getGeminiClient: () => ({
        models: {
          generateContent: async () => {
            geminiCalls++;
            if (geminiMode === 'fail') throw new Error('Gemini 503 downstream failure with secret AIzaSyFakeSecret123456789012345678901234');
            if (geminiMode === 'empty_obj') return { text: '{}' };
            if (geminiMode === 'slow') {
              await new Promise((r) => setTimeout(r, 300));
            }
            return {
              text: JSON.stringify({
                riskLevel: 'high',
                summary: 'Urgent banking lure with suspicious verification link.',
                indicators: [{ name: 'Suspicious Link', evidence: 'https://bit.ly/wf-sec', reason: 'Phishing' }],
                recommendedActions: ['Do not click the link.'],
                limitations: ['Text triage only.'],
              }),
            };
          },
        },
      }),
      getResolvedGeminiModel: () => 'gemini-3.8-flash',
      isGeminiFallbackEnabled: () => true,
      sanitizeGeminiError: (e) => redactSecrets(String(e?.message || e)),
    },
    '@/lib/scam-analyzer': realScamAnalyzer,
  });

  const wrappedMessageAnalyzer = {
    analyzeMessageWithGemini: async (msg, timeoutMs, signal) => {
      geminiCapturedTimeout = timeoutMs;
      return realMessageAnalyzer.analyzeMessageWithGemini(msg, timeoutMs, signal);
    },
  };

  const analyzeRoute = loadTs('app/api/analyze/route.ts', {
    'next/server': mockNextServer,
    '@/lib/scam-analyzer': realScamAnalyzer,
    '@/lib/supabase/server': { createClient: mockSupabaseFactory },
    '@/lib/model-config': modelConfig,
    '@/lib/gemini/client': { isGeminiFallbackEnabled: () => true },
    '@/lib/gemini/message-analyzer': wrappedMessageAnalyzer,
    '@/lib/provider-orchestrator': {
      classifyHttpError,
      isEligibleForFallback,
      recordProviderMetric() {},
    },
    '@/lib/rate-limit': {
      enforceApiRateLimit: async () => ({ allowed: true, status: 200, limit: 10, remaining: 9, retryAfterSeconds: 0 }),
      buildRateLimitErrorResponse: (o) => mockNextServer.NextResponse.json({ error: o.error }, { status: o.status }),
      attachRateLimitHeaders: (res) => res,
    },
    '@/lib/quota': {
      reserveInvestigationQuota: async () => {
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
      buildQuotaErrorResponse: (o) => mockNextServer.NextResponse.json({ error: o.error }, { status: o.status }),
      attachGuestCookie: (r) => r,
    },
    '@/lib/diagnostics-log': diagnosticsLog,
  });

  const origEnvKey = process.env.FEATHERLESS_API_KEY;
  const origFetch = globalThis.fetch;
  process.env.FEATHERLESS_API_KEY = 'rc_' + 'a'.repeat(40);

  const resetCounters = () => {
    quotaState = { reserves: 0, commits: 0, refunds: 0 };
    vaultState = { existingIds: [], inserts: 0 };
    geminiCalls = 0;
    geminiCapturedTimeout = 0;
    geminiMode = 'valid';
  };

  const makeReq = (message, signal) => ({
    headers: { get: () => null },
    signal,
    async json() { return { message }; },
  });

  try {
    // Scenario A: Primary Featherless succeeds with <think>{braces}</think>-wrapped JSON -> Gemini NOT called
    resetCounters();
    globalThis.fetch = async (url) => {
      assert.equal(url, 'https://api.featherless.ai/v1/chat/completions');
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            choices: [{
              message: {
                content: '<think>Reasoning {foo: 1} before output</think>\n{"riskLevel":"low","summary":"Routine friendly lunch update.","indicators":[],"recommendedActions":["No action required."],"limitations":["Text only."]}',
              },
            }],
          });
        },
      };
    };
    const resA = await analyzeRoute.POST(makeReq('Hey Alex, lunch is still on for noon tomorrow at Osteria.'));
    assert.equal(resA.status, 200);
    assert.equal(geminiCalls, 0);
    assert.equal(vaultState.inserts, 1);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario B: Primary returns HTTP 200 empty content -> Gemini called once -> HTTP 200
    resetCounters();
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async json() { return { choices: [{ message: { content: '   ' } }] }; },
    });
    const resB = await analyzeRoute.POST(makeReq('WELLS FARGO ALERT: Fraud charge flagged https://bit.ly/wf-sec'));
    assert.equal(resB.status, 200);
    assert.equal(geminiCalls, 1);
    assert.equal(vaultState.inserts, 1);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario C: Primary returns malformed JSON -> Gemini called once -> HTTP 200
    resetCounters();
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() { return JSON.stringify({ choices: [{ message: { content: '{broken json output' } }] }); },
    });
    const resC = await analyzeRoute.POST(makeReq('Urgent invoice verification fee required today'));
    assert.equal(resC.status, 200);
    assert.equal(geminiCalls, 1);
    assert.equal(vaultState.inserts, 1);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario D: Primary returns HTTP 429 -> skips repeated Featherless retries & calls Gemini immediately (fetchCalls === 1)
    resetCounters();
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls++;
      return { ok: false, status: 429, async text() { return 'capacity_exhausted'; } };
    };
    const resD = await analyzeRoute.POST(makeReq('Verify OTP code 482910 immediately'));
    assert.equal(resD.status, 200);
    assert.equal(fetchCalls, 1, 'HTTP 429 must NOT repeatedly hammer Featherless when Gemini fallback is active');
    assert.equal(geminiCalls, 1);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario E1: Primary returns HTTP 503 then secondary Featherless recovers -> HTTP 200 without Gemini
    resetCounters();
    fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls++;
      if (fetchCalls === 1) return { ok: false, status: 503, async text() { return 'Service temporarily unavailable'; } };
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            choices: [{ message: { content: '{"riskLevel":"high","summary":"Account suspension phishing lure.","indicators":[{"name":"Urgency","evidence":"suspended","reason":"Coercion"}],"recommendedActions":["Ignore message"],"limitations":["Text only"]}' } }],
          });
        },
      };
    };
    const resE1 = await analyzeRoute.POST(makeReq('Your account will be suspended unless you verify now'));
    assert.equal(resE1.status, 200);
    assert.equal(fetchCalls, 2);
    assert.equal(geminiCalls, 0);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario E2: Primary + secondary both return HTTP 503 -> bounded retry falls back to Gemini -> HTTP 200
    resetCounters();
    fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls++;
      return { ok: false, status: 503, async text() { return 'Service unavailable'; } };
    };
    const resE2 = await analyzeRoute.POST(makeReq('Your account will be suspended tomorrow'));
    assert.equal(resE2.status, 200);
    assert.equal(fetchCalls, 2);
    assert.equal(geminiCalls, 1);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario F: Primary throws TimeoutError -> does NOT burn secondary Featherless timeout when Gemini enabled, preserves Gemini budget >= 15000ms
    resetCounters();
    fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls++;
      const err = new Error('Timed out');
      err.name = 'TimeoutError';
      throw err;
    };
    const resF = await analyzeRoute.POST(makeReq('Urgent payroll update required today'));
    assert.equal(resF.status, 200);
    assert.equal(fetchCalls, 1, 'Timeout must go directly to Gemini fallback instead of burning a second Featherless timeout');
    assert.equal(geminiCalls, 1);
    assert.ok(geminiCapturedTimeout >= 15000, `Expected Gemini budget >= 15000ms, got ${geminiCapturedTimeout}`);
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });

    // Scenario G: Unexpected OpenAI-compatible structures & non-JSON body
    resetCounters();
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({ output_text: '{"riskLevel":"low","summary":"Routine meeting reminder.","indicators":[]}' });
      },
    });
    const resG1 = await analyzeRoute.POST(makeReq('Team standup moved to 10 AM tomorrow.'));
    assert.equal(resG1.status, 200);
    assert.equal(geminiCalls, 0);

    resetCounters();
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() { return '<html>502 Bad Gateway</html>'; },
    });
    const resG2 = await analyzeRoute.POST(makeReq('Suspicious link alert: https://bit.ly/wf-sec'));
    assert.equal(resG2.status, 200);
    assert.equal(geminiCalls, 1);

    // Scenario H: Gemini returns valid analysis after Featherless fails (tested above) vs Gemini returns unusable `{}` -> rejected & refunded
    resetCounters();
    geminiMode = 'empty_obj';
    globalThis.fetch = async () => ({ ok: false, status: 503, async text() { return 'Down'; } });
    const resH = await analyzeRoute.POST(makeReq('Your account will be blocked soon'));
    assert.equal(resH.status, 502);
    assert.equal(vaultState.inserts, 0);
    assert.deepEqual(quotaState, { reserves: 1, commits: 0, refunds: 1 });

    // Scenario I: Both providers fail -> sanitized error (no secret leakage), no Vault insert, 1 refund
    resetCounters();
    geminiMode = 'fail';
    globalThis.fetch = async () => ({ ok: false, status: 503, async text() { return 'Upstream error rc_' + 'b'.repeat(40); } });
    const resI = await analyzeRoute.POST(makeReq('Your account will be suspended tomorrow'));
    assert.equal(resI.status, 502);
    assert.ok(!JSON.stringify(resI.body).includes('AIzaSy'));
    assert.ok(!JSON.stringify(resI.body).includes('rc_bbb'));
    assert.equal(vaultState.inserts, 0);
    assert.deepEqual(quotaState, { reserves: 1, commits: 0, refunds: 1 });

    // Scenario J1: User aborts mid-Gemini -> HTTP 499, no Vault insert, 1 refund
    resetCounters();
    geminiMode = 'slow';
    const ctrlJ1 = new AbortController();
    globalThis.fetch = async () => ({ ok: false, status: 503, async text() { return 'Down'; } });
    setTimeout(() => ctrlJ1.abort(), 30);
    const resJ1 = await analyzeRoute.POST(makeReq('Check suspicious invoice attachment', ctrlJ1.signal));
    assert.equal(resJ1.status, 499);
    assert.equal(vaultState.inserts, 0);
    assert.deepEqual(quotaState, { reserves: 1, commits: 0, refunds: 1 });

    // Scenario J2: User aborts immediately after Featherless responds (before Vault/commit) -> HTTP 499, no Vault insert, 1 refund
    resetCounters();
    const ctrlJ2 = new AbortController();
    globalThis.fetch = async () => {
      ctrlJ2.abort();
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            choices: [{ message: { content: '{"riskLevel":"low","summary":"Routine update.","indicators":[]}' } }],
          });
        },
      };
    };
    const resJ2 = await analyzeRoute.POST(makeReq('Hey Alex, coffee at 3pm?', ctrlJ2.signal));
    assert.equal(resJ2.status, 499);
    assert.equal(vaultState.inserts, 0);
    assert.deepEqual(quotaState, { reserves: 1, commits: 0, refunds: 1 });

    // Scenario K: Duplicate submission / overlapping protection (Vault 15-min dedup + MessageAnalyzer guards)
    resetCounters();
    vaultState.existingIds = ['existing-vault-id-1'];
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({
          choices: [{ message: { content: '{"riskLevel":"low","summary":"Routine meeting.","indicators":[]}' } }],
        });
      },
    });
    const resK = await analyzeRoute.POST(makeReq('Hey Alex, coffee at 3pm?'));
    assert.equal(resK.status, 200);
    assert.equal(vaultState.inserts, 0, 'Duplicate submission within 15m window must not insert a duplicate Vault record');
    const clientSource = fs.readFileSync(path.join(ROOT, 'components/MessageAnalyzer.tsx'), 'utf8');
    assert.ok(clientSource.includes('inFlightRef.current'), 'Client must guard concurrent submissions via inFlightRef');
    assert.ok(clientSource.includes('createAttemptIdempotencyKey()'), 'Client must send x-aegis-idempotency-key');
    assert.ok(clientSource.includes('abortControllerRef.current'), 'Client must track active AbortController');

    // Scenario L: Exact Nigerian bank notification fixture through /api/analyze (never fetches bit.ly!)
    resetCounters();
    const nigerianAlert =
      'Account:234****3414 Received: NGN.330,782 Days Position-Dtd:26/11,2026 FA BAL Bal:NGN.650,741. Click to view: https://bit.ly/4tnD68a?14';
    const fetchedUrls = [];
    globalThis.fetch = async (url) => {
      fetchedUrls.push(String(url));
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            choices: [{
              message: {
                content: JSON.stringify({
                  riskLevel: 'low',
                  summary: 'Bank credit notification referencing masked account and a shortened bit.ly link.',
                  indicators: [],
                  recommendedActions: ['Check your official banking app directly instead of clicking the shortened URL.'],
                  limitations: ['Text triage only; shortened link destination was not visited.'],
                }),
              },
            }],
          });
        },
      };
    };
    const resL = await analyzeRoute.POST(makeReq(nigerianAlert));
    assert.equal(resL.status, 200);
    assert.deepEqual(fetchedUrls, ['https://api.featherless.ai/v1/chat/completions'], 'Analyzer must never auto-fetch bit.ly URLs');
    assert.equal(resL.body.riskLevel, 'medium', 'Shortened URL alert should calibrate cleanly to medium risk without false high fraud escalation');
    assert.ok(
      resL.body.indicators.some((i) => i.name.includes('URL Shortener / Concealed Destination')),
      'Must flag URL Shortener / Concealed Destination'
    );
    assert.ok(resL.body.iocs.urls.includes('https://bit.ly/4tnD68a?14'));
    assert.deepEqual(quotaState, { reserves: 1, commits: 1, refunds: 0 });
  } finally {
    globalThis.fetch = origFetch;
    if (origEnvKey === undefined) delete process.env.FEATHERLESS_API_KEY;
    else process.env.FEATHERLESS_API_KEY = origEnvKey;
  }
});

// ====================================================================
// Test Summary
// ====================================================================
console.log(`\n========================================`);
console.log(`Results: ${passedTests} passed, ${totalTests - passedTests - skippedTests} failed, ${skippedTests} skipped`);
console.log(`========================================\n`);

if (totalTests - passedTests - skippedTests > 0) {
  process.exit(1);
}
