import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';

const require = createRequire(import.meta.url);

console.log('🧪 Starting AegisFlow Phase 1 — Persistent Usage Quota & Credit Architecture Test Suite...\n');

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
      specifier === 'crypto' ||
      specifier === 'node:net' ||
      specifier === 'net' ||
      specifier === 'path'
    ) {
      return require(specifier);
    }
    throw new Error(`Unexpected require("${specifier}") in ${relativePath}`);
  };

  fn(mod.exports, localRequire, mod, fullPath, path.dirname(fullPath));
  return mod.exports;
}

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

  function makeResponse(body, init = {}) {
    const headers = new MockHeaders();
    if (init.headers) {
      for (const [k, v] of Object.entries(init.headers)) {
        headers.set(k, v);
      }
    }
    const cookieJar = new Map();
    return {
      status: init.status ?? 200,
      ok: (init.status ?? 200) >= 200 && (init.status ?? 200) < 300,
      headers,
      body,
      cookies: {
        set(name, value, options) {
          cookieJar.set(name, { value, options });
          const parts = [
            `${name}=${encodeURIComponent(value)}`,
            `Path=${options?.path || '/'}`,
            `Max-Age=${options?.maxAge ?? 31536000}`,
          ];
          if (options?.httpOnly) parts.push('HttpOnly');
          if (options?.sameSite) {
            parts.push(`SameSite=${String(options.sameSite).charAt(0).toUpperCase()}${String(options.sameSite).slice(1)}`);
          }
          if (options?.secure) parts.push('Secure');
          headers.set('set-cookie', parts.join('; '));
        },
        get(name) {
          return cookieJar.get(name);
        },
      },
      async json() {
        return body;
      },
    };
  }

  return {
    NextResponse: {
      json(body, init = {}) {
        return makeResponse(body, init);
      },
      redirect(url, status = 307) {
        return makeResponse(null, { status, headers: { location: String(url) } });
      },
    },
  };
}

const mockNextServer = createNextServerMock();
const modelConfig = compileTsModule('lib/model-config.ts');
const quotaTypes = compileTsModule('lib/quota-types.ts');

const authHarness = {
  user: null,
  exchangeUser: null,
  verifyOtpUser: null,
};

const mockSupabaseServer = {
  async createClient() {
    return {
      auth: {
        async getUser() {
          if (!authHarness.user) return { data: { user: null }, error: null };
          return { data: { user: authHarness.user }, error: null };
        },
        async exchangeCodeForSession(code) {
          if (code === 'valid_code' && authHarness.exchangeUser) {
            return { data: { user: authHarness.exchangeUser }, error: null };
          }
          return { data: { user: null }, error: { message: 'Invalid code' } };
        },
        async verifyOtp({ token_hash }) {
          if (token_hash === 'valid_otp' && authHarness.verifyOtpUser) {
            return { data: { user: authHarness.verifyOtpUser }, error: null };
          }
          return { data: { user: null }, error: { message: 'Invalid OTP' } };
        },
      },
      from() {
        return {
          select() {
            const chain = {
              eq() { return chain; },
              gte() { return chain; },
              async limit() { return { data: [] }; },
            };
            return chain;
          },
          async insert() {
            return { error: null };
          },
        };
      },
    };
  },
};

const mockSupabaseJs = {
  createClient() {
    throw new Error('Supabase JS createClient should be injected in quota tests');
  },
};

const quotaMod = compileTsModule('lib/quota.ts', {
  '@supabase/supabase-js': mockSupabaseJs,
  'next/server': mockNextServer,
  '@/lib/supabase/server': mockSupabaseServer,
  '@/lib/model-config': modelConfig,
  '@/lib/quota-types': quotaTypes,
});

/**
 * Simulated PostgreSQL 0006_usage_quotas.sql RPC store preserving exact atomic/idempotency guarantees.
 */
function createSimulatedQuotaSupabase({ failRpc = false } = {}) {
  const guestIdentities = new Map();
  const accounts = new Map();
  const balances = new Map(); // `${accountKey}:${bucket}` -> { balance, lifetime_granted, lifetime_used }
  const reservations = new Map();
  const idempotency = new Map();
  const ledger = [];
  let seq = 1;

  function snapshotFor(accountKey) {
    const acc = accounts.get(accountKey);
    if (!acc) return { exists: false };
    if (acc.owner_type === 'guest') {
      const g = guestIdentities.get(acc.guest_id_hash);
      const b = balances.get(`${accountKey}:guest_shared`)?.balance ?? 0;
      return {
        exists: true,
        ownerType: 'guest',
        planTier: acc.plan_tier,
        initialGrantIssued: acc.initial_grant_issued,
        claimedByUser: Boolean(g?.claimed_by_user_id),
        sharedRemaining: b,
        sharedLimit: 12,
        balances: {
          message_analysis: b,
          document_scan: b,
          fact_check: b,
          url_investigation: b,
        },
        totalRemaining: b,
      };
    }
    const msg = balances.get(`${accountKey}:message_analysis`)?.balance ?? 0;
    const doc = balances.get(`${accountKey}:document_scan`)?.balance ?? 0;
    const fc = balances.get(`${accountKey}:fact_check`)?.balance ?? 0;
    const url = balances.get(`${accountKey}:url_investigation`)?.balance ?? 0;
    return {
      exists: true,
      ownerType: 'user',
      planTier: acc.plan_tier,
      initialGrantIssued: acc.initial_grant_issued,
      claimedByUser: false,
      sharedRemaining: null,
      sharedLimit: null,
      balances: {
        message_analysis: msg,
        document_scan: doc,
        fact_check: fc,
        url_investigation: url,
      },
      totalRemaining: msg + doc + fc + url,
    };
  }

  return {
    guestIdentities,
    accounts,
    balances,
    reservations,
    ledger,
    async rpc(fnName, params) {
      if (failRpc) {
        return { data: null, error: { code: '42P01', message: 'relation "public.quota_accounts" does not exist' } };
      }

      if (fnName === 'ensure_guest_quota') {
        let hash = String(params.p_guest_hash || '').toLowerCase().trim();
        if (!/^[a-f0-9]{64}$/.test(hash)) {
          return { data: { ok: false, errorCode: 'invalid_guest_token' }, error: null };
        }
        let g = guestIdentities.get(hash);
        let depth = 0;
        while (g && g.superseded_by_hash && depth < 10) {
          depth++;
          hash = g.superseded_by_hash;
          g = guestIdentities.get(hash);
        }
        const accountKey = `guest:${hash}`;
        if (!g) {
          if (params.p_create_if_missing === false) {
            return { data: { ok: false, errorCode: 'unrecognized_guest_token' }, error: null };
          }
          g = {
            guest_id_hash: hash,
            rotated_from_hash: null,
            superseded_by_hash: null,
            claimed_by_user_id: null,
            claimed_at: null,
          };
          guestIdentities.set(hash, g);
        }
        if (!accounts.has(accountKey)) {
          accounts.set(accountKey, {
            account_key: accountKey,
            owner_type: 'guest',
            guest_id_hash: hash,
            plan_tier: 'guest_trial',
            initial_grant_issued: false,
          });
        }
        const acc = accounts.get(accountKey);
        if (!acc.initial_grant_issued) {
          const credits = Math.max(0, Math.min(Number(params.p_initial_credits ?? 12), 12));
          balances.set(`${accountKey}:guest_shared`, {
            balance: credits,
            lifetime_granted: credits,
            lifetime_used: 0,
          });
          acc.initial_grant_issued = true;
          ledger.push({ accountKey, bucket: 'guest_shared', delta: credits, entry_type: 'initial_grant' });
        }
        return {
          data: { ok: true, accountKey, canonicalGuestHash: hash, snapshot: snapshotFor(accountKey) },
          error: null,
        };
      }

      if (fnName === 'ensure_user_quota') {
        const uid = params.p_user_id;
        if (!uid) return { data: { ok: false, errorCode: 'invalid_user' }, error: null };
        const cleanGuest = String(params.p_claim_guest_hash || '').toLowerCase().trim();
        const validGuest = /^[a-f0-9]{64}$/.test(cleanGuest) ? cleanGuest : null;
        if (validGuest) {
          const existingGuest = guestIdentities.get(validGuest);
          if (existingGuest) {
            if (!existingGuest.claimed_by_user_id) {
              existingGuest.claimed_by_user_id = uid;
              existingGuest.claimed_at = new Date().toISOString();
            }
          } else {
            guestIdentities.set(validGuest, {
              guest_id_hash: validGuest,
              claimed_by_user_id: uid,
              claimed_at: new Date().toISOString(),
            });
          }
        }
        const accountKey = `user:${uid}`;
        if (!accounts.has(accountKey)) {
          accounts.set(accountKey, {
            account_key: accountKey,
            owner_type: 'user',
            user_id: uid,
            plan_tier: 'free',
            initial_grant_issued: false,
            claimed_guest_hash: validGuest,
          });
        }
        const acc = accounts.get(accountKey);
        if (!acc.claimed_guest_hash && validGuest) acc.claimed_guest_hash = validGuest;
        if (!acc.initial_grant_issued) {
          for (const bucket of ['message_analysis', 'document_scan', 'fact_check', 'url_investigation']) {
            balances.set(`${accountKey}:${bucket}`, {
              balance: 5,
              lifetime_granted: 5,
              lifetime_used: 0,
            });
            ledger.push({ accountKey, bucket, delta: 5, entry_type: 'initial_grant' });
          }
          acc.initial_grant_issued = true;
        }
        return { data: { ok: true, accountKey, snapshot: snapshotFor(accountKey) }, error: null };
      }

      if (fnName === 'rotate_guest_identity') {
        const oldH = String(params.p_old_hash || '').toLowerCase().trim();
        const newH = String(params.p_new_hash || '').toLowerCase().trim();
        const oldG = guestIdentities.get(oldH);
        if (!oldG) return { data: { ok: false, errorCode: 'unrecognized_guest_token' }, error: null };
        if (oldG.superseded_by_hash) return { data: { ok: false, errorCode: 'token_already_rotated' }, error: null };
        const oldKey = `guest:${oldH}`;
        const newKey = `guest:${newH}`;
        guestIdentities.set(newH, {
          guest_id_hash: newH,
          rotated_from_hash: oldH,
          claimed_by_user_id: oldG.claimed_by_user_id,
          claimed_at: oldG.claimed_at,
        });
        oldG.superseded_by_hash = newH;
        accounts.set(newKey, {
          account_key: newKey,
          owner_type: 'guest',
          guest_id_hash: newH,
          plan_tier: 'guest_trial',
          initial_grant_issued: true,
        });
        const oldBal = balances.get(`${oldKey}:guest_shared`) || { balance: 0, lifetime_granted: 12, lifetime_used: 12 };
        balances.set(`${newKey}:guest_shared`, { ...oldBal });
        balances.set(`${oldKey}:guest_shared`, { ...oldBal, balance: 0 });
        return { data: { ok: true, accountKey: newKey, snapshot: snapshotFor(newKey) }, error: null };
      }

      if (fnName === 'reserve_investigation_quota') {
        const accountKey = params.p_account_key;
        const cap = params.p_capability;
        const idem = params.p_idempotency_key ? String(params.p_idempotency_key).trim() : null;
        const acc = accounts.get(accountKey);
        if (!acc) return { data: { allowed: false, errorCode: 'account_not_found' }, error: null };
        if (idem && idempotency.has(`${accountKey}:${idem}`)) {
          const resId = idempotency.get(`${accountKey}:${idem}`);
          const existingRes = reservations.get(resId);
          return {
            data: { allowed: true, idempotent: true, reservationId: resId, bucket: existingRes.bucket, snapshot: snapshotFor(accountKey) },
            error: null,
          };
        }
        const bucket = acc.owner_type === 'guest' ? 'guest_shared' : cap;
        const row = balances.get(`${accountKey}:${bucket}`);
        if (!row || row.balance < 1) {
          return {
            data: {
              allowed: false,
              errorCode: 'quota_exhausted',
              bucket,
              ownerType: acc.owner_type,
              snapshot: snapshotFor(accountKey),
            },
            error: null,
          };
        }
        row.balance -= 1;
        row.lifetime_used += 1;
        const resId = `00000000-0000-4000-8000-${String(seq++).padStart(12, '0')}`;
        reservations.set(resId, {
          id: resId,
          account_key: accountKey,
          bucket,
          capability: cap,
          amount: 1,
          status: 'reserved',
        });
        if (idem) idempotency.set(`${accountKey}:${idem}`, resId);
        ledger.push({ accountKey, bucket, delta: -1, entry_type: 'consume_reserve', reservationId: resId });
        return {
          data: { allowed: true, idempotent: false, reservationId: resId, bucket, snapshot: snapshotFor(accountKey) },
          error: null,
        };
      }

      if (fnName === 'finalize_investigation_quota') {
        const resId = params.p_reservation_id;
        const outcome = params.p_outcome;
        const res = reservations.get(resId);
        if (!res) return { data: { ok: false, errorCode: 'reservation_not_found' }, error: null };
        if (res.status !== 'reserved') {
          return {
            data: { ok: true, alreadyResolved: true, status: res.status, snapshot: snapshotFor(res.account_key) },
            error: null,
          };
        }
        if (outcome === 'commit') {
          res.status = 'committed';
          return { data: { ok: true, alreadyResolved: false, status: 'committed', snapshot: snapshotFor(res.account_key) }, error: null };
        }
        res.status = 'refunded';
        const row = balances.get(`${res.account_key}:${res.bucket}`);
        row.balance += res.amount;
        row.lifetime_used = Math.max(0, row.lifetime_used - res.amount);
        ledger.push({ accountKey: res.account_key, bucket: res.bucket, delta: res.amount, entry_type: 'refund', reservationId: resId });
        return { data: { ok: true, alreadyResolved: false, status: 'refunded', snapshot: snapshotFor(res.account_key) }, error: null };
      }

      throw new Error(`Unexpected RPC ${fnName}`);
    },
  };
}

function createMockRequest({
  url = 'https://aegisflowx.vercel.app/api/quota',
  headers = {},
  jsonBody = {},
  aborted = false,
  formDataFile = null,
} = {}) {
  const normalized = new Map();
  for (const [k, v] of Object.entries(headers)) {
    normalized.set(k.toLowerCase(), v);
  }
  return {
    url,
    signal: { aborted },
    headers: {
      get(name) {
        return normalized.get(String(name).toLowerCase()) ?? null;
      },
    },
    async json() {
      return jsonBody;
    },
    async formData() {
      return {
        get(k) {
          return k === 'file' ? formDataFile : null;
        },
      };
    },
  };
}

const TEST_ENV = {
  NODE_ENV: 'production',
  NEXT_PUBLIC_SUPABASE_URL: 'https://test-project.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'service_role_test_secret_key_that_is_very_long_12345',
  GUEST_TOKEN_SECRET: 'guest_signing_test_secret_with_sufficient_length',
  RATE_LIMIT_HASH_SALT: 'quota-test-salt',
};

// =========================================================================
// TEST 1: Cryptographic guest token integrity, fail-closed tampering & rotation
// =========================================================================
await test('1. Signed guest cookie validates HMAC, persists only SHA-256 hashes, rejects tampered/unknown tokens & rotates without resetting credits', async () => {
  const db = createSimulatedQuotaSupabase();
  const deps = {
    env: TEST_ENV,
    serviceClient: db,
    resolveUser: async () => ({ status: 'guest', userId: null }),
  };

  // Initial guest request mints signed token and 12 shared credits
  const initOut = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), deps);
  assert.equal(initOut.ok, true);
  assert.equal(initOut.status, 200);
  assert.equal(initOut.snapshot.ownerType, 'guest');
  assert.equal(initOut.snapshot.sharedRemaining, 12);
  assert.ok(initOut.cookieToSet?.value, 'Initial guest request must mint cookie');

  const rawToken = initOut.cookieToSet.value;
  const cookieHeaderStr = quotaMod.buildGuestCookieHeader(quotaMod.GUEST_COOKIE_NAME, rawToken, true);
  assert.ok(cookieHeaderStr.includes('HttpOnly'));
  assert.ok(cookieHeaderStr.includes('SameSite=Lax'));
  assert.ok(cookieHeaderStr.includes('Secure'));

  // DB stores only SHA-256 hash, never raw token or tokenId
  const [tokenId] = rawToken.split('.');
  const storedHashes = Array.from(db.guestIdentities.keys());
  assert.equal(storedHashes.length, 1);
  assert.match(storedHashes[0], /^[a-f0-9]{64}$/);
  assert.ok(!storedHashes[0].includes(tokenId) && !storedHashes[0].includes(rawToken));

  // Spend 3 credits
  for (let i = 0; i < 3; i++) {
    const res = await quotaMod.reserveInvestigationQuota(
      createMockRequest({ headers: { cookie: `aegis_guest_token=${encodeURIComponent(rawToken)}` } }),
      'message_analysis',
      deps
    );
    assert.equal(res.allowed, true);
    await quotaMod.commitQuotaReservation(res.reservation, deps);
  }

  // Tampered HMAC signature -> fail closed 403 without creating new 12-credit identity
  const tamperedToken = `${tokenId}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
  const tamperedRes = await quotaMod.reserveInvestigationQuota(
    createMockRequest({ headers: { cookie: `aegis_guest_token=${encodeURIComponent(tamperedToken)}` } }),
    'message_analysis',
    deps
  );
  assert.equal(tamperedRes.allowed, false);
  assert.equal(tamperedRes.status, 403);
  assert.equal(tamperedRes.errorCode, 'invalid_guest_token');
  assert.equal(db.guestIdentities.size, 1);

  // Correctly signed token NOT present in DB -> unrecognized token fails closed 403 (never mints 12 fresh credits)
  const forgedValidSig = quotaMod.mintSignedGuestToken(TEST_ENV);
  const unrecognizedRes = await quotaMod.reserveInvestigationQuota(
    createMockRequest({ headers: { cookie: `aegis_guest_token=${encodeURIComponent(forgedValidSig.cookieValue)}` } }),
    'fact_check',
    deps
  );
  assert.equal(unrecognizedRes.allowed, false);
  assert.equal(unrecognizedRes.status, 403);
  assert.equal(unrecognizedRes.errorCode, 'invalid_guest_token');

  // Rotate token -> new cookie issued, balance remains 9 (NOT reset to 12), old token rejected on rotation
  const rotated = await quotaMod.rotateGuestToken(
    createMockRequest({ headers: { cookie: `aegis_guest_token=${encodeURIComponent(rawToken)}` } }),
    deps
  );
  assert.equal(rotated.ok, true);
  assert.equal(rotated.snapshot.sharedRemaining, 9);
  assert.notEqual(rotated.cookieToSet.value, rawToken);

  const replayOld = await quotaMod.rotateGuestToken(
    createMockRequest({ headers: { cookie: `aegis_guest_token=${encodeURIComponent(rawToken)}` } }),
    deps
  );
  assert.equal(replayOld.ok, false);
  assert.equal(replayOld.status, 403);
});

// =========================================================================
// TEST 2: Guest shared 12-credit non-renewing pool across all 4 capabilities
// =========================================================================
await test('2. Guest 12-credit shared allowance deducts across all 4 tools, survives restarts, and blocks 13th at 403', async () => {
  const db = createSimulatedQuotaSupabase();
  const depsA = { env: TEST_ENV, serviceClient: db, resolveUser: async () => ({ status: 'guest', userId: null }) };

  const initOut = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), depsA);
  const cookieHeader = { cookie: `aegis_guest_token=${encodeURIComponent(initOut.cookieToSet.value)}` };

  // Simulate separate server instance (depsB) consuming 3 from each of the 4 capabilities = 12 total
  const depsB = { env: TEST_ENV, serviceClient: db, resolveUser: async () => ({ status: 'guest', userId: null }) };
  const caps = ['message_analysis', 'document_scan', 'fact_check', 'url_investigation'];

  let expectedRemaining = 12;
  for (let round = 0; round < 3; round++) {
    for (const cap of caps) {
      const r = await quotaMod.reserveInvestigationQuota(
        createMockRequest({ headers: cookieHeader }),
        cap,
        depsB
      );
      expectedRemaining--;
      assert.equal(r.allowed, true);
      assert.equal(r.snapshot.sharedRemaining, expectedRemaining);
      await quotaMod.commitQuotaReservation(r.reservation, depsB);
    }
  }

  assert.equal(expectedRemaining, 0);

  // 13th call on any capability blocks with 403 quota_exhausted & requiresRegistration: true
  for (const cap of caps) {
    const blocked = await quotaMod.reserveInvestigationQuota(
      createMockRequest({ headers: cookieHeader }),
      cap,
      depsB
    );
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.status, 403);
    assert.equal(blocked.errorCode, 'quota_exhausted');
    assert.equal(blocked.requiresRegistration, true);
    assert.equal(blocked.snapshot.sharedRemaining, 0);
  }
});

// =========================================================================
// TEST 3: Registered verified user 5/5/5/5 isolation + email verification gate
// =========================================================================
await test('3. Unverified email is blocked (403); verified user receives 5/5/5/5 with independent per-capability exhaustion', async () => {
  const db = createSimulatedQuotaSupabase();

  // Unverified user blocked cleanly
  const unverifiedDeps = {
    env: TEST_ENV,
    serviceClient: db,
    resolveUser: async () => ({ status: 'unverified', userId: '22222222-2222-4222-8222-222222222222' }),
  };
  const unverifiedSnap = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), unverifiedDeps);
  assert.equal(unverifiedSnap.ok, false);
  assert.equal(unverifiedSnap.status, 403);
  assert.equal(unverifiedSnap.errorCode, 'email_verification_required');

  const unverifiedReserve = await quotaMod.reserveInvestigationQuota(
    createMockRequest(),
    'message_analysis',
    unverifiedDeps
  );
  assert.equal(unverifiedReserve.allowed, false);
  assert.equal(unverifiedReserve.status, 403);
  assert.equal(unverifiedReserve.errorCode, 'email_verification_required');

  // Verified user receives 5/5/5/5
  const verifiedUid = '33333333-3333-4333-8333-333333333333';
  const verifiedDeps = {
    env: TEST_ENV,
    serviceClient: db,
    resolveUser: async () => ({ status: 'verified', userId: verifiedUid }),
  };

  const snap = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), verifiedDeps);
  assert.equal(snap.ok, true);
  assert.equal(snap.snapshot.ownerType, 'user');
  assert.equal(snap.snapshot.totalRemaining, 20);
  assert.deepEqual(snap.snapshot.balances, {
    message_analysis: 5,
    document_scan: 5,
    fact_check: 5,
    url_investigation: 5,
  });

  // Exhaust message_analysis (5 calls) -> 6th blocked at 403
  for (let i = 0; i < 5; i++) {
    const res = await quotaMod.reserveInvestigationQuota(createMockRequest(), 'message_analysis', verifiedDeps);
    assert.equal(res.allowed, true);
    await quotaMod.commitQuotaReservation(res.reservation, verifiedDeps);
  }
  const blockedMsg = await quotaMod.reserveInvestigationQuota(createMockRequest(), 'message_analysis', verifiedDeps);
  assert.equal(blockedMsg.allowed, false);
  assert.equal(blockedMsg.status, 403);
  assert.equal(blockedMsg.errorCode, 'quota_exhausted');
  assert.equal(blockedMsg.requiresRegistration, false);

  // Other 3 capabilities still have 5 credits each!
  for (const cap of ['document_scan', 'fact_check', 'url_investigation']) {
    const ok = await quotaMod.reserveInvestigationQuota(createMockRequest(), cap, verifiedDeps);
    assert.equal(ok.allowed, true, `${cap} must still be usable after exhausting message_analysis`);
    assert.equal(ok.snapshot.balances[cap], 4);
    assert.equal(ok.snapshot.balances.message_analysis, 0);
    await quotaMod.commitQuotaReservation(ok.reservation, verifiedDeps);
  }
});

// =========================================================================
// TEST 4: Sign-up/login transition, guest claim, and anti-reset across sign-out/sign-in
// =========================================================================
await test('4. Account registration claims guest token without transferring unused guest credits, and sign-out/sign-in cannot reset quotas', async () => {
  const db = createSimulatedQuotaSupabase();
  const guestDeps = { env: TEST_ENV, serviceClient: db, resolveUser: async () => ({ status: 'guest', userId: null }) };

  // Guest spends 4 of 12 credits (8 left)
  const guestInit = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), guestDeps);
  const guestCookie = { cookie: `aegis_guest_token=${encodeURIComponent(guestInit.cookieToSet.value)}` };
  for (let i = 0; i < 4; i++) {
    const r = await quotaMod.reserveInvestigationQuota(createMockRequest({ headers: guestCookie }), 'url_investigation', guestDeps);
    await quotaMod.commitQuotaReservation(r.reservation, guestDeps);
  }

  // Test auth/callback route claiming guest cookie on PKCE exchange
  const registeredUid = '44444444-4444-4444-8444-444444444444';
  authHarness.exchangeUser = { id: registeredUid, email_confirmed_at: new Date().toISOString() };

  const callbackRoute = compileTsModule('app/auth/callback/route.ts', {
    'next/server': mockNextServer,
    '@/lib/supabase/server': mockSupabaseServer,
    '@/lib/quota': {
      getOrInitializeQuotaSnapshot: (req, extraDeps) =>
        quotaMod.getOrInitializeQuotaSnapshot(req, { ...extraDeps, env: TEST_ENV, serviceClient: db }),
    },
  });

  const cbRes = await callbackRoute.GET(
    createMockRequest({
      url: 'https://aegisflowx.vercel.app/auth/callback?code=valid_code',
      headers: guestCookie,
    })
  );
  assert.equal(cbRes.status, 307);

  // User starts at strictly 5/5/5/5 (total 20), NOT 20 + 8 unused guest credits!
  const userDeps = { env: TEST_ENV, serviceClient: db, resolveUser: async () => ({ status: 'verified', userId: registeredUid }) };
  const afterClaim = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest({ headers: guestCookie }), userDeps);
  assert.equal(afterClaim.snapshot.totalRemaining, 20);
  assert.deepEqual(afterClaim.snapshot.balances, {
    message_analysis: 5,
    document_scan: 5,
    fact_check: 5,
    url_investigation: 5,
  });

  // Guest token is permanently marked claimed in DB, and its remaining guest balance stays 8 (no free refresh)
  const guestCheck = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest({ headers: guestCookie }), guestDeps);
  assert.equal(guestCheck.snapshot.claimedByUser, true);
  assert.equal(guestCheck.snapshot.sharedRemaining, 8);

  // Spend 2 document_scan credits as verified user -> 3 left; simulate sign-out and sign-in -> STILL 3 left!
  for (let i = 0; i < 2; i++) {
    const r = await quotaMod.reserveInvestigationQuota(createMockRequest(), 'document_scan', userDeps);
    await quotaMod.commitQuotaReservation(r.reservation, userDeps);
  }
  const afterSignInAgain = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest({ headers: guestCookie }), userDeps);
  assert.equal(afterSignInAgain.snapshot.balances.document_scan, 3);
  assert.equal(afterSignInAgain.snapshot.totalRemaining, 18);
});

// =========================================================================
// TEST 5: Compiled API routes (all 4 endpoints + /api/quota): invalid/rate-limited never spend; failure/abort refund once
// =========================================================================
await test('5. All 4 routes + /api/quota: 400/422/429 never spend credits; 503/499 refund reserved credit at most once', async () => {
  const db = createSimulatedQuotaSupabase();
  let currentUid = null;
  let rateLimitAllow = true;
  let forceDownstreamFail = false;

  const quotaWrapper = {
    reserveInvestigationQuota: (req, cap) =>
      quotaMod.reserveInvestigationQuota(req, cap, {
        env: TEST_ENV,
        serviceClient: db,
        resolveUser: async () =>
          currentUid ? { status: 'verified', userId: currentUid } : { status: 'guest', userId: null },
      }),
    getOrInitializeQuotaSnapshot: (req) =>
      quotaMod.getOrInitializeQuotaSnapshot(req, {
        env: TEST_ENV,
        serviceClient: db,
        resolveUser: async () =>
          currentUid ? { status: 'verified', userId: currentUid } : { status: 'guest', userId: null },
      }),
    commitQuotaReservation: (r) => quotaMod.commitQuotaReservation(r, { env: TEST_ENV, serviceClient: db }),
    refundQuotaReservation: (r, reason) => quotaMod.refundQuotaReservation(r, reason, { env: TEST_ENV, serviceClient: db }),
    buildQuotaErrorResponse: quotaMod.buildQuotaErrorResponse,
    attachGuestCookie: quotaMod.attachGuestCookie,
  };

  const mockRateLimit = {
    async enforceApiRateLimit() {
      if (!rateLimitAllow) {
        return { allowed: false, status: 429, errorCode: 'rate_limit_exceeded', error: 'Slow down', retryAfterSeconds: 30 };
      }
      return { allowed: true, status: 200, limit: 10, remaining: 9, retryAfterSeconds: 0, scope: 'guest' };
    },
    buildRateLimitErrorResponse(out) {
      return mockNextServer.NextResponse.json({ error: out.error, errorCode: out.errorCode }, { status: out.status });
    },
    attachRateLimitHeaders(res) {
      return res;
    },
  };

  const mockMessageAnalyzer = {
    async analyzeMessageWithGemini() {
      if (forceDownstreamFail) throw new Error('Upstream provider outage');
      return {
        modelUsed: 'mock-msg',
        result: { riskLevel: 'low', severityScore: 10, summary: 'Ok', indicators: [], recommendedActions: [], limitations: [] },
      };
    },
  };
  const mockFactChecker = {
    async generateFactCheckReport() {
      if (forceDownstreamFail) throw new Error('Search provider outage');
      return {
        executiveSummary: 'Ok', threatSeverity: 'low', severityScore: 5, suspiciousIndicators: [],
        confidenceLevel: 'high', confidenceRationale: 'Ok', evidenceSufficiency: 'sufficient',
        extractedClaims: [], recommendations: {}, sources: [], researchLimitations: [],
      };
    },
  };
  const mockUrlInvestigator = {
    validateAndNormalizeUrl(raw) {
      try { return { isValid: true, parsedUrl: new URL(raw) }; } catch { return { isValid: false, error: 'Malformed URL' }; }
    },
    async screenUrlForSsrf(u) {
      if (u.hostname === '127.0.0.1') return { safe: false, reason: 'Loopback forbidden' };
      return { safe: true };
    },
    async investigateUrl(raw) {
      if (forceDownstreamFail) throw new Error('URL intelligence downstream failure');
      return {
        urlComponents: { rawUrl: raw, normalizedUrl: raw, displayUrl: raw, hostname: 'example.com', domain: 'example.com' },
        overallSeverity: 'low', severityScore: 5, executiveSummary: 'Ok', indicators: [],
        recommendedActions: {}, evidenceLimitations: [], webEvidence: [], threatIntel: [], domainIntelligence: {},
        confidenceLevel: 'high', confidenceRationale: 'Ok', modelUsed: 'mock-url',
      };
    },
  };
  const mockScamAnalyzer = { extractIOCsFromMessage: () => ({}), validateAnalysisPayload: () => ({ valid: true }) };
  const mockGeminiClient = { isGeminiFallbackEnabled: () => true, isGeminiDocumentFallbackEnabled: () => true };
  const mockOrchestrator = { classifyHttpError: () => 'unavailable', isEligibleForFallback: () => true, recordProviderMetric() {} };
  const mockVaultNorm = { normalizeIndicators: (x) => x || [] };
  const mockDocScanner = {
    validateUploadedFileBuffer: (buf) => buf.length === 0 ? { valid: false, error: 'Empty', errorCode: 'EMPTY' } : { valid: true },
    extractTextFromPdf: async () => ({ text: 'hello', pageCount: 1, isScannedOrEmpty: false }),
    validateDocumentScanPayload: () => ({ valid: true }),
  };
  const mockGeminiDoc = {
    async analyzeDocumentWithGemini() {
      if (forceDownstreamFail) throw new Error('Doc AI unavailable');
      return { modelUsed: 'mock-doc', result: { riskLevel: 'low', severityScore: 10, summary: 'Ok', indicators: [], recommendedActions: [], limitations: [] } };
    },
    GeminiDocumentFallbackError: class GeminiDocumentFallbackError extends Error {},
    classifyGeminiError: () => 'unavailable',
  };

  const quotaRoute = compileTsModule('app/api/quota/route.ts', {
    'next/server': mockNextServer,
    '@/lib/quota': quotaWrapper,
    '@/lib/model-config': modelConfig,
  });
  const analyzeRoute = compileTsModule('app/api/analyze/route.ts', {
    'next/server': mockNextServer,
    '@/lib/scam-analyzer': mockScamAnalyzer,
    '@/lib/supabase/server': mockSupabaseServer,
    '@/lib/model-config': modelConfig,
    '@/lib/gemini/client': mockGeminiClient,
    '@/lib/gemini/message-analyzer': mockMessageAnalyzer,
    '@/lib/provider-orchestrator': mockOrchestrator,
    '@/lib/rate-limit': mockRateLimit,
    '@/lib/quota': quotaWrapper,
  });
  const scanRoute = compileTsModule('app/api/scan-document/route.ts', {
    'next/server': mockNextServer,
    '@/lib/document-scanner': mockDocScanner,
    '@/lib/scam-analyzer': mockScamAnalyzer,
    '@/lib/supabase/server': mockSupabaseServer,
    '@/lib/model-config': modelConfig,
    '@/lib/gemini/client': mockGeminiClient,
    '@/lib/gemini/document-analyzer': mockGeminiDoc,
    '@/lib/provider-orchestrator': mockOrchestrator,
    '@/lib/rate-limit': mockRateLimit,
    '@/lib/quota': quotaWrapper,
  });
  const fcRoute = compileTsModule('app/api/fact-check/route.ts', {
    'next/server': mockNextServer,
    '@/lib/fact-checker/fact-checker': mockFactChecker,
    '@/lib/supabase/server': mockSupabaseServer,
    '@/lib/model-config': modelConfig,
    '@/lib/rate-limit': mockRateLimit,
    '@/lib/quota': quotaWrapper,
  });
  const urlRoute = compileTsModule('app/api/url-investigation/route.ts', {
    'next/server': mockNextServer,
    '@/lib/url-investigation/investigator': mockUrlInvestigator,
    '@/lib/supabase/server': mockSupabaseServer,
    '@/lib/model-config': modelConfig,
    '@/lib/vault-normalization': mockVaultNorm,
    '@/lib/rate-limit': mockRateLimit,
    '@/lib/quota': quotaWrapper,
  });

  // 1. GET /api/quota initializes guest cookie with Cache-Control: no-store
  const qRes = await quotaRoute.GET(createMockRequest());
  assert.equal(qRes.status, 200);
  assert.equal(qRes.headers.get('cache-control'), 'no-store, max-age=0');
  const setCookie = qRes.headers.get('set-cookie');
  assert.ok(setCookie && setCookie.includes('aegis_guest_token='));
  const tokenMatch = /aegis_guest_token=([^;]+)/.exec(setCookie);
  const guestHeaders = { cookie: `aegis_guest_token=${tokenMatch[1]}` };

  // 2. Invalid input (400 empty/SSRF/empty file) and 429 rate-limit NEVER deduct credits
  await analyzeRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { message: '' } }));
  await fcRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { text: '' } }));
  await urlRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { url: 'http://127.0.0.1/admin' } }));
  await scanRoute.POST(createMockRequest({ headers: guestHeaders, formDataFile: null }));
  rateLimitAllow = false;
  const rlRes = await analyzeRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { message: 'Valid text' } }));
  assert.equal(rlRes.status, 429);
  rateLimitAllow = true;

  const snapAfterInvalid = await quotaRoute.GET(createMockRequest({ headers: guestHeaders }));
  assert.equal(snapAfterInvalid.body.quota.sharedRemaining, 12, 'Invalid inputs & 429 rate limits must NOT consume credits');

  // 3. Downstream failure refunds reserved credit cleanly
  forceDownstreamFail = true;
  const failAnalyze = await analyzeRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { message: 'Suspicious invoice' } }));
  assert.equal(failAnalyze.status, 503);
  const failFc = await fcRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { text: 'Public policy claim' } }));
  assert.equal(failFc.status, 500);
  const failUrl = await urlRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { url: 'https://example.com' } }));
  assert.equal(failUrl.status, 500);
  forceDownstreamFail = false;

  const snapAfterFailures = await quotaRoute.GET(createMockRequest({ headers: guestHeaders }));
  assert.equal(snapAfterFailures.body.quota.sharedRemaining, 12, 'Failed downstream calls must refund credits');

  // 4. Client abort (499) also refunds reserved credit
  const abortUrl = await urlRoute.POST(createMockRequest({ headers: guestHeaders, jsonBody: { url: 'https://example.com' }, aborted: true }));
  assert.equal(abortUrl.status, 499);
  const snapAfterAbort = await quotaRoute.GET(createMockRequest({ headers: guestHeaders }));
  assert.equal(snapAfterAbort.body.quota.sharedRemaining, 12, 'Aborted request must refund credit');

  // 5. Idempotent double-refund protection on direct reservation handle
  const directReserve = await quotaMod.reserveInvestigationQuota(
    createMockRequest({ headers: guestHeaders }),
    'fact_check',
    { env: TEST_ENV, serviceClient: db, resolveUser: async () => ({ status: 'guest', userId: null }) }
  );
  assert.equal(directReserve.snapshot.sharedRemaining, 11);
  await quotaMod.refundQuotaReservation(directReserve.reservation, 'first', { env: TEST_ENV, serviceClient: db });
  const afterSecondRefund = await quotaMod.refundQuotaReservation(directReserve.reservation, 'second', { env: TEST_ENV, serviceClient: db });
  assert.equal(afterSecondRefund.sharedRemaining, 12, 'Double refund must be strictly idempotent');
});

// =========================================================================
// TEST 6: Concurrent burst overrun protection + production fail-closed + static SQL/privacy audit
// =========================================================================
await test('6. Concurrent burst cannot overrun balance < 0; prod without DB fails closed (503); SQL & client privacy invariants hold', async () => {
  const db = createSimulatedQuotaSupabase();
  const uid = '55555555-5555-4555-8555-555555555555';
  const deps = { env: TEST_ENV, serviceClient: db, resolveUser: async () => ({ status: 'verified', userId: uid }) };

  // Pre-spend 2 of 5 credits (3 left)
  for (let i = 0; i < 2; i++) {
    const r = await quotaMod.reserveInvestigationQuota(createMockRequest(), 'url_investigation', deps);
    await quotaMod.commitQuotaReservation(r.reservation, deps);
  }

  // Burst 10 concurrent reservations -> strictly 3 allowed, 7 rejected with 403, balance stays 0
  const results = await Promise.all(
    Array.from({ length: 10 }, () =>
      quotaMod.reserveInvestigationQuota(createMockRequest(), 'url_investigation', deps)
    )
  );
  const allowed = results.filter((r) => r.allowed);
  const rejected = results.filter((r) => !r.allowed && r.status === 403);
  assert.equal(allowed.length, 3);
  assert.equal(rejected.length, 7);
  assert.equal(db.balances.get(`user:${uid}:url_investigation`).balance, 0);

  // Production without serviceClient fails closed 503
  const prodNoDb = await quotaMod.reserveInvestigationQuota(createMockRequest(), 'message_analysis', {
    env: TEST_ENV,
    serviceClient: null,
    resolveUser: async () => ({ status: 'guest', userId: null }),
  });
  assert.equal(prodNoDb.allowed, false);
  assert.equal(prodNoDb.status, 503);
  assert.equal(prodNoDb.errorCode, 'quota_service_unavailable');

  // SQL migration 0006 assertions
  const sql = fs.readFileSync(path.join(repoRoot, 'supabase/migrations/0006_usage_quotas.sql'), 'utf8').toLowerCase();
  for (const tbl of ['guest_identities', 'quota_accounts', 'quota_balances', 'quota_reservations', 'quota_ledger', 'referral_claims']) {
    assert.ok(sql.includes(`alter table public.${tbl} enable row level security`), `RLS missing on ${tbl}`);
    assert.ok(sql.includes(`revoke all on table public.${tbl} from public, anon, authenticated`), `Revoke missing on ${tbl}`);
    assert.ok(sql.includes(`grant select, insert, update, delete on table public.${tbl} to service_role`), `Grant missing on ${tbl}`);
  }
  assert.ok(sql.includes('balance integer not null default 0 check (balance >= 0)'));
  assert.ok(sql.includes('security definer'));
  assert.ok(sql.includes('set search_path = public'));

  // Client bundle & privacy assertions (zero service keys, zero server quota module imports, zero provider names)
  const clientFiles = [
    'lib/quota-types.ts',
    'hooks/use-quota.ts',
    'components/QuotaStatusBanner.tsx',
    'components/MessageAnalyzer.tsx',
    'components/DocumentScanner.tsx',
    'components/FactCheckInput.tsx',
    'components/url-intelligence/InvestigationConsole.tsx',
    'app/analyze/page.tsx',
    'app/url-investigation/page.tsx',
    'app/page.tsx',
  ];
  for (const rel of clientFiles) {
    const src = fs.readFileSync(path.join(repoRoot, rel), 'utf8');
    assert.ok(!src.includes('SUPABASE_SERVICE_ROLE_KEY'), `${rel} must not reference service role key`);
    assert.ok(!src.includes('GUEST_TOKEN_SECRET'), `${rel} must not reference GUEST_TOKEN_SECRET`);
    assert.ok(!src.includes('NEXT_PUBLIC_GUEST_TOKEN_SECRET'), `${rel} must not expose guest signing secret via NEXT_PUBLIC_`);
    assert.ok(!src.includes("from '@/lib/quota'"), `${rel} must not import server-only @/lib/quota`);
    assert.ok(!/featherless|qwen|serper|gemini/i.test(src), `${rel} must not expose third-party provider names in UI`);
  }
});

// =========================================================================
// TEST 7: Missing migration 0006 RPC (PGRST202): prod fails closed 503, dev falls back locally
// =========================================================================
await test('7. Missing migration 0006 RPC (PGRST202) fails closed (503) in production and falls back cleanly to local store in development', async () => {
  const missingMigrationClient = {
    async rpc() {
      return {
        data: null,
        error: {
          code: 'PGRST202',
          message: 'Could not find the function public.ensure_guest_quota(p_create_if_missing, p_guest_hash, p_initial_credits) in the schema cache',
        },
      };
    },
  };

  // Production MUST fail closed (503)
  const prodInit = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), {
    env: TEST_ENV,
    serviceClient: missingMigrationClient,
    resolveUser: async () => ({ status: 'guest', userId: null }),
  });
  assert.equal(prodInit.ok, false);
  assert.equal(prodInit.status, 503);
  assert.equal(prodInit.errorCode, 'quota_service_unavailable');

  const prodReserve = await quotaMod.reserveInvestigationQuota(createMockRequest(), 'message_analysis', {
    env: TEST_ENV,
    serviceClient: missingMigrationClient,
    resolveUser: async () => ({ status: 'guest', userId: null }),
  });
  assert.equal(prodReserve.allowed, false);
  assert.equal(prodReserve.status, 503);
  assert.equal(prodReserve.errorCode, 'quota_service_unavailable');

  // Non-production dev falls back cleanly to localStore without 503
  const devEnv = { ...TEST_ENV, NODE_ENV: 'development' };
  const devStore = quotaMod.createLocalQuotaStore();
  const devInit = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest({ url: 'http://localhost:3000/api/quota' }), {
    env: devEnv,
    serviceClient: missingMigrationClient,
    localStore: devStore,
    resolveUser: async () => ({ status: 'guest', userId: null }),
  });
  assert.equal(devInit.ok, true);
  assert.equal(devInit.status, 200);
  assert.equal(devInit.snapshot.sharedRemaining, 12);
  assert.ok(devInit.cookieToSet?.value);

  const devReserve = await quotaMod.reserveInvestigationQuota(
    createMockRequest({
      url: 'http://localhost:3000/api/analyze',
      headers: { cookie: `aegis_guest_token=${encodeURIComponent(devInit.cookieToSet.value)}` },
    }),
    'message_analysis',
    {
      env: devEnv,
      serviceClient: missingMigrationClient,
      localStore: devStore,
      resolveUser: async () => ({ status: 'guest', userId: null }),
    }
  );
  assert.equal(devReserve.allowed, true);
  assert.equal(devReserve.status, 200);
  assert.equal(devReserve.snapshot.sharedRemaining, 11);
});

// =========================================================================
// TEST 8: Production GUEST_TOKEN_SECRET enforcement, fail-closed checks & redaction
// =========================================================================
await test('8. Production strictly mandates valid GUEST_TOKEN_SECRET (no fallback to service-role/ephemeral), fails closed 503, and redacts secret', async () => {
  const db = createSimulatedQuotaSupabase();
  const validSecret = TEST_ENV.GUEST_TOKEN_SECRET;
  const mintedValid = quotaMod.mintSignedGuestToken(TEST_ENV);
  assert.ok(mintedValid?.cookieValue);

  // Even when SUPABASE_SERVICE_ROLE_KEY & RATE_LIMIT_HASH_SALT are set, production MUST reject missing/short/placeholder GUEST_TOKEN_SECRET
  const invalidProdEnvs = [
    { ...TEST_ENV, GUEST_TOKEN_SECRET: undefined },
    { ...TEST_ENV, GUEST_TOKEN_SECRET: '' },
    { ...TEST_ENV, GUEST_TOKEN_SECRET: 'too_short_secret' },
    { ...TEST_ENV, GUEST_TOKEN_SECRET: 'YOUR_GUEST_TOKEN_SECRET_DO_NOT_USE_123456' },
    { ...TEST_ENV, GUEST_TOKEN_SECRET: 'a'.repeat(64) },
  ];

  for (const badEnv of invalidProdEnvs) {
    assert.equal(quotaMod.mintSignedGuestToken(badEnv), null, 'Production must return null when GUEST_TOKEN_SECRET is missing or invalid');

    const verifyOut = quotaMod.verifySignedGuestToken(mintedValid.cookieValue, badEnv);
    assert.equal(verifyOut.valid, false);
    assert.equal(verifyOut.reason, 'unconfigured');

    // Without cookie -> fail closed 503
    const snapNoCookie = await quotaMod.getOrInitializeQuotaSnapshot(createMockRequest(), {
      env: badEnv,
      serviceClient: db,
      resolveUser: async () => ({ status: 'guest', userId: null }),
    });
    assert.equal(snapNoCookie.ok, false);
    assert.equal(snapNoCookie.status, 503);
    assert.equal(snapNoCookie.errorCode, 'quota_service_unavailable');

    // With existing cookie -> fail closed 503 (never 403 tampered & never ephemeral fallback)
    const cookieHdr = { cookie: `aegis_guest_token=${encodeURIComponent(mintedValid.cookieValue)}` };
    const snapWithCookie = await quotaMod.getOrInitializeQuotaSnapshot(
      createMockRequest({ headers: cookieHdr }),
      {
        env: badEnv,
        serviceClient: db,
        resolveUser: async () => ({ status: 'guest', userId: null }),
      }
    );
    assert.equal(snapWithCookie.ok, false);
    assert.equal(snapWithCookie.status, 503);
    assert.equal(snapWithCookie.errorCode, 'quota_service_unavailable');

    const reserveWithCookie = await quotaMod.reserveInvestigationQuota(
      createMockRequest({ headers: cookieHdr }),
      'message_analysis',
      {
        env: badEnv,
        serviceClient: db,
        resolveUser: async () => ({ status: 'guest', userId: null }),
      }
    );
    assert.equal(reserveWithCookie.allowed, false);
    assert.equal(reserveWithCookie.status, 503);
    assert.equal(reserveWithCookie.errorCode, 'quota_service_unavailable');

    const rotateWithCookie = await quotaMod.rotateGuestToken(
      createMockRequest({ headers: cookieHdr }),
      { env: badEnv, serviceClient: db }
    );
    assert.equal(rotateWithCookie.ok, false);
    assert.equal(rotateWithCookie.status, 503);
    assert.equal(rotateWithCookie.errorCode, 'quota_service_unavailable');
  }

  // Non-production dev mode still signs/verifies even without GUEST_TOKEN_SECRET
  const devNoSecretEnv = { NODE_ENV: 'development' };
  const devMinted = quotaMod.mintSignedGuestToken(devNoSecretEnv);
  assert.ok(devMinted?.cookieValue);
  assert.equal(quotaMod.verifySignedGuestToken(devMinted.cookieValue, devNoSecretEnv).valid, true);

  // redactSecrets masks GUEST_TOKEN_SECRET
  const prevSecret = process.env.GUEST_TOKEN_SECRET;
  try {
    process.env.GUEST_TOKEN_SECRET = validSecret;
    const redacted = modelConfig.redactSecrets(`Diagnostic failure leaked ${validSecret} in log`);
    assert.ok(!redacted.includes(validSecret), 'redactSecrets must mask GUEST_TOKEN_SECRET');
    assert.ok(redacted.includes('[REDACTED_GUEST_TOKEN_SECRET]'));
  } finally {
    if (prevSecret === undefined) delete process.env.GUEST_TOKEN_SECRET;
    else process.env.GUEST_TOKEN_SECRET = prevSecret;
  }
});

console.log(`\n========================================`);
console.log(`Phase 1 Usage Quota Results: ${passedTests}/${totalTests} passed`);
console.log(`========================================\n`);

if (passedTests !== totalTests) {
  process.exit(1);
}

