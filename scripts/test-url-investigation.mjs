import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const repoRoot = process.cwd();
const moduleCache = new Map();

function compileTsModule(relativePath, extraRequire = {}) {
  const fullPath = path.resolve(repoRoot, relativePath);
  if (moduleCache.has(fullPath)) {
    return moduleCache.get(fullPath);
  }

  const source = fs.readFileSync(fullPath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true,
      resolveJsonModule: true,
    },
    fileName: fullPath,
  });

  const mod = { exports: {} };
  moduleCache.set(fullPath, mod.exports);

  const fn = new vm.Script(
    `(function(exports, require, module, __filename, __dirname) {\n${transpiled.outputText}\n})`,
    { filename: fullPath }
  ).runInThisContext();

  const localRequire = (id) => {
    if (id in extraRequire) return extraRequire[id];
    if (id.startsWith('./') || id.startsWith('../')) {
      const resolved = path.resolve(path.dirname(fullPath), id);
      const candidates = [resolved, resolved + '.ts', resolved + '.js', resolved + '/index.ts'];
      for (const cand of candidates) {
        if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
          return compileTsModule(path.relative(repoRoot, cand), extraRequire);
        }
      }
    }
    if (id.startsWith('@/')) {
      const rel = id.slice(2);
      const candidates = [
        path.join(repoRoot, rel),
        path.join(repoRoot, rel + '.ts'),
        path.join(repoRoot, rel + '.js'),
        path.join(repoRoot, rel, 'index.ts'),
      ];
      for (const cand of candidates) {
        if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
          return compileTsModule(path.relative(repoRoot, cand), extraRequire);
        }
      }
    }
    return require(id);
  };

  fn(mod.exports, localRequire, mod, fullPath, path.dirname(fullPath));
  moduleCache.set(fullPath, mod.exports);
  return mod.exports;
}

const { validateAndNormalizeUrl, screenUrlForSsrf } = compileTsModule('lib/url-investigation/investigator.ts');
const { resolveUrlRedirects } = compileTsModule('lib/url-investigation/redirect-resolver.ts');

console.log('🧪 Starting AegisFlow Phase 2 URL Intelligence & Evidence Integrity Test Suite...\n');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
  }
}

async function asyncTest(name, fn) {
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

// SUITE 1: SYNTAX, SCHEME & SSRF SECURITY
console.log('--- Suite 1: Syntax, Scheme & SSRF Security ---');

test('1.1 https://www.google.com/ is accepted and parsed correctly', () => {
  const validation = validateAndNormalizeUrl('https://www.google.com/');
  assert.equal(validation.isValid, true);
  assert.equal(validation.urlComponents?.hostname, 'www.google.com');
  assert.equal(validation.urlComponents?.domain, 'google.com');
});

test('1.2 Invalid and obfuscated URLs are rejected', () => {
  assert.equal(validateAndNormalizeUrl('javascript:alert(1)').isValid, false);
  assert.equal(validateAndNormalizeUrl('file:///etc/passwd').isValid, false);
  assert.equal(validateAndNormalizeUrl('//attacker.com/path').isValid, false);
  assert.equal(validateAndNormalizeUrl('https://example.com\\@evil.com').isValid, false);
});

asyncTest('1.3 Private IP / loopback redirect attempts trigger SSRF firewall block', async () => {
  const parsed = new URL('http://127.0.0.1:8080/admin');
  const ssrf = await screenUrlForSsrf(parsed);
  assert.equal(ssrf.safe, false);
  assert.match(ssrf.reason, /loopback|private|blocked/i);
});

asyncTest('1.4 Cloud metadata IP (169.254.169.254) is blocked', async () => {
  const parsed = new URL('http://169.254.169.254/latest/meta-data/');
  const ssrf = await screenUrlForSsrf(parsed);
  assert.equal(ssrf.safe, false);
});

// SUITE 2: SAFE REDIRECT RESOLUTION & ATTRIBUTION
console.log('\n--- Suite 2: Safe Redirect Resolution & Attribution ---');

await asyncTest('2.1 Normal Google redirect URL with benign destination is parsed and resolved', async () => {
  const raw = 'https://www.google.com/url?q=https://example.com';
  const redirectRes = await resolveUrlRedirects(raw);
  assert.equal(redirectRes.isRedirect, true);
  assert.equal(redirectRes.decodedDestination, 'https://example.com');
  assert.equal(redirectRes.suspiciousDomainChange, true);
});

await asyncTest('2.2 Google redirect URL with suspicious destination (nibss-plc domain) is properly decoded', async () => {
  const raw = 'https://www.google.com/url?q=https://contactcentre.nibss-plc.com.ng/verify';
  const redirectRes = await resolveUrlRedirects(raw);
  assert.equal(redirectRes.decodedDestination, 'https://contactcentre.nibss-plc.com.ng/verify');
  assert.equal(redirectRes.suspiciousDomainChange, true);
});

await asyncTest('2.3 Multiple nested redirects and parameter decoding are handled correctly', async () => {
  const raw = 'https://www.google.com/url?q=https%3A%2F%2Fbit.ly%2F3example';
  const redirectRes = await resolveUrlRedirects(raw);
  assert.equal(redirectRes.decodedDestination, 'https://bit.ly/3example');
  assert.equal(redirectRes.isRedirect, true);
});

// SUITE 3: LIVE HTTP API ENDPOINT VERIFICATION
console.log('\n--- Suite 3: Live HTTP API Endpoint Verification ---');

const BASE_URL = process.env.TEST_APP_URL || 'http://localhost:3000';
let skippedTests = 0;

try {
  let isServerAvailable = false;
  try {
    const probeCtrl = new AbortController();
    const probeTimer = setTimeout(() => probeCtrl.abort(), 2000);
    const probe = await fetch(`${BASE_URL}/api/url-investigation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: '' }),
      signal: probeCtrl.signal,
    }).finally(() => clearTimeout(probeTimer));

    if (probe.status === 400) {
      isServerAvailable = true;
    }
  } catch {
    // Dev server not running
  }

  if (isServerAvailable) {
    await asyncTest('Live HTTP API rejects empty payload with HTTP 400', async () => {
      const res = await fetch(`${BASE_URL}/api/url-investigation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: '' }),
      });
      assert.equal(res.status, 400);
    });

    await asyncTest('Live HTTP API accepts valid example domain without crashing', async () => {
      const res = await fetch(`${BASE_URL}/api/url-investigation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
      });
      assert.equal(res.status, 200);
    });
  } else {
    console.log(`  ℹ️ Dev server is not listening on ${BASE_URL}. Skipping live HTTP endpoint integration tests.`);
    skippedTests += 2;
  }
} catch {
  skippedTests += 2;
}

console.log(`\n========================================`);
console.log(`Results: ${passedTests} passed, ${totalTests - passedTests} failed, ${skippedTests} skipped`);
console.log(`========================================\n`);

if (passedTests !== totalTests) {
  process.exit(1);
}
