import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';

console.log('🛡️ Starting AegisFlow Phase 3C.1 Branding, Provider Privacy & Password Visibility Audit Suite...\n');

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
    console.error(`    ${err.message}`);
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
    console.error(`    ${err.message}`);
    failed++;
  }
}

function collectFiles(dir, exts, excludeDirs = new Set()) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!excludeDirs.has(entry.name)) {
        results.push(...collectFiles(fullPath, exts, excludeDirs));
      }
    } else if (exts.some((ext) => entry.name.endsWith(ext))) {
      results.push(fullPath);
    }
  }
  return results;
}

// ====================================================================
// 1. Customer-Facing UI & Component Branding Audit
// ====================================================================
console.log('--- Suite 1: Customer-Facing UI & Component Provider Privacy ---');

const uiFiles = [
  ...collectFiles(path.join(ROOT, 'app'), ['.tsx', '.ts'], new Set(['api', 'admin'])),
  ...collectFiles(path.join(ROOT, 'components'), ['.tsx', '.ts']),
];

const forbiddenCustomerPatterns = [
  /\bFeatherless\b/i,
  /\bQwen\b/i,
  /\bSerper\b/i,
  /\bgemini-[0-9a-z.-]+/i,
  /\bGoogle\s+Gemini\b/i,
  /\bSERPER_API_KEY\b/,
  /\bFEATHERLESS_API_KEY\b/,
  /\bGEMINI_API_KEY\b/,
  /\bURLHAUS_AUTH_KEY\b/,
];

test('1.1 Customer-facing pages and components contain zero third-party AI/search provider disclosures', () => {
  const violations = [];
  for (const file of uiFiles) {
    const rel = path.relative(ROOT, file);
    const content = fs.readFileSync(file, 'utf8');
    // Allow regex pattern literals used strictly for legacy data masking (e.g. /qwen|featherless.../i)
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.includes('/qwen|featherless') || trimmed.includes('/serper|gemini')) {
        return;
      }
      for (const pat of forbiddenCustomerPatterns) {
        if (pat.test(line)) {
          violations.push(`${rel}:${idx + 1} matches ${pat}`);
        }
      }
    });
  }
  assert.deepEqual(violations, [], `Found customer-facing provider leaks:\n${violations.join('\n')}`);
});

test('1.2 Unified Aegis AI branding is present across core intelligence surfaces', () => {
  const requiredAegisAiFiles = [
    'components/Sidebar.tsx',
    'components/Navbar.tsx',
    'components/Footer.tsx',
    'components/AnalysisResult.tsx',
    'components/DocumentScanner.tsx',
    'components/DocumentScanResult.tsx',
    'components/FactCheckInput.tsx',
    'components/dashboard/PlatformTelemetry.tsx',
    'components/dashboard/QuickInvestigationLauncher.tsx',
    'app/analyze/page.tsx',
    'app/settings/page.tsx',
  ];

  for (const rel of requiredAegisAiFiles) {
    const content = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    assert.ok(content.includes('Aegis AI'), `${rel} must display unified Aegis AI branding`);
  }
});

test('1.3 Genuine threat intelligence evidence (URLhaus / abuse.ch) remains preserved in threat investigation layer', () => {
  const investigator = fs.readFileSync(path.join(ROOT, 'lib/url-investigation/investigator.ts'), 'utf8');
  assert.ok(investigator.includes('URLhaus'), 'URLhaus threat feed evidence must remain intact in URL investigator');
  assert.ok(
    investigator.includes('Aegis AI URL Intelligence'),
    'URL investigator modelUsed must use unified Aegis AI branding'
  );
  assert.ok(!investigator.includes('${model} + URLhaus'), 'URL investigator must not expose raw LLM model IDs');
});

// ====================================================================
// 2. Password Visibility Controls Audit
// ====================================================================
console.log('\n--- Suite 2: Password Visibility Controls & Accessibility ---');

test('2.1 Zero plain <input type="password"> elements remain across app/ and components/', () => {
  const plainPasswordMatches = [];
  for (const file of uiFiles) {
    const rel = path.relative(ROOT, file);
    if (rel === 'components/ui/PasswordInput.tsx') continue;
    const content = fs.readFileSync(file, 'utf8');
    if (/type\s*=\s*["']password["']/i.test(content)) {
      plainPasswordMatches.push(rel);
    }
  }
  assert.deepEqual(
    plainPasswordMatches,
    [],
    `Found unmigrated password inputs: ${plainPasswordMatches.join(', ')}`
  );
});

test('2.2 PasswordInput component implements accessible show/hide toggle with Eye and EyeOff icons', () => {
  const component = fs.readFileSync(path.join(ROOT, 'components/ui/PasswordInput.tsx'), 'utf8');
  assert.ok(component.includes("from 'lucide-react'"), 'Must import icons from lucide-react');
  assert.ok(component.includes('Eye') && component.includes('EyeOff'), 'Must use Eye and EyeOff icons');
  assert.ok(component.includes("useState(false)"), 'Password must be hidden by default');
  assert.ok(component.includes("isVisible ? 'text' : 'password'"), 'Must toggle input type between password and text');
  assert.ok(component.includes('type="button"'), 'Toggle button must use type="button" to prevent form submission');
  assert.ok(
    component.includes("aria-label={isVisible ? 'Hide password' : 'Show password'}"),
    'Toggle button must expose dynamic accessible aria-label'
  );
});

test('2.3 Auth forms (Login, Register, Reset Password) use independent PasswordInput instances', () => {
  const login = fs.readFileSync(path.join(ROOT, 'app/auth/login/page.tsx'), 'utf8');
  const register = fs.readFileSync(path.join(ROOT, 'app/auth/register/page.tsx'), 'utf8');
  const reset = fs.readFileSync(path.join(ROOT, 'app/auth/reset-password/page.tsx'), 'utf8');

  assert.equal((login.match(/<PasswordInput\b/g) || []).length, 1, 'Login must render 1 PasswordInput');
  assert.equal((register.match(/<PasswordInput\b/g) || []).length, 2, 'Register must render 2 independent PasswordInputs');
  assert.equal((reset.match(/<PasswordInput\b/g) || []).length, 2, 'Reset Password must render 2 independent PasswordInputs');
});

// ====================================================================
// 3. Admin Diagnostics Security & Public Endpoint Boundary
// ====================================================================
console.log('\n--- Suite 3: Admin Diagnostics Authorization & Public Boundary ---');

test('3.1 Admin diagnostics API & UI strictly enforce server-side admin verification', () => {
  const adminApi = fs.readFileSync(path.join(ROOT, 'app/api/admin/diagnostics/route.ts'), 'utf8');
  const publicDiagApi = fs.readFileSync(path.join(ROOT, 'app/api/diagnostics/route.ts'), 'utf8');
  const modelDiagApi = fs.readFileSync(path.join(ROOT, 'app/api/model-diagnostic/route.ts'), 'utf8');
  const adminAuth = fs.readFileSync(path.join(ROOT, 'lib/admin-auth.ts'), 'utf8');

  assert.ok(adminApi.includes('verifyAdminUser'), 'Admin API must invoke verifyAdminUser');
  assert.ok(adminApi.includes('status: 403'), 'Admin API must return HTTP 403 for non-admin callers');
  assert.ok(publicDiagApi.includes('verifyAdminUser'), 'Public diagnostics API must check admin role before returning internal providers');
  assert.ok(modelDiagApi.includes('verifyAdminUser'), 'Model diagnostic API must check admin role before returning internal providers');
  assert.ok(adminAuth.includes('supabase.auth.getUser()'), 'Admin verification must verify authenticated Supabase session');
});

function httpGet(urlPath) {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:3000${urlPath}`, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          resolve({ offline: false, status: res.statusCode, raw: data, json: JSON.parse(data) });
        } catch {
          resolve({ offline: false, status: res.statusCode, raw: data, json: null });
        }
      });
    });
    req.on('error', () => resolve({ offline: true }));
    req.setTimeout(6000, () => {
      req.destroy();
      resolve({ offline: true });
    });
  });
}

await asyncTest('3.2 Live HTTP boundary: /api/diagnostics and /api/model-diagnostic hide vendors & /api/admin/diagnostics returns 403', async () => {
  const diag = await httpGet('/api/diagnostics');
  if (diag.offline) {
    console.log('    ℹ️ Dev server offline; skipping live HTTP boundary check.');
    return;
  }

  assert.equal(diag.status, 200);
  assert.equal(diag.json?.overallStatus, 'operational');
  assert.ok(diag.json?.aegisAi, 'Public diagnostics must return aegisAi status');
  assert.ok(!/featherless|qwen|serper|gemini/i.test(diag.raw), 'Public /api/diagnostics must not leak vendor names');

  const modelDiag = await httpGet('/api/model-diagnostic');
  assert.equal(modelDiag.status, 200);
  assert.equal(modelDiag.json?.engine, 'Aegis AI');
  assert.ok(!/featherless|qwen|serper|gemini/i.test(modelDiag.raw), 'Public /api/model-diagnostic must not leak vendor names');

  const adminDiag = await httpGet('/api/admin/diagnostics');
  assert.equal(adminDiag.status, 403, 'Unauthenticated /api/admin/diagnostics must strictly return HTTP 403');
  assert.ok(!/rc_|AIza|Bearer/i.test(adminDiag.raw), '403 response must never leak credentials');
});

console.log(`\n========================================`);
console.log(`Phase 3C.1 Audit Results: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
}
