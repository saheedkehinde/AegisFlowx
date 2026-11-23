import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import ts from 'typescript';

console.log('🧪 Starting AegisFlow Phase 2A — URL Investigation & Vault Data Integrity Test Suite...\n');

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
    throw new Error(`Unexpected require("${specifier}") in ${relativePath}`);
  };

  fn(mod.exports, localRequire, mod, fullPath, path.dirname(fullPath));
  return mod.exports;
}

// Compile actual production TypeScript modules
const vaultNorm = compileTsModule('lib/vault-normalization.ts');

// Mock browser storage + React.useSyncExternalStore to test actual lib/session-store.ts
const storageMap = new Map();
const listeners = new Map();

globalThis.window = {
  addEventListener(type, cb) {
    if (!listeners.has(type)) listeners.set(type, new Set());
    listeners.get(type).add(cb);
  },
  removeEventListener(type, cb) {
    listeners.get(type)?.delete(cb);
  },
  dispatchEvent(ev) {
    const type = ev?.type || ev;
    for (const cb of listeners.get(type) || []) cb();
  },
};
globalThis.Event = class Event {
  constructor(type) {
    this.type = type;
  }
};
globalThis.sessionStorage = {
  getItem: (k) => (storageMap.has(k) ? storageMap.get(k) : null),
  setItem: (k, v) => storageMap.set(k, String(v)),
  removeItem: (k) => storageMap.delete(k),
};

const sessionStore = compileTsModule('lib/session-store.ts', {
  react: {
    useSyncExternalStore: (_sub, getSnapshot) => getSnapshot(),
  },
  './vault-normalization': vaultNorm,
  './scam-analyzer': {},
});

// =========================================================================
// 1. String-based URL indicators
// =========================================================================
test('1. Normalizes legacy string[] URL indicators cleanly without inventing evidence', () => {
  const result = vaultNorm.normalizeIndicators([
    '[HOSTNAME] Brand Impersonation: Uses lookalike hyphenated domain',
    '[PROTOCOL] Unencrypted Transport: Link uses plain http:// instead of https://',
    'Plain standalone string indicator',
  ]);

  assert.equal(result.length, 3);
  assert.deepEqual(result[0], {
    name: '[HOSTNAME] Brand Impersonation',
    evidence: '',
    reason: 'Uses lookalike hyphenated domain',
  });
  assert.deepEqual(result[1], {
    name: '[PROTOCOL] Unencrypted Transport',
    evidence: '',
    reason: 'Link uses plain http:// instead of https://',
  });
  assert.deepEqual(result[2], {
    name: 'Plain standalone string indicator',
    evidence: '',
    reason: '',
  });
});

// =========================================================================
// 2. Structured indicator objects (ThreatIndicator & UrlIndicatorItem)
// =========================================================================
test('2. Normalizes structured ThreatIndicator and UrlIndicatorItem objects', () => {
  const result = vaultNorm.normalizeIndicators([
    {
      name: 'Artificial Urgency',
      evidence: 'Act within 2 hours or lose access',
      reason: 'Pressures victim to bypass verification.',
    },
    {
      id: 'ind-url-1',
      category: 'reputation',
      severity: 'high',
      title: 'Confirmed Malware Distribution Host',
      description: 'Host matched active phishing feeds.',
      evidence: 'http://login-verify.example.invalid/auth',
    },
  ]);

  assert.equal(result.length, 2);
  assert.deepEqual(result[0], {
    name: 'Artificial Urgency',
    evidence: 'Act within 2 hours or lose access',
    reason: 'Pressures victim to bypass verification.',
  });
  assert.deepEqual(result[1], {
    name: '[REPUTATION] Confirmed Malware Distribution Host',
    evidence: 'http://login-verify.example.invalid/auth',
    reason: 'Host matched active phishing feeds.',
  });
});

// =========================================================================
// 3. Missing optional indicator fields
// =========================================================================
test('3. Handles partial indicator objects with missing optional fields safely', () => {
  const result = vaultNorm.normalizeIndicators([
    { name: 'Domain Age Anomaly' },
    { name: 'Missing Reason', evidence: 'https://bit.ly/3x', reason: undefined },
    { title: 'Suspicious TLD', category: 'hostname' },
    { evidence: 'Direct IP literal URL 198.51.100.42' },
  ]);

  assert.equal(result.length, 4);
  assert.deepEqual(result[0], { name: 'Domain Age Anomaly', evidence: '', reason: '' });
  assert.deepEqual(result[1], { name: 'Missing Reason', evidence: 'https://bit.ly/3x', reason: '' });
  assert.deepEqual(result[2], { name: '[HOSTNAME] Suspicious TLD', evidence: '', reason: '' });
  assert.deepEqual(result[3], {
    name: 'Threat Indicator',
    evidence: 'Direct IP literal URL 198.51.100.42',
    reason: '',
  });
});

// =========================================================================
// 4. Legacy guest records without inputType
// =========================================================================
test('4. Normalizes legacy guest sessionStorage records lacking inputType and mixed text/snippet fields', () => {
  storageMap.clear();
  const legacyRecords = [
    {
      id: 'legacy-url-1',
      timestamp: '10:15 AM',
      snippet: '[URL] https://secure-login-update.example.com',
      riskLevel: 'high',
      severityScore: 88,
      model: 'Aegis AI URL Intelligence',
      indicatorsCount: 2,
      summary: 'High risk phishing link.',
    },
    {
      id: 'legacy-doc-1',
      timestamp: '10:12 AM',
      snippet: '[invoice_2026.pdf] Requesting immediate wire transfer.',
      riskLevel: 'high',
      severityScore: 81,
      model: 'Aegis AI',
      indicatorsCount: 1,
      summary: 'Suspicious PDF invoice.',
    },
    {
      id: 'legacy-shot-1',
      timestamp: '10:10 AM',
      snippet: '[bank_alert.png] Fake SMS screenshot.',
      riskLevel: 'medium',
      severityScore: 60,
      model: 'Aegis AI',
      indicatorsCount: 1,
      summary: 'Suspicious screenshot.',
    },
    {
      id: 'legacy-msg-text-1',
      timestamp: '10:05 AM',
      text: 'Your payroll password expires today, click here.',
      riskLevel: 'medium',
      severityScore: 55,
      summary: 'Credential lure.',
      indicators: ['Urgency phrasing'],
    },
  ];

  globalThis.sessionStorage.setItem('aegisflow_recent_analyses_v1', JSON.stringify(legacyRecords));
  const loaded = sessionStore.getSessionAnalyses();
  assert.equal(loaded.length, 4);
  assert.equal(loaded[0].inputType, 'url_investigation');
  assert.equal(loaded[1].inputType, 'document');
  assert.equal(loaded[2].inputType, 'screenshot');
  assert.equal(loaded[3].inputType, 'message');
  assert.equal(loaded[3].snippet, 'Your payroll password expires today, click here.');
  assert.deepEqual(loaded[3].indicators, [{ name: 'Urgency phrasing', evidence: '', reason: '' }]);

  const hookSnap = sessionStore.useSessionAnalyses();
  assert.equal(hookSnap.length, 4);
  assert.equal(sessionStore.useSessionAnalyses(), hookSnap, 'useSessionAnalyses snapshot must preserve reference equality');
});

// =========================================================================
// 5 & 6. Database records using input_type: 'message' and legacy 'text'
// =========================================================================
test('5 & 6. Normalizes DB records with input_type "message", legacy "text", and empty/unknown types', () => {
  const msgDbRow = vaultNorm.normalizeAnalysisHistoryRecord({
    id: 'db-msg-1',
    user_id: 'user-1',
    input_type: 'message',
    input_snippet: 'Hi, urgent wire transfer needed.',
    threat_severity: 'high',
    severity_score: 90,
    summary: 'BEC wire fraud attempt.',
    indicators: [{ name: 'BEC Urgency', evidence: 'urgent wire', reason: 'Financial pressure.' }],
    recommended_actions: ['Verify by phone'],
    limitations: [],
    evidence_sufficiency: 'sufficient',
    model_confidence: 'high',
    created_at: '2026-03-01T12:00:00.000Z',
  });

  const legacyTextDbRow = vaultNorm.normalizeAnalysisHistoryRecord({
    id: 'db-text-1',
    user_id: 'user-1',
    input_type: 'text',
    text: 'Legacy text column message',
    threat_severity: 'medium',
    severity_score: 52,
    summary: 'Legacy text record',
    indicators: ['Legacy string indicator'],
    created_at: '2026-02-01T12:00:00.000Z',
  });

  const unknownDbRow = vaultNorm.normalizeAnalysisHistoryRecord({
    id: 'db-unk-1',
    user_id: 'user-1',
    input_type: 'telemetry_export_v0',
    input_snippet: 'Custom unmapped entry',
    threat_severity: 'low',
    severity_score: 10,
    summary: 'Safe legacy export',
    indicators: null,
    created_at: '2026-02-02T12:00:00.000Z',
  });

  assert.equal(msgDbRow.input_type, 'message');
  assert.equal(legacyTextDbRow.input_type, 'message');
  assert.equal(legacyTextDbRow.input_snippet, 'Legacy text column message');
  assert.equal(unknownDbRow.input_type, 'unknown');
  assert.deepEqual(unknownDbRow.indicators, []);
});

// =========================================================================
// 7. URL, message, and document filters (Vault & Dashboard)
// =========================================================================
test('7. Vault and Dashboard filters accurately classify URLs, messages, documents, screenshots, and fact-checks', () => {
  const urlRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: '1',
    input_type: 'url_investigation',
    input_snippet: '[URL] https://phish.example.com',
    threat_severity: 'high',
    summary: 'Phishing URL',
    indicators: ['[HOSTNAME] Brand Spoof: Imitates bank'],
  });
  const msgRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: '2',
    input_type: 'message',
    input_snippet: 'Verify OTP code 1234',
    threat_severity: 'medium',
    summary: 'OTP lure',
  });
  const docRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: '3',
    input_type: 'document',
    input_snippet: '[PDF: invoice.pdf] Wire request',
    threat_severity: 'high',
    summary: 'Fraudulent PDF',
  });
  const shotRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: '4',
    input_type: 'screenshot',
    input_snippet: '[PNG: alert.png] Fake security warning',
    threat_severity: 'high',
    summary: 'Tech support scam',
  });
  const factRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: '5',
    input_type: 'fact_check',
    input_snippet: '[Fact-Check] Bank announced zero fees',
    threat_severity: 'low',
    summary: 'Claim verified',
  });
  const legacyTextRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: '6',
    input_type: 'text',
    input_snippet: 'Legacy text record',
    threat_severity: 'low',
    summary: 'Low risk text',
  });

  assert.equal(vaultNorm.matchesVaultTypeFilter(msgRecord, 'message'), true);
  assert.equal(vaultNorm.matchesVaultTypeFilter(legacyTextRecord, 'message'), true);
  assert.equal(vaultNorm.matchesVaultTypeFilter(msgRecord, 'text'), true, 'Legacy "text" filter value aliases to "message"');
  assert.equal(vaultNorm.matchesVaultTypeFilter(docRecord, 'message'), false, 'Documents must never match Messages');
  assert.equal(vaultNorm.matchesVaultTypeFilter(shotRecord, 'message'), false, 'Screenshots must never match Messages');
  assert.equal(vaultNorm.matchesVaultTypeFilter(factRecord, 'message'), false, 'Fact-checks must never match Messages');
  assert.equal(vaultNorm.matchesVaultTypeFilter(urlRecord, 'url_investigation'), true);
  assert.equal(vaultNorm.matchesVaultTypeFilter(docRecord, 'document'), true);
  assert.equal(vaultNorm.matchesVaultTypeFilter(shotRecord, 'screenshot'), true);
  assert.equal(vaultNorm.matchesVaultTypeFilter(factRecord, 'fact_check'), true);

  const guestDoc = {
    id: 'g-doc',
    snippet: '[invoice.pdf] Wire request',
    riskLevel: 'high',
    severityScore: 80,
    model: 'Aegis AI',
    indicatorsCount: 1,
    summary: 'Invoice scam',
    inputType: 'document',
    timestamp: '12:00',
  };
  const guestShot = {
    id: 'g-shot',
    snippet: '[screen.png] Alert',
    riskLevel: 'medium',
    severityScore: 50,
    model: 'Aegis AI',
    indicatorsCount: 0,
    summary: 'Screenshot',
    inputType: 'screenshot',
    timestamp: '12:01',
  };
  const guestMsg = {
    id: 'g-msg',
    snippet: 'Urgent password reset',
    riskLevel: 'medium',
    severityScore: 60,
    model: 'Aegis AI',
    indicatorsCount: 0,
    summary: 'Message',
    inputType: 'message',
    timestamp: '12:02',
  };
  const guestUrl = {
    id: 'g-url',
    snippet: '[URL] https://bad.example.com',
    riskLevel: 'high',
    severityScore: 95,
    model: 'Aegis AI URL Intelligence',
    indicatorsCount: 1,
    summary: 'URL',
    inputType: 'url_investigation',
    timestamp: '12:03',
  };

  assert.equal(vaultNorm.matchesDashboardFilter(guestDoc, 'message'), false, 'Guest document must not match Messages filter');
  assert.equal(vaultNorm.matchesDashboardFilter(guestShot, 'message'), false, 'Guest screenshot must not match Messages filter');
  assert.equal(vaultNorm.matchesDashboardFilter(guestUrl, 'message'), false);
  assert.equal(vaultNorm.matchesDashboardFilter(guestMsg, 'message'), true);
  assert.equal(vaultNorm.matchesDashboardFilter(guestDoc, 'document'), true);
  assert.equal(vaultNorm.matchesDashboardFilter(guestShot, 'document'), true);
  assert.equal(vaultNorm.matchesDashboardFilter(guestUrl, 'url'), true);
  assert.equal(vaultNorm.matchesDashboardFilter(guestDoc, 'high'), true);
});

// =========================================================================
// 8. Empty or malformed indicator / record data
// =========================================================================
test('8. Handles empty, null, undefined, and malformed indicator/storage inputs safely', () => {
  assert.deepEqual(vaultNorm.normalizeIndicators(null), []);
  assert.deepEqual(vaultNorm.normalizeIndicators(undefined), []);
  assert.deepEqual(vaultNorm.normalizeIndicators('not-an-array'), []);
  assert.deepEqual(vaultNorm.normalizeIndicators(42), []);
  assert.deepEqual(vaultNorm.normalizeIndicators({}), []);
  assert.deepEqual(
    vaultNorm.normalizeIndicators([null, undefined, 123, true, [], {}, '   ']),
    []
  );

  assert.equal(vaultNorm.normalizeAnalysisHistoryRecord(null), null);
  assert.equal(vaultNorm.normalizeAnalysisHistoryRecord([]), null);
  assert.equal(vaultNorm.normalizeAnalysisHistoryRecord('bad'), null);

  storageMap.clear();
  globalThis.sessionStorage.setItem('aegisflow_recent_analyses_v1', '{not valid json');
  assert.deepEqual(sessionStore.getSessionAnalyses(), []);

  globalThis.sessionStorage.setItem('aegisflow_recent_analyses_v1', JSON.stringify({ not: 'an-array' }));
  assert.deepEqual(sessionStore.getSessionAnalyses(), []);
});

// =========================================================================
// 9. Vault search filtering & end-to-end persistence shape verification
// =========================================================================
test('9. Vault search filtering works seamlessly across legacy string[] and structured indicators without crashing', () => {
  const legacyUrlRecord = vaultNorm.normalizeAnalysisHistoryRecord({
    id: 'url-legacy-99',
    input_type: 'url_investigation',
    input_snippet: '[URL] https://apple-support-verify.example.invalid',
    threat_severity: 'high',
    severity_score: 92,
    summary: 'Phishing infrastructure imitating device support portal.',
    indicators: [
      '[HOSTNAME] Brand Impersonation Signal: Domain contains apple-support keywords on unrelated host',
      'Missing DMARC record on domain',
    ],
    iocs: {
      urls: ['https://apple-support-verify.example.invalid'],
    },
    created_at: '2026-03-10T08:00:00.000Z',
  });

  assert.equal(vaultNorm.matchesVaultSearchQuery(legacyUrlRecord, 'Brand Impersonation'), true);
  assert.equal(vaultNorm.matchesVaultSearchQuery(legacyUrlRecord, 'unrelated host'), true);
  assert.equal(vaultNorm.matchesVaultSearchQuery(legacyUrlRecord, 'DMARC'), true);
  assert.equal(vaultNorm.matchesVaultSearchQuery(legacyUrlRecord, 'apple-support-verify'), true);
  assert.equal(vaultNorm.matchesVaultSearchQuery(legacyUrlRecord, 'nonexistent-ioc-token'), false);
  assert.equal(vaultNorm.matchesVaultSearchQuery(legacyUrlRecord, ''), true);

  storageMap.clear();
  const savedAfterUrl = sessionStore.saveSessionUrlInvestigation({
    id: 'url-rep-1',
    urlComponents: { rawUrl: 'https://login-check.example.com', displayUrl: 'https://login-check.example.com' },
    overallSeverity: 'high',
    severityScore: 85,
    modelUsed: 'Aegis AI URL Intelligence',
    indicators: [
      {
        id: 'u1',
        category: 'hostname',
        severity: 'high',
        title: 'Credential Lure Keyword',
        description: 'Contains login keyword.',
        evidence: 'login-check',
      },
    ],
    executiveSummary: 'High risk URL.',
  });
  assert.equal(savedAfterUrl[0].inputType, 'url_investigation');
  assert.deepEqual(savedAfterUrl[0].indicators, [
    {
      name: '[HOSTNAME] Credential Lure Keyword',
      evidence: 'login-check',
      reason: 'Contains login keyword.',
    },
  ]);

  const savedAfterDoc = sessionStore.saveSessionAnalysis(
    {
      riskLevel: 'medium',
      severityScore: 62,
      confidence: 'moderate',
      confidenceRationale: 'Heuristic cues.',
      summary: 'Suspicious PDF attachment.',
      indicators: [{ name: 'Macro Prompt', evidence: 'Enable Content', reason: 'Social engineering' }],
      recommendedActions: ['Verify sender'],
      limitations: [],
      evidenceSufficiency: 'moderate',
      iocs: { urls: [], emails: [], phoneNumbers: [], keywords: [] },
      model: 'Aegis AI',
      analyzedAt: '11:00 AM',
      documentContent: { mimeType: 'application/pdf', filename: 'wire.pdf' },
    },
    '[wire.pdf] Suspicious PDF attachment.',
    'document'
  );
  assert.equal(savedAfterDoc[0].inputType, 'document');
});

test('10. Source integration invariants: route persistence, Vault tabs, and Dashboard filters are wired cleanly', () => {
  const urlRouteSrc = fs.readFileSync(path.join(repoRoot, 'app/api/url-investigation/route.ts'), 'utf8');
  assert.ok(
    urlRouteSrc.includes('normalizeIndicators(report.indicators)'),
    'app/api/url-investigation/route.ts must persist structured indicators via normalizeIndicators'
  );

  const vaultPageSrc = fs.readFileSync(path.join(repoRoot, 'app/investigations/page.tsx'), 'utf8');
  assert.ok(
    vaultPageSrc.includes("id: 'message'") && !vaultPageSrc.includes("id: 'text'"),
    'Investigation Vault filter tabs must use canonical id: "message"'
  );
  assert.ok(
    vaultPageSrc.includes('normalizeAnalysisHistoryRecord') &&
      vaultPageSrc.includes('matchesVaultTypeFilter') &&
      vaultPageSrc.includes('matchesVaultSearchQuery'),
    'Investigation Vault must use shared normalization and filtering helpers'
  );

  const recentCasesSrc = fs.readFileSync(
    path.join(repoRoot, 'components/dashboard/RecentInvestigations.tsx'),
    'utf8'
  );
  assert.ok(
    recentCasesSrc.includes('matchesDashboardFilter') &&
      recentCasesSrc.includes("setFilterType('document')"),
    'RecentInvestigations must use matchesDashboardFilter and expose document filtering'
  );
});

console.log(`\n📊 Vault Data Integrity Results: ${passedTests}/${totalTests} passed.`);
if (passedTests !== totalTests) {
  process.exit(1);
}
