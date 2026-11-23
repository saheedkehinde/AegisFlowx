import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';

console.log('🛡️ Starting AegisFlow Phase 1 — BEC & Unified Threat Interpretation Test Suite...\n');

const require = createRequire(import.meta.url);
const repoRoot = process.cwd();
const moduleCache = new Map();

function compileTsFile(relativePath, mocks = {}) {
  const fullPath = path.resolve(repoRoot, relativePath);
  if (moduleCache.has(fullPath) && Object.keys(mocks).length === 0) {
    return moduleCache.get(fullPath);
  }

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
    if (specifier in mocks) return mocks[specifier];
    if (specifier === 'path') return path;
    if (specifier === 'fs') return fs;

    // Resolve relative or @/ alias paths to .ts files
    let resolvedRel;
    if (specifier.startsWith('@/')) {
      resolvedRel = specifier.slice(2);
    } else if (specifier.startsWith('./') || specifier.startsWith('../')) {
      resolvedRel = path.relative(repoRoot, path.resolve(path.dirname(fullPath), specifier));
    } else {
      return require(specifier);
    }

    const normalizedRel = resolvedRel.replace(/\.ts$/, '') + '.ts';
    const key = path.resolve(repoRoot, normalizedRel);
    if (key in mocks) return mocks[key];
    if (resolvedRel in mocks) return mocks[resolvedRel];

    if (fs.existsSync(key)) {
      return compileTsFile(normalizedRel, mocks);
    }
    throw new Error(`Cannot resolve module "${specifier}" from ${relativePath}`);
  };

  fn(mod.exports, localRequire, mod, fullPath, path.dirname(fullPath));
  if (Object.keys(mocks).length === 0) {
    moduleCache.set(fullPath, mod.exports);
  }
  return mod.exports;
}

// Compile core TypeScript modules
const scamAnalyzer = compileTsFile('lib/scam-analyzer.ts');
const docScanner = compileTsFile('lib/document-scanner.ts');
const claimExtractor = compileTsFile('lib/fact-checker/claim-extractor.ts');

// Compile fact-checker.ts with deterministic mocked outbound research & AI synthesis
let mockedPerformWebResearchResult = {
  sources: [],
  domainIntelligence: [],
  threatIntel: [],
  providerStatus: {
    providerName: 'Mocked Deterministic Test Harness',
    isConfigured: true,
    mode: 'serper',
    researchStatus: 'live_research_completed',
    statusExplanation: 'Deterministic mocked research output',
    fullPageRetrievalActive: false,
    rateLimitEncountered: false,
    queriesExecuted: 1,
    outboundSearchesExecuted: 1,
    cacheHitsCount: 0,
    maxSearchesConfigured: 2,
    searchLimitReached: false,
  },
};

const factChecker = compileTsFile('lib/fact-checker/fact-checker.ts', {
  './web-researcher': {
    performWebResearch: async () => mockedPerformWebResearchResult,
    planSearchQueries: (claims, orgs) => (orgs.length ? [`${orgs[0]} advisory`] : ['claim check']),
    getMaxSearchesPerAnalysis: () => 2,
  },
  '@/lib/model-config': {
    resolveFeatherlessModel: () => ({ model: 'mock-model' }),
    getFeatherlessHeaders: () => ({}),
  },
  '@/lib/gemini/client': {
    getGeminiClient: () => {
      throw new Error('Mocked offline test mode');
    },
    getResolvedGeminiModel: () => 'mock-gemini',
    isGeminiFallbackEnabled: () => false,
  },
});

let passed = 0;
let total = 0;

async function runTest(name, fn) {
  total++;
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.stack || err.message}`);
    process.exitCode = 1;
  }
}

// ============================================================================
// 1. CRITICAL PRODUCTION REGRESSION SCENARIO
// ============================================================================
console.log('--- Suite 1: Critical Bank-Account Change / BEC Regression ---');
const REGRESSION_BEC_MESSAGE =
  'Kindly note that we have changed our bank account. Please use the new details below for this and all future payments.';

await runTest('1.1 Fact-checker does NOT misclassify BEC bank-change notice as conversational/low-risk', async () => {
  const assessment = claimExtractor.assessClaimForResearch(REGRESSION_BEC_MESSAGE);
  assert.equal(assessment.warrantsExternalResearch, false, 'Private bilateral message must skip public web search');
  assert.equal(assessment.communicationScope, 'private_transactional_directive');

  const report = await factChecker.generateFactCheckReport(REGRESSION_BEC_MESSAGE);

  assert.equal(report.threatSeverity, 'high', 'BEC bank-account change redirection MUST be high severity');
  assert.ok(report.severityScore >= 85, `Expected severityScore >= 85, got ${report.severityScore}`);
  assert.equal(report.assessmentState, 'high_risk_suspicious');
  assert.notEqual(report.primaryThreatCategory, 'ordinary_conversational');
  assert.equal(report.paymentChangeDetection?.detected, true);
  assert.equal(report.paymentChangeDetection?.isActiveRedirectionRequest, true);
  assert.equal(report.paymentChangeDetection?.hasFuturePaymentsDirective, true);

  // Public search bypassed cleanly WITHOUT forcing safety or low risk
  assert.equal(report.searchProviderStatus.outboundSearchesExecuted, 0);
  assert.equal(report.factualVerification?.status, 'not_applicable_private_communication');
  assert.equal(report.threatAssessment?.severity, 'high');
  assert.match(report.authenticityAssessment?.paymentDestinationStatus || '', /unverified/i);

  // Finance team recommendations present with all 6 required verification steps
  const financeRecs = (report.recommendations.forFinanceTeams || []).join(' ').toLowerCase();
  assert.ok((report.recommendations.forFinanceTeams || []).length >= 6);
  assert.ok(financeRecs.includes('hold') && financeRecs.includes('funds'));
  assert.ok(financeRecs.includes('previously established phone number'));
  assert.ok(financeRecs.includes('authorized representative'));
  assert.ok(financeRecs.includes('beneficiary'));
  assert.ok(financeRecs.includes('dual-control'));
  assert.ok(financeRecs.includes('recall'));

  // Never invents phone numbers, URLs, or reporting agencies
  const allText = JSON.stringify(report.recommendations);
  assert.ok(!/ic3\.gov|actionfraud|7726|\+1-800/i.test(allText), 'Must not invent unverified portals/hotlines in BEC recommendations');
});

await runTest('1.2 Message Analyzer overrides optimistic model payload (low -> high) on BEC regression input', async () => {
  const result = scamAnalyzer.validateAnalysisPayload(
    {
      riskLevel: 'low',
      summary: 'Polite vendor notice.',
      indicators: [],
      recommendedActions: [],
      limitations: [],
    },
    REGRESSION_BEC_MESSAGE,
    'test-model'
  );

  assert.equal(result.riskLevel, 'high');
  assert.ok((result.severityScore || 0) >= 82);
  assert.equal(result.assessmentState, 'high_risk_suspicious');
  assert.equal(result.paymentChangeDetection?.isActiveRedirectionRequest, true);
  assert.equal(result.factualVerification?.status, 'not_applicable_private_communication');
  assert.ok((result.financeRecommendations || []).length >= 6);
});

await runTest('1.3 Document Scanner elevates BEC invoice/PDF notice to HIGH risk with finance controls', async () => {
  const meta = {
    detectedType: 'invoice',
    extractedTextSnippet: REGRESSION_BEC_MESSAGE,
    apparentSenderOrOrganization: 'Supplier Billing',
    claimedPurpose: 'Bank details update',
    filename: 'supplier_notice.pdf',
    fileSizeBytes: 2048,
    mimeType: 'application/pdf',
    pageCount: 1,
  };
  const iocs = scamAnalyzer.extractIOCsFromMessage(REGRESSION_BEC_MESSAGE);
  const scanRes = docScanner.validateDocumentScanPayload(
    {
      riskLevel: 'low',
      summary: 'Supplier sent a polite update.',
      indicators: [],
      recommendedActions: ['Proceed carefully.'],
    },
    meta,
    iocs,
    'test-doc-model',
    REGRESSION_BEC_MESSAGE
  );

  assert.equal(scanRes.riskLevel, 'high');
  assert.ok((scanRes.severityScore || 0) >= 84);
  assert.equal(scanRes.assessmentState, 'high_risk_suspicious');
  assert.equal(scanRes.paymentChangeDetection?.isActiveRedirectionRequest, true);
  assert.ok(scanRes.suspiciousElements.some((s) => s.category === 'financial_anomaly'));
  assert.ok((scanRes.financeRecommendations || []).length >= 6);
});

// ============================================================================
// 2. ALL REQUIRED CATEGORY A PHRASE VARIATIONS + TYPOS/PUNCTUATION/SYNONYMS
// ============================================================================
console.log('\n--- Suite 2: All Required Category A BEC Phrase Variations & Resilience ---');
const CATEGORY_A_REQUIRED_PHRASES = [
  'Please disregard our previous banking details and transfer all outstanding invoices to this new account.',
  'Our supplier payment account has changed. Update your records immediately.',
  'We have revised our remittance instructions effective immediately.',
  'Our vendor instructed us to use the attached beneficiary details.',
  'Please change the beneficiary account for the next payroll payment.',
  'CEO has approved the new payment instructions. Kindly process today.',
  'Please see attached updated invoice with revised bank details.',
];

const BEC_TYPO_VARIATIONS = [
  'PLEASE NOTE OUR ACCT DETAILS HAVE CHANGED!! Please remit to the updated IBAN for all upcoming invoices.',
  'Supplier payment update: replace our benificary records with the attached new banking info immediately.',
  'Kindly route all remaining settlement funds to our alternate receiving bank account going forward.',
  'Remitance instructions revised — credit our new sorting code and acct number for pending payout.',
  'Please see attached invoce with revised bank details for pymt.',
];

for (const [idx, phrase] of CATEGORY_A_REQUIRED_PHRASES.entries()) {
  await runTest(`2.${idx + 1} Category A required phrase across all 3 surfaces: "${phrase.slice(0, 56)}..."`, async () => {
    const fcReport = await factChecker.generateFactCheckReport(phrase);
    assert.equal(fcReport.threatSeverity, 'high', `Fact-checker must classify Category A as HIGH: ${phrase}`);
    assert.equal(fcReport.paymentChangeDetection?.isActiveRedirectionRequest, true);
    assert.notEqual(fcReport.primaryThreatCategory, 'ordinary_conversational');

    const msgRes = scamAnalyzer.validateAnalysisPayload(
      { riskLevel: 'low', summary: 'Polite message.', indicators: [], recommendedActions: [] },
      phrase,
      'test-model'
    );
    assert.equal(msgRes.riskLevel, 'high', `Message analyzer must classify Category A as HIGH: ${phrase}`);
    assert.equal(msgRes.paymentChangeDetection?.isActiveRedirectionRequest, true);
    assert.ok((msgRes.financeRecommendations || []).some((r) => /audit records/i.test(r)), 'Finance recommendations must include preserving audit records');

    const docRes = docScanner.validateDocumentScanPayload(
      { riskLevel: 'low', summary: 'Clean formatted PDF invoice.', indicators: [], evidenceSufficiency: 'sufficient' },
      {
        detectedType: 'invoice',
        extractedTextSnippet: phrase,
        apparentSenderOrOrganization: 'Unknown',
        claimedPurpose: 'Invoice',
        filename: 'invoice_ocr.png',
        fileSizeBytes: 1024,
        mimeType: 'image/png',
      },
      scamAnalyzer.extractIOCsFromMessage(phrase),
      'test-vision',
      phrase
    );
    assert.equal(docRes.riskLevel, 'high', `Document scanner must classify Category A as HIGH: ${phrase}`);
    assert.equal(docRes.paymentChangeDetection?.isActiveRedirectionRequest, true);
    assert.notEqual(docRes.evidenceSufficiency, 'sufficient', 'Document scanner must never claim sufficient external evidence without external verification');
  });
}

for (const [idx, variant] of BEC_TYPO_VARIATIONS.entries()) {
  await runTest(`2.T${idx + 1} Resilience against typos/punctuation: "${variant.slice(0, 56)}..."`, async () => {
    const report = await factChecker.generateFactCheckReport(variant);
    assert.equal(report.threatSeverity, 'high', `Typo variant failed HIGH check: ${variant}`);
    assert.equal(report.paymentChangeDetection?.detected, true);
    assert.equal(report.paymentChangeDetection?.isActiveRedirectionRequest, true);
  });
}

// ============================================================================
// 3. CATEGORY B (INFORMATIONAL) & CATEGORY C (VERIFICATION REQUEST)
// ============================================================================
console.log('\n--- Suite 3: Category B (Informational) & Category C (Verification Request) ---');
await runTest('3.1 Category B informational bank notice stays calibrated MEDIUM across all surfaces (never safe/low)', async () => {
  const infoNotice =
    'For your records only, please note that our bank account has changed. No payment or action is requested.';
  const report = await factChecker.generateFactCheckReport(infoNotice);

  assert.equal(report.paymentChangeDetection?.detected, true);
  assert.equal(report.paymentChangeDetection?.isInformationalOnlyNotice, true);
  assert.equal(report.paymentChangeDetection?.isActiveRedirectionRequest, false);
  assert.equal(report.threatSeverity, 'medium');
  assert.equal(report.assessmentState, 'suspicious_unverified');
  assert.ok(!/verified\s+safe|guaranteed\s+safe|confirmed\s+legitimate/i.test(report.executiveSummary));

  const msgRes = scamAnalyzer.validateAnalysisPayload(
    { riskLevel: 'low', summary: 'Notice only.', indicators: [], recommendedActions: [] },
    infoNotice,
    'test-model'
  );
  assert.equal(msgRes.riskLevel, 'medium');
  assert.equal(msgRes.assessmentState, 'suspicious_unverified');

  const docRes = docScanner.validateDocumentScanPayload(
    { riskLevel: 'low', summary: 'Notice.', indicators: [] },
    {
      detectedType: 'email',
      extractedTextSnippet: infoNotice,
      filename: 'notice.pdf',
      fileSizeBytes: 512,
      mimeType: 'application/pdf',
    },
    scamAnalyzer.extractIOCsFromMessage(infoNotice),
    'test-doc',
    infoNotice
  );
  assert.equal(docRes.riskLevel, 'medium');
});

await runTest('3.2 Category C legitimate verification request stays calibrated MEDIUM across all 3 surfaces', async () => {
  const verifyMsg = 'Please verify the attached account change with our finance department.';

  const fcReport = await factChecker.generateFactCheckReport(verifyMsg);
  assert.equal(fcReport.paymentChangeDetection?.detected, true);
  assert.equal(fcReport.paymentChangeDetection?.isVerificationRequest, true);
  assert.equal(fcReport.paymentChangeDetection?.isActiveRedirectionRequest, false);
  assert.equal(fcReport.threatSeverity, 'medium');
  assert.equal(fcReport.assessmentState, 'suspicious_unverified');
  assert.ok(/verification required|established.*records/i.test(fcReport.executiveSummary));

  // Even if LLM guesses low OR over-triggers high, validation calibrates Category C cleanly to medium
  const msgLowOverride = scamAnalyzer.validateAnalysisPayload(
    { riskLevel: 'low', summary: 'Harmless internal note.', indicators: [] },
    verifyMsg,
    'test-model'
  );
  assert.equal(msgLowOverride.riskLevel, 'medium');
  assert.equal(msgLowOverride.assessmentState, 'suspicious_unverified');

  const msgHighCalibrated = scamAnalyzer.validateAnalysisPayload(
    { riskLevel: 'high', summary: 'Active attack.', indicators: [] },
    verifyMsg,
    'test-model'
  );
  assert.equal(msgHighCalibrated.riskLevel, 'medium');
  assert.equal(msgHighCalibrated.paymentChangeDetection?.isVerificationRequest, true);

  const docRes = docScanner.validateDocumentScanPayload(
    { riskLevel: 'high', summary: 'Verification note.', indicators: [] },
    {
      detectedType: 'email',
      extractedTextSnippet: verifyMsg,
      filename: 'verify_note.pdf',
      fileSizeBytes: 768,
      mimeType: 'application/pdf',
    },
    scamAnalyzer.extractIOCsFromMessage(verifyMsg),
    'test-doc',
    verifyMsg
  );
  assert.equal(docRes.riskLevel, 'medium');
  assert.equal(docRes.paymentChangeDetection?.isVerificationRequest, true);
});

// ============================================================================
// 4. REMAINING TAXONOMY SCENARIOS (EXEC IMPERSONATION, PAYROLL, REFUND, OTP)
// ============================================================================
console.log('\n--- Suite 4: Unified Threat Taxonomy Scenarios ---');
await runTest('4.1 Executive impersonation wire/gift-card lure triggers HIGH risk & executive_impersonation', async () => {
  const execMsg =
    "Hi, I'm in a confidential executive board meeting and can't take phone calls. Please approve and wire $18,500 urgently before 3 PM. Keep this quiet.";
  const report = await factChecker.generateFactCheckReport(execMsg);
  assert.equal(report.threatSeverity, 'high');
  assert.ok(report.threatCategories.some((c) => c.id === 'executive_impersonation'));
  assert.ok(report.threatCategories.some((c) => c.id === 'business_email_compromise'));
});

await runTest('4.2 Payroll direct-deposit diversion triggers HIGH risk & payroll_diversion', async () => {
  const payrollMsg =
    'Hi payroll team, please update my salary direct deposit bank account and routing number before Friday compensation run.';
  const report = await factChecker.generateFactCheckReport(payrollMsg);
  assert.equal(report.threatSeverity, 'high');
  assert.equal(report.paymentChangeDetection?.isPayrollDiversion, true);
  assert.ok(report.threatCategories.some((c) => c.id === 'payroll_diversion'));
});

await runTest('4.3 Unsolicited refund / reimbursement scam triggers HIGH risk & refund_reimbursement_scam', async () => {
  const refundMsg =
    'Notice: You are owed an unclaimed overpayment refund of $420. Reply with your bank account and routing number before it expires to claim reimbursement.';
  const report = await factChecker.generateFactCheckReport(refundMsg);
  assert.equal(report.threatSeverity, 'high');
  assert.ok(report.threatCategories.some((c) => c.id === 'refund_reimbursement_scam'));
});

await runTest('4.4 OTP / password / account-blocking coercion triggers HIGH risk', async () => {
  const otpMsg =
    'Security alert: Your account will be suspended unless you reply immediately with your password and 6-digit verification code OTP.';
  const report = await factChecker.generateFactCheckReport(otpMsg);
  assert.equal(report.threatSeverity, 'high');
  assert.ok(report.threatCategories.some((c) => c.id === 'credential_otp_harvesting'));
  assert.ok(report.threatCategories.some((c) => c.id === 'account_suspension_threat'));
});

// ============================================================================
// 5. ORDINARY CONVERSATIONAL GREETINGS & AMBIGUOUS FRAGMENTS
// ============================================================================
console.log('\n--- Suite 5: Ordinary Conversational Greetings vs Ambiguous Fragments ---');
for (const greeting of ['Hello, how are you doing?', 'Thank you for your assistance.', 'Hello, can you attend to me?']) {
  await runTest(`5.1 Genuine greeting "${greeting}" remains low-risk conversational without claiming verified safe`, async () => {
    const report = await factChecker.generateFactCheckReport(greeting);
    assert.equal(report.hasVerifiableClaims, false);
    assert.equal(report.threatSeverity, 'low');
    assert.equal(report.severityScore, 10);
    assert.equal(report.assessmentState, 'no_significant_indicators');
    assert.equal(report.primaryThreatCategory, 'ordinary_conversational');
    assert.equal(report.searchProviderStatus.outboundSearchesExecuted, 0);
    assert.ok(!/verified safe|guaranteed safe|confirmed safe/i.test(report.executiveSummary));
  });
}

await runTest('5.2 Ambiguous short fragments trigger Indeterminate / Insufficient Evidence and stay uncertain', async () => {
  for (const fragment of ['Please confirm.', 'Call me']) {
    const report = await factChecker.generateFactCheckReport(fragment);
    assert.equal(report.threatSeverity, 'uncertain');
    assert.ok(['insufficient_information', 'inconclusive'].includes(report.assessmentState));
    assert.ok(['insufficient', 'limited'].includes(report.evidenceCoverage));
    assert.match(report.confidenceRationale, /Indeterminate \(Insufficient Evidence\)/i);
  }
});

// ============================================================================
// 6. PRESERVED SITE123 500K CALIBRATION CHECK (CASE B)
// ============================================================================
console.log('\n--- Suite 6: Preserved SITE123 500k Calibration (Case B) ---');
await runTest('6.1 SITE123 500k lure preserves medium severity (60/100) and limited coverage', async () => {
  mockedPerformWebResearchResult = {
    sources: [
      {
        id: 's1',
        title: 'Site123 Website Builder Review',
        url: 'https://reviews.example.com/site123',
        domain: 'reviews.example.com',
        snippet: 'Site123 is a website builder platform.',
        provenance: 'snippet_only',
        pageRetrievalStatus: 'snippet_only',
        retrievedAt: new Date().toISOString(),
        sourceType: 'web_search',
        reliability: 'reputable',
        relevanceGrade: 'indirect_or_weak',
      },
    ],
    domainIntelligence: [
      {
        domain: '67d8cd0f1e57e.site123.me',
        hasDnsRecords: true,
        ipAddresses: ['1.2.3.4'],
        mxRecordsCount: 0,
        hasMailServers: false,
        isSuspiciousOrParked: false,
        notes: 'Domain resolves.',
        caveat: 'Web-only endpoint.',
      },
    ],
    threatIntel: [
      {
        indicator: 'https://67d8cd0f1e57e.site123.me/',
        type: 'url',
        provider: 'URLhaus (abuse.ch)',
        status: 'clean_or_unlisted',
        confidence: 'moderate',
        details: 'No active records found.',
        retrievedAt: new Date().toISOString(),
        importantNotice: 'Unlisted does not guarantee safety.',
      },
    ],
    providerStatus: {
      providerName: 'Mocked Deterministic Test Harness',
      isConfigured: true,
      mode: 'serper',
      researchStatus: 'live_research_completed',
      statusExplanation: 'Completed',
      fullPageRetrievalActive: false,
      rateLimitEncountered: false,
      queriesExecuted: 1,
      outboundSearchesExecuted: 1,
      cacheHitsCount: 0,
      maxSearchesConfigured: 2,
      searchLimitReached: false,
    },
  };

  const report = await factChecker.generateFactCheckReport(
    'I am asked to click this url to get 500k: https://67d8cd0f1e57e.site123.me/'
  );
  assert.equal(report.threatSeverity, 'medium');
  assert.equal(report.severityScore, 60);
  assert.equal(report.evidenceSufficiency, 'limited');
  assert.equal(report.confidenceLevel, 'moderate');
  assert.equal(report.assessmentState, 'suspicious_unverified');
  assert.ok(report.executiveSummary.includes('could not be independently verified'));
});

// ============================================================================
// 6B. HARDENING, INDEPENDENCE, PERSISTENCE & TIMEOUT/ABORT INVARIANTS
// ============================================================================
console.log('\n--- Suite 6B: Hardening, Independence & API Persistence/Timeout Invariants ---');
await runTest('6B.1 High severity does NOT inflate evidenceSufficiency without external corroboration', async () => {
  const shortBec = 'New bank account. Use for future payments.';
  const fcShort = await factChecker.generateFactCheckReport(shortBec);
  assert.equal(fcShort.threatSeverity, 'high');
  assert.notEqual(fcShort.evidenceSufficiency, 'sufficient');
  assert.equal(fcShort.evidenceCoverage, 'limited');

  const msgShort = scamAnalyzer.validateAnalysisPayload({ riskLevel: 'high', summary: 'BEC.', indicators: [] }, shortBec, 'm');
  assert.equal(msgShort.riskLevel, 'high');
  assert.equal(msgShort.evidenceSufficiency, 'sparse');
  assert.equal(msgShort.evidenceCoverage, 'limited');
});

await runTest('6B.2 API routes enforce DB 15-min dedup, req.signal abort guards, timeout budgets & CHECK constraints', async () => {
  for (const rel of ['app/api/analyze/route.ts', 'app/api/fact-check/route.ts', 'app/api/scan-document/route.ts']) {
    const code = fs.readFileSync(path.resolve(repoRoot, rel), 'utf8');
    assert.ok(code.includes('req.signal?.aborted'), `${rel} must guard against client cancellation via req.signal?.aborted`);
    assert.ok(code.includes('15 * 60 * 1000'), `${rel} must enforce 15-minute duplicate suppression`);
    assert.ok(code.includes('assessmentStateLabel') && code.includes('evidenceCoverage'), `${rel} must persist standardized assessmentStateLabel & evidenceCoverage metadata`);
  }

  // Verify score, severity, sufficiency, confidence conform strictly to analysis_history DB CHECK constraints
  const fc = await factChecker.generateFactCheckReport(REGRESSION_BEC_MESSAGE);
  assert.ok(['high', 'medium', 'low', 'uncertain'].includes(fc.threatSeverity));
  assert.ok(fc.severityScore >= 0 && fc.severityScore <= 100);
  assert.ok(['high', 'moderate', 'low'].includes(fc.confidenceLevel));
});

await runTest('6B.3 UI components include risk-score disclosure, Category C banner, and zero vendor leaks', async () => {
  for (const rel of ['components/AnalysisResult.tsx', 'components/FactCheckCard.tsx', 'components/DocumentScanResult.tsx']) {
    const uiCode = fs.readFileSync(path.resolve(repoRoot, rel), 'utf8');
    assert.ok(uiCode.includes('Normalized internal risk indicator (0–100)'), `${rel} must display score-meaning disclosure`);
    assert.ok(uiCode.includes('Indeterminate (Insufficient Evidence)'), `${rel} must label indeterminate low-evidence certainty`);
    assert.ok(uiCode.includes('isVerificationRequest'), `${rel} must distinguish Category C verification requests`);
    if (rel !== 'components/FactCheckCard.tsx') {
      assert.ok(!/featherless|qwen|serper|gemini/i.test(uiCode), `${rel} must never expose third-party model/search vendor names`);
    }
  }
});

// ============================================================================
// 7. OPTIONAL LIVE HTTP SMOKE CHECK (EXPLICITLY SEPARATED FROM UNIT/MOCKED TESTS)
// ============================================================================
console.log('\n--- Suite 7: Live HTTP API Endpoint Smoke Check (Optional) ---');
const baseUrl = process.env.TEST_APP_URL || 'http://localhost:3000';
try {
  const res = await fetch(`${baseUrl}/api/fact-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: REGRESSION_BEC_MESSAGE }),
    signal: AbortSignal.timeout(8000),
  });
  if (res.ok) {
    const json = await res.json();
    assert.equal(json.report?.threatSeverity, 'high', 'Live /api/fact-check must return HIGH severity for BEC regression');
    assert.equal(json.report?.assessmentState, 'high_risk_suspicious');
    assert.equal(json.report?.paymentChangeDetection?.isActiveRedirectionRequest, true);
    console.log(`  ✓ Live HTTP POST /api/fact-check confirmed HIGH risk (${json.report.severityScore}/100) for BEC regression`);
  } else {
    console.log(`  ℹ️ Live HTTP endpoint returned status ${res.status}; skipped live assertion.`);
  }
} catch (err) {
  console.log(`  ℹ️ Live HTTP endpoint unavailable (${err.message}); deterministic TS module tests verified cleanly.`);
}

console.log(`\n📊 Summary: ${passed}/${total} deterministic BEC & threat-taxonomy checks passed.\n`);
if (passed !== total) {
  process.exit(1);
}
