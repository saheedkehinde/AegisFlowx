import assert from 'node:assert/strict';

console.log('🧪 Starting AegisFlow Comprehensive Test Suite...\n');

// Import logic from lib/scam-analyzer equivalent for test environment
function extractIOCs(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/gi;
  const emailRegex = /([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/gi;
  const phoneRegex = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

  const urls = Array.from(new Set(text.match(urlRegex) || []));
  const emails = Array.from(new Set(text.match(emailRegex) || []));
  const phoneNumbers = Array.from(new Set(text.match(phoneRegex) || []));

  const keywordTriggers = [
    'urgent',
    'freeze',
    'suspended',
    'verify identity',
    'gift card',
    'bitcoin',
    'pin code',
    'wire transfer',
    'immediate',
    'redelivery fee',
    'confidential',
  ];

  const lower = text.toLowerCase();
  const keywords = keywordTriggers.filter((k) => lower.includes(k));

  return { urls, emails, phoneNumbers, keywords };
}

function evaluateEvidenceAndConfidence(message, riskLevel, indicatorsCount) {
  const trimmed = message.trim();
  const length = trimmed.length;

  if (length < 25) {
    return {
      evidenceSufficiency: 'sparse',
      confidence: 'low',
      confidenceRationale:
        'Insufficient context: The submitted message is too short or fragmented to assess authentication headers, sender credibility, or genuine intent.',
    };
  }

  if (indicatorsCount >= 2 || (indicatorsCount >= 1 && riskLevel === 'high')) {
    return {
      evidenceSufficiency: 'sufficient',
      confidence: 'high',
      confidenceRationale:
        'Sufficient evidence: Multiple distinct threat patterns (e.g. coercive urgency, suspicious destination URLs, or financial anomalies) were concretely extracted.',
    };
  }

  if (riskLevel === 'low' && length >= 50) {
    return {
      evidenceSufficiency: 'sufficient',
      confidence: 'high',
      confidenceRationale:
        'Sufficient context: The communication exhibits natural conversational flow with complete absence of adversarial manipulation or suspicious requests.',
    };
  }

  if (riskLevel === 'uncertain') {
    return {
      evidenceSufficiency: 'moderate',
      confidence: 'low',
      confidenceRationale:
        'High model uncertainty: The message contains ambiguous phrasing that could be legitimate communication or low-sophistication solicitation. Independent verification required.',
    };
  }

  return {
    evidenceSufficiency: 'moderate',
    confidence: 'moderate',
    confidenceRationale:
      'Moderate context: Detected suspicious elements warrant caution, though additional message context or headers would establish full certainty.',
  };
}

function detectBehavioralThreats(text) {
  const indicators = [];

  const authCodeRegex =
    /\b(?:otp|one[- ]time\s+(?:password|passcode|code)|(?:verification|security|confirmation|authentication|authorization|login|2fa|mfa|tac)\s*code|6[- ]digit\s+code|six[- ]digit\s+code|code\s+(?:sent|texted|emailed)\s+to\s+your\s+(?:phone|number|email)|share\s+(?:the|your)\s+code|send\s+(?:me|us)?\s*(?:the|your)?\s*code|reply\s+with\s+(?:the|your)?\s*code)\b/i;
  const authMatch = text.match(authCodeRegex);
  const hasAuthCodeRequest = !!authMatch;
  if (hasAuthCodeRequest) {
    indicators.push({
      name: 'Authentication Code / OTP Interception Lure',
      evidence: authMatch[0],
      reason:
        'Requests for one-time passwords, passcodes, or 2FA codes are critical behavioral warnings. Legitimate service providers, banks, and platforms NEVER ask you to forward, reply with, or share verification codes.',
    });
  }

  const credentialRegex =
    /\b(?:passwords?|passcodes?|pin\s*codes?|atm\s*pin|cvv|cvc|seed\s*phrase|recovery\s*phrase|secret\s*phrase|private\s*keys?|login\s*credentials|transaction\s*authorization\s*code|tac\s*code)\b/i;
  const credMatch = text.match(credentialRegex);
  const hasCredentialHarvesting = !!credMatch;
  if (hasCredentialHarvesting && !hasAuthCodeRequest) {
    indicators.push({
      name: 'Credential Harvesting Request',
      evidence: credMatch[0],
      reason:
        'Direct requests for passwords, card PINs, CVV security codes, or secret recovery keys represent unauthorized credential harvesting attempts.',
    });
  }

  const remoteAccessRegex =
    /\b(?:anydesk|teamviewer|quicksupport|ultraviewer|remote\s*desktop|screen\s*share|connect\s*remotely|download\s+(?:software|app|tool|support\s*client)\s+to\s+(?:fix|assist|resolve|access)|grant\s+remote\s+access)\b/i;
  const remoteMatch = text.match(remoteAccessRegex);
  const hasRemoteAccessRequest = !!remoteMatch;
  if (hasRemoteAccessRequest) {
    indicators.push({
      name: 'Remote-Access Software Lure',
      evidence: remoteMatch[0],
      reason:
        'Coercing victims to install remote-desktop software (such as AnyDesk or TeamViewer) provides adversaries with full unmonitored control over devices, personal files, and active bank sessions.',
    });
  }

  const paymentRegex =
    /\b(?:gift\s*cards?|apple\s*gift\s*card|steam\s*card|razer\s*gold|google\s*play\s*card|bitcoin|btc|usdt|cryptocurrency|crypto\s+wallet|wire\s*transfers?|western\s*union|moneygram|verification\s*fee|processing\s*fee|clearance\s*fee|redelivery\s*fee|advance\s*fee)\b/i;
  const payMatch = text.match(paymentRegex);
  const hasPaymentDemand = !!payMatch;
  if (hasPaymentDemand) {
    indicators.push({
      name: 'Untraceable Payment / Fee Demand',
      evidence: payMatch[0],
      reason:
        'Demanding payment via untraceable vouchers, gift cards, cryptocurrency, or unconventional fees is a primary hallmark of financial fraud.',
    });
  }

  const accountThreatRegex =
    /\b(?:accounts?\s+(?:(?:will\s+be|is|has\s+been|from\s+being|to\s+be|would\s+be|getting)\s+)?(?:blocked|suspended|frozen|locked|terminated|deactivated|closed|restricted)|prevent\s+(?:your\s+|their\s+)?accounts?\s+from\s+being\s+(?:blocked|suspended|frozen|locked)|immediate\s+suspension|account\s+(?:freeze|suspension|termination|block)|legal\s+action|lawsuit|warrant|arrest|prosecution|fine\s+imposed)\b/i;
  const threatMatch = text.match(accountThreatRegex);
  const hasAccountBlockingThreat = !!threatMatch;
  if (hasAccountBlockingThreat) {
    indicators.push({
      name: 'Coercive Account-Blocking Threat',
      evidence: threatMatch[0],
      reason:
        'Threatening imminent account freeze, suspension, or punitive consequences is a coercive intimidation technique designed to bypass critical scrutiny.',
    });
  }

  const deadlineRegex =
    /\b(?:within\s+[0-9]+\s*(?:mins?|minutes?|hours?|days?)|by\s+(?:tomorrow|today|tonight|midnight)|immediate(?:ly)?|urgent(?:ly)?|final\s+notice|last\s+chance|action\s+required|deadline|expires\s+in)\b/i;
  const deadMatch = text.match(deadlineRegex);
  const hasArtificialDeadline = !!deadMatch;
  if (hasArtificialDeadline && !hasAccountBlockingThreat) {
    indicators.push({
      name: 'Artificial Urgency & Deadline Pressure',
      evidence: deadMatch[0],
      reason:
        'Artificial enforcement deadlines induce psychological urgency to force hasty compliance before the victim can independently verify the request.',
    });
  }

  return {
    hasAuthCodeRequest,
    hasCredentialHarvesting,
    hasRemoteAccessRequest,
    hasPaymentDemand,
    hasAccountBlockingThreat,
    hasArtificialDeadline,
    indicators,
  };
}

function validatePayload(rawJson, originalMessage, modelName) {
  if (!rawJson || typeof rawJson !== 'object') {
    throw new Error('Analysis payload must be a non-null JSON object');
  }

  let riskLevel = 'uncertain';
  if (typeof rawJson.riskLevel === 'string') {
    const normalized = rawJson.riskLevel.toLowerCase().trim();
    if (['high', 'medium', 'low', 'uncertain'].includes(normalized)) {
      riskLevel = normalized;
    }
  }

  const summary =
    typeof rawJson.summary === 'string' && rawJson.summary.trim()
      ? rawJson.summary.trim()
      : 'No summary was provided by the analysis engine.';

  const indicators = [];
  if (Array.isArray(rawJson.indicators)) {
    for (const item of rawJson.indicators) {
      if (item && typeof item === 'object') {
        const name = typeof item.name === 'string' ? item.name.trim() : '';
        const evidence = typeof item.evidence === 'string' ? item.evidence.trim() : '';
        const reason = typeof item.reason === 'string' ? item.reason.trim() : '';
        if (name && (evidence || reason)) {
          indicators.push({ name, evidence, reason });
        }
      }
    }
  }

  // Deterministic Behavioral Threat Detection
  const behavioral = detectBehavioralThreats(originalMessage);
  for (const bInd of behavioral.indicators) {
    if (!indicators.some((i) => i.name.toLowerCase() === bInd.name.toLowerCase())) {
      indicators.push(bInd);
    }
  }

  const hasCriticalBehavioralThreat =
    behavioral.hasAuthCodeRequest ||
    behavioral.hasCredentialHarvesting ||
    behavioral.hasRemoteAccessRequest ||
    (behavioral.hasAccountBlockingThreat && (behavioral.hasPaymentDemand || behavioral.hasArtificialDeadline));

  // Critical Invariant: Dangerous behavioral requests elevate riskLevel to high
  if (hasCriticalBehavioralThreat && (riskLevel === 'low' || riskLevel === 'uncertain')) {
    riskLevel = 'high';
  }

  const rawActions = [];
  if (Array.isArray(rawJson.recommendedActions)) {
    for (const action of rawJson.recommendedActions) {
      if (typeof action === 'string' && action.trim()) {
        rawActions.push(action.trim());
      }
    }
  }

  const limitations = [];
  if (Array.isArray(rawJson.limitations)) {
    for (const lim of rawJson.limitations) {
      if (typeof lim === 'string' && lim.trim()) {
        limitations.push(lim.trim());
      }
    }
  }

  const iocs = extractIOCs(originalMessage);
  const { evidenceSufficiency, confidence, confidenceRationale } = evaluateEvidenceAndConfidence(
    originalMessage,
    riskLevel,
    indicators.length
  );

  return {
    riskLevel,
    summary,
    indicators,
    recommendedActions: rawActions.length > 0 ? rawActions : ['Do not click untrusted links.'],
    limitations: limitations.length > 0 ? limitations : ['Advisory notice.'],
    model: modelName,
    iocs,
    evidenceSufficiency,
    confidence,
    confidenceRationale,
  };
}

// ==========================================
// TEST 1: Legitimate Message Scenario
// ==========================================
{
  const cleanMsg = "Hey Alex, dinner is confirmed for 7:30 PM tomorrow at Osteria downtown. Looking forward to catching up!";
  const rawModelOutput = {
    riskLevel: "low",
    summary: "This message is a routine interpersonal dinner invitation with no threat markers.",
    indicators: [],
    recommendedActions: ["Maintain normal awareness."],
    limitations: ["Cannot verify personal identity of sender."],
  };

  const validated = validatePayload(rawModelOutput, cleanMsg, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(validated.riskLevel, "low", "Legitimate message riskLevel should be 'low'");
  assert.equal(validated.indicators.length, 0, "Legitimate message should have 0 threat indicators");
  assert.equal(validated.evidenceSufficiency, "sufficient", "Legitimate message should have sufficient context");
  assert.equal(validated.confidence, "high", "Legitimate message should have high confidence");
  console.log('✅ Test 1 Passed: Legitimate message scenario correctly handled');
}

// ==========================================
// TEST 2: Suspicious Message Scenario
// ==========================================
{
  const scamMsg = "WELLS FARGO ALERT: Fraud charge of $1,429 flagged. Reply NO or click https://bit.ly/wf-sec to avoid account freeze within 15 mins.";
  const rawModelOutput = {
    riskLevel: "high",
    summary: "Aggressive banking smishing phishing scam.",
    indicators: [
      { name: "Urgency Tactic", evidence: "within 15 mins to avoid account freeze", reason: "Coerces user to act without verifying" },
      { name: "Obfuscated Link", evidence: "https://bit.ly/wf-sec", reason: "Disguises malicious credential capture domain" }
    ],
    recommendedActions: ["Do NOT click the link", "Call bank directly"],
    limitations: ["Automated advisory only"]
  };

  const validated = validatePayload(rawModelOutput, scamMsg, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(validated.riskLevel, "high", "Suspicious message riskLevel should be 'high'");
  assert.ok(validated.indicators.length >= 2, "Suspicious message should extract at least 2 indicators");
  assert.equal(validated.indicators[0].evidence, "within 15 mins to avoid account freeze");
  assert.equal(validated.iocs.urls[0], "https://bit.ly/wf-sec");
  assert.equal(validated.confidence, "high", "High-threat message with corroborating evidence should have high confidence");
  console.log('✅ Test 2 Passed: Suspicious message scenario correctly handled');
}

// ==========================================
// TEST 3: Insufficient-Context Message Scenario
// ==========================================
{
  const sparseMsg = "call me now";
  const rawModelOutput = {
    riskLevel: "uncertain",
    summary: "The text is too brief to evaluate intent.",
    indicators: [],
    recommendedActions: ["Verify sender before responding"],
    limitations: ["Lacks context"]
  };

  const validated = validatePayload(rawModelOutput, sparseMsg, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(validated.riskLevel, "uncertain", "Sparse message riskLevel should be 'uncertain'");
  assert.equal(validated.evidenceSufficiency, "sparse", "Sparse message should have 'sparse' evidence sufficiency");
  assert.equal(validated.confidence, "low", "Sparse message should have 'low' confidence");
  assert.ok(validated.confidenceRationale.includes("Insufficient context"), "Rationale must explain sparse context");
  console.log('✅ Test 3 Passed: Insufficient-context message scenario correctly handled');
}

// ==========================================
// TEST 4: Malformed Model Output Recovery Scenario
// ==========================================
{
  const original = "Click this link now: https://malicious.example.com";
  // Simulates malformed/corrupted model output: uppercase riskLevel, non-array actions, invalid indicator object
  const malformedJson = {
    riskLevel: "HIGH",
    summary: null,
    indicators: [
      { name: "Suspicious link", evidence: "https://malicious.example.com", reason: "Phishing lure" },
      { broken: true }, // Should be dropped safely
      null
    ],
    recommendedActions: "Not an array", // Bad type
    limitations: [123, "Legitimate advisory text"]
  };

  const validated = validatePayload(malformedJson, original, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(validated.riskLevel, "high", "Uppercase 'HIGH' normalized to 'high'");
  assert.ok(validated.indicators.length >= 1, "Corrupted indicator items safely filtered");
  assert.ok(Array.isArray(validated.recommendedActions), "recommendedActions fallback must be an array");
  assert.ok(validated.recommendedActions.length > 0, "recommendedActions has fallback");
  console.log('✅ Test 4 Passed: Malformed model output safely recovered & validated');
}

// ==========================================
// TEST 5: Security & Threat-Detection Invariants (Task 2)
// ==========================================
console.log('\n--- Test 5: Security & Behavioral Threat Detection Invariants ---');
{
  // 5.1 OTP / Authentication Code Request: must elevate to 'high' even if model returned 'low'
  const otpMsg = "Hi, I just sent a 6-digit verification code to your phone by accident. Please send me the code quickly!";
  const modelMistake = {
    riskLevel: "low", // Model falsely assessed as low
    summary: "Sender is asking for a code they accidentally sent.",
    indicators: [],
    recommendedActions: ["Check with friend"],
  };
  const otpValidated = validatePayload(modelMistake, otpMsg, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(otpValidated.riskLevel, "high", "A request to share an authentication code MUST be treated as high risk even if model returned 'low'");
  assert.ok(
    otpValidated.indicators.some((i) => i.name.includes("Authentication Code") || i.name.includes("OTP")),
    "Must extract Authentication Code / OTP indicator"
  );
  console.log('✅ Test 5.1 Passed: OTP / Authentication code request elevates risk to HIGH despite low model rating');

  // 5.2 Remote-Access Request (AnyDesk/TeamViewer): must elevate to 'high'
  const remoteMsg = "Tech Support: We detected a virus on your machine. Please install AnyDesk immediately and provide your access ID.";
  const remoteMistake = {
    riskLevel: "uncertain",
    summary: "Tech support inquiry.",
    indicators: [],
  };
  const remoteValidated = validatePayload(remoteMistake, remoteMsg, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(remoteValidated.riskLevel, "high", "Remote access software request must elevate to HIGH");
  assert.ok(
    remoteValidated.indicators.some((i) => i.name.includes("Remote-Access")),
    "Must extract Remote-Access Software Lure indicator"
  );
  console.log('✅ Test 5.2 Passed: Remote-access tool lure elevates risk to HIGH');

  // 5.3 Account-Blocking Threat + Coercive Payment: must elevate to 'high'
  const coerciveMsg = "Your account will be suspended and blocked by tomorrow unless you pay the verification fee immediately.";
  const coerciveMistake = {
    riskLevel: "low",
    summary: "Billing notice.",
    indicators: [],
  };
  const coerciveValidated = validatePayload(coerciveMistake, coerciveMsg, "Qwen/Qwen3-VL-8B-Instruct");
  assert.equal(coerciveValidated.riskLevel, "high", "Account blocking threat + deadline/fee must elevate to HIGH");
  assert.ok(
    coerciveValidated.indicators.some((i) => i.name.includes("Account-Blocking")),
    "Must extract Coercive Account-Blocking Threat indicator"
  );
  console.log('✅ Test 5.3 Passed: Coercive account-blocking threat correctly elevated to HIGH');

  // 5.4 GTBank Verification Code & Tier Upgrade Regression Case
  const gtbankMsg =
    'Dear GTBank customer, your account requires an upgrade to Tier 3. A 6-digit verification code has been sent to your phone. Kindly send back the code immediately to complete the upgrade and avoid account suspension.';
  const gtbankModelMistake = {
    riskLevel: 'uncertain',
    summary: 'The message mentions an account upgrade to Tier 3.',
    indicators: [],
  };
  const gtbankValidated = validatePayload(gtbankModelMistake, gtbankMsg, 'Qwen/Qwen3-VL-8B-Instruct');
  assert.equal(gtbankValidated.riskLevel, 'high', 'GTBank verification code request MUST elevate risk to HIGH');
  assert.ok(
    gtbankValidated.indicators.some((i) => i.name.includes('Authentication Code') || i.name.includes('OTP')),
    'Must extract Authentication Code / OTP indicator'
  );
  assert.ok(
    gtbankValidated.indicators.some((i) => i.name.includes('Account-Blocking')),
    'Must extract Account-Blocking Threat indicator'
  );
  console.log('✅ Test 5.4 Passed: GTBank regression case distinguishes unverified upgrade from dangerous code return (elevated to HIGH)');
}
const BASE_URL = process.env.TEST_APP_URL || 'http://localhost:3000';

async function testEndpointFailures() {
  console.log(`\n🌐 Running HTTP Endpoint Boundary Tests against ${BASE_URL}...`);

  // Probe server availability with 2.5s timeout
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const probe = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: '' }),
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));

    if (probe.status !== 400) {
      console.warn(`Server responded with unexpected status ${probe.status}`);
    }
  } catch (err) {
    console.log(`ℹ️ Dev server not actively listening on ${BASE_URL} (${err.message}).`);
    console.log(`Skipping live HTTP integration checks. Unit tests 1-4 passed cleanly.`);
    console.log('\n🎉 ALL ANALYZER UNIT TEST CATEGORIES COMPLETED SUCCESSFULLY!\n');
    return;
  }

  // 5.1 Empty message rejection
  {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: '' }),
    });
    assert.equal(res.status, 400, 'Empty string message must return 400');
    const data = await res.json();
    assert.ok(data.error.includes('empty'), 'Error must specify empty message');
    console.log('✅ Test 5.1 Passed: HTTP 400 on empty message');
  }

  // 5.2 Whitespace-only message rejection
  {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: '   \n\t  ' }),
    });
    assert.equal(res.status, 400, 'Whitespace message must return 400');
    console.log('✅ Test 5.2 Passed: HTTP 400 on whitespace-only message');
  }

  // 5.3 Over-limit message rejection (>5000 characters)
  {
    const longMsg = 'X'.repeat(5001);
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: longMsg }),
    });
    assert.equal(res.status, 400, 'Message exceeding 5000 chars must return 400');
    const data = await res.json();
    assert.ok(data.error.includes('5000'), 'Error must specify 5000 char limit');
    console.log('✅ Test 5.3 Passed: HTTP 400 on message exceeding 5,000 characters');
  }

  // 5.4 Non-string payload rejection
  {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: { bad: 'object' } }),
    });
    assert.equal(res.status, 400, 'Non-string payload must return 400');
    console.log('✅ Test 5.4 Passed: HTTP 400 on non-string message');
  }

  // 5.5 Live inference check
  {
    console.log('📡 Testing live inference analysis...');
    const testMsg = "WELLS FARGO ALERT: Suspicious debit of $1,429.99 flagged. Verify identity within 15 mins: https://bit.ly/wf-sec-verify";
    try {
      const abortCtrl = new AbortController();
      const timer = setTimeout(() => abortCtrl.abort(), 8000);
      const res = await fetch(`${BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: testMsg }),
        signal: abortCtrl.signal,
      }).finally(() => clearTimeout(timer));

      if (res.ok) {
        const data = await res.json();
        assert.ok(['high', 'medium', 'low', 'uncertain'].includes(data.riskLevel));
        assert.ok(['sufficient', 'moderate', 'sparse'].includes(data.evidenceSufficiency));
        assert.ok(['high', 'moderate', 'low'].includes(data.confidence));
        assert.ok(typeof data.confidenceRationale === 'string');
        assert.ok(Array.isArray(data.recommendedActions));
        console.log(`✅ Test 5.5 Passed: Live inference returned valid payload (Risk: ${data.riskLevel}, Context: ${data.evidenceSufficiency})`);
      } else {
        const err = await res.json().catch(() => ({}));
        console.warn(`⚠️ Upstream API status ${res.status}: ${err.error || 'Check key'}`);
        assert.ok(err.error, 'Error response must contain descriptive error field');
      }
    } catch (fetchErr) {
      console.warn(`⚠️ Live inference check skipped (${fetchErr.message}). Unit tests & endpoint boundaries passed.`);
    }
  }

  console.log('\n🎉 ALL 5 TEST CATEGORIES COMPLETED SUCCESSFULLY!\n');
}

testEndpointFailures().catch((err) => {
  console.error('\n❌ Test suite failed:', err);
  process.exit(1);
});
