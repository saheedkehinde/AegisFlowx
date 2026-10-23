export type RiskLevel = 'high' | 'medium' | 'low' | 'uncertain';
export type EvidenceSufficiency = 'sufficient' | 'moderate' | 'sparse';
export type ModelConfidence = 'high' | 'moderate' | 'low';

export interface ThreatIndicator {
  name: string;
  evidence: string;
  reason: string;
}

export interface ExtractedIOCs {
  urls: string[];
  emails: string[];
  phoneNumbers: string[];
  keywords: string[];
}

export interface ScamAnalysisResult {
  riskLevel: RiskLevel;
  summary: string;
  indicators: ThreatIndicator[];
  recommendedActions: string[];
  limitations: string[];
  model?: string;
  analyzedAt?: string;
  severityScore?: number; // 0-100 severity index
  iocs?: ExtractedIOCs;
  evidenceSufficiency: EvidenceSufficiency;
  confidence: ModelConfidence;
  confidenceRationale: string;
  unverifiedClaims?: string[];
  externalEvidenceObtained?: boolean;
}

export interface ExampleMessage {
  id: string;
  title: string;
  category: string;
  text: string;
  description: string;
  threatType: string;
}

export const SAMPLE_MESSAGES: ExampleMessage[] = [
  {
    id: 'bank-sms',
    title: 'Urgent Bank Fraud Alert (SMS)',
    category: 'Bank Smishing',
    threatType: 'Financial Impersonation & Credential Harvesting',
    text: "WELLS FARGO ALERT: Suspicious debit of $1,429.99 to 'BEST BUY ONLINE' flagged on your card ending in 4082. Reply NO if not authorized, or verify identity within 15 minutes to avoid complete account freeze: https://bit.ly/wf-sec-verify-408",
    description: 'High-urgency bank alert impersonation driving victims to a shortened credential-harvesting phishing link.',
  },
  {
    id: 'ceo-giftcard',
    title: 'Executive Impersonation (Email)',
    category: 'Business Email Compromise (BEC)',
    threatType: 'Authority Impersonation & Voucher Fraud',
    text: "Hi, I'm currently stuck in an all-day confidential executive board review with our major investors and can't take phone calls. I urgently need you to purchase 5x $100 Apple Gift Cards from the nearest store for our strategic partner awards. Please scratch off the back and email photos of the PIN codes directly to this email before 3 PM. Keep this quiet.",
    description: 'Classic CEO fraud coercing an employee to purchase untraceable gift cards under the guise of secrecy.',
  },
  {
    id: 'usps-delivery',
    title: 'Package Delivery Failed (SMS)',
    category: 'Delivery Smishing',
    threatType: 'Postal Service Phishing & Credit Card Theft',
    text: "USPS Tracking: Package shipment #US940012847 cannot be delivered due to incomplete street address numbers. Please update your delivery details and pay the mandatory $1.85 redelivery insurance fee at https://usps-track-resolve.top/deliver within 24 hours or item will be returned to sender.",
    description: 'Deceptive postal notification using small payment fees to harvest credit card details.',
  },
];

export const SAFE_SAMPLE_MESSAGE: ExampleMessage = {
  id: 'safe-message',
  title: 'Legitimate Friendly Note',
  category: 'Clean Baseline',
  threatType: 'Normal Interpersonal Communication',
  text: "Hey Alex, dinner is confirmed for 7:30 PM tomorrow at Osteria downtown. Looking forward to catching up! Let me know if you need a ride or if you want to invite Sarah as well.",
  description: 'Standard informal communication with no malicious indicators, urgency pressure, or link demands.',
};

/**
 * Extracts Indicators of Compromise (IOCs) deterministically from untrusted text
 */
export function extractIOCsFromMessage(text: string): ExtractedIOCs {
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

/**
 * Calculates normalized 0-100 severity score based on risk level and detected indicators
 */
export function calculateSeverityScore(riskLevel: RiskLevel, indicatorsCount: number): number {
  switch (riskLevel) {
    case 'high':
      return Math.min(98, Math.max(75, 75 + indicatorsCount * 6));
    case 'medium':
      return Math.min(74, Math.max(45, 45 + indicatorsCount * 7));
    case 'low':
      return Math.max(5, Math.min(25, 10 + indicatorsCount * 4));
    case 'uncertain':
    default:
      return 50;
  }
}

/**
 * Evaluates evidence sufficiency and model confidence distinctly from threat risk level
 */
export function evaluateEvidenceAndConfidence(
  message: string,
  riskLevel: RiskLevel,
  indicatorsCount: number
): {
  evidenceSufficiency: EvidenceSufficiency;
  confidence: ModelConfidence;
  confidenceRationale: string;
} {
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

/**
 * Detects specific high-risk behavioral threat patterns deterministically
 */
export interface DetectedBehavioralThreats {
  hasAuthCodeRequest: boolean;
  hasCredentialHarvesting: boolean;
  hasRemoteAccessRequest: boolean;
  hasPaymentDemand: boolean;
  hasAccountBlockingThreat: boolean;
  hasArtificialDeadline: boolean;
  hasInstitutionImpersonation: boolean;
  hasSuspiciousLink: boolean;
  hasMonetaryIncentiveLure: boolean;
  isAmbiguousMessage: boolean;
  indicators: ThreatIndicator[];
}

export function detectBehavioralThreats(text: string): DetectedBehavioralThreats {
  const lower = text.toLowerCase().trim();
  const indicators: ThreatIndicator[] = [];

  // 1. Requests for OTPs, 2FA, and authentication codes
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

  // 2. Requests for passwords, PINs, recovery codes, and transaction authorization codes
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

  // 3. Remote-access requests (AnyDesk, TeamViewer, QuickSupport, screen sharing)
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

  // 4. Payment demands (untraceable channels, verification fees, gift cards)
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

  // 5. Account-blocking threats & coercive penalties
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

  // 6. Artificial deadlines & urgency pressure
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

  // 7. Impersonation of financial or regulatory institutions
  const impersonationRegex =
    /\b(?:central\s+bank|cbn|federal\s+reserve|internal\s+revenue\s+service|irs|fbi|police|social\s+security|sec\b|ftc\b|wells\s+fargo|bank\s+of\s+america|chase\s+bank|citibank|hsbc|barclays|usps|fedex|geek\s+squad|microsoft\s+support|apple\s+support)\b/i;
  const impMatch = text.match(impersonationRegex);
  const hasInstitutionImpersonation = !!impMatch;
  if (hasInstitutionImpersonation) {
    indicators.push({
      name: 'Institutional / Authority Impersonation',
      evidence: impMatch[0],
      reason:
        'Claiming authority from recognized banks, regulators, or couriers establishes unearned trust to make fraudulent demands appear mandatory.',
    });
  }

  // 8. Calibrated Link Analysis: Distinguish shorteners, direct IPs, free hosting, random subdomains, high-risk TLDs
  let hasSuspiciousLink = false;

  const urlMatches = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  const directIpRegex = /\bhttps?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:\/[^\s]*)?\b/i;
  const ipMatch = text.match(directIpRegex);

  // A. URL Shorteners
  const shortenerRegex = /\bhttps?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|ow\.ly|buff\.ly|cutt\.ly|rb\.gy)\/[^\s]*/i;
  const shortenerMatch = text.match(shortenerRegex);
  if (shortenerMatch) {
    hasSuspiciousLink = true;
    indicators.push({
      name: 'URL Shortener / Concealed Destination',
      evidence: shortenerMatch[0],
      reason:
        'URL shorteners conceal the authentic landing destination and hostname, preventing pre-click verification of the target server.',
    });
  }

  // B. Direct-IP URLs
  if (ipMatch && !shortenerMatch) {
    hasSuspiciousLink = true;
    indicators.push({
      name: 'Direct-IP Host Destination',
      evidence: ipMatch[0],
      reason:
        'Using a raw numeric IP address instead of a registered domain bypasses standard domain name registration accountability and TLS hostname verification.',
    });
  }

  // C. Free hosting / web-builder platforms
  const freeHostingRegex = /\bhttps?:\/\/([a-zA-Z0-9-]+\.(?:site123\.me|weebly\.com|wixsite\.com|webflow\.io|000webhostapp\.com|firebaseapp\.com|pages\.dev|github\.io|glitch\.me|pantheonsite\.io))[^\s]*/i;
  const freeHostingMatch = text.match(freeHostingRegex);
  if (freeHostingMatch) {
    hasSuspiciousLink = true;
    indicators.push({
      name: 'Free Web-Hosting Platform Subdomain',
      evidence: freeHostingMatch[0],
      reason:
        'The link uses a free website-builder or hosting subdomain. While used legitimately, free hosting platforms are frequently exploited by adversaries to host disposable forms and prize claims without domain verification.',
    });
  }

  // D. Random-looking or unusually generated subdomains (e.g. 67d8cd0f1e57e.site123.me)
  for (const rawUrl of urlMatches) {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      const hostname = parsed.hostname.toLowerCase();
      const parts = hostname.split('.');
      if (parts.length >= 3) {
        const sub = parts[0];
        // High-entropy or hex subdomains >= 10 chars
        if (/^[a-f0-9]{10,}$/i.test(sub) || (/^[a-z0-9_-]{12,}$/i.test(sub) && /[0-9]/.test(sub) && /[a-z]/.test(sub))) {
          indicators.push({
            name: 'Unusual / Machine-Generated Subdomain',
            evidence: hostname,
            reason:
              'The subdomain appears machine-generated or an automated account identifier. While common on cloud and free hosting infrastructure, appearance alone does not establish malicious activity; content must be verified independently.',
          });
          break;
        }
      }
    } catch {
      // Ignore URL parsing errors
    }
  }

  // E. High-risk / low-cost TLDs (distinct from subdomains)
  const highRiskTldRegex = /\bhttps?:\/\/[a-zA-Z0-9-]+\.(?:top|xyz|icu|click|work|download|link|fun|loan|stream)\b[^\s]*/i;
  const highRiskTldMatch = text.match(highRiskTldRegex);
  if (highRiskTldMatch && !freeHostingMatch) {
    hasSuspiciousLink = true;
    indicators.push({
      name: 'High-Risk / Low-Cost Top-Level Domain',
      evidence: highRiskTldMatch[0],
      reason:
        'The destination domain utilizes a top-level domain with low registration overhead and elevated abuse rates in threat-intelligence datasets.',
    });
  }

  // 8B. Unsolicited Monetary Incentive / High-Value Lure
  const monetaryLureRegex =
    /\b(?:get|claim|receive|win|won|awarded|rewarded|collect|payout)\s+(?:up\s+to\s+)?(?:\$|₦|€|£)?\s*(?:[0-9]+k|[0-9]+(?:\.[0-9]{2})?\s*(?:usd|eur|gbp|ngn|dollars)|[0-9]{3,}|500k|cash\s+prize|reward|payout)\b/i;
  const monetaryLureMatch = text.match(monetaryLureRegex);
  const hasMonetaryIncentiveLure = !!monetaryLureMatch;
  if (hasMonetaryIncentiveLure) {
    indicators.push({
      name: 'Unsolicited Monetary Incentive / High-Value Lure',
      evidence: monetaryLureMatch[0],
      reason:
        'Unsolicited promises of large financial payouts or rewards tied to clicking an external link are standard psychological lures used to induce hasty click-throughs.',
    });
  }

  // 9. Ambiguous messages requiring more context
  const isAmbiguousMessage =
    lower.length < 50 &&
    !hasAuthCodeRequest &&
    !hasCredentialHarvesting &&
    !hasRemoteAccessRequest &&
    !hasPaymentDemand &&
    !hasSuspiciousLink &&
    !hasMonetaryIncentiveLure &&
    /(?:call\s+me|contact\s+me|reply\s+back|need\s+a\s+favor|are\s+you\s+available|are\s+you\s+there)/i.test(lower);

  if (isAmbiguousMessage) {
    indicators.push({
      name: 'Ambiguous Context / Initial Engagement Lure',
      evidence: text.slice(0, 50),
      reason:
        'Vague, context-free opening inquiries are frequently deployed as conversational probes in multi-stage social engineering before pivoting to financial requests.',
    });
  }

  return {
    hasAuthCodeRequest,
    hasCredentialHarvesting,
    hasRemoteAccessRequest,
    hasPaymentDemand,
    hasAccountBlockingThreat,
    hasArtificialDeadline,
    hasInstitutionImpersonation,
    hasSuspiciousLink,
    hasMonetaryIncentiveLure,
    isAmbiguousMessage,
    indicators,
  };
}

/**
 * Generates indicator-relevant safety actions tailored to detected threats
 */
export function deriveRelevantActions(
  modelActions: string[],
  indicators: ThreatIndicator[],
  iocs: ExtractedIOCs,
  riskLevel: RiskLevel,
  originalMessage: string = ''
): string[] {
  const actions: string[] = [...modelActions];
  const behavioral = detectBehavioralThreats(originalMessage);

  // 1. Critical Authentication Code / Credential Safety
  if (behavioral.hasAuthCodeRequest || behavioral.hasCredentialHarvesting) {
    actions.unshift(
      'Never share one-time passwords (OTPs), verification codes, PINs, or passwords with anyone. Legitimate service providers and banks NEVER request verification codes via message.'
    );
  }

  // 2. Remote Access Defense
  if (behavioral.hasRemoteAccessRequest) {
    actions.unshift(
      'Never download or install remote-access software (such as AnyDesk or TeamViewer) or grant screen-sharing permissions to unsolicited callers or messagers.'
    );
  }

  // 3. Payment & Gift Card Defense
  if (behavioral.hasPaymentDemand) {
    actions.unshift(
      'Never purchase gift cards, transfer cryptocurrency, or wire funds to satisfy unexpected payment demands or alleged verification fees.'
    );
  }

  // 4. URL & Link Safety
  const hasUrl =
    iocs.urls.length > 0 ||
    behavioral.hasSuspiciousLink ||
    indicators.some((i) => i.name.toLowerCase().includes('link') || i.name.toLowerCase().includes('url'));
  if (hasUrl && !actions.some((a) => a.toLowerCase().includes('link') || a.toLowerCase().includes('url'))) {
    actions.unshift('Do NOT click, preview, or paste the embedded link into your web browser.');
  }

  // 5. Artificial Deadline / Urgency Defense
  if (behavioral.hasArtificialDeadline || behavioral.hasAccountBlockingThreat) {
    actions.push('Pause and do not let artificial deadlines or threats of account suspension force you into hasty decisions.');
  }

  // 6. Direct Institutional Verification
  const msgContext = (originalMessage + ' ' + indicators.map((i) => i.evidence).join(' ')).toLowerCase();
  const isBankingOrInstitutional =
    behavioral.hasInstitutionImpersonation ||
    /cbn|central bank|bank|account|bvn|nin|verification fee|block|frozen|debit|transfer|toll-free|wire|irs|tax/i.test(msgContext);

  if (isBankingOrInstitutional) {
    if (!actions.some((a) => a.toLowerCase().includes('not pay') || a.toLowerCase().includes('never pay'))) {
      actions.unshift('Do NOT pay the suspicious demand, transfer funds, or provide payment fees under any circumstances.');
    }
    if (!actions.some((a) => a.toLowerCase().includes('back of your') || a.toLowerCase().includes('independently'))) {
      actions.push(
        'Contact the institution directly using independently verified contact details (such as the number on the back of your card or in your official mobile app), never details supplied in the message.'
      );
    }
    if (!actions.some((a) => a.toLowerCase().includes('fraud'))) {
      actions.push("Report suspicious fraudulent communications directly to the institution's official fraud department through verified channels.");
    }
  }

  if (behavioral.isAmbiguousMessage) {
    actions.push('Request more context through an independent, verified communication channel before responding to vague requests.');
  }

  // Deduplicate and trim
  const unique = Array.from(new Set(actions.map((a) => a.trim()))).filter((a) => a.length > 0);
  return unique.slice(0, 6);
}

/**
 * Validates and normalizes raw model JSON into a type-safe ScamAnalysisResult
 */
export function validateAnalysisPayload(
  rawJson: any,
  originalMessage: string,
  modelName: string
): ScamAnalysisResult {
  if (!rawJson || typeof rawJson !== 'object') {
    throw new Error('Analysis payload must be a non-null JSON object');
  }

  // Validate and normalize riskLevel
  let riskLevel: RiskLevel = 'uncertain';
  if (typeof rawJson.riskLevel === 'string') {
    const normalized = rawJson.riskLevel.toLowerCase().trim();
    if (['high', 'medium', 'low', 'uncertain'].includes(normalized)) {
      riskLevel = normalized as RiskLevel;
    }
  }

  // Validate summary
  const summary =
    typeof rawJson.summary === 'string' && rawJson.summary.trim()
      ? rawJson.summary.trim()
      : 'No summary was provided by the analysis engine.';

  // Validate indicators (only retain concrete items with valid fields)
  const indicators: ThreatIndicator[] = [];
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

  // CRITICAL INVARIANT: A request to share an authentication code, password, or remote-access grant
  // must be treated as a significant behavioral warning even when the associated factual claim
  // cannot be independently verified. An inconclusive factual verdict or uncertain model output
  // MUST NOT produce a low-risk assessment when the message requests dangerous behavior.
  const hasCriticalBehavioralThreat =
    behavioral.hasAuthCodeRequest ||
    behavioral.hasCredentialHarvesting ||
    behavioral.hasRemoteAccessRequest ||
    (behavioral.hasAccountBlockingThreat && (behavioral.hasPaymentDemand || behavioral.hasArtificialDeadline));

  if (hasCriticalBehavioralThreat && (riskLevel === 'low' || riskLevel === 'uncertain')) {
    riskLevel = 'high';
  }

  // Calibrate summary tone (avoid categorical statements of absolute certainty unless supported by direct records)
  let calibratedSummary = summary;
  if (hasCriticalBehavioralThreat && !/otp|code|credential|remote|phishing|high risk|unverified/i.test(calibratedSummary)) {
    if (behavioral.hasAuthCodeRequest) {
      calibratedSummary = `High Risk: This message requests sensitive authentication or verification codes. Legitimate service providers and banks never request verification codes via direct messages. This represents a strong phishing indicator that should not be acted upon.`;
    } else if (behavioral.hasRemoteAccessRequest) {
      calibratedSummary = `High Risk: This message instructs the recipient to install remote-access software (such as AnyDesk or TeamViewer). Unsolicited remote-access demands are primary vectors for full device takeover and should not be acted upon.`;
    } else if (behavioral.hasCredentialHarvesting) {
      calibratedSummary = `High Risk: This message solicits private account credentials or PIN codes. This is an unverified request that should not be acted upon.`;
    }
  }

  // Validate recommendedActions
  const rawActions: string[] = [];
  if (Array.isArray(rawJson.recommendedActions)) {
    for (const action of rawJson.recommendedActions) {
      if (typeof action === 'string' && action.trim()) {
        rawActions.push(action.trim());
      }
    }
  }

  // Validate limitations
  const limitations: string[] = [];
  if (Array.isArray(rawJson.limitations)) {
    for (const lim of rawJson.limitations) {
      if (typeof lim === 'string' && lim.trim()) {
        limitations.push(lim.trim());
      }
    }
  }

  // Validate unverified claims
  const unverifiedClaims: string[] = [];
  if (Array.isArray(rawJson.unverifiedClaims)) {
    for (const clm of rawJson.unverifiedClaims) {
      if (typeof clm === 'string' && clm.trim()) {
        unverifiedClaims.push(clm.trim());
      }
    }
  }

  const iocs = extractIOCsFromMessage(originalMessage);
  let severityScore = calculateSeverityScore(riskLevel, indicators.length);
  if (hasCriticalBehavioralThreat) {
    severityScore = Math.max(82, severityScore);
  }

  const { evidenceSufficiency, confidence, confidenceRationale } = evaluateEvidenceAndConfidence(
    originalMessage,
    riskLevel,
    indicators.length
  );

  const recommendedActions = deriveRelevantActions(rawActions, indicators, iocs, riskLevel, originalMessage);

  return {
    riskLevel,
    summary: calibratedSummary,
    indicators,
    recommendedActions:
      recommendedActions.length > 0
        ? recommendedActions
        : [
            'Do not click on unexpected links or download attachments.',
            'Independently verify the message through an official phone number or website.',
          ],
    limitations:
      limitations.length > 0
        ? limitations
        : [
            'This direct-message analysis evaluates message content and behavioral indicators. Findings reflect absence of verified headers; external web research was not executed for this triage.',
          ],
    model: modelName,
    analyzedAt: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    severityScore,
    iocs,
    evidenceSufficiency,
    confidence,
    confidenceRationale,
    unverifiedClaims: unverifiedClaims.length > 0 ? unverifiedClaims : undefined,
    externalEvidenceObtained: false,
  };
}
