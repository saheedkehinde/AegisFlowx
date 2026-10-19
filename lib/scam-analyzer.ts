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

  const hasUrl = iocs.urls.length > 0 || indicators.some((i) => i.name.toLowerCase().includes('link') || i.name.toLowerCase().includes('url'));
  const hasPayment = iocs.keywords.some((k) => ['gift card', 'bitcoin', 'wire transfer', 'pin code', 'fee'].includes(k)) || indicators.some((i) => i.name.toLowerCase().includes('payment') || i.name.toLowerCase().includes('gift card'));
  const hasUrgency = indicators.some((i) => i.name.toLowerCase().includes('urgency') || i.name.toLowerCase().includes('pressure') || i.name.toLowerCase().includes('freeze'));

  if (hasUrl && !actions.some((a) => a.toLowerCase().includes('link') || a.toLowerCase().includes('url'))) {
    actions.unshift('Do NOT click, preview, or paste the embedded link into your web browser.');
  }

  if (hasPayment && !actions.some((a) => a.toLowerCase().includes('payment') || a.toLowerCase().includes('gift card') || a.toLowerCase().includes('money'))) {
    actions.unshift('Never purchase gift cards, send wire transfers, or provide voucher PIN codes under pressure.');
  }

  if (hasUrgency && !actions.some((a) => a.toLowerCase().includes('pause') || a.toLowerCase().includes('verify') || a.toLowerCase().includes('official'))) {
    actions.push('Pause and do not let artificial deadlines force you into hasty decisions.');
  }

  if ((riskLevel === 'high' || riskLevel === 'medium') && !actions.some((a) => a.toLowerCase().includes('official') || a.toLowerCase().includes('directly'))) {
    actions.push('Independently contact the claimed institution via an official phone number or app, not the contacts provided in the message.');
  }

  const msgContext = (originalMessage + ' ' + indicators.map((i) => i.evidence).join(' ')).toLowerCase();
  const isBankingOrFinancial =
    /cbn|central bank|bank|account|bvn|nin|verification fee|block|frozen|debit|transfer|toll-free|wire/i.test(msgContext);

  if (isBankingOrFinancial) {
    if (!actions.some((a) => a.toLowerCase().includes('not pay') || a.toLowerCase().includes('never pay') || a.toLowerCase().includes('do not pay'))) {
      actions.unshift('Do NOT pay the suspicious demand, transfer funds, or provide payment fees under any circumstances.');
    }
    if (!actions.some((a) => a.toLowerCase().includes('otp') || a.toLowerCase().includes('pin'))) {
      actions.push('Never share one-time passwords (OTPs), card PINs, banking passwords, or identity credentials with anyone.');
    }
    if (!actions.some((a) => a.toLowerCase().includes('back of your') || a.toLowerCase().includes('independently'))) {
      actions.push('Contact your bank directly using independently obtained contact info (such as the phone number on the back of your debit card or in your official mobile banking app), never numbers or links supplied in the message.');
    }
    if (!actions.some((a) => a.toLowerCase().includes('report') && a.toLowerCase().includes('fraud'))) {
      actions.push('Report suspicious fraudulent communications directly to your bank\'s official fraud desk through verified channels.');
    }
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
  const severityScore = calculateSeverityScore(riskLevel, indicators.length);
  const { evidenceSufficiency, confidence, confidenceRationale } = evaluateEvidenceAndConfidence(
    originalMessage,
    riskLevel,
    indicators.length
  );

  const recommendedActions = deriveRelevantActions(rawActions, indicators, iocs, riskLevel, originalMessage);

  return {
    riskLevel,
    summary,
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
