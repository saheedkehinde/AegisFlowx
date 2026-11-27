export type RiskLevel = 'high' | 'medium' | 'low' | 'uncertain';
export type EvidenceSufficiency = 'sufficient' | 'moderate' | 'sparse';
export type EvidenceCoverage = 'sufficient' | 'moderate' | 'limited' | 'insufficient';
export type ModelConfidence = 'high' | 'moderate' | 'low';

export type AssessmentState =
  | 'confirmed_malicious'
  | 'high_risk_suspicious'
  | 'suspicious_unverified'
  | 'inconclusive'
  | 'no_significant_indicators'
  | 'insufficient_information';

export const ASSESSMENT_STATE_LABELS: Record<AssessmentState, string> = {
  confirmed_malicious: 'Confirmed malicious',
  high_risk_suspicious: 'High-risk suspicious behavior',
  suspicious_unverified: 'Suspicious but unverified',
  inconclusive: 'Inconclusive',
  no_significant_indicators: 'No significant indicators detected',
  insufficient_information: 'Insufficient information',
};

export type ThreatCategoryId =
  | 'business_email_compromise'
  | 'bank_account_change'
  | 'supplier_payment_redirection'
  | 'invoice_beneficiary_manipulation'
  | 'executive_impersonation'
  | 'payroll_diversion'
  | 'fake_banking_instructions'
  | 'payment_authorization_manipulation'
  | 'gift_card_crypto_demand'
  | 'credential_otp_harvesting'
  | 'account_suspension_threat'
  | 'refund_reimbursement_scam'
  | 'romance_task_investment_advance_fee'
  | 'delivery_package_phishing'
  | 'government_regulatory_impersonation'
  | 'ordinary_conversational';

export const THREAT_CATEGORY_LABELS: Record<ThreatCategoryId, string> = {
  business_email_compromise: 'Business Email Compromise (BEC)',
  bank_account_change: 'Bank-Account Change Notification',
  supplier_payment_redirection: 'Supplier / Vendor Payment Redirection',
  invoice_beneficiary_manipulation: 'Invoice & Beneficiary Manipulation',
  executive_impersonation: 'Executive Impersonation',
  payroll_diversion: 'Payroll Diversion',
  fake_banking_instructions: 'Unverified Banking Instructions',
  payment_authorization_manipulation: 'Payment Authorization Manipulation',
  gift_card_crypto_demand: 'Gift-Card / Cryptocurrency Demand',
  credential_otp_harvesting: 'Credential & OTP Harvesting',
  account_suspension_threat: 'Account Suspension Threat',
  refund_reimbursement_scam: 'Refund / Reimbursement Scam',
  romance_task_investment_advance_fee: 'Romance / Task / Investment / Advance-Fee Lure',
  delivery_package_phishing: 'Delivery / Package Phishing',
  government_regulatory_impersonation: 'Government / Regulatory Impersonation',
  ordinary_conversational: 'Ordinary Conversational Message',
};

export interface ThreatCategoryMatch {
  id: ThreatCategoryId;
  label: string;
  confidence: ModelConfidence;
  matchedSignals: string[];
}

export interface PaymentChangeAnalysis {
  detected: boolean;
  isActiveRedirectionRequest: boolean;
  isInformationalOnlyNotice: boolean;
  isVerificationRequest: boolean;
  isPayrollDiversion: boolean;
  isVendorOrInvoiceUpdate: boolean;
  hasBankingDetailsChange: boolean;
  hasFuturePaymentsDirective: boolean;
  hasBeneficiaryReplacement: boolean;
  hasTransferOrApprovalDirective: boolean;
  matchedSignals: string[];
  evidenceSnippets: string[];
  rationale: string;
}

export interface ThreatAssessmentDimension {
  severity: RiskLevel;
  severityScore: number;
  assessmentState: AssessmentState;
  assessmentStateLabel: string;
  primaryCategory: ThreatCategoryId;
  primaryCategoryLabel: string;
  categories: ThreatCategoryMatch[];
  paymentChangeDetected: boolean;
  isActivePaymentRedirection: boolean;
  behavioralIndicators: ThreatIndicator[];
  summary: string;
}

export interface FactualVerificationDimension {
  status:
    | 'supported'
    | 'contradicted'
    | 'unverified'
    | 'inconclusive'
    | 'not_applicable_private_communication'
    | 'not_executed';
  hasVerifiablePublicClaims: boolean;
  claimsSummary: string;
  verifiedClaimsCount: number;
  contradictedClaimsCount: number;
  unverifiedClaimsCount: number;
}

export interface AuthenticityAssessmentDimension {
  status: 'unverified' | 'anomalous' | 'partially_corroborated' | 'not_assessable';
  senderIdentityVerified: boolean;
  organizationIdentityStatus: string;
  domainOrChannelStatus: string;
  paymentDestinationStatus: string;
  summary: string;
}

export interface UnifiedThreatTaxonomyResult {
  primaryCategory: ThreatCategoryId;
  primaryCategoryLabel: string;
  categories: ThreatCategoryMatch[];
  paymentChange: PaymentChangeAnalysis;
  isOrdinaryConversational: boolean;
  hasCriticalThreatVector: boolean;
  hasModerateThreatVector: boolean;
}

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
  evidenceCoverage?: EvidenceCoverage;
  confidence: ModelConfidence;
  confidenceRationale: string;
  assessmentState?: AssessmentState;
  assessmentStateLabel?: string;
  primaryThreatCategory?: ThreatCategoryId;
  threatCategories?: ThreatCategoryMatch[];
  paymentChangeDetection?: PaymentChangeAnalysis;
  threatAssessment?: ThreatAssessmentDimension;
  factualVerification?: FactualVerificationDimension;
  authenticityAssessment?: AuthenticityAssessmentDimension;
  financeRecommendations?: string[];
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
 * Normalizes untrusted text for resilient semantic/intent matching across
 * punctuation noise, irregular whitespace, smart quotes, and minor typos.
 */
export function normalizeForIntentMatching(text: string): string {
  if (!text || typeof text !== 'string') return '';
  let normalized = text
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[_*|~`]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // Common spelling/obfuscation normalizations for resilience against minor typos
  const typoReplacements: Array<[RegExp, string | ((m: string) => string)]> = [
    [/\bac+o?u?n+t+s?\b/g, (m: string) => (m === 'accounts' || m === 'account' ? m : m.endsWith('s') ? 'accounts' : 'account')],
    [/\bacct\b/g, 'account'],
    [/\bbenif[ei]c[ei]ar(?:y|ies)\b/g, 'beneficiary'],
    [/\bbeneficary\b/g, 'beneficiary'],
    [/\bpaym+e?n+t+s?\b/g, (m: string) => (m.endsWith('s') ? 'payments' : 'payment')],
    [/\bpymt\b/g, 'payment'],
    [/\binvoc+e?s?\b/g, 'invoice'],
    [/\binvoce\b/g, 'invoice'],
    [/\bsalry\b/g, 'salary'],
    [/\bpayrol+\b/g, 'payroll'],
    [/\bverf[iy]cat[iy]on\b/g, 'verification'],
    [/\bverfy\b/g, 'verify'],
    [/\bremitance\b/g, 'remittance'],
    [/\bsup+lier\b/g, 'supplier'],
    [/\bvendour\b/g, 'vendor'],
    [/\breimbursment\b/g, 'reimbursement'],
    [/\bcryptocurency\b/g, 'cryptocurrency'],
  ];

  for (const [pat, rep] of typoReplacements) {
    normalized = typeof rep === 'string' ? normalized.replace(pat, rep) : normalized.replace(pat, rep);
  }

  return normalized;
}

export interface MessageInputValidationResult {
  valid: boolean;
  trimmed: string;
  errorCode?: 'empty_message' | 'message_too_long' | 'meaningless_input';
  error?: string;
}

const MAX_MESSAGE_CHAR_LIMIT = 5000;

const RECOGNIZED_SHORT_SECURITY_OR_GREETING_CUE =
  /\b(?:otp|pin|code|2fa|mfa|cvv|cvc|bank|wire|pay|paid|card|acct|account|login|log\s*in|sign\s*in|verify|urgent|alert|irs|fbi|ftc|cbn|usps|fedex|dhl|ups|hello|hi|hey|dear|help|call|text|reply|send|click|tap|link|fee|tax|refund|invoice|payroll|salary|gift|btc|usdt|crypto|freeze|frozen|suspend|suspended|block|blocked|locked|reset|password|passcode|beneficiary|remittance|iban|routing|swift|package|parcel|delivery|claim|prize|reward|won|win)\b/i;

const KEYBOARD_MASH_SUBSTRINGS = [
  'qwerty',
  'wertyu',
  'ertyui',
  'rtyuio',
  'tyuiop',
  'asdfgh',
  'sdfghj',
  'dfghjk',
  'fghjkl',
  'zxcvbn',
  'xcvbnm',
  'qazwsx',
  'wsxedc',
  'poiuyt',
  'lkjhgf',
  'mnbvcx',
];

function isGibberishAlphaToken(token: string): boolean {
  const lower = token.toLowerCase();
  if (lower.length < 3) return false;

  if (KEYBOARD_MASH_SUBSTRINGS.some((seq) => lower.includes(seq))) {
    return true;
  }

  // Repeated single character runs like "aaaaaa" or "xxxxx"
  if (/(.)\1{3,}/.test(lower)) {
    return true;
  }

  // 3+ letter token with zero vowels (and not a known acronym like SMS/PDF/SSN/ATM/CEO/CFO/HR/IT/URL)
  const knownVowelLessTokens = new Set([
    'sms', 'pdf', 'ssn', 'atm', 'ceo', 'cfo', 'coo', 'cto', 'hr', 'it', 'url', 'id',
    'pin', 'cvv', 'cvc', 'otp', 'btc', 'eth', 'cbn', 'irs', 'fbi', 'ftc', 'dhl', 'ups',
    'usps', 'kyc', 'bvn', 'nin', 'b2b', 'p2p', 'pls', 'plz', 'thx', 'msg', 'fwd', 're',
  ]);
  if (!knownVowelLessTokens.has(lower) && !/[aeiouy]/.test(lower)) {
    return true;
  }

  // 5+ consecutive consonants in a single token (e.g. "asdkjhqw" -> "sdkjh")
  if (/[bcdfghjklmnpqrstvwxz]{5,}/.test(lower)) {
    return true;
  }

  // Very long token (>10 chars) with unusually low vowel density (<18%)
  const vowelCount = (lower.match(/[aeiouy]/g) || []).length;
  if (lower.length >= 10 && vowelCount / lower.length < 0.18) {
    return true;
  }

  return false;
}

/**
 * Deterministic validation of user-submitted message text prior to quota reservation or AI calls.
 * Rejects empty, oversized, symbol-noise, isolated digits without context, and gibberish/keyboard-mash
 * inputs while preserving legitimate short SMS fraud alerts, OTP lures, BEC lines, and greetings.
 */
export function validateMessageInput(rawMessage: unknown): MessageInputValidationResult {
  if (typeof rawMessage !== 'string') {
    return {
      valid: false,
      trimmed: '',
      errorCode: 'empty_message',
      error: 'Message cannot be empty. Please provide text to analyze.',
    };
  }

  const trimmed = rawMessage.trim();
  if (trimmed.length === 0) {
    return {
      valid: false,
      trimmed: '',
      errorCode: 'empty_message',
      error: 'Message cannot be empty. Please provide text to analyze.',
    };
  }

  if (trimmed.length > MAX_MESSAGE_CHAR_LIMIT) {
    return {
      valid: false,
      trimmed,
      errorCode: 'message_too_long',
      error: `Message exceeds maximum allowed length of ${MAX_MESSAGE_CHAR_LIMIT} characters (submitted: ${trimmed.length} characters). Please shorten the text and try again.`,
    };
  }

  const nonWhitespace = trimmed.replace(/\s+/g, '');
  const alnumChars = trimmed.match(/[a-zA-Z0-9]/g) || [];

  // Must contain at least one alphanumeric character (rejects "???!!!", "---", emojis-only)
  if (alnumChars.length === 0) {
    return {
      valid: false,
      trimmed,
      errorCode: 'meaningless_input',
      error:
        'Please enter a meaningful message, email, or SMS alert to analyze rather than punctuation or symbols alone.',
    };
  }

  // Immediate allowlist for real communication/security markers (URLs, emails, phone numbers, security/greeting cues)
  const hasUrlOrDomain =
    /https?:\/\/[^\s]+|www\.[^\s]+|\b[a-z0-9-]{2,}\.(?:com|org|net|io|co|gov|edu|top|xyz|info|biz|me|uk|ng)\b/i.test(
      trimmed
    );
  const hasEmail = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/.test(trimmed);
  const hasPhone = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/.test(trimmed);
  const hasRecognizedCue = RECOGNIZED_SHORT_SECURITY_OR_GREETING_CUE.test(trimmed);

  // Even when a cue exists, ensure text isn't overwhelmingly repeated single character
  const distinctAlnum = new Set(alnumChars.map((c) => c.toLowerCase()));
  if (alnumChars.length >= 6 && distinctAlnum.size <= 2 && !hasUrlOrDomain && !hasEmail) {
    return {
      valid: false,
      trimmed,
      errorCode: 'meaningless_input',
      error:
        'Submitted text appears to be repetitive characters without analyzable message content. Please paste a real message or alert.',
    };
  }

  if (hasUrlOrDomain || hasEmail || hasPhone || hasRecognizedCue) {
    return { valid: true, trimmed };
  }

  // Excessive non-alphanumeric symbol spam (e.g. "!@#$%^&*()_+ a")
  if (nonWhitespace.length >= 6 && alnumChars.length / nonWhitespace.length < 0.35) {
    return {
      valid: false,
      trimmed,
      errorCode: 'meaningless_input',
      error:
        'Submitted text consists mostly of symbols without readable communication content. Please paste a real message to investigate.',
    };
  }

  const alphaTokens = trimmed.match(/[a-zA-Z]+/g) || [];
  const digitTokens = trimmed.match(/\d+/g) || [];

  // Pure isolated digits without any words/context (e.g. "123456" or "998877")
  if (alphaTokens.length === 0 && digitTokens.length > 0) {
    return {
      valid: false,
      trimmed,
      errorCode: 'meaningless_input',
      error:
        'Numbers alone lack surrounding context for threat triage. Please paste the full message or alert containing the number.',
    };
  }

  // Very short fragments (< 3 alphabetic characters total and no cues/URLs, e.g. "ab", "x1")
  const totalAlphaLen = alphaTokens.reduce((sum, t) => sum + t.length, 0);
  if (totalAlphaLen < 3) {
    return {
      valid: false,
      trimmed,
      errorCode: 'meaningless_input',
      error:
        'Message is too brief and lacks recognizable context. Please paste a full sentence, alert, or email excerpt.',
    };
  }

  // Check for keyboard-mash / random gibberish alphabetic tokens
  const longAlphaTokens = alphaTokens.filter((t) => t.length >= 3);
  if (longAlphaTokens.length > 0) {
    const gibberishTokens = longAlphaTokens.filter(isGibberishAlphaToken);
    if (
      gibberishTokens.length === longAlphaTokens.length ||
      (longAlphaTokens.length >= 2 && gibberishTokens.length / longAlphaTokens.length >= 0.5)
    ) {
      return {
        valid: false,
        trimmed,
        errorCode: 'meaningless_input',
        error:
          'Submitted text appears to contain random or unintelligible characters rather than a real communication. Please paste an actual message to analyze.',
      };
    }
  }

  // Detect repetitive filler words (e.g. "blah blah blah", "test test test", "aaa bbb aaa bbb")
  const normalizedWords = trimmed.toLowerCase().match(/[a-z0-9]+/g) || [];
  if (normalizedWords.length >= 3 && new Set(normalizedWords).size === 1) {
    return {
      valid: false,
      trimmed,
      errorCode: 'meaningless_input',
      error:
        'Submitted text repeats a single token without analyzable message context. Please paste a complete communication.',
    };
  }

  return { valid: true, trimmed };
}

/**
 * Verifies that parsed JSON from an upstream LLM contains minimum usable structure
 * before passing into normalization/scoring (so empty `{}` triggers fallback instead of fake output).
 */
export function isUsableModelJson(rawJson: unknown): rawJson is Record<string, unknown> {
  if (!rawJson || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
    return false;
  }
  const obj = rawJson as Record<string, unknown>;
  const hasValidRisk =
    typeof obj.riskLevel === 'string' &&
    ['high', 'medium', 'low', 'uncertain'].includes(obj.riskLevel.toLowerCase().trim());
  const hasValidSummary = typeof obj.summary === 'string' && obj.summary.trim().length > 0;
  const hasValidIndicator =
    Array.isArray(obj.indicators) &&
    obj.indicators.some(
      (item) =>
        item &&
        typeof item === 'object' &&
        typeof (item as Record<string, unknown>).name === 'string' &&
        String((item as Record<string, unknown>).name).trim().length > 0
    );

  return hasValidSummary || (hasValidRisk && hasValidIndicator);
}

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
    'bank account',
    'new details',
    'future payments',
    'beneficiary',
    'remittance',
    'iban',
    'routing number',
    'payroll',
  ];

  const lower = normalizeForIntentMatching(text);
  const keywords = keywordTriggers.filter((k) => lower.includes(k));

  return { urls, emails, phoneNumbers, keywords };
}

/**
 * Dedicated deterministic payment-change & BEC payment-redirection analyzer.
 * Distinguishes active payment-redirection instructions from purely informational notices
 * without payment-transfer directives, while never marking unverified accounts safe.
 */
export function detectPaymentChangeAndBec(text: string): PaymentChangeAnalysis {
  const norm = normalizeForIntentMatching(text);
  const matchedSignals: string[] = [];
  const evidenceSnippets: string[] = [];

  const captureEvidence = (regex: RegExp, label: string): boolean => {
    const m = text.match(regex) || norm.match(regex);
    if (m) {
      matchedSignals.push(label);
      if (m[0] && !evidenceSnippets.includes(m[0].trim())) {
        evidenceSnippets.push(m[0].trim());
      }
      return true;
    }
    return false;
  };

  // 1. Bank account / beneficiary / settlement / remittance / routing change announcements
  const bankDetailsChanged =
    captureEvidence(
      /\b(?:changed|updated|modified|revised|switched|migrated|moved|replaced|new|alternate|different|temporary|previous|old|former|disregard|ignore|supersede)\s+(?:(?:\w+\s+){0,3})?(?:bank(?:ing)?\s+(?:account|details?|info(?:rmation)?|instructions?|coordinates)|account\s+(?:details?|number|info(?:rmation)?)|beneficiary(?:\s+account|\s+details?)?|remittance\s+(?:details?|instructions?|account|address)|settlement\s+(?:account|details?|instructions?)|iban|swift(?:\s+code)?|routing(?:\s+number)?|sort\s*code|ach\s+(?:details?|account)|wire\s+(?:instructions?|details?|account)|receiving\s+account|payment\s+(?:details?|account|destination|instructions?|coordinates))\b/i,
      'Bank / Account Details Change Notification'
    ) ||
    captureEvidence(
      /\b(?:bank(?:ing)?\s+(?:account|details?|info(?:rmation)?)|account\s+(?:details?|number)|payment\s+account|supplier\s+(?:payment\s+)?account|beneficiary(?:\s+account)?|remittance(?:\s+instructions?)?|iban|routing\s+number)\s+(?:have|has|was|were|are|is)?\s*(?:been\s+)?(?:changed|updated|modified|revised|switched|moved|replaced)\b/i,
      'Bank / Account Details Change Notification'
    ) ||
    captureEvidence(
      /\b(?:attached|proposed|requested|pending|recent)?\s*(?:bank(?:ing)?\s+)?account\s+change\b/i,
      'Bank / Account Details Change Reference'
    );

  // 2. "New details below / attached / following" or new payment destination phrasing
  const hasNewDetailsOffer = captureEvidence(
    /\b(?:new|updated|revised|following|attached|below)\s+(?:bank(?:ing)?\s+)?(?:account\s+)?(?:beneficiary\s+)?(?:details?|information|instructions?|iban|routing|beneficiary|remittance|payment\s+(?:destination|instructions?|details?))\b/i,
    'New / Unverified Payment Details Provided'
  );

  // 3. Redirection toward "this and all future payments / upcoming invoices"
  const hasFuturePaymentsDirective =
    captureEvidence(
      /\b(?:for\s+)?(?:this\s+and\s+(?:all\s+)?)?(?:future|upcoming|subsequent|pending|outstanding|remaining|next)\s+(?:payments?|invoices?|remittances?|transfers?|settlements?|billing|payouts?)\b/i,
      'Future Payments Redirection Scope'
    ) ||
    captureEvidence(
      /\b(?:all\s+)?(?:payments?|transfers?|remittances?|settlements?)\s+(?:going\s+forward|from\s+now\s+on|henceforth|moving\s+forward|effective\s+immediately)\b/i,
      'Future Payments Redirection Scope'
    ) ||
    captureEvidence(
      /\beffective\s+immediately\b/i,
      'Immediate Effective Payment Change Scope'
    );

  // 4. Explicit beneficiary/vendor record replacement directives
  const hasBeneficiaryReplacement = captureEvidence(
    /\b(?:update|replace|change|modify|amend|correct|overwrite|swap|switch)\s+(?:your|our|the)?\s*(?:records?|master\s*file|vendor\s+(?:file|record|profile|portal|details?)|supplier\s+(?:file|record|details?)|beneficiary(?:\s+account|\s+details?|\s+records?)?|banking\s+(?:records?|details?|info)|direct\s+deposit(?:\s+details?)?|payment\s+(?:records?|method|instructions?|account))\b/i,
    'Beneficiary / Master-Record Update Instruction'
  );

  // 5. Active instruction to send, remit, wire, pay, or use new account/details
  const hasUseOrPayInstruction =
    captureEvidence(
      /\b(?:please\s+|kindly\s+|instructed\s+(?:us\s+)?to\s+)?(?:use|utilize|remit(?:\s+to)?|send(?:\s+(?:funds|money|payment|payments|wires?))?\s+(?:to|into)|pay(?:\s+to|\s+into)?|wire(?:\s+to)?|transfer|route(?:\s+to)?|direct(?:\s+to)?|deposit(?:\s+into)?|credit(?:\s+to)?|make\s+(?:payments?|transfers?)\s+to|settle\s+(?:via|to|into|using))\s+(?:(?:\w+\s+){0,6})?(?:the\s+|this\s+|our\s+)?(?:new|updated|revised|below|attached|following|above)\s+(?:bank(?:ing)?\s+)?(?:beneficiary\s+)?(?:account|details?|info(?:rmation)?|instructions?|iban|routing|beneficiary|remittance)\b/i,
      'Active Payment Redirection Instruction'
    ) ||
    captureEvidence(
      /\b(?:use|remit|transfer|wire|send|pay)\s+(?:(?:\w+\s+){0,4})?(?:new|updated|revised|below|attached)\s+(?:bank|account|beneficiary|details?|instructions?)\s+(?:for|on|toward)\s+(?:this|the|all|any|your|our|future|upcoming|outstanding)\b/i,
      'Active Payment Redirection Instruction'
    );

  // 6. Supplier / Vendor / Invoice context
  const isVendorOrInvoiceUpdate = captureEvidence(
    /\b(?:supplier|vendor|contractor|subcontractor|partner|accounts?\s+payable|ap\s+team|procurement|billing\s+department|remittance|invoice(?:\s*#|\s+number|\s+payment)?)\b/i,
    'Supplier / Vendor / Invoice Context'
  );

  // 7. Payroll / Salary Direct-Deposit Diversion
  const isPayrollDiversion =
    /\b(?:payroll|salary|wages?|paycheck|direct\s+deposit|hr\s+portal|compensation)\b/i.test(norm) &&
    /\b(?:change|update|switch|new\s+(?:bank|account|routing)|divert|re-?route|direct\s+deposit|beneficiary(?:\s+account|\s+details?)?)\b/i.test(
      norm
    );
  if (isPayrollDiversion) {
    matchedSignals.push('Payroll / Direct-Deposit Diversion Signal');
    const pMatch = text.match(/\b(?:payroll|salary|direct\s+deposit|paycheck|beneficiary\s+account|bank\s+account)[^.!?\n]{0,80}/i);
    if (pMatch && !evidenceSnippets.includes(pMatch[0].trim())) {
      evidenceSnippets.push(pMatch[0].trim());
    }
  }

  // 8. Check explicit negative/informational-only guard (no payment instruction present AND explicitly non-transactional or purely aware)
  const explicitlyDeclinesPaymentInstruction =
    /\b(?:no\s+(?:payment|action)(?:\s+or\s+(?:payment|action))?\s+(?:is\s+)?(?:requested|needed|required)|do\s+not\s+(?:send|transfer|remit|update)|purely\s+(?:for\s+)?(?:your\s+)?(?:awareness|information)|for\s+your\s+records\s+only|no\s+action\s+(?:is\s+)?required)\b/i.test(
      norm
    );

  // 9. Payment process/approval directive (e.g. "CEO has approved the new payment instructions. Kindly process today.")
  const hasProcessOrApproveDirective =
    /\b(?:(?:please|kindly)\s+(?:process|release|approve|authorize|wire|transfer|remit|pay)|(?:approved|authorized)\s+(?:the\s+)?(?:new|updated|revised)\s+(?:payment|bank(?:ing)?|wire|remittance)\s+(?:instructions?|details?|account))\b/i.test(
      norm
    );

  const hasBankingDetailsChange = bankDetailsChanged || hasNewDetailsOffer;
  const hasTransferOrApprovalDirective =
    hasUseOrPayInstruction ||
    hasBeneficiaryReplacement ||
    hasFuturePaymentsDirective ||
    isPayrollDiversion ||
    hasProcessOrApproveDirective;

  const detected =
    hasBankingDetailsChange ||
    isPayrollDiversion ||
    (isVendorOrInvoiceUpdate && (hasTransferOrApprovalDirective || hasBeneficiaryReplacement)) ||
    (hasFuturePaymentsDirective && /\b(?:account|bank|details?|remit|iban|routing|beneficiary)\b/i.test(norm));

  // 10. Category C: Explicit request asking to independently verify a proposed account change before funds move
  const hasExplicitVerificationAskingPhrase =
    /\b(?:(?:please|kindly)\s+)?(?:verify|confirm|validate|check|authenticate|double[- ]check)\s+(?:the\s+|this\s+|any\s+)?(?:attached\s+|proposed\s+|requested\s+|pending\s+)?(?:bank(?:ing)?\s+)?(?:account|beneficiary|payment|remittance)\s*(?:change|update|details?|instructions?)\b/i.test(
      norm
    ) ||
    /\b(?:verify|confirm|validate|check)\s+(?:before\s+(?:processing|releasing|sending|updating|making)\s+(?:any\s+)?(?:payment|transfer|funds))\b/i.test(
      norm
    );

  const isVerificationRequest =
    detected &&
    hasExplicitVerificationAskingPhrase &&
    !explicitlyDeclinesPaymentInstruction &&
    !hasUseOrPayInstruction &&
    !hasBeneficiaryReplacement &&
    !hasFuturePaymentsDirective &&
    !isPayrollDiversion &&
    !hasProcessOrApproveDirective;

  const isActiveRedirectionRequest =
    detected &&
    !explicitlyDeclinesPaymentInstruction &&
    !isVerificationRequest &&
    (hasUseOrPayInstruction ||
      hasFuturePaymentsDirective ||
      hasBeneficiaryReplacement ||
      isPayrollDiversion ||
      hasProcessOrApproveDirective ||
      (isVendorOrInvoiceUpdate && hasBankingDetailsChange));

  const isInformationalOnlyNotice = detected && !isActiveRedirectionRequest && !isVerificationRequest;

  let rationale = 'No bank-account change or payment-redirection patterns identified.';
  if (isActiveRedirectionRequest) {
    rationale =
      'Message announces changed or updated banking/beneficiary details and directs the recipient to redirect current or future payments, update remittance records, or divert payroll. Even when polite and free of links or deadlines, unverified payment-redirection instructions are a primary Business Email Compromise (BEC) vector.';
  } else if (isVerificationRequest) {
    rationale =
      'Communication asks to verify a proposed banking or account change before funds move. It does not instruct transferring funds or replacing beneficiary records on its own, though the referenced change remains unverified until confirmed through established internal or vendor records.';
  } else if (isInformationalOnlyNotice) {
    rationale =
      'Message references a change in banking details without an explicit payment-transfer or beneficiary-replacement instruction. Treat as unverified informational notice requiring out-of-band confirmation before altering any payment workflow.';
  }

  return {
    detected,
    isActiveRedirectionRequest,
    isInformationalOnlyNotice,
    isVerificationRequest,
    isPayrollDiversion,
    isVendorOrInvoiceUpdate,
    hasBankingDetailsChange,
    hasFuturePaymentsDirective,
    hasBeneficiaryReplacement,
    hasTransferOrApprovalDirective,
    matchedSignals: Array.from(new Set(matchedSignals)),
    evidenceSnippets: evidenceSnippets.slice(0, 5),
    rationale,
  };
}

/**
 * Pure conversational / benign social greeting detection (strictly only when NO threat cues exist)
 */
export function isPureConversationalGreeting(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed || trimmed.length > 140) return false;

  const greetingPatterns = [
    /^(?:hello|hi|hey|good\s+(?:morning|afternoon|evening|day)|greetings|howdy)[,!\s.]*(?:how\s+are\s+you(?:\s+doing)?|how(?:'s|\s+is)\s+it\s+going|are\s+you\s+there|can\s+you\s+(?:attend|help|assist|talk|hear)\s+(?:to\s+)?me|what\s+is\s+up|hope\s+you(?:'re|\s+are)\s+(?:doing\s+)?well)?[\s?!.,]*$/i,
    /^(?:can\s+you\s+(?:attend|help|assist|talk|hear)\s+(?:to\s+)?me|are\s+you\s+there|how\s+are\s+you(?:\s+doing)?|what(?:'s|\s+is)\s+up)[\s?!.,]*$/i,
    /^(?:thank\s+you(?:\s+(?:very\s+much|so\s+much|for\s+your\s+(?:assistance|help|time|support|reply)))?|thanks(?:\s+(?:a\s+lot|for\s+your\s+(?:assistance|help|time)))?|ok(?:ay)?|got\s+it|understood|sounds\s+good|bye|goodbye|have\s+a\s+(?:nice|great|good)\s+day)[\s,!.]*$/i,
  ];

  return greetingPatterns.some((pat) => pat.test(trimmed));
}

/**
 * Unified 16-category Communication-Threat Classifier.
 * Uses multi-signal intent, semantic context, and behavioral correlations rather than fragile single keywords.
 */
export function classifyCommunicationThreats(text: string): UnifiedThreatTaxonomyResult {
  const norm = normalizeForIntentMatching(text);
  const paymentChange = detectPaymentChangeAndBec(text);
  const categories: ThreatCategoryMatch[] = [];

  const addCat = (id: ThreatCategoryId, confidence: ModelConfidence, signals: string[]) => {
    if (!categories.some((c) => c.id === id)) {
      categories.push({
        id,
        label: THREAT_CATEGORY_LABELS[id],
        confidence,
        matchedSignals: signals,
      });
    }
  };

  // 1 & 2 & 3 & 4 & 6 & 7 & 8: BEC & Payment Redirection family
  if (paymentChange.hasBankingDetailsChange) {
    addCat(
      'bank_account_change',
      paymentChange.isActiveRedirectionRequest ? 'high' : 'moderate',
      paymentChange.matchedSignals
    );
  }
  if (
    paymentChange.isActiveRedirectionRequest ||
    (!paymentChange.isVerificationRequest && paymentChange.isVendorOrInvoiceUpdate && paymentChange.hasBankingDetailsChange)
  ) {
    addCat('supplier_payment_redirection', 'high', paymentChange.matchedSignals);
  }
  if (
    !paymentChange.isVerificationRequest &&
    paymentChange.isVendorOrInvoiceUpdate &&
    (paymentChange.hasBankingDetailsChange || paymentChange.hasBeneficiaryReplacement)
  ) {
    addCat('invoice_beneficiary_manipulation', 'high', paymentChange.matchedSignals);
  }
  if (paymentChange.isPayrollDiversion) {
    addCat('payroll_diversion', 'high', paymentChange.matchedSignals);
  }
  if (
    !paymentChange.isVerificationRequest &&
    paymentChange.hasBankingDetailsChange &&
    (paymentChange.hasFuturePaymentsDirective || /\b(?:iban|routing|swift|account\s+number|new\s+details)\b/i.test(norm))
  ) {
    addCat('fake_banking_instructions', paymentChange.isActiveRedirectionRequest ? 'high' : 'moderate', paymentChange.matchedSignals);
  }

  // Executive impersonation
  const hasExecRole = /\b(?:ceo|cfo|coo|cto|managing\s+director|executive\s+director|president|chairman|founder|vp\s+finance|controller|director|boss)\b/i.test(
    norm
  );
  const hasExecContext =
    /\b(?:in\s+(?:a|an)\s+(?:all[- ]day\s+)?(?:board\s+)?meeting|board\s+review|conference|can(?:'t|not)\s+take\s+(?:phone\s+)?calls|keep\s+this\s+(?:quiet|confidential|between\s+us)|discreet|strictly\s+confidential|do\s+not\s+discuss|urgent\s+(?:favor|task|request|wire|transfer))\b/i.test(
      norm
    );
  const hasPaymentOrGiftAction = /\b(?:wire|transfer|gift\s*cards?|send\s+(?:money|funds)|pay(?:ment)?|process|approve|release|bank\s+account|payment\s+instructions?)\b/i.test(
    norm
  );
  if ((hasExecRole && (hasExecContext || hasPaymentOrGiftAction)) || (hasExecContext && hasPaymentOrGiftAction)) {
    addCat('executive_impersonation', 'high', [
      hasExecRole ? 'Executive title reference' : 'Executive secrecy/unavailability framing',
      hasPaymentOrGiftAction ? 'Financial or payment action request' : 'Confidentiality/urgency pressure',
    ]);
  }

  // Payment authorization manipulation
  const hasAuthManipulation =
    /\b(?:bypass|skip|override|waive)\s+(?:verification|approval|dual\s+control|policy|check)\b/i.test(norm) ||
    (!paymentChange.isVerificationRequest &&
      /\b(?:authorize|approve|release|expedite|sign\s+off|kindly\s+process|please\s+process)\b/i.test(norm) &&
      /\b(?:wire|transfer|payment|invoice|funds|settlement|urgent|immediately|today|instructions?)\b/i.test(norm));
  if (hasAuthManipulation || (paymentChange.isActiveRedirectionRequest && paymentChange.hasTransferOrApprovalDirective)) {
    addCat('payment_authorization_manipulation', hasAuthManipulation ? 'high' : 'moderate', [
      'Financial approval / payment execution directive',
    ]);
  }

  // Parent BEC category whenever any active BEC sub-vector matches (excluding purely verification-request notices)
  if (
    !paymentChange.isVerificationRequest &&
    (paymentChange.isActiveRedirectionRequest ||
      categories.some((c) =>
        [
          'supplier_payment_redirection',
          'invoice_beneficiary_manipulation',
          'executive_impersonation',
          'payroll_diversion',
          'payment_authorization_manipulation',
        ].includes(c.id)
      ))
  ) {
    addCat('business_email_compromise', paymentChange.isActiveRedirectionRequest || hasExecRole ? 'high' : 'moderate', [
      ...paymentChange.matchedSignals,
    ]);
  }

  // 9. Gift-card & cryptocurrency payment demands
  if (
    /\b(?:gift\s*cards?|apple\s*gift\s*card|steam\s*card|razer\s*gold|google\s*play\s*card|itune|amazon\s+card|bitcoin|btc|usdt|ethereum|eth|crypto(?:currency)?|crypto\s+wallet|wallet\s+address|seed\s+phrase)\b/i.test(
      norm
    )
  ) {
    addCat('gift_card_crypto_demand', 'high', ['Gift card or cryptocurrency payment vector']);
  }

  // 10. Credential & OTP harvesting
  if (
    /\b(?:otp|one[- ]time\s+(?:password|passcode|code)|(?:verification|security|confirmation|authentication|authorization|login|2fa|mfa|tac)\s*code|6[- ]digit\s+code|six[- ]digit\s+code|share\s+(?:the|your)\s+code|send\s+(?:me|us|back)?\s*(?:the|your)?\s*code|reply\s+with\s+(?:the|your)?\s*code|passwords?|passcodes?|pin\s*codes?|atm\s*pin|cvv|cvc|recovery\s*phrase|private\s*keys?|login\s*credentials)\b/i.test(
      norm
    )
  ) {
    addCat('credential_otp_harvesting', 'high', ['OTP, passcode, or credential solicitation']);
  }

  // 11. Account suspension threats
  if (
    /\b(?:accounts?\s+(?:(?:will\s+be|is|has\s+been|from\s+being|to\s+be|would\s+be|getting)\s+)?(?:blocked|suspended|frozen|locked|terminated|deactivated|closed|restricted)|prevent\s+(?:your\s+|their\s+)?accounts?\s+from\s+being\s+(?:blocked|suspended|frozen|locked)|immediate\s+suspension|account\s+(?:freeze|suspension|termination|block))\b/i.test(
      norm
    )
  ) {
    addCat('account_suspension_threat', 'high', ['Coercive account freeze / suspension threat']);
  }

  // 12. Refund & reimbursement scams
  if (
    /\b(?:refund|reimbursement|overpayment|unclaimed\s+(?:funds|money|refund)|tax\s+rebate|chargeback\s+credit|billing\s+error\s+refund|credit\s+owed)\b/i.test(
      norm
    ) &&
    /\b(?:claim|click|verify|confirm|bank|account|card|routing|fee|return\s+excess|send\s+back|reply|http|www\.|urgent|expire)\b/i.test(
      norm
    )
  ) {
    addCat('refund_reimbursement_scam', 'high', ['Unsolicited refund or reimbursement claim requesting action/details']);
  }

  // 13. Romance / task / investment / advance-fee scams
  if (
    (/\b(?:guaranteed\s+(?:returns?|profit|roi)|daily\s+(?:profit|returns?|income)|passive\s+income|crypto\s+mining|trading\s+platform|mentor|telegram\s+group|whatsapp\s+group)\b/i.test(
      norm
    ) &&
      /\b(?:invest|deposit|withdraw|profit|bonus|wallet|usdt|btc)\b/i.test(norm)) ||
    /\b(?:easy\s+online\s+tasks?|like\s+videos?\s+to\s+earn|earn\s+\$?\d+\s*(?:per\s+day|daily)|commission\s+task|advance\s+fee|inheritance|next\s+of\s+kin|lottery\s+win(?:ner)?|selected\s+(?:winner|recipient))\b/i.test(
      norm
    ) ||
    /\b(?:get|claim|receive|win|won|awarded|collect|payout)\s+(?:up\s+to\s+)?(?:\$|₦|€|£)?\s*(?:[0-9]+k|500k|[0-9]{3,}|cash\s+prize|reward)\b/i.test(
      norm
    )
  ) {
    addCat('romance_task_investment_advance_fee', 'moderate', ['High-yield investment, task, prize, or advance-fee lure']);
  }

  // 14. Delivery / package phishing
  if (
    /\b(?:usps|fedex|ups|dhl|royal\s+mail|nipost|package|parcel|shipment|delivery|courier|customs)\b/i.test(norm) &&
    /\b(?:redelivery|incomplete\s+(?:address|street)|held\s+at\s+customs|delivery\s+fee|customs\s+fee|tracking|update\s+(?:your\s+)?delivery|https?:\/\/)\b/i.test(
      norm
    )
  ) {
    addCat('delivery_package_phishing', 'high', ['Courier / package delivery fee or link lure']);
  }

  // 15. Government / regulatory impersonation
  if (
    /\b(?:central\s+bank|cbn|federal\s+reserve|irs|internal\s+revenue|fbi|ftc|sec\b|social\s+security|hmrc|tax\s+authority|ministry|court\s+summons|warrant|prosecution|arrest)\b/i.test(
      norm
    ) &&
    /\b(?:fee|fine|penalty|pay|arrest|warrant|lawsuit|suspended|blocked|verify|tax|directive|circular|mandate|announced)\b/i.test(
      norm
    )
  ) {
    addCat('government_regulatory_impersonation', 'high', ['Government or regulatory mandate / penalty claim']);
  }

  // 16. Ordinary conversational fallback check (strictly requires zero threat categories & no links/financial terms)
  const hasAnyUrl = /https?:\/\/|www\./i.test(norm);
  const hasAnyFinancialOrActionCue =
    /\b(?:bank|account|wire|transfer|invoice|payment|beneficiary|iban|routing|password|otp|pin|fee|gift\s*card|bitcoin|usdt|payroll|refund|urgent|suspended|blocked)\b/i.test(
      norm
    );

  const isOrdinaryConversational =
    categories.length === 0 &&
    !hasAnyUrl &&
    !hasAnyFinancialOrActionCue &&
    (isPureConversationalGreeting(text) ||
      (/^(?:hey|hi|hello|dear)\b/i.test(norm) &&
        /\b(?:dinner|lunch|coffee|tomorrow|weekend|catching up|meeting you|how are you)\b/i.test(norm)));

  if (isOrdinaryConversational) {
    addCat('ordinary_conversational', 'moderate', ['Routine conversational greeting or interpersonal note with no detected threat triggers']);
  }

  const primaryCategory: ThreatCategoryId = categories[0]?.id || 'ordinary_conversational';
  const primaryCategoryLabel = THREAT_CATEGORY_LABELS[primaryCategory];

  const hasCriticalThreatVector =
    paymentChange.isActiveRedirectionRequest ||
    categories.some((c) =>
      [
        'business_email_compromise',
        'supplier_payment_redirection',
        'invoice_beneficiary_manipulation',
        'executive_impersonation',
        'payroll_diversion',
        'payment_authorization_manipulation',
        'gift_card_crypto_demand',
        'credential_otp_harvesting',
        'account_suspension_threat',
        'delivery_package_phishing',
        'government_regulatory_impersonation',
        'refund_reimbursement_scam',
      ].includes(c.id)
    );

  const hasModerateThreatVector =
    !hasCriticalThreatVector &&
    (paymentChange.isInformationalOnlyNotice ||
      paymentChange.isVerificationRequest ||
      categories.some((c) => c.id !== 'ordinary_conversational'));

  return {
    primaryCategory,
    primaryCategoryLabel,
    categories,
    paymentChange,
    isOrdinaryConversational,
    hasCriticalThreatVector,
    hasModerateThreatVector,
  };
}

/**
 * Calculates normalized 0-100 severity score based on risk level and detected indicators
 */
export function calculateSeverityScore(riskLevel: RiskLevel, indicatorsCount: number): number {
  switch (riskLevel) {
    case 'high':
      return Math.min(98, Math.max(78, 76 + indicatorsCount * 5));
    case 'medium':
      return Math.min(74, Math.max(45, 45 + indicatorsCount * 7));
    case 'low':
      return Math.max(5, Math.min(25, 10 + indicatorsCount * 4));
    case 'uncertain':
    default:
      return 48;
  }
}

/**
 * Maps RiskLevel + evidence context into one of the 6 explicit assessment states.
 */
export function determineAssessmentState(params: {
  riskLevel: RiskLevel;
  hasConfirmedMaliciousIntel?: boolean;
  hasContradictedClaims?: boolean;
  isShortInsufficient?: boolean;
  hasThreatIndicators: boolean;
  isConversationalClean?: boolean;
}): AssessmentState {
  if (params.hasConfirmedMaliciousIntel || params.hasContradictedClaims) {
    return 'confirmed_malicious';
  }
  if (params.riskLevel === 'high') {
    return 'high_risk_suspicious';
  }
  if (params.riskLevel === 'medium' || (params.riskLevel === 'uncertain' && params.hasThreatIndicators)) {
    return 'suspicious_unverified';
  }
  if (params.isShortInsufficient) {
    return 'insufficient_information';
  }
  if (params.riskLevel === 'uncertain') {
    return 'inconclusive';
  }
  if (params.isConversationalClean || (params.riskLevel === 'low' && !params.hasThreatIndicators)) {
    return 'no_significant_indicators';
  }
  return 'inconclusive';
}

/**
 * Evaluates evidence sufficiency, coverage, and confidence strictly from extracted evidence volume
 * and external corroboration — never deriving evidence sufficiency from threat severity.
 */
export function evaluateEvidenceAndConfidence(
  message: string,
  _riskLevel: RiskLevel,
  indicatorsCount: number,
  options?: {
    isConversationalClean?: boolean;
    hasPrivatePaymentChange?: boolean;
    externalEvidenceObtained?: boolean;
    onlyAmbiguousIndicators?: boolean;
  }
): {
  evidenceSufficiency: EvidenceSufficiency;
  evidenceCoverage: EvidenceCoverage;
  confidence: ModelConfidence;
  confidenceRationale: string;
} {
  const trimmed = message.trim();
  const length = trimmed.length;
  const externalObtained = Boolean(options?.externalEvidenceObtained);
  const noConcreteIndicators = indicatorsCount === 0 || Boolean(options?.onlyAmbiguousIndicators);

  if (length < 25 && !options?.hasPrivatePaymentChange && noConcreteIndicators) {
    return {
      evidenceSufficiency: 'sparse',
      evidenceCoverage: 'insufficient',
      confidence: 'low',
      confidenceRationale:
        'Indeterminate (Insufficient Evidence): Submitted text is too brief and lacks sender headers, organizational metadata, or external corroboration to determine intent.',
    };
  }

  if (options?.hasPrivatePaymentChange) {
    return {
      evidenceSufficiency: length >= 60 ? 'moderate' : 'sparse',
      evidenceCoverage: externalObtained ? 'moderate' : 'limited',
      confidence: indicatorsCount >= 2 ? 'high' : 'moderate',
      confidenceRationale:
        'Behavioral and transactional payment-change markers were concretely detected in the text. However, sender authenticity, email authentication headers (SPF/DKIM/DMARC), and beneficiary account ownership remain unverified.',
    };
  }

  if (!options?.onlyAmbiguousIndicators && indicatorsCount >= 2) {
    return {
      evidenceSufficiency: externalObtained ? 'sufficient' : length >= 60 ? 'moderate' : 'sparse',
      evidenceCoverage: externalObtained ? 'sufficient' : 'limited',
      confidence: 'high',
      confidenceRationale: externalObtained
        ? 'Corroborating behavioral threat signals and external verification evidence support this risk assessment.'
        : 'Multiple concrete behavioral social-engineering indicators were extracted from the submitted content; live sender headers and external verification were not available.',
    };
  }

  if (!options?.onlyAmbiguousIndicators && indicatorsCount === 1) {
    return {
      evidenceSufficiency: externalObtained ? 'moderate' : 'sparse',
      evidenceCoverage: externalObtained ? 'moderate' : 'limited',
      confidence: 'moderate',
      confidenceRationale: externalObtained
        ? 'A concrete behavioral warning sign and partial external telemetry were observed; independent verification of sender identity remains advisable.'
        : 'One concrete behavioral indicator was detected in the submitted text, but sender headers and external corroboration were not present.',
    };
  }

  if (options?.isConversationalClean) {
    return {
      evidenceSufficiency: length >= 50 ? 'moderate' : 'sparse',
      evidenceCoverage: 'limited',
      confidence: 'moderate',
      confidenceRationale:
        'No adversarial or transactional threat markers were observed in the text. Absence of indicators in message text alone does not prove sender identity or safety.',
    };
  }

  return {
    evidenceSufficiency: externalObtained ? 'moderate' : 'sparse',
    evidenceCoverage: length < 35 && !externalObtained ? 'insufficient' : 'limited',
    confidence: 'low',
    confidenceRationale:
      length < 35 && !externalObtained
        ? 'Indeterminate (Insufficient Evidence): Ambiguous or incomplete context lacks sender authentication and external evidence to determine intent.'
        : 'Ambiguous or incomplete context: Available signals cannot establish benign or malicious intent with confidence. Independent out-of-band verification is required.',
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
  hasPaymentChangeRedirection: boolean;
  hasInformationalPaymentNotice: boolean;
  hasVerificationRequest: boolean;
  hasExecutiveImpersonation: boolean;
  hasPayrollDiversion: boolean;
  hasRefundScam: boolean;
  hasAccountBlockingThreat: boolean;
  hasArtificialDeadline: boolean;
  hasInstitutionImpersonation: boolean;
  hasSuspiciousLink: boolean;
  hasMonetaryIncentiveLure: boolean;
  isAmbiguousMessage: boolean;
  taxonomy: UnifiedThreatTaxonomyResult;
  indicators: ThreatIndicator[];
}

export function detectBehavioralThreats(text: string): DetectedBehavioralThreats {
  const lower = normalizeForIntentMatching(text);
  const indicators: ThreatIndicator[] = [];
  const taxonomy = classifyCommunicationThreats(text);
  const pc = taxonomy.paymentChange;

  // 0. Dedicated BEC / Bank-Account Change / Supplier Payment Redirection
  const hasPaymentChangeRedirection = pc.isActiveRedirectionRequest;
  const hasInformationalPaymentNotice = pc.isInformationalOnlyNotice;
  const hasVerificationRequest = pc.isVerificationRequest;
  const hasPayrollDiversion = pc.isPayrollDiversion;

  if (hasPaymentChangeRedirection) {
    indicators.push({
      name: pc.isPayrollDiversion
        ? 'Payroll / Direct-Deposit Bank Change Redirection'
        : 'Bank Account Change & Payment Redirection Request (BEC Indicator)',
      evidence: pc.evidenceSnippets.join(' | ') || text.slice(0, 120),
      reason:
        'Unverified instructions announcing changed bank details and directing current or future payments to new account details are classic hallmarks of Business Email Compromise (BEC) and vendor impersonation fraud, even when phrased politely without links or urgency.',
    });
  } else if (hasVerificationRequest) {
    indicators.push({
      name: 'Bank-Account Change Verification Request',
      evidence: pc.evidenceSnippets.join(' | ') || text.slice(0, 120),
      reason:
        'Communication requests verification of a proposed banking or account change prior to fund release. Confirm strictly via previously established contact records rather than assuming legitimacy from the message alone.',
    });
  } else if (hasInformationalPaymentNotice) {
    indicators.push({
      name: 'Unverified Bank-Account Change Reference',
      evidence: pc.evidenceSnippets.join(' | ') || text.slice(0, 120),
      reason:
        'References a banking or beneficiary change without independent verification. Never treat unverified banking-change notices as safe without out-of-band confirmation.',
    });
  }

  if (pc.hasBeneficiaryReplacement && hasPaymentChangeRedirection) {
    indicators.push({
      name: 'Beneficiary / Payment Record Manipulation Directive',
      evidence: pc.evidenceSnippets[0] || text.slice(0, 100),
      reason:
        'Directing recipients to overwrite existing bank, supplier, or beneficiary records enables persistent diversion of future invoice settlements.',
    });
  }

  const hasExecutiveImpersonation = taxonomy.categories.some((c) => c.id === 'executive_impersonation');
  if (hasExecutiveImpersonation) {
    const execEvidence =
      text.match(/\b(?:ceo|cfo|president|director|boss|board\s+(?:meeting|review)|keep\s+this\s+quiet|confidential|can(?:'t|not)\s+take\s+(?:phone\s+)?calls)[^.!?\n]{0,80}/i)?.[0] ||
      text.slice(0, 100);
    indicators.push({
      name: 'Executive / Authority Impersonation & Secrecy Lure',
      evidence: execEvidence,
      reason:
        'Claiming executive authority while claiming unavailability for phone calls or requesting secrecy is a hallmark CEO/BEC fraud technique designed to bypass payment approval controls.',
    });
  }

  const hasRefundScam = taxonomy.categories.some((c) => c.id === 'refund_reimbursement_scam');
  if (hasRefundScam) {
    const refEvidence = text.match(/\b(?:refund|reimbursement|overpayment|rebate)[^.!?\n]{0,80}/i)?.[0] || text.slice(0, 100);
    indicators.push({
      name: 'Unsolicited Refund / Reimbursement Social-Engineering Lure',
      evidence: refEvidence,
      reason:
        'Unexpected refund or overpayment notices frequently trick victims into revealing banking credentials, issuing reverse transfers, or clicking phishing links.',
    });
  }

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

  // 8. Calibrated Link Analysis
  let hasSuspiciousLink = false;
  const urlMatches = text.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  const directIpRegex = /\bhttps?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:\/[^\s]*)?\b/i;
  const ipMatch = text.match(directIpRegex);

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

  if (ipMatch && !shortenerMatch) {
    hasSuspiciousLink = true;
    indicators.push({
      name: 'Direct-IP Host Destination',
      evidence: ipMatch[0],
      reason:
        'Using a raw numeric IP address instead of a registered domain bypasses standard domain name registration accountability and TLS hostname verification.',
    });
  }

  const freeHostingRegex =
    /\bhttps?:\/\/([a-zA-Z0-9-]+\.(?:site123\.me|weebly\.com|wixsite\.com|webflow\.io|000webhostapp\.com|firebaseapp\.com|pages\.dev|github\.io|glitch\.me|pantheonsite\.io))[^\s]*/i;
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

  for (const rawUrl of urlMatches) {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      const hostname = parsed.hostname.toLowerCase();
      const parts = hostname.split('.');
      if (parts.length >= 3) {
        const sub = parts[0];
        if (
          /^[a-f0-9]{10,}$/i.test(sub) ||
          (/^[a-z0-9_-]{12,}$/i.test(sub) && /[0-9]/.test(sub) && /[a-z]/.test(sub))
        ) {
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

  const highRiskTldRegex =
    /\bhttps?:\/\/[a-zA-Z0-9-]+\.(?:top|xyz|icu|click|work|download|link|fun|loan|stream)\b[^\s]*/i;
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

  // 9. Ambiguous messages requiring more context (excluding pure greetings and detected threats)
  const isAmbiguousMessage =
    lower.length < 50 &&
    !hasPaymentChangeRedirection &&
    !hasInformationalPaymentNotice &&
    !hasExecutiveImpersonation &&
    !hasAuthCodeRequest &&
    !hasCredentialHarvesting &&
    !hasRemoteAccessRequest &&
    !hasPaymentDemand &&
    !hasSuspiciousLink &&
    !hasMonetaryIncentiveLure &&
    /(?:call\s+me|contact\s+me|reply\s+back|need\s+a\s+favor|are\s+you\s+available|are\s+you\s+there)/i.test(lower);

  if (isAmbiguousMessage && !isPureConversationalGreeting(text)) {
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
    hasPaymentChangeRedirection,
    hasInformationalPaymentNotice,
    hasVerificationRequest,
    hasExecutiveImpersonation,
    hasPayrollDiversion,
    hasRefundScam,
    hasAccountBlockingThreat,
    hasArtificialDeadline,
    hasInstitutionImpersonation,
    hasSuspiciousLink,
    hasMonetaryIncentiveLure,
    isAmbiguousMessage,
    taxonomy,
    indicators,
  };
}

/**
 * Generates audience-specific safety recommendations tailored to detected BEC,
 * payment redirection, credential theft, or general threat categories without
 * ever inventing agencies, official phone numbers, or portal URLs.
 */
export function buildAudienceSafetyRecommendations(
  text: string,
  behavioral?: DetectedBehavioralThreats
): {
  forIndividuals: string[];
  forOrganizations: string[];
  forFinanceTeams: string[];
  forSecurityTeams: string[];
} {
  const b = behavioral || detectBehavioralThreats(text);
  const pc = b.taxonomy.paymentChange;
  const isPaymentOrBec =
    pc.detected ||
    b.hasExecutiveImpersonation ||
    b.hasPayrollDiversion ||
    b.taxonomy.categories.some((c) =>
      [
        'business_email_compromise',
        'bank_account_change',
        'supplier_payment_redirection',
        'invoice_beneficiary_manipulation',
        'fake_banking_instructions',
        'payment_authorization_manipulation',
      ].includes(c.id)
    );

  if (isPaymentOrBec) {
    return {
      forIndividuals: [
        'Do not transfer funds or update payment details until the request is independently verified.',
        'Ignore phone numbers, email reply addresses, or links embedded inside the suspicious communication itself.',
        'Contact the purported sender or organization using a previously established and independently verified contact number or directory.',
        'Verify the exact beneficiary name and account details directly before authorizing any settlement or transfer.',
        'If the communication claims to come from your bank, verify solely through the official mobile banking app or the telephone number printed on the back of your bank card.',
        'Do not disclose one-time passcodes (OTPs), PINs, passwords, or authentication codes under any circumstances.',
        'If funds have already been sent, immediately contact your sending bank’s fraud or payment-recall department.',
      ],
      forOrganizations: [
        'Place the requested account or beneficiary change on hold until out-of-band verification via a pre-existing vendor/partner record is completed.',
        'Treat polite, link-free, or deadline-free bank-change requests as high-priority Business Email Compromise (BEC) risks until independently verified.',
        'Review email authentication headers (SPF, DKIM, DMARC) when email headers are available, and watch for lookalike domain spoofing or compromised partner mailboxes.',
        'Preserve the original email, message, invoice, attachments, and relevant audit records, and escalate via established internal incident-response procedures.',
      ],
      forFinanceTeams: [
        'Place any account-change or payment-destination update on immediate hold and suspend pending disbursements to the affected vendor, employee, or partner.',
        'Contact an authorized representative of the vendor, partner, or colleague using a previously established phone number from existing company master records—never a number from the new message.',
        'Require independent confirmation through a second communication channel before updating any supplier, payroll, or beneficiary details.',
        'Verify beneficiary name, bank, IBAN/routing details, and ownership against approved vendor master records.',
        'Follow dual-control authorization and formal payment-approval procedures before modifying master banking records or releasing funds.',
        'Preserve the original email, message, invoice, attachments, and relevant audit records without altering or deleting evidence.',
        'If funds have already been sent, immediately contact the sending bank’s fraud or payment-recall department and retain all wire/transfer reference identifiers.',
      ],
      forSecurityTeams: [
        'Preserve full message headers, original emails, invoices, attachments, and relevant audit records intact for forensic investigation.',
        'Investigate sender authentication (SPF, DKIM, DMARC) and lookalike domains when original email headers and mail-gateway logs are available.',
        'Examine any referenced URLs or attachments exclusively within safe, isolated inspection infrastructure.',
        'Escalate confirmed or suspected Business Email Compromise attempts through established internal incident-response procedures and alert accounts payable and payroll staff.',
      ],
    };
  }

  if (b.hasAuthCodeRequest || b.hasCredentialHarvesting) {
    return {
      forIndividuals: [
        'Do not disclose one-time passcodes (OTPs), 2FA codes, PINs, or account passwords—legitimate banks and services never ask you to forward or reply with verification codes.',
        'Ignore phone numbers and links inside the suspicious message; if the notice claims to be from your bank, open your official app or call the number on the back of your bank card.',
        'If you already shared a code or password, reset your credentials immediately and contact your financial institution’s fraud department.',
      ],
      forOrganizations: [
        'Warn employees against MFA fatigue and OTP interception lures impersonating IT helpdesks or banks.',
        'Audit recent authentication and session logs if any credential or verification code may have been disclosed.',
      ],
      forFinanceTeams: [
        'Ensure corporate banking portals enforce phishing-resistant MFA and alert treasury staff immediately if credential disclosure is suspected.',
        'Preserve the original communication and relevant audit records for incident review.',
      ],
      forSecurityTeams: [
        'Preserve message headers, original messages, attachments, and authentication audit records.',
        'Revoke active sessions, reset compromised credentials, examine embedded URLs safely, and escalate via established incident-response procedures.',
      ],
    };
  }

  if (b.taxonomy.isOrdinaryConversational && !b.hasSuspiciousLink && !b.hasPaymentDemand) {
    return {
      forIndividuals: [
        'No adversarial payment or credential indicators were detected in this message text.',
        'Do not share OTPs, PINs, passwords, or transfer funds if an unfamiliar contact later introduces financial or verification requests without independent confirmation.',
      ],
      forOrganizations: [
        'Standard awareness: remind staff that social engineering campaigns can begin with benign casual greetings before pivoting to sensitive requests.',
      ],
      forFinanceTeams: [
        'No payment-change or invoice-redirection directives were identified in this message.',
      ],
      forSecurityTeams: [
        'No active threat indicators identified in the submitted text; maintain routine monitoring if sent by an unknown external contact.',
      ],
    };
  }

  return {
    forIndividuals: [
      'Do not transfer funds until the request and beneficiary details are independently verified.',
      'Ignore phone numbers or links inside suspicious messages; use a previously established, independently verified contact number, your official bank app, or the number on the back of your bank card.',
      'Do not disclose OTPs, PINs, passwords, or authentication codes based on any message.',
    ],
    forOrganizations: [
      'Verify unexpected financial, account, or administrative requests out-of-band before acting.',
      'Preserve the original communication, attachments, and relevant audit records, and escalate via established incident-response procedures.',
    ],
    forFinanceTeams: [
      'Place questionable payment or account updates on hold, verify beneficiary details against approved vendor records via a second channel, and follow dual-authorization procedures.',
      'Preserve the original email, message, invoice, attachments, and relevant audit records, and contact the sending bank’s fraud/recall department immediately if funds moved.',
    ],
    forSecurityTeams: [
      'Preserve message headers, original emails, attachments, and relevant audit records.',
      'Investigate sender authentication where email headers exist, inspect URLs/attachments via safe inspection tooling, and escalate via established incident-response procedures.',
    ],
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
  const behavioral = detectBehavioralThreats(originalMessage);
  const audience = buildAudienceSafetyRecommendations(originalMessage, behavioral);
  const actions: string[] = [];

  if (
    behavioral.hasPaymentChangeRedirection ||
    behavioral.hasInformationalPaymentNotice ||
    behavioral.hasVerificationRequest ||
    behavioral.hasExecutiveImpersonation ||
    behavioral.hasPayrollDiversion
  ) {
    actions.push(...audience.forFinanceTeams);
  }

  // 1. Critical Authentication Code / Credential Safety
  if (behavioral.hasAuthCodeRequest || behavioral.hasCredentialHarvesting) {
    actions.push(
      'Never share one-time passwords (OTPs), verification codes, PINs, or passwords with anyone. Legitimate service providers and banks NEVER request verification codes via message.'
    );
  }

  // 2. Remote Access Defense
  if (behavioral.hasRemoteAccessRequest) {
    actions.push(
      'Never download or install remote-access software (such as AnyDesk or TeamViewer) or grant screen-sharing permissions to unsolicited callers or messagers.'
    );
  }

  // 3. Payment & Gift Card Defense
  if (behavioral.hasPaymentDemand) {
    actions.push(
      'Never purchase gift cards, transfer cryptocurrency, or wire funds to satisfy unexpected payment demands or alleged verification fees.'
    );
  }

  // 4. URL & Link Safety
  const hasUrl =
    iocs.urls.length > 0 ||
    behavioral.hasSuspiciousLink ||
    indicators.some((i) => i.name.toLowerCase().includes('link') || i.name.toLowerCase().includes('url'));
  if (hasUrl) {
    actions.push('Do NOT click, preview, or paste the embedded link into your web browser.');
  }

  // 5. Artificial Deadline / Urgency Defense
  if (behavioral.hasArtificialDeadline || behavioral.hasAccountBlockingThreat) {
    actions.push('Pause and do not let artificial deadlines or threats of account suspension force you into hasty decisions.');
  }

  // 6. Direct Institutional Verification
  const msgContext = (originalMessage + ' ' + indicators.map((i) => i.evidence).join(' ')).toLowerCase();
  const isBankingOrInstitutional =
    behavioral.hasInstitutionImpersonation ||
    /cbn|central bank|bank|account|bvn|nin|verification fee|block|frozen|debit|transfer|wire|irs|tax/i.test(msgContext);

  if (isBankingOrInstitutional && !behavioral.hasPaymentChangeRedirection) {
    actions.push('Do NOT pay the suspicious demand, transfer funds, or provide payment fees under any circumstances.');
    actions.push(
      'Contact the institution directly using independently verified contact details (such as the number on the back of your card or in your official mobile app), never details supplied in the message.'
    );
  }

  if (behavioral.isAmbiguousMessage) {
    actions.push('Request more context through an independent, verified communication channel before responding to vague requests.');
  }

  actions.push(...modelActions);

  // Deduplicate and preserve up to 6 prioritized actions
  const unique = Array.from(new Set(actions.map((a) => a.trim()))).filter((a) => a.length > 0);
  if (unique.length === 0) {
    return audience.forIndividuals;
  }
  return unique.slice(0, 6);
}

/**
 * Builds the three cleanly separated assessment dimensions for any analysis result.
 */
export function buildSeparatedAssessmentDimensions(params: {
  message: string;
  riskLevel: RiskLevel;
  severityScore: number;
  indicators: ThreatIndicator[];
  behavioral: DetectedBehavioralThreats;
  assessmentState: AssessmentState;
  factualStatus?: FactualVerificationDimension['status'];
  factualSummary?: string;
  hasVerifiablePublicClaims?: boolean;
  verifiedClaimsCount?: number;
  contradictedClaimsCount?: number;
  unverifiedClaimsCount?: number;
  externalEvidenceObtained?: boolean;
  iocs?: ExtractedIOCs;
}): {
  threatAssessment: ThreatAssessmentDimension;
  factualVerification: FactualVerificationDimension;
  authenticityAssessment: AuthenticityAssessmentDimension;
} {
  const { behavioral, riskLevel, severityScore, indicators, assessmentState } = params;
  const taxonomy = behavioral.taxonomy;
  const pc = taxonomy.paymentChange;

  let threatSummary = 'No significant behavioral threat indicators identified in the submitted text.';
  if (pc.isActiveRedirectionRequest) {
    threatSummary =
      'High-risk Business Email Compromise (BEC) / payment-redirection pattern: message attempts to redirect current or future payments or modify beneficiary bank details without independent verification.';
  } else if (pc.isVerificationRequest) {
    threatSummary =
      'Verification-required banking-change reference: communication asks to verify a proposed account change before funds move. Confirm strictly through established internal or vendor records.';
  } else if (pc.isInformationalOnlyNotice) {
    threatSummary =
      'Moderate-risk banking-change notice: banking/account change is referenced without independent verification. Confirm through pre-established channels before acting.';
  } else if (riskLevel === 'high') {
    threatSummary = `High-risk social-engineering behavior detected under ${taxonomy.primaryCategoryLabel}.`;
  } else if (riskLevel === 'medium') {
    threatSummary = `Elevated behavioral or contextual risk indicators detected under ${taxonomy.primaryCategoryLabel}.`;
  } else if (riskLevel === 'uncertain') {
    threatSummary = 'Ambiguous or insufficient context; behavioral risk could not be ruled out.';
  }

  const threatAssessment: ThreatAssessmentDimension = {
    severity: riskLevel,
    severityScore,
    assessmentState,
    assessmentStateLabel: ASSESSMENT_STATE_LABELS[assessmentState],
    primaryCategory: taxonomy.primaryCategory,
    primaryCategoryLabel: taxonomy.primaryCategoryLabel,
    categories: taxonomy.categories,
    paymentChangeDetected: pc.detected,
    isActivePaymentRedirection: pc.isActiveRedirectionRequest,
    behavioralIndicators: indicators,
    summary: threatSummary,
  };

  const factualStatus: FactualVerificationDimension['status'] =
    params.factualStatus ||
    (params.hasVerifiablePublicClaims
      ? params.contradictedClaimsCount
        ? 'contradicted'
        : params.verifiedClaimsCount
        ? 'supported'
        : 'unverified'
      : pc.detected || taxonomy.hasCriticalThreatVector
      ? 'not_applicable_private_communication'
      : 'not_executed');

  const factualSummary =
    params.factualSummary ||
    (factualStatus === 'not_applicable_private_communication'
      ? 'No publicly indexable entity, URL, or factual claim was identified; this is a private bilateral/transactional communication where public web search cannot verify account ownership.'
      : params.externalEvidenceObtained
      ? 'Publicly available records and web sources were cross-examined against claims extracted from the communication.'
      : 'External public web verification was not applicable or not executed for this message.');

  const factualVerification: FactualVerificationDimension = {
    status: factualStatus,
    hasVerifiablePublicClaims: Boolean(params.hasVerifiablePublicClaims),
    claimsSummary: factualSummary,
    verifiedClaimsCount: params.verifiedClaimsCount ?? 0,
    contradictedClaimsCount: params.contradictedClaimsCount ?? 0,
    unverifiedClaimsCount: params.unverifiedClaimsCount ?? (pc.detected ? 1 : 0),
  };

  const hasUrls = (params.iocs?.urls?.length || 0) > 0;
  const hasEmails = (params.iocs?.emails?.length || 0) > 0;

  const authenticityAssessment: AuthenticityAssessmentDimension = {
    status: behavioral.hasSuspiciousLink || behavioral.hasInstitutionImpersonation || pc.isActiveRedirectionRequest
      ? 'anomalous'
      : params.externalEvidenceObtained
      ? 'partially_corroborated'
      : 'unverified',
    senderIdentityVerified: false,
    organizationIdentityStatus: behavioral.hasInstitutionImpersonation
      ? 'Claimed institutional identity is unverified in message text alone.'
      : hasEmails
      ? `Sender email (${params.iocs?.emails?.[0]}) authenticity (SPF/DKIM/DMARC) cannot be verified from plain text.`
      : 'No authenticated sender headers, cryptographic signature, or verified organizational identity provided.',
    domainOrChannelStatus: hasUrls
      ? 'Embedded URL/domain requires independent verification; unlisted threat-feed status does not prove authenticity.'
      : 'No verified official portal or domain authentication headers available.',
    paymentDestinationStatus: pc.detected
      ? 'Destination bank account / beneficiary details are completely unverified. Never assume newly supplied payment coordinates are legitimate.'
      : 'No verified payment destination records available.',
    summary: pc.detected
      ? 'Sender authority and new banking/beneficiary details are unverified. Independent out-of-band confirmation via a previously trusted phone number or channel is mandatory.'
      : 'Sender identity, organizational affiliation, and communication headers are not cryptographically verified from text alone.',
  };

  return {
    threatAssessment,
    factualVerification,
    authenticityAssessment,
  };
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

  let riskLevel: RiskLevel = 'uncertain';
  if (typeof rawJson.riskLevel === 'string') {
    const normalized = rawJson.riskLevel.toLowerCase().trim();
    if (['high', 'medium', 'low', 'uncertain'].includes(normalized)) {
      riskLevel = normalized as RiskLevel;
    }
  }

  const summary =
    typeof rawJson.summary === 'string' && rawJson.summary.trim()
      ? rawJson.summary.trim()
      : 'No summary was provided by the analysis engine.';

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

  // Deterministic Behavioral Threat + Unified Taxonomy Detection
  const behavioral = detectBehavioralThreats(originalMessage);
  const taxonomy = behavioral.taxonomy;
  const pc = taxonomy.paymentChange;

  for (const bInd of behavioral.indicators) {
    if (!indicators.some((i) => i.name.toLowerCase() === bInd.name.toLowerCase())) {
      indicators.push(bInd);
    }
  }

  const hasCriticalBehavioralThreat =
    behavioral.hasAuthCodeRequest ||
    behavioral.hasCredentialHarvesting ||
    behavioral.hasRemoteAccessRequest ||
    behavioral.hasPaymentChangeRedirection ||
    behavioral.hasExecutiveImpersonation ||
    behavioral.hasPayrollDiversion ||
    behavioral.hasRefundScam ||
    (behavioral.hasAccountBlockingThreat && (behavioral.hasPaymentDemand || behavioral.hasArtificialDeadline)) ||
    taxonomy.hasCriticalThreatVector;

  const hasModerateBehavioralThreat =
    !hasCriticalBehavioralThreat &&
    (behavioral.hasInformationalPaymentNotice ||
      behavioral.hasVerificationRequest ||
      behavioral.hasPaymentDemand ||
      behavioral.hasAccountBlockingThreat ||
      behavioral.hasSuspiciousLink ||
      behavioral.hasMonetaryIncentiveLure ||
      taxonomy.hasModerateThreatVector);

  if (hasCriticalBehavioralThreat && riskLevel !== 'high') {
    riskLevel = 'high';
  } else if (hasModerateBehavioralThreat && (riskLevel === 'low' || (pc.isVerificationRequest && riskLevel === 'high'))) {
    riskLevel = 'medium';
  }

  // Ensure ordinary conversational messages aren't falsely kept at 'uncertain' if model agrees clean,
  // while never marking ambiguous fragments as high confidence safe
  if (taxonomy.isOrdinaryConversational && indicators.length === 0 && riskLevel === 'uncertain') {
    riskLevel = 'low';
  }

  // Calibrate summary tone
  let calibratedSummary = summary;
  if (hasCriticalBehavioralThreat) {
    if (pc.isActiveRedirectionRequest && !/bank|account|redirect|compromise|bec|beneficiary|payment|high risk/i.test(calibratedSummary)) {
      calibratedSummary =
        'High Risk (Potential Business Email Compromise / Payment Redirection): This message requests using newly supplied banking or payment details for current or future payments. Even without links or explicit urgency, unverified bank-account change instructions must be held and verified out-of-band via a previously known phone number before releasing any funds.';
    } else if (!/otp|code|credential|remote|phishing|high risk|unverified|redirect|bank|impersonation|refund/i.test(calibratedSummary)) {
      if (behavioral.hasAuthCodeRequest) {
        calibratedSummary = `High Risk: This message requests sensitive authentication or verification codes. Legitimate service providers and banks never request verification codes via direct messages. This represents a strong phishing indicator that should not be acted upon.`;
      } else if (behavioral.hasRemoteAccessRequest) {
        calibratedSummary = `High Risk: This message instructs the recipient to install remote-access software (such as AnyDesk or TeamViewer). Unsolicited remote-access demands are primary vectors for full device takeover and should not be acted upon.`;
      } else if (behavioral.hasCredentialHarvesting) {
        calibratedSummary = `High Risk: This message solicits private account credentials or PIN codes. This is an unverified request that should not be acted upon.`;
      } else if (behavioral.hasExecutiveImpersonation) {
        calibratedSummary = `High Risk: This message exhibits executive impersonation and confidential financial-pressure hallmarks consistent with Business Email Compromise (BEC). Do not execute the request without independent voice verification.`;
      }
    }
  } else if (pc.isVerificationRequest && riskLevel === 'medium') {
    calibratedSummary = `Verification Required: This message asks to verify a proposed banking or account change before funds move. It does not instruct sending funds or altering beneficiary records on its own, though the referenced change must be confirmed strictly via established internal or vendor records.`;
  } else if (pc.isInformationalOnlyNotice && riskLevel === 'medium') {
    calibratedSummary = `Advisory Warning: ${summary} No verified proof confirms authenticity of the referenced bank-account change; confirm through an independently known contact channel before altering payment records.`;
  }

  const rawActions: string[] = [];
  if (Array.isArray(rawJson.recommendedActions)) {
    for (const action of rawJson.recommendedActions) {
      if (typeof action === 'string' && action.trim()) {
        rawActions.push(action.trim());
      }
    }
  }

  const limitations: string[] = [];
  if (Array.isArray(rawJson.limitations)) {
    for (const lim of rawJson.limitations) {
      if (typeof lim === 'string' && lim.trim()) {
        limitations.push(lim.trim());
      }
    }
  }

  const unverifiedClaims: string[] = [];
  if (Array.isArray(rawJson.unverifiedClaims)) {
    for (const clm of rawJson.unverifiedClaims) {
      if (typeof clm === 'string' && clm.trim()) {
        unverifiedClaims.push(clm.trim());
      }
    }
  }
  if (pc.detected && unverifiedClaims.length === 0) {
    unverifiedClaims.push(
      'Authenticity of sender and authorization to change bank account or beneficiary payment instructions.'
    );
  }

  const iocs = extractIOCsFromMessage(originalMessage);
  let severityScore = calculateSeverityScore(riskLevel, indicators.length);
  if (hasCriticalBehavioralThreat) {
    severityScore = Math.max(82, severityScore);
  }

  const concreteIndicators = indicators.filter((i) => !i.name.startsWith('Ambiguous Context'));
  const onlyAmbiguousIndicators = indicators.length > 0 && concreteIndicators.length === 0;

  const { evidenceSufficiency, evidenceCoverage, confidence, confidenceRationale } = evaluateEvidenceAndConfidence(
    originalMessage,
    riskLevel,
    indicators.length,
    {
      isConversationalClean: taxonomy.isOrdinaryConversational && concreteIndicators.length === 0,
      hasPrivatePaymentChange: pc.detected,
      externalEvidenceObtained: false,
      onlyAmbiguousIndicators,
    }
  );

  const assessmentState = determineAssessmentState({
    riskLevel,
    isShortInsufficient: originalMessage.trim().length < 25 && concreteIndicators.length === 0,
    hasThreatIndicators: concreteIndicators.length > 0 || pc.detected,
    isConversationalClean: taxonomy.isOrdinaryConversational && concreteIndicators.length === 0,
  });

  const { threatAssessment, factualVerification, authenticityAssessment } = buildSeparatedAssessmentDimensions({
    message: originalMessage,
    riskLevel,
    severityScore,
    indicators,
    behavioral,
    assessmentState,
    externalEvidenceObtained: false,
    iocs,
  });

  const recommendedActions = deriveRelevantActions(rawActions, indicators, iocs, riskLevel, originalMessage);
  const audienceRecs = buildAudienceSafetyRecommendations(originalMessage, behavioral);

  return {
    riskLevel,
    summary: calibratedSummary,
    indicators,
    recommendedActions:
      recommendedActions.length > 0
        ? recommendedActions
        : audienceRecs.forIndividuals,
    limitations:
      limitations.length > 0
        ? limitations
        : [
            'This direct-message analysis evaluates message content and behavioral indicators. Absence of verified email headers (SPF/DKIM/DMARC) or external web confirmation means sender identity and account ownership cannot be verified from text alone.',
          ],
    model: modelName,
    analyzedAt: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    severityScore,
    iocs,
    evidenceSufficiency,
    evidenceCoverage,
    confidence,
    confidenceRationale,
    assessmentState,
    assessmentStateLabel: ASSESSMENT_STATE_LABELS[assessmentState],
    primaryThreatCategory: taxonomy.primaryCategory,
    threatCategories: taxonomy.categories,
    paymentChangeDetection: pc,
    threatAssessment,
    factualVerification,
    authenticityAssessment,
    financeRecommendations: audienceRecs.forFinanceTeams,
    unverifiedClaims: unverifiedClaims.length > 0 ? unverifiedClaims : undefined,
    externalEvidenceObtained: false,
  };
}

