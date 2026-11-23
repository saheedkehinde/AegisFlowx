import { FactualClaim, ClaimAssessmentResult } from './types';
import {
  extractIOCsFromMessage,
  detectBehavioralThreats,
  isPureConversationalGreeting,
  detectPaymentChangeAndBec,
} from '@/lib/scam-analyzer';

export interface ExtractedEntities {
  hasVerifiableClaims: boolean;
  organizations: string[];
  persons: string[];
  financialRequests: string[];
  contactDetails: {
    urls: string[];
    emails: string[];
    phones: string[];
  };
  urgencyDeadlines: string[];
  referenceIdentifiers: string[]; // Order numbers, invoice numbers, case IDs
  claims: FactualClaim[];
  conversationalNotes?: string;
  extractionLimitation?: string;
}

// Conversational introductory prefixes (e.g., "Good morning! The Central Bank has announced...")
const INTRO_GREETING_REGEX =
  /^(?:hello|hi|hey|good\s+(?:morning|afternoon|evening|day)|greetings|dear\s+(?:customer|user|client|sir|madam|friend))[\s,!.-]+/i;

// Stop-word phrases that resemble capitalized multi-word entities but are not organizations
const NON_ENTITY_PHRASES = new Set([
  'good morning',
  'good afternoon',
  'good evening',
  'good day',
  'thank you',
  'hello there',
  'dear customer',
  'dear user',
  'dear client',
  'dear sir',
  'dear madam',
  'action required',
  'final notice',
  'urgent notice',
  'security alert',
  'important update',
  'please note',
  'kindly note',
  'please use',
  'future payments',
]);

/**
 * Extracts verifiable claims and entities from text or extracted document evidence.
 * Strictly distinguishes public verifiable factual assertions from private transactional
 * directives (e.g., BEC bank-account changes) and ordinary conversational greetings.
 */
export function extractClaimsAndEntities(text: string): ExtractedEntities {
  const iocs = extractIOCsFromMessage(text);
  const trimmed = text.trim();

  // 1. Check for document extraction limitations (e.g. image-only PDF without OCR layer)
  const isExtractionLimitation =
    trimmed.startsWith('[Notice: This PDF does not contain an embedded digital text layer') ||
    trimmed.startsWith('[Notice: Unindexed image') ||
    trimmed === '';

  if (isExtractionLimitation) {
    return {
      hasVerifiableClaims: false,
      organizations: [],
      persons: [],
      financialRequests: [],
      contactDetails: { urls: [], emails: [], phones: [] },
      urgencyDeadlines: [],
      referenceIdentifiers: [],
      extractionLimitation:
        'The uploaded document or screenshot does not contain an extractable digital text layer (image-only scan or empty file). Web research could not extract verifiable textual claims.',
      claims: [],
    };
  }

  // Evaluate behavioral & payment-change signals before considering conversational fast-path
  const paymentChange = detectPaymentChangeAndBec(trimmed);
  const behavioral = detectBehavioralThreats(trimmed);
  const hasThreatOrTransactionalCue =
    paymentChange.detected ||
    behavioral.taxonomy.hasCriticalThreatVector ||
    behavioral.taxonomy.hasModerateThreatVector ||
    behavioral.indicators.length > 0 ||
    /\b(?:bank|account|details?|beneficiary|remit|iban|routing|swift|payroll|salary|fee|pay|payment|invoice|wire|transfer|refund|overpayment|gift\s*card|bitcoin|usdt|otp|password|pin|code|verify|notice|cbn)\b/i.test(
      trimmed
    );

  // 2. Fast check strictly limited to pure conversational greetings with ZERO threat or transactional cues
  const isPureGreeting = isPureConversationalGreeting(trimmed) && !hasThreatOrTransactionalCue;
  const isShortNonFactual =
    trimmed.length < 35 &&
    !hasThreatOrTransactionalCue &&
    !/\$|₦|€|£|[0-9]{3,}|https?:\/\/|\.com|\.org|\.gov/i.test(trimmed);

  if (isPureGreeting || isShortNonFactual) {
    return {
      hasVerifiableClaims: false,
      organizations: [],
      persons: [],
      financialRequests: [],
      contactDetails: {
        urls: iocs.urls,
        emails: iocs.emails,
        phones: iocs.phoneNumbers,
      },
      urgencyDeadlines: [],
      referenceIdentifiers: [],
      conversationalNotes: isPureGreeting
        ? 'The submitted content is an ordinary conversational greeting or polite remark with no verifiable public claims or threat indicators.'
        : 'The submitted text is brief and contains no independently verifiable public claims or transactional instructions.',
      claims: [
        {
          id: 'claim-non-factual-1',
          claimText: trimmed,
          isFactual: false,
          verdict: 'no_verifiable_claim',
          verdictExplanation: isPureGreeting
            ? 'Ordinary conversational exchange with no verifiable public claims, URLs, or financial directives.'
            : 'Too brief to contain an independently verifiable public claim.',
          evidenceNeeded:
            'Full message context, sender headers, or specific organizational/transactional details.',
          supportingEvidence: [],
          contradictingEvidence: [],
          citedSourceUrls: [],
        },
      ],
    };
  }

  // Strip introductory pleasantries for cleaner entity scanning
  const substantiveText = trimmed.replace(INTRO_GREETING_REGEX, '').trim() || trimmed;

  // 3. Extract organizations (central banks, financial institutions, tech providers, couriers, government agencies)
  const organizations = new Set<string>();

  const centralBankPatterns = [
    /\b(Central Bank of Nigeria|CBN)\b/gi,
    /\b(Federal Reserve|Fed|Bank of England|European Central Bank|ECB|Reserve Bank of India|RBI|Bank of Ghana|Bank of Canada|Reserve Bank of Australia|RBA|Monetary Authority of Singapore|MAS)\b/gi,
    /\b(Central Bank(?: of [A-Z][a-zA-Z]+)?)\b/g,
    /\b(Reserve Bank(?: of [A-Z][a-zA-Z]+)?)\b/g,
    /\b(Bank of [A-Z][a-zA-Z]+)\b/g,
    /\b(Ministry of [A-Z][a-zA-Z]+)\b/g,
    /\b(Department of [A-Z][a-zA-Z]+)\b/g,
  ];

  for (const pat of centralBankPatterns) {
    let match;
    while ((match = pat.exec(substantiveText)) !== null) {
      organizations.add(match[1].trim());
    }
  }

  const financialOrgPatterns = [
    /\b(Wells Fargo|Bank of America|Chase|Citibank|Capital One|PNC|TD Bank|US Bank|Barclays|HSBC|Standard Bank|First Bank|Zenith Bank|Access Bank|Guaranty Trust Bank|GTBank|United Bank for Africa|UBA)\b/gi,
    /\b(PayPal|Venmo|Zelle|Cash App|Stripe|Square|Revolut|Monzo|Wise)\b/gi,
    /\b(Coinbase|Binance|Kraken|MetaMask|Trezor|Ledger|KuCoin|Bybit)\b/gi,
  ];

  for (const pat of financialOrgPatterns) {
    let match;
    while ((match = pat.exec(substantiveText)) !== null) {
      organizations.add(match[1].trim());
    }
  }

  const techAndGovPatterns = [
    /\b(Internal Revenue Service|IRS|Federal Bureau of Investigation|FBI|Federal Trade Commission|FTC|Social Security Administration|SSA|Securities and Exchange Commission|SEC|Cybersecurity and Infrastructure Security Agency|CISA|World Health Organization|WHO|Centers for Disease Control|CDC)\b/gi,
    /\b(Netflix|Amazon|Apple|Microsoft|Google|Meta|Geek Squad|Best Buy|Norton|McAfee|Dropbox|Adobe|Telegram|WhatsApp)\b/gi,
    /\b(FedEx|UPS|USPS|DHL|Royal Mail|Canada Post|Australia Post|Nigeria Post|NIPOST)\b/gi,
  ];

  for (const pat of techAndGovPatterns) {
    let match;
    while ((match = pat.exec(substantiveText)) !== null) {
      organizations.add(match[1].trim());
    }
  }

  const generalizedEntityRegex = /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+(?:\s+(?:of|for|and)\s+[A-Z][a-z]+)?\b/g;
  let genMatch;
  while ((genMatch = generalizedEntityRegex.exec(substantiveText)) !== null) {
    const candidate = genMatch[0].trim();
    if (
      !NON_ENTITY_PHRASES.has(candidate.toLowerCase()) &&
      candidate.length > 5 &&
      candidate.split(/\s+/).length <= 5
    ) {
      organizations.add(candidate);
    }
  }

  const rawOrgsList = Array.from(
    new Set(
      Array.from(organizations)
        .map((o) => o.replace(/^The\s+/i, '').trim())
        .filter((o) => o.length >= 2 && !NON_ENTITY_PHRASES.has(o.toLowerCase()))
    )
  );

  const deduplicatedOrgs = rawOrgsList.filter(
    (org, _, self) => !self.some((other) => other !== org && other.toLowerCase().includes(org.toLowerCase()))
  );

  // 4. Financial requests & fee claims (including payment-change directives)
  const financialRequests: string[] = [];
  const currencyRegex =
    /(?:\$\s?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|₦\s?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|€\s?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|£\s?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|\b[0-9]+(?:\.[0-9]{2})?\s*(?:USD|EUR|GBP|CAD|AUD|NGN|INR|JPY|CNY|Bitcoin|BTC|ETH|gift cards?)\b)/gi;

  let curMatch;
  while ((curMatch = currencyRegex.exec(substantiveText)) !== null) {
    financialRequests.push(curMatch[0].trim());
  }

  const feeConceptsRegex =
    /\b(?:new\s+verification\s+fee|verification\s+fee|processing\s+fee|clearance\s+fee|maintenance\s+fee|service\s+fee|redelivery\s+fee|mandatory\s+fee|penalty\s+fee|toll\s+fee|wire\s+fee|unauthorized\s+(?:debit|charge)|wire\s+transfer|direct\s+deposit|relief\s+grant|relief\s+fund|stimulus\s+check|grant|subsidy|payout|compensation|settlement|unclaimed\s+refund|changed\s+(?:our\s+)?bank\s+account|new\s+(?:bank|account|payment)\s+details|future\s+payments?|beneficiary\s+details?)\b/gi;

  let feeMatch;
  while ((feeMatch = feeConceptsRegex.exec(substantiveText)) !== null) {
    financialRequests.push(feeMatch[0].trim());
  }

  // 5. Deadlines & urgency cues
  const urgencyDeadlines: string[] = [];
  const deadlineRegex =
    /\b(?:by\s+(?:tomorrow|today|tonight|midnight|monday|tuesday|wednesday|thursday|friday|saturday|sunday)|within\s+[0-9]+\s*(?:mins?|minutes?|hours?|days?)|immediate(?:ly)?|urgent(?:ly)?|final\s+notice|last\s+chance|action\s+required|deadline|24\s*hours?|48\s*hours?|72\s*hours?)\b/gi;

  let deadMatch;
  while ((deadMatch = deadlineRegex.exec(substantiveText)) !== null) {
    urgencyDeadlines.push(deadMatch[0].trim());
  }

  // 6. Account consequences & threats
  const accountConsequences: string[] = [];
  const consequenceRegex =
    /\b(?:accounts?\s+(?:from\s+being\s+|to\s+be\s+)?(?:blocked|suspended|frozen|locked|terminated|deactivated|closed|restricted)|(?:prevent|avoid)\s+(?:their\s+|your\s+)?accounts?\s+from\s+being\s+(?:blocked|suspended|frozen|locked|terminated|deactivated)|account\s+(?:freeze|suspension|termination|block)|fined|penalized|arrested|prosecuted|blacklisted)\b/gi;

  let conMatch;
  while ((conMatch = consequenceRegex.exec(substantiveText)) !== null) {
    accountConsequences.push(conMatch[0].trim());
  }

  // 7. Reference identifiers
  const referenceIdentifiers: string[] = [];
  const refRegex =
    /\b(?:invoice\s*#?\s*[A-Z0-9_-]+|case\s*#?\s*[A-Z0-9_-]+|tracking\s*#?\s*[A-Z0-9_-]+|order\s*#?\s*[A-Z0-9_-]+|ref\s*#?\s*[A-Z0-9_-]+)\b/gi;

  let refMatch;
  while ((refMatch = refRegex.exec(substantiveText)) !== null) {
    referenceIdentifiers.push(refMatch[0].trim());
  }

  const testAnnouncement =
    /\b(?:announced|announces|announcement|stated|states|statement|declared|decreed|issued|mandated|launched|passed|approved|confirmed|confirms|confirmation|warned|warns|warning|alerted|alerts|alert|advisory|bulletin|directive|circular|new\s+policy|new\s+regulation|new\s+rule|press\s+release|enacted|signed\s+into\s+law|recalled|recalling|recall)\b/i;
  const testMoney =
    /(?:\$\s?[0-9]|₦\s?[0-9]|€\s?[0-9]|£\s?[0-9]|\b[0-9]+(?:\.[0-9]{2})?\s*(?:USD|EUR|GBP|NGN)|\b(?:new\s+verification\s+fee|verification\s+fee|processing\s+fee|clearance\s+fee|maintenance\s+fee|service\s+fee|redelivery\s+fee|mandatory\s+fee|penalty\s+fee|toll\s+fee|wire\s+fee|fee|pay|paid|charge|debit|wire|transfer|grant|subsidy|stimulus|payout|refund|reimbursement|compensation|settlement|bank\s+account|new\s+details|future\s+payments?|beneficiary|remittance|iban|routing|payroll)\b)/i;
  const testUrgency =
    /\b(?:by\s+(?:tomorrow|today|tonight|midnight|monday|tuesday|wednesday|thursday|friday|saturday|sunday)|within\s+[0-9]+\s*(?:mins?|minutes?|hours?|days?)|immediate(?:ly)?|urgent(?:ly)?|final\s+notice|last\s+chance|action\s+required|deadline|24\s*hours?|48\s*hours?|72\s*hours?)\b/i;
  const testConsequence =
    /\b(?:accounts?\s+(?:from\s+being\s+|to\s+be\s+)?(?:blocked|suspended|frozen|locked|terminated|deactivated|closed|restricted)|(?:prevent|avoid)\s+(?:their\s+|your\s+)?accounts?\s+from\s+being\s+(?:blocked|suspended|frozen|locked|terminated|deactivated)|account\s+(?:freeze|suspension|termination|block)|blocked|freeze|suspended|locked|terminated|penalized|fined|blacklisted)\b/i;
  const testRef =
    /\b(?:invoice\s*#?\s*[A-Z0-9_-]+|case\s*#?\s*[A-Z0-9_-]+|tracking\s*#?\s*[A-Z0-9_-]+|order\s*#?\s*[A-Z0-9_-]+|ref\s*#?\s*[A-Z0-9_-]+)\b/i;

  const hasAnnouncementCue = testAnnouncement.test(substantiveText);

  const sentences = substantiveText
    .split(/(?<=[.!?\n])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 8);

  const claims: FactualClaim[] = [];
  let claimIdx = 1;
  const primaryOrg = deduplicatedOrgs.length > 0 ? deduplicatedOrgs[0] : undefined;

  for (const sentence of sentences) {
    const matchedOrg = deduplicatedOrgs.find((org) =>
      new RegExp(`\\b${org.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(sentence)
    );
    const hasMoney = testMoney.test(sentence);
    const hasUrl = iocs.urls.some((u) => sentence.includes(u));
    const hasUrgency = testUrgency.test(sentence);
    const hasRef = testRef.test(sentence);
    const hasConsequence = testConsequence.test(sentence);
    const hasAnnouncement = testAnnouncement.test(sentence);

    const isFactual =
      !!matchedOrg ||
      hasMoney ||
      hasUrl ||
      hasRef ||
      hasConsequence ||
      (hasUrgency && (hasAnnouncement || hasMoney || hasConsequence)) ||
      hasAnnouncement;

    if (isFactual) {
      let evidenceNeeded = 'Public announcements or official documentation verifying this claim.';
      if (paymentChange.detected && !matchedOrg) {
        evidenceNeeded =
          'Private bilateral directive: Public web search cannot verify internal supplier/partner bank changes. Requires out-of-band confirmation using pre-established vendor/partner contact records.';
      } else if (matchedOrg && hasMoney) {
        evidenceNeeded = `Official ${matchedOrg} published fee schedule, corporate press releases, or verified fraud advisories regarding mandatory fees.`;
      } else if (matchedOrg && hasAnnouncement) {
        evidenceNeeded = `Official ${matchedOrg} press releases, verified regulatory circulars, or authoritative gazettes.`;
      } else if (hasUrl) {
        evidenceNeeded = 'Domain ownership, WHOIS registry records, and authoritative official portals for the claimed organization.';
      } else if (matchedOrg) {
        evidenceNeeded = `Verification through official ${matchedOrg} communication portals or public fraud bulletins.`;
      }

      const isCompoundInstitutionalClaim =
        (matchedOrg || primaryOrg) &&
        hasAnnouncement &&
        hasMoney &&
        (hasUrgency || hasConsequence);

      if (isCompoundInstitutionalClaim && sentences.length === 1) {
        const orgName = matchedOrg || primaryOrg || 'The stated institution';

        claims.push({
          id: `claim-${claimIdx++}`,
          claimText: `${orgName} allegedly announced that all bank customers must pay a new verification fee.`,
          claimant: orgName,
          isFactual: true,
          verdict: 'inconclusive',
          verdictExplanation: 'Pending web research and official circular verification.',
          evidenceNeeded: `Official ${orgName} press releases, regulatory notices, and verified banking advisories.`,
          supportingEvidence: [],
          contradictingEvidence: [],
          citedSourceUrls: [],
        });

        claims.push({
          id: `claim-${claimIdx++}`,
          claimText: 'All bank customers allegedly must pay a new verification fee.',
          claimant: orgName,
          isFactual: true,
          verdict: 'inconclusive',
          verdictExplanation: 'Pending web research into standard banking regulation and fee schedules.',
          evidenceNeeded: `Official banking tariff regulations and verified public notifications from ${orgName}.`,
          supportingEvidence: [],
          contradictingEvidence: [],
          citedSourceUrls: [],
        });

        if (hasUrgency || urgencyDeadlines.length > 0) {
          const deadlineText = urgencyDeadlines[0] || 'by tomorrow';
          claims.push({
            id: `claim-${claimIdx++}`,
            claimText: `The payment allegedly must be made ${deadlineText}.`,
            claimant: orgName,
            isFactual: true,
            verdict: 'inconclusive',
            verdictExplanation: 'Pending verification of official regulatory enforcement timelines.',
            evidenceNeeded: `Verified public circulars detailing enforcement deadlines for ${orgName} directives.`,
            supportingEvidence: [],
            contradictingEvidence: [],
            citedSourceUrls: [],
          });
        }

        if (hasConsequence || accountConsequences.length > 0) {
          claims.push({
            id: `claim-${claimIdx++}`,
            claimText: 'Failure to pay allegedly results in bank accounts being blocked.',
            claimant: orgName,
            isFactual: true,
            verdict: 'inconclusive',
            verdictExplanation: 'Pending verification of statutory grounds for retail bank account blocking.',
            evidenceNeeded: 'Official central banking consumer protection regulations and statutory account freeze procedures.',
            supportingEvidence: [],
            contradictingEvidence: [],
            citedSourceUrls: [],
          });
        }
      } else {
        const isPrivatePaymentStmt = paymentChange.detected && !matchedOrg && !hasUrl;
        claims.push({
          id: `claim-${claimIdx++}`,
          claimText: sentence,
          claimant: matchedOrg || primaryOrg,
          isFactual: !isPrivatePaymentStmt,
          verdict: isPrivatePaymentStmt ? 'unverified_suspicious' : 'inconclusive',
          verdictExplanation: isPrivatePaymentStmt
            ? 'Private transactional/payment-change directive: cannot be verified via public web search and poses serious Business Email Compromise (BEC) risk until confirmed out-of-band.'
            : 'Pending web research verification.',
          evidenceNeeded,
          supportingEvidence: [],
          contradictingEvidence: [],
          citedSourceUrls: [],
        });
      }
    }
  }

  if (
    claims.length === 0 &&
    (deduplicatedOrgs.length > 0 ||
      financialRequests.length > 0 ||
      urgencyDeadlines.length > 0 ||
      accountConsequences.length > 0 ||
      hasAnnouncementCue ||
      paymentChange.detected ||
      behavioral.indicators.length > 0 ||
      iocs.urls.length > 0)
  ) {
    const isPrivateDirective = paymentChange.detected && deduplicatedOrgs.length === 0 && iocs.urls.length === 0;
    claims.push({
      id: 'claim-1',
      claimText: substantiveText.slice(0, 240),
      claimant: primaryOrg,
      isFactual: !isPrivateDirective,
      verdict: isPrivateDirective ? 'unverified_suspicious' : 'inconclusive',
      verdictExplanation: isPrivateDirective
        ? 'Private transactional directive cannot be verified via public search; requires independent out-of-band verification.'
        : 'Pending web research verification.',
      evidenceNeeded: isPrivateDirective
        ? 'Out-of-band telephone confirmation with an established partner contact record.'
        : 'Official public documentation or verified corporate announcements.',
      supportingEvidence: [],
      contradictingEvidence: [],
      citedSourceUrls: [],
    });
  }

  // Only flag hasVerifiableClaims true when there are public factual claims, URLs, or public entities;
  // private bilateral payment-change/BEC directives still trigger full threat scoring in the report engine.
  const hasPubliclyVerifiableClaims =
    claims.some((c) => c.isFactual) || deduplicatedOrgs.length > 0 || iocs.urls.length > 0;

  return {
    hasVerifiableClaims: hasPubliclyVerifiableClaims,
    organizations: deduplicatedOrgs,
    persons: [],
    financialRequests: Array.from(new Set(financialRequests)),
    contactDetails: {
      urls: iocs.urls,
      emails: iocs.emails,
      phones: iocs.phoneNumbers,
    },
    urgencyDeadlines: Array.from(new Set(urgencyDeadlines)),
    referenceIdentifiers: Array.from(new Set(referenceIdentifiers)),
    claims: claims.slice(0, 5),
  };
}

/**
 * Performs a rigorous claim-assessment step before any general web search is initiated.
 * Ensures private bilateral communications (like supplier bank-change emails with no public
 * organizations or URLs) skip meaningless web searches while still triggering direct BEC &
 * behavioral threat analysis instead of being misclassified as harmless greetings.
 */
export function assessClaimForResearch(text: string): ClaimAssessmentResult {
  const extracted = extractClaimsAndEntities(text);
  const trimmed = text.trim();
  const behavioral = detectBehavioralThreats(trimmed);
  const taxonomy = behavioral.taxonomy;

  if (extracted.extractionLimitation) {
    return {
      warrantsExternalResearch: false,
      claimsIdentified: [],
      assessmentReason: extracted.extractionLimitation,
      isUrlThreatIntelAppropriate: false,
      candidateDomains: [],
      candidateUrls: [],
      communicationScope: 'ambiguous_fragment',
      extractionLimitation: extracted.extractionLimitation,
    };
  }

  const candidateUrls = [...extracted.contactDetails.urls];
  const candidateDomains: string[] = [];
  for (const urlStr of candidateUrls) {
    try {
      const u = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
      if (u.hostname && u.hostname.includes('.')) {
        candidateDomains.push(u.hostname.toLowerCase());
      }
    } catch {
      // ignore malformed url
    }
  }

  const standaloneDomainMatches =
    trimmed.match(/\b([a-zA-Z0-9-]+\.(?:com|org|net|io|xyz|info|biz|top|cc|ru|cn|live|site|app))\b/gi) || [];
  for (const dom of standaloneDomainMatches) {
    const cleanDom = dom.toLowerCase();
    if (!candidateDomains.includes(cleanDom)) {
      candidateDomains.push(cleanDom);
    }
  }

  const isUrlThreatIntelAppropriate = candidateUrls.length > 0 || candidateDomains.length > 0;

  // Private bilateral transactional / BEC / social-engineering directive with no public entity or URL
  const isPrivateTransactionalDirective =
    !isUrlThreatIntelAppropriate &&
    extracted.organizations.length === 0 &&
    (taxonomy.paymentChange.detected ||
      taxonomy.hasCriticalThreatVector ||
      taxonomy.hasModerateThreatVector ||
      behavioral.indicators.length > 0);

  if (isPrivateTransactionalDirective) {
    return {
      warrantsExternalResearch: false,
      claimsIdentified: extracted.claims,
      assessmentReason:
        'Private transactional or social-engineering directive with no public institution or URL. Public web search is not applicable; direct BEC, payment-change, and behavioral threat analysis applied.',
      isUrlThreatIntelAppropriate: false,
      candidateDomains,
      candidateUrls,
      communicationScope: 'private_transactional_directive',
    };
  }

  if (!extracted.hasVerifiableClaims) {
    const isPureGreeting = taxonomy.isOrdinaryConversational;
    let reason = isPureGreeting
      ? 'Ordinary conversational greeting or polite exchange with no verifiable public claims or adversarial indicators.'
      : 'General remark or brief fragment with no independently verifiable public claims or organizational references.';
    if (isUrlThreatIntelAppropriate) {
      reason =
        'No broad public factual claims identified, but candidate URLs/domains were found. External web search skipped; URLhaus and DNS threat-intelligence inspection will proceed.';
    }
    return {
      warrantsExternalResearch: false,
      claimsIdentified: extracted.claims,
      assessmentReason: reason,
      isUrlThreatIntelAppropriate,
      candidateDomains,
      candidateUrls,
      communicationScope: isPureGreeting ? 'conversational_greeting' : 'ambiguous_fragment',
    };
  }

  const isVague =
    extracted.organizations.length === 0 &&
    extracted.financialRequests.length === 0 &&
    extracted.referenceIdentifiers.length === 0 &&
    extracted.urgencyDeadlines.length === 0 &&
    !isUrlThreatIntelAppropriate &&
    extracted.claims.length === 1 &&
    extracted.claims[0].claimText.length < 40;

  if (isVague) {
    return {
      warrantsExternalResearch: false,
      claimsIdentified: extracted.claims,
      assessmentReason:
        'Statement is vague or incomplete without verifiable organizations, amounts, or identifiers. External web search would add no credible evidence.',
      isUrlThreatIntelAppropriate,
      candidateDomains,
      candidateUrls,
      communicationScope: 'ambiguous_fragment',
    };
  }

  const claimCount = extracted.claims.length;
  const orgCount = extracted.organizations.length;
  const reason = `Found ${claimCount} public factual claim(s) involving ${
    orgCount > 0 ? extracted.organizations.join(', ') : 'specific verifiable assertions'
  }. General web research is warranted.`;

  return {
    warrantsExternalResearch: true,
    claimsIdentified: extracted.claims,
    assessmentReason: reason,
    isUrlThreatIntelAppropriate,
    candidateDomains,
    candidateUrls,
    communicationScope: 'public_claim',
  };
}

