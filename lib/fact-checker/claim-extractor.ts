import { FactualClaim } from './types';
import { extractIOCsFromMessage } from '@/lib/scam-analyzer';

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
}

// Patterns identifying conversational greetings, polite chit-chat, or subjective statements
const CONVERSATIONAL_PATTERNS = [
  /^(?:hello|hi|hey|good\s+(?:morning|afternoon|evening|day)|greetings)[\s,!.]*$/i,
  /^(?:can\s+you\s+(?:attend|help|assist|talk|hear)\s+(?:to\s+)?me|are\s+you\s+there|how\s+are\s+you|what\s+is\s+up)[\s?!.]*$/i,
  /^(?:thank\s+you|thanks|ok|okay|cool|great|bye|goodbye)[\s,!.]*$/i,
];

/**
 * Extracts verifiable claims and entities from text or extracted document evidence.
 * Strictly separates verifiable factual assertions from greetings, opinions, and subjective predictions.
 */
export function extractClaimsAndEntities(text: string): ExtractedEntities {
  const iocs = extractIOCsFromMessage(text);
  const trimmed = text.trim();

  // 1. Fast check for pure conversational greetings or empty input
  const isPureGreeting = CONVERSATIONAL_PATTERNS.some((pat) => pat.test(trimmed));
  const isShortNonFactual =
    trimmed.length < 40 &&
    !/\$|[0-9]{3,}|https?:\/\/|\.com|\.org|\.gov|bank|account|invoice|wire|verify/i.test(trimmed);

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
      conversationalNotes:
        'The submitted content consists of conversational greetings, polite inquiries, or subjective remarks with no verifiable factual claims.',
      claims: [
        {
          id: 'claim-non-factual-1',
          claimText: trimmed,
          isFactual: false,
          verdict: 'no_verifiable_claim',
          verdictExplanation:
            'No independently verifiable factual claims (such as claimed organizations, account actions, monetary demands, or specific public events) were identified in this communication.',
          evidenceNeeded:
            'Verifiable factual context such as the claimed sender identity, transaction reference number, or specific account action.',
          supportingEvidence: [],
          contradictingEvidence: [],
          citedSourceUrls: [],
        },
      ],
    };
  }

  // 2. Extract organizations (financial institutions, cloud/tech providers, couriers, government agencies)
  const orgPatterns = [
    /\b(Wells Fargo|Bank of America|Chase|Citibank|Capital One|PNC|TD Bank|US Bank|PayPal|Venmo|Zelle|Cash App)\b/gi,
    /\b(Netflix|Amazon|Apple|Microsoft|Google|Meta|Geek Squad|Best Buy|Norton|McAfee|Dropbox|Adobe)\b/gi,
    /\b(FedEx|UPS|USPS|DHL|Internal Revenue Service|IRS|FBI|Federal Bureau of Investigation|Social Security Administration|SSA|FTC|Federal Trade Commission)\b/gi,
    /\b(Coinbase|Binance|Kraken|MetaMask|Trezor|Ledger)\b/gi,
  ];

  const organizations = new Set<string>();
  for (const pat of orgPatterns) {
    let match;
    while ((match = pat.exec(trimmed)) !== null) {
      organizations.add(match[1]);
    }
  }

  // 3. Financial requests (dollar amounts, wire transfers, crypto, gift cards)
  const financialRequests: string[] = [];
  const dollarRegex = /\$\s?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|\b[0-9]+(?:\.[0-9]{2})?\s*(?:USD|EUR|GBP|CAD|AUD|Bitcoin|BTC|ETH|gift cards?)\b/gi;
  let finMatch;
  while ((finMatch = dollarRegex.exec(trimmed)) !== null) {
    financialRequests.push(finMatch[0]);
  }

  // 4. Deadlines & urgency cues
  const urgencyDeadlines: string[] = [];
  const deadlineRegex = /\b(?:within\s+[0-9]+\s*(?:mins?|minutes?|hours?|days?)|immediate(?:ly)?|urgent(?:ly)?|suspend(?:ed)?|terminat(?:ed?|ion)|freeze|action required|final notice|24 hours?|48 hours?)\b/gi;
  let deadMatch;
  while ((deadMatch = deadlineRegex.exec(trimmed)) !== null) {
    urgencyDeadlines.push(deadMatch[0]);
  }

  // 5. Reference identifiers (invoices, tracking numbers, case IDs)
  const referenceIdentifiers: string[] = [];
  const refRegex = /\b(?:invoice\s*#?\s*[A-Z0-9_-]+|case\s*#?\s*[A-Z0-9_-]+|tracking\s*#?\s*[A-Z0-9_-]+|order\s*#?\s*[A-Z0-9_-]+|ref\s*#?\s*[A-Z0-9_-]+)\b/gi;
  let refMatch;
  while ((refMatch = refRegex.exec(trimmed)) !== null) {
    referenceIdentifiers.push(refMatch[0]);
  }

  // 6. Segment text into candidate claim sentences
  const sentences = trimmed
    .split(/(?<=[.!?\n])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 10);

  const claims: FactualClaim[] = [];
  let claimIdx = 1;

  for (const sentence of sentences) {
    // Check if sentence makes a verifiable factual claim:
    // contains an organization, an amount, a deadline, a reference ID, a URL, or an account event
    const matchedOrg = Array.from(organizations).find((org) =>
      new RegExp(`\\b${org}\\b`, 'i').test(sentence)
    );
    const hasMoney = dollarRegex.test(sentence);
    dollarRegex.lastIndex = 0;
    const hasUrl = iocs.urls.some((u) => sentence.includes(u));
    const hasUrgency = deadlineRegex.test(sentence);
    deadlineRegex.lastIndex = 0;
    const hasRef = refRegex.test(sentence);
    refRegex.lastIndex = 0;
    const hasActionVerb = /\b(?:charged|billed|sent|deposited|signed|failed|locked|renewed|authorized|debited|refunded|flagged|delivered)\b/i.test(sentence);

    const isFactual = !!matchedOrg || hasMoney || hasUrl || hasRef || (hasUrgency && hasActionVerb);

    if (isFactual) {
      // Determine what evidence is needed to verify this statement
      let evidenceNeeded = 'Public announcements or official documentation verifying this claim.';
      if (matchedOrg && hasMoney) {
        evidenceNeeded = `Official ${matchedOrg} billing policies, public fraud advisories, or transaction dispute procedures regarding ${financialRequests[0] || 'the stated amount'}.`;
      } else if (hasUrl) {
        evidenceNeeded = 'Domain ownership, WHOIS registry records, and official web portals for the claimed organization.';
      } else if (matchedOrg) {
        evidenceNeeded = `Verification through official ${matchedOrg} support channels or published security warnings.`;
      }

      claims.push({
        id: `claim-${claimIdx++}`,
        claimText: sentence,
        claimant: matchedOrg || (organizations.size > 0 ? Array.from(organizations)[0] : undefined),
        isFactual: true,
        verdict: 'inconclusive', // Will be evaluated after research
        verdictExplanation: 'Pending web research verification.',
        evidenceNeeded,
        supportingEvidence: [],
        contradictingEvidence: [],
        citedSourceUrls: [],
      });
    }
  }

  // Fallback: If no granular sentences qualified but indicators exist (e.g. org or money present),
  // capture the overall message as a single factual claim
  if (claims.length === 0 && (organizations.size > 0 || financialRequests.length > 0 || iocs.urls.length > 0)) {
    claims.push({
      id: 'claim-1',
      claimText: trimmed.slice(0, 240),
      claimant: organizations.size > 0 ? Array.from(organizations)[0] : undefined,
      isFactual: true,
      verdict: 'inconclusive',
      verdictExplanation: 'Pending web research verification.',
      evidenceNeeded: 'Official public documentation or verified corporate announcements.',
      supportingEvidence: [],
      contradictingEvidence: [],
      citedSourceUrls: [],
    });
  }

  const hasVerifiableClaims = claims.length > 0;

  return {
    hasVerifiableClaims,
    organizations: Array.from(organizations),
    persons: [],
    financialRequests: Array.from(new Set(financialRequests)),
    contactDetails: {
      urls: iocs.urls,
      emails: iocs.emails,
      phones: iocs.phoneNumbers,
    },
    urgencyDeadlines: Array.from(new Set(urgencyDeadlines)),
    referenceIdentifiers: Array.from(new Set(referenceIdentifiers)),
    claims: claims.slice(0, 5), // Top 5 verifiable claims
  };
}
