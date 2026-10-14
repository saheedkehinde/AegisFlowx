import { FactualClaim } from './types';
import { extractIOCsFromMessage } from '@/lib/scam-analyzer';

export interface ExtractedEntities {
  organizations: string[];
  persons: string[];
  financialRequests: string[];
  contactDetails: {
    urls: string[];
    emails: string[];
    phones: string[];
  };
  urgencyDeadlines: string[];
  claims: FactualClaim[];
}

/**
 * Extracts verifiable claims and entities from text or extracted document evidence.
 * Strict separation of verifiable factual statements from subjective predictions.
 */
export function extractClaimsAndEntities(text: string): ExtractedEntities {
  const iocs = extractIOCsFromMessage(text);
  const trimmed = text.trim();

  // Extract common impersonated organizations
  const orgPatterns = [
    /\b(Wells Fargo|Bank of America|Chase|Citibank|Capital One|PayPal|Venmo|Zelle)\b/gi,
    /\b(Netflix|Amazon|Apple|Microsoft|Google|Meta|Geek Squad|Best Buy|Norton|McAfee)\b/gi,
    /\b(FedEx|UPS|USPS|DHL|Internal Revenue Service|IRS|FBI|Social Security Administration|SSA)\b/gi,
  ];

  const organizations = new Set<string>();
  for (const pat of orgPatterns) {
    let match;
    while ((match = pat.exec(trimmed)) !== null) {
      organizations.add(match[1]);
    }
  }

  // Financial requests (dollar amounts, wire transfers, crypto, gift cards)
  const financialRequests: string[] = [];
  const dollarRegex = /\$\s?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|\b[0-9]+(?:\.[0-9]{2})?\s*(?:USD|EUR|GBP|Bitcoin|BTC|ETH|gift cards?)\b/gi;
  let finMatch;
  while ((finMatch = dollarRegex.exec(trimmed)) !== null) {
    financialRequests.push(finMatch[0]);
  }

  // Deadlines & urgency cues
  const urgencyDeadlines: string[] = [];
  const deadlineRegex = /\b(?:within\s+[0-9]+\s*(?:mins?|minutes?|hours?|days?)|immediate(?:ly)?|urgent(?:ly)?|suspend(?:ed)?|terminat(?:ed?|ion)|freeze|action required)\b/gi;
  let deadMatch;
  while ((deadMatch = deadlineRegex.exec(trimmed)) !== null) {
    urgencyDeadlines.push(deadMatch[0]);
  }

  // Segment text into candidate claim sentences
  const sentences = trimmed
    .split(/(?<=[.!?\n])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 10);

  const claims: FactualClaim[] = [];
  let claimIdx = 1;

  for (const sentence of sentences) {
    // Check if sentence makes a verifiable factual claim:
    // contains an organization, an amount, a deadline, an account action, or a URL
    const hasOrg = Array.from(organizations).some((org) =>
      new RegExp(`\\b${org}\\b`, 'i').test(sentence)
    );
    const hasMoney = dollarRegex.test(sentence);
    dollarRegex.lastIndex = 0;
    const hasUrl = iocs.urls.some((u) => sentence.includes(u));
    const hasUrgency = deadlineRegex.test(sentence);
    deadlineRegex.lastIndex = 0;

    const isFactual = hasOrg || hasMoney || hasUrl || hasUrgency || /\b(was|is|charged|billed|sent|deposited|signed|failed)\b/i.test(sentence);

    if (isFactual) {
      claims.push({
        id: `claim-${claimIdx++}`,
        claimText: sentence,
        claimant: organizations.size > 0 ? Array.from(organizations)[0] : undefined,
        isFactual: true,
        verdict: 'inconclusive', // Populated after web research
        verdictExplanation: 'Pending web research verification.',
        supportingEvidence: [],
        contradictingEvidence: [],
        citedSourceUrls: [],
      });
    }
  }

  // If no granular sentences were extracted, treat snippet as a single claim
  if (claims.length === 0 && trimmed.length > 0) {
    claims.push({
      id: 'claim-1',
      claimText: trimmed.slice(0, 200),
      isFactual: true,
      verdict: 'inconclusive',
      verdictExplanation: 'Pending web research verification.',
      supportingEvidence: [],
      contradictingEvidence: [],
      citedSourceUrls: [],
    });
  }

  return {
    organizations: Array.from(organizations),
    persons: [],
    financialRequests: Array.from(new Set(financialRequests)),
    contactDetails: {
      urls: iocs.urls,
      emails: iocs.emails,
      phones: iocs.phoneNumbers,
    },
    urgencyDeadlines: Array.from(new Set(urgencyDeadlines)),
    claims: claims.slice(0, 5), // Top 5 verifiable claims
  };
}
