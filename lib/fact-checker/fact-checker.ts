import {
  FactCheckReport,
  FactualClaim,
  AudienceRecommendations,
} from './types';
import { extractClaimsAndEntities } from './claim-extractor';
import { performWebResearch } from './web-researcher';
import { resolveFeatherlessModel, getFeatherlessHeaders } from '@/lib/model-config';

/**
 * Conducts complete end-to-end web research and fact checking on submitted communication.
 */
export async function generateFactCheckReport(
  submittedContent: string,
  userContext?: string
): Promise<FactCheckReport> {
  const extracted = extractClaimsAndEntities(submittedContent);

  // Extract domain names from extracted URLs
  const candidateDomains: string[] = [];
  for (const urlStr of extracted.contactDetails.urls) {
    try {
      const u = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
      candidateDomains.push(u.hostname);
    } catch {
      // Ignore invalid URL
    }
  }

  // Construct search queries based on organizations and claims
  const searchQueries: string[] = [];
  if (extracted.organizations.length > 0) {
    searchQueries.push(`${extracted.organizations[0]} fraud alert scam notice`);
  }
  if (extracted.claims.length > 0) {
    const mainClaim = extracted.claims[0].claimText;
    // Take key words from claim
    const words = mainClaim.replace(/[^a-zA-Z0-9\s]/g, '').split(/\s+/).slice(0, 6).join(' ');
    searchQueries.push(`${words} scam advisory`);
  }
  if (candidateDomains.length > 0) {
    searchQueries.push(`${candidateDomains[0]} scam reputation review`);
  }

  // Fallback search query if none generated
  if (searchQueries.length === 0) {
    searchQueries.push(`${submittedContent.slice(0, 60)} phishing alert`);
  }

  // Execute live web research and DNS intelligence
  const { sources, domainIntelligence, providerUsed } = await performWebResearch(
    searchQueries,
    candidateDomains
  );

  // Evaluate claims against sources
  const evaluatedClaims: FactualClaim[] = extracted.claims.map((claim) => {
    const claimLower = claim.claimText.toLowerCase();
    const supporting: string[] = [];
    const contradicting: string[] = [];
    const citedUrls: string[] = [];

    for (const src of sources) {
      const snippetLower = src.snippet.toLowerCase();

      // Check for corroborating fraud warnings or advisories
      if (
        snippetLower.includes('scam') ||
        snippetLower.includes('fraud') ||
        snippetLower.includes('phishing') ||
        snippetLower.includes('warning')
      ) {
        contradicting.push(
          `[${src.title}] Warns: "${src.snippet.slice(0, 160)}..."`
        );
        citedUrls.push(src.url);
      } else if (
        extracted.organizations.some((org) => snippetLower.includes(org.toLowerCase())) &&
        snippetLower.includes('official')
      ) {
        supporting.push(`[${src.title}] Corroborates entity reference: "${src.snippet.slice(0, 140)}..."`);
        citedUrls.push(src.url);
      }
    }

    // Determine verdict
    let verdict: FactualClaim['verdict'] = 'inconclusive';
    let explanation = 'Insufficient public web evidence found to independently confirm this specific claim.';

    if (contradicting.length > 0) {
      verdict = 'contradicted';
      explanation = 'Public advisories or domain records contradict the legitimacy of this communication pattern.';
    } else if (supporting.length > 0) {
      verdict = 'unverified_suspicious';
      explanation = 'The mentioned entity exists in public registries, but the communication channel lacks authentication.';
    }

    return {
      ...claim,
      verdict,
      verdictExplanation: explanation,
      supportingEvidence: supporting.slice(0, 3),
      contradictingEvidence: contradicting.slice(0, 3),
      citedSourceUrls: Array.from(new Set(citedUrls)),
    };
  });

  // Synthesize executive summary with Featherless AI if available, else deterministic
  let executiveSummary = '';
  const apiKey = process.env.FEATHERLESS_API_KEY;

  if (apiKey && apiKey !== 'YOUR_FEATHERLESS_API_KEY') {
    const { model } = resolveFeatherlessModel(false);
    try {
      const researchContext = sources.map((s) => `- ${s.title}: "${s.snippet}"`).join('\n');
      const prompt = `You are a cybersecurity fact-checking analyst. Given the submitted message and the live web research evidence retrieved, summarize whether the claims in the message are authentic or fraudulent.
Submitted Message:
"""${submittedContent.slice(0, 500)}"""

Retrieved Web Evidence:
${researchContext.slice(0, 1500)}

Provide a concise 2-3 sentence executive fact-check summary. State clearly what is supported vs contradicted by evidence.`;

      const aiRes = await fetch('https://api.featherless.ai/v1/chat/completions', {
        method: 'POST',
        headers: getFeatherlessHeaders(apiKey),
        body: JSON.stringify({
          model,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.1,
          max_tokens: 300,
        }),
        signal: AbortSignal.timeout(12000),
      });

      if (aiRes.ok) {
        const data = await aiRes.json();
        executiveSummary = data?.choices?.[0]?.message?.content?.trim() || '';
      }
    } catch {
      // Fallback to deterministic summary
    }
  }

  if (!executiveSummary) {
    const org = extracted.organizations[0] || 'Unknown Sender';
    const hasContradiction = evaluatedClaims.some((c) => c.verdict === 'contradicted');
    executiveSummary = hasContradiction
      ? `Web research indicates that claims mimicking ${org} match established phishing and social engineering patterns. Public advisories advise against clicking links or making unverified payments.`
      : `Investigation conducted on ${extracted.claims.length} claims. No authoritative primary sources verified the legitimacy of the submitted request.`;
  }

  // Construct recommendations tailored for individuals, organizations, and security teams
  const recommendations: AudienceRecommendations = {
    forIndividuals: [
      'Do not click any embedded links or provide payment/card details.',
      'Contact the claimed organization using a phone number or URL you independently looked up (e.g., from the back of your card).',
      'Forward suspicious phishing messages to official reporting channels (e.g., 7726 for SMS or reportphishing@apwg.org).',
    ],
    forOrganizations: [
      'Verify any payment detail or routing changes out-of-band via an established secondary verification contact.',
      'Escalate potential Business Email Compromise (BEC) attempts to your IT/Security compliance team.',
      'Ensure email authentication headers (SPF, DKIM, DMARC) are validated before acting on urgent notices.',
    ],
    forSecurityTeams: [
      'Block and correlate extracted indicators (URLs, domains, and phone numbers) in your SIEM / firewall.',
      'Review mail server logs for similar subject lines or sender IP clusters.',
      'Preserve full RFC-822 email headers and submitted files for forensic chain-of-custody analysis.',
    ],
  };

  const researchLimitations = [
    'Web research checks publicly indexable sources, encyclopedic records, and public DNS telemetry.',
    'Private internal enterprise emails, authenticated banking portals, and deleted domains cannot be accessed via public search.',
    'Findings reflect evidence available at the time of inquiry and should be verified through out-of-band channels.',
  ];

  return {
    id: `fc-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    analyzedAt: new Date().toISOString(),
    executiveSummary,
    originalInputSnippet: submittedContent.slice(0, 300),
    extractedClaims: evaluatedClaims,
    sources,
    domainIntelligence,
    suspiciousIndicators: [
      ...extracted.financialRequests.map((f) => ({
        name: 'Financial Request',
        evidence: f,
        reason: 'Payment demands or dollar amounts require out-of-band secondary verification.',
      })),
      ...extracted.urgencyDeadlines.map((u) => ({
        name: 'Urgency / Coercion Lure',
        evidence: u,
        reason: 'Artificial deadlines are standard psychological pressure triggers in social engineering.',
      })),
    ],
    confidenceLevel: sources.length > 2 ? 'high' : 'moderate',
    confidenceRationale: `Analysis based on ${sources.length} public web sources and ${domainIntelligence.length} domain DNS records.`,
    unresolvedQuestions: [
      'Was this message received from a verified carrier or official sender shortcode?',
      'Has the claimed account balance or status been checked via direct official app login?',
    ],
    recommendations,
    researchLimitations,
    searchProviderUsed: providerUsed,
  };
}
