import {
  FactCheckReport,
  FactualClaim,
  AudienceRecommendations,
} from './types';
import { extractClaimsAndEntities } from './claim-extractor';
import { performWebResearch } from './web-researcher';
import { resolveFeatherlessModel, getFeatherlessHeaders } from '@/lib/model-config';

/**
 * Conducts complete end-to-end web research, threat intelligence evaluation,
 * and fact-checking on submitted communication.
 */
export async function generateFactCheckReport(
  submittedContent: string,
  userContext?: string
): Promise<FactCheckReport> {
  const extracted = extractClaimsAndEntities(submittedContent);

  // If the input has no verifiable claims (e.g. conversational greeting or non-factual text),
  // return an honest report without claiming to have searched or verified non-existent claims
  if (!extracted.hasVerifiableClaims) {
    const nonFactualRecommendations: AudienceRecommendations = {
      forIndividuals: [
        'Be cautious of unsolicited conversational greetings ("Hello", "Are you there?") from unknown numbers or profiles, which frequently serve as introductory lures for pig-butchering or romance scams.',
        'Do not reply or confirm your phone number/identity to unsolicited senders.',
        'If the sender subsequently asks for money, investment opportunities, or crypto transfers, cease communication immediately.',
      ],
      forOrganizations: [
        'Remind personnel that social engineering attacks frequently begin with casual conversational reconnaissance.',
        'Encourage employees to report unsolicited external messages that attempt to establish rapport before asking for sensitive actions.',
      ],
      forSecurityTeams: [
        'Log sender telephone number or handle if part of a widespread inbound spam campaign.',
        'Monitor for follow-up spear-phishing or credential-harvesting messages targeted at company staff.',
      ],
    };

    return {
      id: `fc-nf-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      analyzedAt: new Date().toISOString(),
      executiveSummary:
        'The submitted communication contains conversational greetings or general inquiries with no independently verifiable factual assertions. External web research was not executed because there are no specific claims, institutions, or monetary demands to investigate. Guidance is provided below for evaluating conversational lures.',
      originalInputSnippet: submittedContent.slice(0, 300),
      hasVerifiableClaims: false,
      extractedClaims: extracted.claims,
      sources: [],
      domainIntelligence: [],
      threatIntel: [],
      suspiciousIndicators: [
        {
          name: 'Conversational Lure Risk',
          evidence: submittedContent.slice(0, 60),
          reason:
            'Unsolicited casual greetings from unknown senders often serve as initial probes in multi-stage social engineering schemes.',
        },
      ],
      confidenceLevel: 'high',
      confidenceRationale:
        'Conclusive assessment: The message lacks factual or transactional claims. No external web research was required.',
      unresolvedQuestions: [
        'Who is the sender of this message and do you have an existing relationship with them?',
        'Did this message arrive unsolicited via SMS, WhatsApp, LinkedIn, or email?',
      ],
      recommendations: nonFactualRecommendations,
      researchLimitations: [
        'Web research applies to verifiable factual claims, organizations, public announcements, and internet infrastructure.',
        'Subjective remarks, casual greetings, and personal conversations cannot be confirmed through web indices.',
      ],
      searchProviderStatus: {
        providerName: 'Bypassed (No Verifiable Claims)',
        isConfigured: true,
        mode: 'public_web_fallback',
        fullPageRetrievalActive: false,
        rateLimitEncountered: false,
        queriesExecuted: 0,
      },
      searchProviderUsed: 'None (Conversational Message)',
    };
  }

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

  // Construct targeted search queries based on organizations and claims (max 2 queries)
  const searchQueries: string[] = [];
  if (extracted.organizations.length > 0) {
    const mainOrg = extracted.organizations[0];
    if (extracted.financialRequests.length > 0) {
      searchQueries.push(`${mainOrg} unauthorized wire charge scam alert`);
    } else {
      searchQueries.push(`${mainOrg} fraud alert security notice`);
    }
  }

  if (extracted.claims.length > 0 && searchQueries.length < 2) {
    const mainClaim = extracted.claims[0].claimText;
    const cleanWords = mainClaim.replace(/[^a-zA-Z0-9\s]/g, '').split(/\s+/).slice(0, 6).join(' ');
    searchQueries.push(`${cleanWords} official advisory`);
  }

  if (candidateDomains.length > 0 && searchQueries.length < 2) {
    searchQueries.push(`${candidateDomains[0]} scam reputation review`);
  }

  // Fallback search query if none generated
  if (searchQueries.length === 0) {
    searchQueries.push(`${submittedContent.slice(0, 60)} phishing notice`);
  }

  // Execute multi-source web research, DNS intelligence, and URLhaus threat intel
  const { sources, domainIntelligence, threatIntel, providerStatus } = await performWebResearch(
    searchQueries,
    candidateDomains
  );

  // Evaluate claims against sources with nuanced, evidence-based reasoning
  const evaluatedClaims: FactualClaim[] = extracted.claims.map((claim) => {
    const claimLower = claim.claimText.toLowerCase();
    const supporting: string[] = [];
    const contradicting: string[] = [];
    const citedUrls: string[] = [];

    // 1. Evaluate against threat intelligence and DNS telemetry
    for (const dnsRecord of domainIntelligence) {
      if (claimLower.includes(dnsRecord.domain.toLowerCase())) {
        if (!dnsRecord.hasDnsRecords) {
          contradicting.push(
            `[Authoritative DNS] Domain "${dnsRecord.domain}" does not exist in public DNS (no A records). It cannot host legitimate services.`
          );
          citedUrls.push(`https://${dnsRecord.domain}`);
        }
      }
    }

    for (const tRecord of threatIntel) {
      if (tRecord.status === 'malicious') {
        contradicting.push(
          `[${tRecord.provider}] Indicator "${tRecord.indicator}" is flagged in active malware or phishing distribution databases.`
        );
        citedUrls.push(`https://${tRecord.indicator}`);
      }
    }

    // 2. Evaluate against web sources
    for (const src of sources) {
      const snippetLower = (src.rawContentExcerpt || src.snippet).toLowerCase();

      // Check for documented scam advisories matching this specific message
      const mentionsScam =
        snippetLower.includes('scam') ||
        snippetLower.includes('fraud') ||
        snippetLower.includes('phishing') ||
        snippetLower.includes('impostor') ||
        snippetLower.includes('warning');

      const matchesClaimOrg = claim.claimant
        ? snippetLower.includes(claim.claimant.toLowerCase())
        : false;

      if (matchesClaimOrg && mentionsScam) {
        contradicting.push(
          `[${src.title}] Warns: "${src.snippet.slice(0, 160)}..."`
        );
        citedUrls.push(src.url);
      } else if (matchesClaimOrg && snippetLower.includes('official')) {
        supporting.push(
          `[${src.title}] Corroborates entity documentation: "${src.snippet.slice(0, 140)}..."`
        );
        citedUrls.push(src.url);
      }
    }

    // Determine qualified verdict (strict avoidance of false certainties)
    let verdict: FactualClaim['verdict'] = 'inconclusive';
    let explanation =
      'Insufficient public web evidence found to independently confirm or refute this specific claim. Note: The absence of search results does not prove a claim is false or safe.';

    if (contradicting.length > 0) {
      verdict = 'contradicted';
      explanation =
        'Public advisories, authoritative DNS telemetry, or threat feeds contradict the legitimacy of this communication pattern.';
    } else if (supporting.length > 0) {
      // If organization exists but payment/urgency is unverified
      if (extracted.financialRequests.length > 0 || extracted.urgencyDeadlines.length > 0) {
        verdict = 'unverified_suspicious';
        explanation =
          'The claimed organization exists in public registries, but the requested urgency or payment channel cannot be verified through official documentation.';
      } else {
        verdict = 'supported';
        explanation =
          'Available public documentation corroborates the existence and public profile of the claimed entity.';
      }
    } else if (sources.length === 0) {
      verdict = 'inconclusive';
      explanation =
        'No relevant public search results were returned for this query. Findings are inconclusive.';
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
      const researchContext = sources
        .slice(0, 5)
        .map((s) => `- ${s.title} (${s.domain}): "${(s.rawContentExcerpt || s.snippet).slice(0, 200)}"`)
        .join('\n');

      const prompt = `You are a cybersecurity fact-checking analyst. Given the submitted communication and the retrieved web research evidence, summarize whether the claims are supported, contradicted, or inconclusive.
Submitted Message:
"""${submittedContent.slice(0, 500)}"""

Retrieved Web Evidence:
${researchContext.slice(0, 1200)}

Guidelines:
- State clearly what is supported vs contradicted by the retrieved evidence.
- Do not claim absolute certainty.
- Explain that findings reflect publicly available evidence at the time of analysis.
- Limit to 2-3 objective, professional sentences.`;

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
      // Fall back to deterministic synthesis
    }
  }

  if (!executiveSummary) {
    const org = extracted.organizations[0] || 'Unknown Organization';
    const hasContradiction = evaluatedClaims.some((c) => c.verdict === 'contradicted');
    const hasSuspicious = evaluatedClaims.some((c) => c.verdict === 'unverified_suspicious');

    if (hasContradiction) {
      executiveSummary = `Public advisories and infrastructure telemetry contradict the legitimacy of this communication purporting to be from ${org}. The patterns match documented social engineering alerts; verify all requests through official out-of-band contacts.`;
    } else if (hasSuspicious) {
      executiveSummary = `While ${org} exists in public registries, the specific transaction demands and urgency cues in this message cannot be verified through official channels and remain unauthenticated.`;
    } else {
      executiveSummary = `Cross-referenced ${extracted.claims.length} claim(s) against public web indices and DNS records. The available evidence is insufficient to verify authenticity; treat unverified links and contact details with caution.`;
    }
  }

  // Construct recommendations tailored for individuals, organizations, and security teams
  const recommendations: AudienceRecommendations = {
    forIndividuals: [
      'Do not click embedded links, download file attachments, or provide payment or account credentials.',
      'Contact the claimed organization using independently obtained contact info (such as the phone number on the back of your bank card or the official website).',
      'Forward suspicious phishing SMS messages to 7726 (SPAM) and report fraudulent emails to official fraud reporting portals.',
    ],
    forOrganizations: [
      'Verify any requested banking, wire transfer, or routing changes out-of-band with an established secondary verification contact.',
      'Escalate potential Business Email Compromise (BEC) or executive impersonation attempts to IT and security leadership.',
      'Verify that domain email authentication headers (SPF, DKIM, DMARC) are enforced on inbound communications.',
    ],
    forSecurityTeams: [
      'Block and correlate extracted indicators (URLs, candidate domains, sender phone numbers) across network firewalls and SIEM/EDR.',
      'Search mail server logs for identical subject lines or sender patterns targeting other employees.',
      'Preserve full RFC-822 email headers and raw attachments to maintain forensic chain-of-custody.',
    ],
  };

  const researchLimitations = [
    'Web research checks publicly indexable sources, encyclopedic records, and public DNS telemetry.',
    'Private internal enterprise communications, authenticated banking portals, and deleted domains cannot be accessed via public search.',
    'The absence of a search result or threat-intelligence listing does NOT guarantee that a domain or claim is benign.',
    'Findings reflect publicly accessible evidence at the time of the investigation.',
  ];

  return {
    id: `fc-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    analyzedAt: new Date().toISOString(),
    executiveSummary,
    originalInputSnippet: submittedContent.slice(0, 300),
    hasVerifiableClaims: true,
    extractedClaims: evaluatedClaims,
    sources,
    domainIntelligence,
    threatIntel,
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
      ...extracted.referenceIdentifiers.map((r) => ({
        name: 'Unverified Reference ID',
        evidence: r,
        reason: 'Reference and invoice numbers often create a false appearance of legitimacy.',
      })),
    ],
    confidenceLevel: sources.length > 2 ? 'high' : 'moderate',
    confidenceRationale: `Analysis based on ${sources.length} public web source(s), ${domainIntelligence.length} domain DNS record(s), and ${threatIntel.length} threat feed check(s).`,
    unresolvedQuestions: [
      'Was this communication received through a verified, authenticated official channel?',
      'Has the claimed account balance, invoice, or status been confirmed via direct login on the official platform?',
    ],
    recommendations,
    researchLimitations,
    searchProviderStatus: providerStatus,
    searchProviderUsed: providerStatus.providerName,
  };
}
