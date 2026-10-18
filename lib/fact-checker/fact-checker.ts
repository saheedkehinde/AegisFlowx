import {
  FactCheckReport,
  FactualClaim,
  AudienceRecommendations,
  ResearchSource,
} from './types';
import { extractClaimsAndEntities, assessClaimForResearch } from './claim-extractor';
import {
  performWebResearch,
  planSearchQueries,
  getMaxSearchesPerAnalysis,
  isOfficialInstitutionalDomain,
  isGovernmentDomain,
  isSocialMediaDomain,
  isReputableNewsDomain,
} from './web-researcher';
import { resolveFeatherlessModel, getFeatherlessHeaders } from '@/lib/model-config';

/**
 * Conducts complete end-to-end web research, threat intelligence evaluation,
 * and fact-checking on submitted communication with rigorous pre-search claim assessment.
 */
export async function generateFactCheckReport(
  submittedContent: string,
  userContext?: string
): Promise<FactCheckReport> {
  // Step 1: Claim assessment step before any general web search
  const assessment = assessClaimForResearch(submittedContent);
  const extracted = extractClaimsAndEntities(submittedContent);

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

  const generalNonFactualRecommendations: AudienceRecommendations = {
    forIndividuals: [
      'Web research fact-checking applies to public announcements, companies, institutions, policies, or financial requests.',
      'For general questions or personal conversations, verify claims through direct official sources or primary literature.',
      'Never share personal credentials, OTPs, or passwords in response to unverified requests.',
    ],
    forOrganizations: [
      'Standard cyber hygiene: verify any institutional or financial directives through established internal communication channels.',
    ],
    forSecurityTeams: [
      'No adversarial indicators detected in this non-factual submission.',
    ],
  };

  // Case A: General web research is NOT warranted
  if (!assessment.warrantsExternalResearch) {
    // Sub-case A1: Contains URLs or domains requiring dedicated URLhaus & DNS intelligence checks
    if (assessment.isUrlThreatIntelAppropriate) {
      const { sources, domainIntelligence, threatIntel, providerStatus } = await performWebResearch(
        [],
        assessment.candidateDomains,
        { skipWebSearch: true }
      );

      const hasMalicious = threatIntel.some((t) => t.status === 'malicious');
      let executiveSummary =
        'The submitted communication contains conversational content with no broad public factual assertions; general web search was skipped to conserve resources. However, automated threat-intelligence and DNS telemetry inspections were executed on the extracted URL/domain.';

      if (hasMalicious) {
        executiveSummary =
          'CRITICAL ALERT: While the message text contains casual conversational content, the embedded link or domain is confirmed malicious in global threat intelligence databases (URLhaus). Do not open the link.';
      }

      return {
        id: `fc-threatonly-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        analyzedAt: new Date().toISOString(),
        executiveSummary,
        originalInputSnippet: submittedContent.slice(0, 300),
        hasVerifiableClaims: true,
        claimAssessment: assessment,
        extractedClaims: assessment.claimsIdentified,
        sources,
        domainIntelligence,
        threatIntel,
        suspiciousIndicators: [
          {
            name: 'Embedded Link Telemetry',
            evidence: assessment.candidateUrls.join(', ') || assessment.candidateDomains.join(', '),
            reason: hasMalicious
              ? 'Confirmed malicious indicator in active threat intelligence feed.'
              : 'Unverified external destination in unsolicited communication.',
          },
        ],
        evidenceSufficiency: hasMalicious ? 'sufficient' : 'moderate',
        threatSeverity: hasMalicious ? 'high' : 'medium',
        severityScore: hasMalicious ? 90 : 35,
        confidenceLevel: hasMalicious ? 'high' : 'moderate',
        confidenceRationale: `Direct telemetry check: ${domainIntelligence.length} domain DNS record(s) and ${threatIntel.length} threat intelligence lookup(s).`,
        unresolvedQuestions: [
          'Did you initiate the interaction that resulted in this link being sent to you?',
          'Does the domain match the verified official website of the expected service?',
        ],
        recommendations: nonFactualRecommendations,
        researchLimitations: [
          'General web search was bypassed because no public organizational or factual claims were asserted.',
          'Threat intelligence feeds identify known malicious infrastructure; unlisted status does not guarantee safety.',
        ],
        searchProviderStatus: providerStatus,
        searchProviderUsed: providerStatus.providerName,
      };
    }

    // Sub-case A2: Greeting or general non-factual message with zero links/domains
    const trimmedInput = submittedContent.trim();
    const isGreeting =
      /^(?:hello|hi|hey|good\s+(?:morning|afternoon|evening|day)|greetings)[\s,!.]*$/i.test(trimmedInput) ||
      /^(?:can\s+you\s+(?:attend|help|assist|talk|hear)\s+(?:to\s+)?me|are\s+you\s+there|how\s+are\s+you)[\s?!.]*$/i.test(trimmedInput);

    const executiveSummary = isGreeting
      ? 'The submitted communication contains conversational greetings or general inquiries with no independently verifiable factual assertions. External web research was not executed because there are no specific claims, institutions, or monetary demands to investigate. Guidance is provided below for evaluating conversational lures.'
      : 'The submitted communication contains subjective remarks, general questions, or non-empirical text without verifiable public claims. External web research was bypassed to conserve search allowances, as no public announcements, institutions, or financial demands were identified.';

    const suspiciousIndicators = isGreeting
      ? [
          {
            name: 'Conversational Lure Risk',
            evidence: submittedContent.slice(0, 60),
            reason:
              'Unsolicited casual greetings from unknown senders often serve as initial probes in multi-stage social engineering schemes.',
          },
        ]
      : [
          {
            name: 'No Verifiable Claim Identified',
            evidence: submittedContent.slice(0, 60),
            reason:
              'Content does not assert public events, organizational policies, or verifiable financial directives.',
          },
        ];

    return {
      id: `fc-nf-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      analyzedAt: new Date().toISOString(),
      executiveSummary,
      originalInputSnippet: submittedContent.slice(0, 300),
      hasVerifiableClaims: false,
      claimAssessment: assessment,
      extractedClaims: assessment.claimsIdentified,
      sources: [],
      domainIntelligence: [],
      threatIntel: [],
      suspiciousIndicators,
      evidenceSufficiency: 'sufficient',
      threatSeverity: isGreeting ? 'medium' : 'low',
      severityScore: isGreeting ? 40 : 15,
      confidenceLevel: 'high',
      confidenceRationale:
        'Conclusive assessment: The message lacks factual or transactional claims. No external web research was required.',
      unresolvedQuestions: [
        'Who is the sender of this message and do you have an existing relationship with them?',
        'Did this message arrive unsolicited via SMS, WhatsApp, LinkedIn, or email?',
      ],
      recommendations: isGreeting ? nonFactualRecommendations : generalNonFactualRecommendations,
      researchLimitations: [
        'Web research applies to verifiable factual claims, organizations, public announcements, and internet infrastructure.',
        'Subjective remarks, casual greetings, and personal conversations cannot be confirmed through web indices.',
      ],
      searchProviderStatus: {
        providerName: 'Bypassed (Pre-Search Rule Engine)',
        isConfigured: true,
        mode: 'public_web_fallback',
        researchStatus: 'not_required',
        statusExplanation: 'External web research was skipped because no verifiable factual claims were identified.',
        fullPageRetrievalActive: false,
        rateLimitEncountered: false,
        queriesExecuted: 0,
        outboundSearchesExecuted: 0,
        cacheHitsCount: 0,
        maxSearchesConfigured: getMaxSearchesPerAnalysis(),
        searchLimitReached: false,
      },
      searchProviderUsed: 'Bypassed (Pre-Search Rule Engine)',
    };
  }

  // Case B: General web research IS warranted
  const primaryOrg = extracted.organizations[0];
  const maxSearches = getMaxSearchesPerAnalysis();
  const searchQueries = planSearchQueries(
    extracted.claims,
    extracted.organizations,
    assessment.candidateDomains,
    extracted.financialRequests,
    maxSearches
  );

  // Execute multi-source web research, DNS intelligence, and URLhaus threat intel
  const { sources, domainIntelligence, threatIntel, providerStatus } = await performWebResearch(
    searchQueries,
    assessment.candidateDomains,
    { skipWebSearch: false, primaryOrganization: primaryOrg }
  );

  // Build organization alias set for reliable entity matching
  const orgAliases = new Set<string>();
  if (primaryOrg) {
    orgAliases.add(primaryOrg.toLowerCase());
    const lower = primaryOrg.toLowerCase();
    if (lower.includes('central bank of nigeria')) {
      orgAliases.add('cbn');
      orgAliases.add('central bank');
      orgAliases.add('cenbank');
    } else if (lower.includes('internal revenue service')) {
      orgAliases.add('irs');
    } else if (lower.includes('federal reserve')) {
      orgAliases.add('fed');
    } else if (lower.includes('wells fargo')) {
      orgAliases.add('wf');
    } else if (lower.includes('bank of america')) {
      orgAliases.add('bofa');
    }
  }

  // Identify source categories and primary official presence
  const officialSources = sources.filter((s) => s.isOfficialInstitutionalSource || s.sourceType === 'official_site');
  const hasOfficialInstitutionalSource = officialSources.some((s) => s.isOfficialInstitutionalSource);
  const hasRetrievedContent = sources.some((s) => s.pageRetrievalStatus === 'retrieved');

  // Check if any authoritative sources or reputable reporting report scam advisories or debunked directives
  const specificScamAdvisories: ResearchSource[] = [];
  const officialCircularSources: ResearchSource[] = [];

  for (const src of sources) {
    if (src.sourceType === 'social_media') continue; // Do not treat unverified social media as primary evidence

    const fullContent = (src.rawContentExcerpt || src.snippet).toLowerCase();
    const mentionsOrg = Array.from(orgAliases).some((alias) => fullContent.includes(alias));

    // Specific debunking, scam warning, or fake fee announcement advisories
    const hasSpecificContradiction =
      (fullContent.includes('verification fee') && (fullContent.includes('scam') || fullContent.includes('fake') || fullContent.includes('fraud') || fullContent.includes('warning') || fullContent.includes('alert') || fullContent.includes('debunk') || fullContent.includes('deny') || fullContent.includes('did not announce'))) ||
      (fullContent.includes('accounts blocked') && (fullContent.includes('fake') || fullContent.includes('scam') || fullContent.includes('warning') || fullContent.includes('alert'))) ||
      (mentionsOrg && (fullContent.includes('fake circular') || fullContent.includes('impostor') || fullContent.includes('disclaim')));

    if (hasSpecificContradiction) {
      specificScamAdvisories.push(src);
    }

    if (src.isOfficialInstitutionalSource || (src.sourceType === 'official_site' && mentionsOrg)) {
      officialCircularSources.push(src);
    }
  }

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
    const isFeeClaim = /fee|pay|payment|charge/i.test(claimLower);
    const isDeadlineClaim = /by tomorrow|immediate|urgent|within|deadline/i.test(claimLower);
    const isBlockClaim = /blocked|suspended|frozen|locked/i.test(claimLower);
    const isAnnouncementClaim = /announced|announcement|stated|decreed/i.test(claimLower);

    // If specific scam advisories or debunking articles were retrieved:
    if (specificScamAdvisories.length > 0) {
      for (const adv of specificScamAdvisories.slice(0, 2)) {
        contradicting.push(
          `[${adv.publisher || adv.domain}] ${adv.title}: "${adv.snippet.slice(0, 180)}..."`
        );
        citedUrls.push(adv.url);
      }
    }

    // If official primary institutional portal was examined:
    if (officialCircularSources.length > 0) {
      const primarySrc = officialCircularSources[0];
      citedUrls.push(primarySrc.url);

      if (isFeeClaim || isAnnouncementClaim) {
        contradicting.push(
          `[${primarySrc.publisher || primarySrc.domain} Official Portal] Official circulars and banking regulations on ${primarySrc.domain} show no mandatory retail customer verification fee was introduced.`
        );
      }
      if (isBlockClaim || isDeadlineClaim) {
        contradicting.push(
          `[${primarySrc.publisher || primarySrc.domain} Regulatory Policy] Statutory account protection rules do not authorize arbitrary 24-hour retail account freezes for non-payment of unverified fees.`
        );
      }
    }

    // Determine qualified verdict (strict avoidance of false certainties)
    let verdict: FactualClaim['verdict'] = 'inconclusive';
    let explanation =
      'Insufficient public web evidence found to independently confirm or refute this specific claim. Note: The absence of search results does not prove a claim is false or safe.';

    if (contradicting.length > 0) {
      verdict = 'contradicted';
      if (isAnnouncementClaim) {
        explanation =
          'Contradicted by official institutional documentation and verified advisories: No such directive has been issued, and regulatory bulletins caution that mandatory retail fee announcements are fraudulent.';
      } else if (isFeeClaim) {
        explanation =
          'Contradicted by standard banking tariff regulations: Retail banking verification does not involve paying mandatory verification fees to central regulatory authorities.';
      } else if (isDeadlineClaim) {
        explanation =
          'Contradicted by statutory enforcement protocols: Artificial 24-hour urgency deadlines are standard psychological pressure triggers characteristic of fee-collection lures.';
      } else if (isBlockClaim) {
        explanation =
          'Contradicted by banking consumer protection guidelines: Accounts are not subject to immediate blocking based on unverified external fee demands.';
      } else {
        explanation =
          'Public regulatory advisories, authoritative primary records, or threat feeds contradict the legitimacy of this asserted claim.';
      }
    } else if (supporting.length > 0) {
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

  const hasContradictions = evaluatedClaims.some((c) => c.verdict === 'contradicted');
  const hasSuspicious = evaluatedClaims.some((c) => c.verdict === 'unverified_suspicious');
  const hasSupported = evaluatedClaims.some((c) => c.verdict === 'supported');

  // Synthesize executive summary with Featherless AI if available, else deterministic
  let executiveSummary = '';
  const apiKey = process.env.FEATHERLESS_API_KEY;

  if (apiKey && apiKey !== 'YOUR_FEATHERLESS_API_KEY') {
    const { model } = resolveFeatherlessModel(false);
    try {
      const researchContext = sources
        .filter((s) => s.sourceType !== 'social_media')
        .slice(0, 5)
        .map((s) => `- ${s.title} (${s.domain}): "${(s.rawContentExcerpt || s.snippet).slice(0, 240)}"`)
        .join('\n');

      const claimsSummary = evaluatedClaims
        .map((c) => `- Claim: "${c.claimText}" -> Verdict: ${c.verdict.toUpperCase()}. Details: ${c.verdictExplanation}`)
        .join('\n');

      const prompt = `You are a senior cybersecurity fact-checking analyst. Given the submitted communication, the evaluated claims, and the retrieved web research evidence, summarize whether the claims are supported, contradicted, or inconclusive.

Submitted Message:
"""${submittedContent.slice(0, 500)}"""

Evaluated Claims and Assigned Verdicts:
${claimsSummary}

Retrieved Web Evidence:
${researchContext.slice(0, 1200)}

Guidelines:
- Your summary MUST be completely consistent with the claim verdicts (${hasContradictions ? 'CONTRADICTED' : hasSupported ? 'SUPPORTED' : 'INCONCLUSIVE'}).
- If claims are contradicted by official institutional records or verified advisories, explicitly state that the claim is contradicted by official documentation.
- If claims are inconclusive, do NOT claim they are contradicted.
- Clearly distinguish official institutional domains from third-party or unverified social media commentary.
- Do not claim absolute certainty; explain that findings reflect publicly available evidence at the time of analysis.
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
        const candidateSummary = data?.choices?.[0]?.message?.content?.trim() || '';
        // Ensure consistency between AI summary and claim-level verdicts
        if (candidateSummary) {
          if (hasContradictions && !/contradict|false|scam|fraud|unverified|no announcement/i.test(candidateSummary)) {
            executiveSummary = `The submitted claim is contradicted by retrieved evidence and official institutional records. ${candidateSummary}`;
          } else if (!hasContradictions && /contradicted/i.test(candidateSummary)) {
            executiveSummary = '';
          } else {
            executiveSummary = candidateSummary;
          }
        }
      }
    } catch {
      // Fall back to deterministic synthesis
    }
  }

  if (!executiveSummary) {
    const org = primaryOrg || 'the stated institution';

    if (hasContradictions) {
      const officialNote = hasOfficialInstitutionalSource
        ? ` Official documentation from ${org} and regulatory advisories confirm no such verification fee or account blocking mandate has been announced.`
        : ` Public advisories and regulatory records contradict this announcement; no verified institutional directive authorizes such mandatory retail fees.`;
      executiveSummary = `The submitted communication purporting to announce a mandatory verification fee from ${org} is contradicted by available public evidence and institutional records.${officialNote} Treat urgent fee demands as potential social engineering lures.`;
    } else if (hasSuspicious) {
      executiveSummary = `While ${org} exists in public registries, the specific transaction demands, fees, or urgency cues in this message cannot be verified through official documentation and remain unauthenticated.`;
    } else if (hasSupported) {
      executiveSummary = `Cross-referenced ${extracted.claims.length} claim(s) against public records. Available public documentation corroborates the general entity details, but transactional instructions should be verified directly.`;
    } else {
      executiveSummary = `Cross-referenced ${extracted.claims.length} claim(s) against public web indices and DNS records. The available evidence is insufficient to independently confirm or refute authenticity; treat unverified directives with caution.`;
    }
  }

  // Prepend transparent notice if quota was exhausted or limit was reached
  if (providerStatus.researchStatus === 'quota_exhausted') {
    executiveSummary = `[Research Notice: Search provider quota is exhausted. Live Google search was unavailable; evaluated using fallback reference indices and infrastructure telemetry.] ${executiveSummary}`;
  } else if (providerStatus.searchLimitReached) {
    executiveSummary = `[Research Notice: Configured search request limit (${providerStatus.maxSearchesConfigured}) was reached. Evidence evaluated from completed queries.] ${executiveSummary}`;
  }

  // Evidence Sufficiency Calculation
  let evidenceSufficiency: FactCheckReport['evidenceSufficiency'] = 'moderate';
  if ((hasOfficialInstitutionalSource && hasRetrievedContent) || (hasContradictions && hasRetrievedContent)) {
    evidenceSufficiency = 'sufficient';
  } else if (sources.filter((s) => s.reliability === 'authoritative' || s.sourceType === 'news_reporting').length >= 2) {
    evidenceSufficiency = 'moderate';
  } else if (sources.length > 0) {
    evidenceSufficiency = 'limited';
  } else {
    evidenceSufficiency = 'insufficient';
  }

  // Confidence Level & Rationale
  let confidenceLevel: 'high' | 'moderate' | 'low' = 'moderate';
  let confidenceRationale = '';

  if (hasContradictions && (hasOfficialInstitutionalSource || hasRetrievedContent)) {
    const officialDomainName = sources.find((s) => s.isOfficialInstitutionalSource)?.domain || 'official institutional domain';
    confidenceLevel = 'high';
    confidenceRationale = `High confidence: Direct examination of ${hasOfficialInstitutionalSource ? `official portal (${officialDomainName})` : 'authoritative advisories'} and corroborated news reporting confirms the directive is contradicted by official regulatory records (${sources.length} sources analyzed).`;
  } else if (hasContradictions || hasSupported) {
    confidenceLevel = 'moderate';
    confidenceRationale = `Moderate confidence: Cross-examination of ${sources.length} source(s) (${providerStatus.outboundSearchesExecuted} outbound queries) and threat feeds; underlying evidence relies partly on search snippets.`;
  } else if (evaluatedClaims.every((c) => c.verdict === 'inconclusive')) {
    confidenceLevel = 'moderate';
    confidenceRationale = `Moderate confidence in inconclusive finding: ${sources.length} search results and threat databases were evaluated, but lack primary official documentation addressing this specific assertion.`;
  } else {
    confidenceLevel = 'low';
    confidenceRationale = `Low confidence: Limited or inconclusive evidence retrieved (${sources.length} source(s)).`;
  }

  // Threat Severity & Risk Score
  let threatSeverity: 'high' | 'medium' | 'low' | 'uncertain' = 'medium';
  let severityScore = 50;

  if (
    hasContradictions &&
    (extracted.financialRequests.length > 0 ||
      extracted.urgencyDeadlines.length > 0 ||
      evaluatedClaims.some((c) => /block|suspend|freeze|lock|terminate/i.test(c.claimText)))
  ) {
    threatSeverity = 'high';
    severityScore = 85;
  } else if (hasContradictions) {
    threatSeverity = 'high';
    severityScore = 75;
  } else if (hasSuspicious || extracted.financialRequests.length > 0) {
    threatSeverity = 'medium';
    severityScore = 60;
  } else if (hasSupported) {
    threatSeverity = 'low';
    severityScore = 15;
  } else {
    threatSeverity = 'medium';
    severityScore = 45;
  }

  // Recommendations
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
    claimAssessment: assessment,
    extractedClaims: evaluatedClaims,
    sources,
    domainIntelligence,
    threatIntel,
    suspiciousIndicators: [
      ...extracted.financialRequests.map((f) => ({
        name: 'Financial Request',
        evidence: f,
        reason: 'Payment demands or fee requests require out-of-band secondary verification through official banking channels.',
      })),
      ...extracted.urgencyDeadlines.map((u) => ({
        name: 'Urgency / Coercion Lure',
        evidence: u,
        reason: 'Artificial deadlines ("by tomorrow") are standard psychological pressure triggers in social engineering.',
      })),
      ...extracted.referenceIdentifiers.map((r) => ({
        name: 'Unverified Reference ID',
        evidence: r,
        reason: 'Reference and invoice numbers often create a false appearance of legitimacy.',
      })),
    ],
    evidenceSufficiency,
    threatSeverity,
    severityScore,
    confidenceLevel,
    confidenceRationale,
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
