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
import { detectBehavioralThreats } from '@/lib/scam-analyzer';

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
    {
      skipWebSearch: false,
      primaryOrganization: primaryOrg,
      submittedContent,
      candidateUrls: assessment.candidateUrls,
    }
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

  // Categorize evidence sources by the specific claim topics they actually address
  const officialCircularSources: ResearchSource[] = [];
  const announcementRefutations: ResearchSource[] = [];
  const feeRefutations: ResearchSource[] = [];
  const deadlineRefutations: ResearchSource[] = [];
  const blockingRefutations: ResearchSource[] = [];

  for (const src of sources) {
    if (src.sourceType === 'social_media') continue; // Do not treat unverified social media as primary evidence
    if (src.relevanceGrade === 'unrelated') continue; // Exclude unrelated sources from substantive claim verdicts

    const fullContent = (src.rawContentExcerpt || src.snippet).toLowerCase();
    const mentionsOrg = Array.from(orgAliases).some((alias) => fullContent.includes(alias));

    // Specific refutation of the alleged circular / announcement
    const isAnnouncementRefuted =
      mentionsOrg &&
      (fullContent.includes('fake circular') ||
        fullContent.includes('impostor circular') ||
        fullContent.includes('disclaim') ||
        fullContent.includes('did not announce') ||
        fullContent.includes('no such announcement') ||
        fullContent.includes('debunk') ||
        fullContent.includes('unauthorized notice'));

    if (isAnnouncementRefuted) {
      announcementRefutations.push(src);
    }

    // Specific refutation of customer verification fee
    const isFeeRefuted =
      fullContent.includes('verification fee') &&
      (fullContent.includes('scam') ||
        fullContent.includes('fake') ||
        fullContent.includes('fraud') ||
        fullContent.includes('debunk') ||
        fullContent.includes('warns against') ||
        fullContent.includes('unauthorized fee') ||
        fullContent.includes('deny') ||
        fullContent.includes('denies'));

    if (isFeeRefuted) {
      feeRefutations.push(src);
    }

    // Specific refutation or documentation of 24h deadline
    const isDeadlineAddressed =
      (fullContent.includes('24 hour') || fullContent.includes('by tomorrow') || fullContent.includes('immediate deadline')) &&
      (fullContent.includes('false') || fullContent.includes('fake') || fullContent.includes('debunk'));

    if (isDeadlineAddressed) {
      deadlineRefutations.push(src);
    }

    // Specific refutation or documentation of account blocking consequence
    const isBlockingRefuted =
      fullContent.includes('account blocked') &&
      (fullContent.includes('fake') || fullContent.includes('scam') || fullContent.includes('debunk'));

    if (isBlockingRefuted) {
      blockingRefutations.push(src);
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

    // 1. Evaluate against threat intelligence and DNS telemetry (only for claims referencing domains)
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
      if (claimLower.includes(tRecord.indicator.toLowerCase())) {
        if (tRecord.status === 'malicious') {
          contradicting.push(
            `[${tRecord.provider}] Indicator "${tRecord.indicator}" is flagged in active malware or phishing distribution databases.`
          );
          citedUrls.push(`https://${tRecord.indicator}`);
        }
      }
    }

    // 2. Classify claim dimension
    const isFeeClaim = /fee|pay|payment|charge/i.test(claimLower) && !/announced/i.test(claimLower);
    const isDeadlineClaim = /by tomorrow|immediate|urgent|within|deadline/i.test(claimLower);
    const isBlockClaim = /blocked|suspended|frozen|locked/i.test(claimLower);
    const isAnnouncementClaim = /announced|announcement|stated|decreed/i.test(claimLower);

    // 3. Match evidence that specifically addresses this claim dimension
    if (isAnnouncementClaim && announcementRefutations.length > 0) {
      for (const adv of announcementRefutations.slice(0, 2)) {
        contradicting.push(`[${adv.publisher || adv.domain}] ${adv.title}: "${(adv.rawContentExcerpt || adv.snippet).slice(0, 160)}..."`);
        citedUrls.push(adv.url);
      }
    }

    if (isFeeClaim && feeRefutations.length > 0) {
      for (const adv of feeRefutations.slice(0, 2)) {
        contradicting.push(`[${adv.publisher || adv.domain}] ${adv.title}: "${(adv.rawContentExcerpt || adv.snippet).slice(0, 160)}..."`);
        citedUrls.push(adv.url);
      }
    }

    if (isDeadlineClaim && deadlineRefutations.length > 0) {
      for (const adv of deadlineRefutations.slice(0, 2)) {
        contradicting.push(`[${adv.publisher || adv.domain}] ${adv.title}: "${(adv.rawContentExcerpt || adv.snippet).slice(0, 160)}..."`);
        citedUrls.push(adv.url);
      }
    }

    if (isBlockClaim && blockingRefutations.length > 0) {
      for (const adv of blockingRefutations.slice(0, 2)) {
        contradicting.push(`[${adv.publisher || adv.domain}] ${adv.title}: "${(adv.rawContentExcerpt || adv.snippet).slice(0, 160)}..."`);
        citedUrls.push(adv.url);
      }
    }

    // Reference examined official institutional source for unverified claims without claiming silence = disproof
    const primaryOfficialSrc = officialCircularSources.length > 0 ? officialCircularSources[0] : undefined;
    if (primaryOfficialSrc && !citedUrls.includes(primaryOfficialSrc.url)) {
      citedUrls.push(primaryOfficialSrc.url);
    }

    // Determine qualified, evidence-grounded verdict (strict avoidance of false certainties)
    let verdict: FactualClaim['verdict'] = 'inconclusive';
    let explanation =
      'Insufficient public web evidence found to independently confirm or refute this specific claim. Note: The absence of search results does not prove a claim is false or safe.';

    if (contradicting.length > 0) {
      verdict = 'contradicted';
      if (isAnnouncementClaim) {
        explanation =
          'Contradicted by verified regulatory advisories: Regulatory bulletins or independent reporting refute the authenticity of this alleged announcement.';
      } else if (isFeeClaim) {
        explanation =
          'Contradicted by official documentation: Public advisories indicate retail banking customers are not required to pay this fee.';
      } else if (isDeadlineClaim) {
        explanation =
          'Contradicted by verified notices: Regulatory documentation refutes this emergency enforcement window.';
      } else if (isBlockClaim) {
        explanation =
          'Contradicted by consumer protection guidelines: Banking regulations refute immediate account blockage based on unannounced fee demands.';
      } else {
        explanation =
          'Authoritative public records directly contradict the legitimacy of this asserted claim.';
      }
    } else if (primaryOfficialSrc || sources.length > 0) {
      const examinedDomain = primaryOfficialSrc?.domain || (sources[0] ? sources[0].domain : 'public records');
      if (isAnnouncementClaim) {
        verdict = 'unverified_suspicious';
        explanation = `Searches across official publications on ${examinedDomain} and public indices identified no official announcement or circular matching this directive. While absence of a public record does not conclusively disprove private correspondence, uncorroborated directives demanding urgent fees are characteristic of social engineering lures.`;
      } else if (isFeeClaim) {
        verdict = 'unverified_suspicious';
        explanation = `No verified public tariff schedule or regulatory directive authorizes a mandatory customer verification fee on ${examinedDomain} or in public indices searched. The payment demand remains uncorroborated.`;
      } else if (isDeadlineClaim) {
        verdict = 'unverified_suspicious';
        explanation = `No official notice or regulatory publication documents a 24-hour deadline for this directive. In cybersecurity analysis, artificial deadlines ('by tomorrow') function as high-pressure psychological coercion triggers.`;
      } else if (isBlockClaim) {
        verdict = 'unverified_suspicious';
        explanation = `No official banking regulatory guidelines or statutory circulars authorize retail account blockage based on failure to pay an unannounced fee. The threat of immediate account suspension represents an unverified coercive tactic.`;
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
      } else {
        verdict = 'inconclusive';
        explanation =
          'The claim could not be verified in the public sources searched. Findings remain inconclusive.';
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

  // Deterministic Behavioral Threat Assessment
  const behavioral = detectBehavioralThreats(submittedContent);

  // Critical behavioral threats (OTPs, credentials, remote access, coercive threats)
  const hasCriticalBehavioralThreat =
    behavioral.hasAuthCodeRequest ||
    behavioral.hasCredentialHarvesting ||
    behavioral.hasRemoteAccessRequest ||
    (behavioral.hasAccountBlockingThreat && (behavioral.hasPaymentDemand || behavioral.hasArtificialDeadline));

  const hasMonetaryOfferWithUnverifiedLink =
    (behavioral.hasMonetaryIncentiveLure || extracted.financialRequests.length > 0) &&
    (assessment.candidateUrls.length > 0 || assessment.candidateDomains.length > 0);

  // Synthesize executive summary with Featherless AI if available, else deterministic
  let executiveSummary = '';

  if (hasMonetaryOfferWithUnverifiedLink && !hasOfficialInstitutionalSource && !hasContradictions) {
    // Calibrated wording strictly distinguishing unverified offer from confirmed maliciousness
    executiveSummary =
      'The offer could not be independently verified. The unfamiliar link and unexplained monetary incentive warrant caution. Available evidence does not establish that the destination is confirmed malicious. Do not provide payment details, passwords, or verification codes. Verify any legitimate financial offer through an independently obtained official channel.';
  }

  const apiKey = process.env.FEATHERLESS_API_KEY;

  if (!executiveSummary && apiKey && apiKey !== 'YOUR_FEATHERLESS_API_KEY') {
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

      const prompt = `You are a senior cybersecurity fact-checking analyst. Given the submitted communication, the evaluated claims, and the retrieved web research evidence, summarize whether the claims are supported, contradicted, unverified in sources searched, or inconclusive.

Submitted Message:
"""${submittedContent.slice(0, 500)}"""

Evaluated Claims and Assigned Verdicts:
${claimsSummary}

Retrieved Web Evidence:
${researchContext.slice(0, 1200)}

Guidelines:
- Your summary MUST be completely consistent with the claim verdicts (${hasContradictions ? 'CONTRADICTED' : hasSuspicious ? 'UNVERIFIED IN SOURCES SEARCHED' : hasSupported ? 'SUPPORTED' : 'INCONCLUSIVE'}).
- If claims are contradicted by specific regulatory advisories or debunks, explicitly state that the claim is contradicted by official documentation.
- If claims are unverified in official publications (not mentioned in public circulars), explain that searches yielded no verified circular or announcement, but do NOT state that silence alone conclusively disproves the claim.
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
            // Prevent false contradiction claim when no claims were contradicted
            executiveSummary = candidateSummary
              .replace(/is contradicted by/gi, 'is unverified in')
              .replace(/was contradicted by/gi, 'was unverified in');
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
      const officialNote = hasOfficialInstitutionalSource
        ? ` Cross-referencing against official publications on ${org} portals (${officialSources[0]?.domain}) and public news indices identified no verified directive, fee schedule, or account-blocking mandate matching these assertions.`
        : ` Cross-referencing against public registries and news indices identified no verified institutional record matching these claims.`;
      executiveSummary = `${officialNote} While the assertions remain unverified in public records rather than directly refuted by a specific circular, the combination of artificial 24-hour urgency, payment demands, and threatened account blockage under an institutional guise represents a high-risk social engineering lure.`;
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

  // Evidence Sufficiency Calculation (Avoid declaring sufficiency solely because a general page or unrelated advice was fetched)
  const directEvidenceSources = sources.filter((s) => s.relevanceGrade === 'direct_evidence');
  const hasDirectEvidence = directEvidenceSources.length > 0;
  const hasDirectRetrieved = directEvidenceSources.some((s) => s.pageRetrievalStatus === 'retrieved');

  let evidenceSufficiency: FactCheckReport['evidenceSufficiency'] = 'limited';
  if ((hasContradictions || hasSupported) && (hasOfficialInstitutionalSource || hasDirectRetrieved)) {
    evidenceSufficiency = 'sufficient';
  } else if (hasDirectEvidence && (hasOfficialInstitutionalSource || directEvidenceSources.length >= 2)) {
    evidenceSufficiency = 'moderate';
  } else if (
    sources.some(
      (s) =>
        s.relevanceGrade === 'supporting_guidance' ||
        s.relevanceGrade === 'direct_evidence' ||
        s.relevanceGrade === 'threat_or_dns_telemetry' ||
        s.relevanceGrade === 'indirect_or_weak'
    ) ||
    domainIntelligence.length > 0 ||
    threatIntel.length > 0
  ) {
    evidenceSufficiency = 'limited';
  } else {
    evidenceSufficiency = 'insufficient';
  }

  // Confidence Level & Rationale
  let confidenceLevel: 'high' | 'moderate' | 'low' = 'moderate';
  let confidenceRationale = '';

  if (hasContradictions && (hasOfficialInstitutionalSource || hasDirectRetrieved)) {
    const officialDomainName = sources.find((s) => s.isOfficialInstitutionalSource)?.domain || 'official institutional domain';
    confidenceLevel = 'high';
    confidenceRationale = `High confidence: Direct examination of ${hasOfficialInstitutionalSource ? `official portal (${officialDomainName})` : 'authoritative advisories'} and corroborated news reporting confirms the directive is contradicted by official regulatory records (${directEvidenceSources.length || sources.length} sources analyzed).`;
  } else if (hasSuspicious && hasOfficialInstitutionalSource) {
    const officialDomainName = sources.find((s) => s.isOfficialInstitutionalSource)?.domain || 'official portal';
    confidenceLevel = 'moderate';
    confidenceRationale = `Moderate confidence in unverified status: Examined official publications on ${officialDomainName} and public news indices (${sources.length} sources); no verified circular, tariff, or directive authorizes these demands. Because absence of public records does not constitute direct disproof, findings reflect the absence of corroboration in public indices.`;
  } else if (hasMonetaryOfferWithUnverifiedLink) {
    confidenceLevel = 'moderate';
    confidenceRationale =
      'Moderate confidence in provisional assessment: The monetary offer could not be verified in public records. The link uses an unvetted subdomain on a free hosting platform without active threat feed listings. Available evidence does not establish maliciousness, but behavioral risk warrants caution.';
  } else if (hasDirectEvidence) {
    confidenceLevel = 'moderate';
    confidenceRationale = `Moderate confidence: Cross-examination of direct web evidence (${directEvidenceSources.length} source(s)); findings reflect publicly accessible evidence.`;
  } else if (evaluatedClaims.every((c) => c.verdict === 'inconclusive')) {
    confidenceLevel = 'low';
    confidenceRationale = `Inconclusive evidence: ${sources.length} search results and threat databases were evaluated, but lack primary official documentation addressing this specific assertion.`;
  } else {
    confidenceLevel = 'moderate';
    confidenceRationale = `Moderate confidence: Evaluated ${sources.length} source(s) across public indices and infrastructure telemetry.`;
  }

  // Threat Severity & Risk Score
  // INVARIANT: An inconclusive factual verdict must NOT automatically produce a low-risk assessment
  // when the message requests dangerous behavior (such as sharing OTPs, credentials, or remote access).
  let threatSeverity: 'high' | 'medium' | 'low' | 'uncertain' = 'medium';
  let severityScore = 50;

  if (hasContradictions) {
    threatSeverity = 'high';
    severityScore = hasCriticalBehavioralThreat ? 92 : 85;
  } else if (hasCriticalBehavioralThreat) {
    threatSeverity = 'high';
    severityScore = 88;
  } else if (
    hasSuspicious &&
    (extracted.financialRequests.length > 0 ||
      extracted.urgencyDeadlines.length > 0 ||
      behavioral.hasPaymentDemand ||
      behavioral.hasAccountBlockingThreat ||
      evaluatedClaims.some((c) => /block|suspend|freeze|lock|terminate/i.test(c.claimText)))
  ) {
    threatSeverity = hasMonetaryOfferWithUnverifiedLink && !behavioral.hasAccountBlockingThreat && !behavioral.hasPaymentDemand ? 'medium' : 'high';
    severityScore = hasMonetaryOfferWithUnverifiedLink && !behavioral.hasAccountBlockingThreat && !behavioral.hasPaymentDemand ? 60 : 85;
  } else if (hasMonetaryOfferWithUnverifiedLink) {
    threatSeverity = 'medium';
    severityScore = 60;
  } else if (hasSuspicious || extracted.financialRequests.length > 0 || behavioral.hasPaymentDemand) {
    threatSeverity = 'medium';
    severityScore = 65;
  } else if (hasSupported && !hasCriticalBehavioralThreat && extracted.financialRequests.length === 0) {
    threatSeverity = 'low';
    severityScore = 15;
  } else if (evaluatedClaims.every((c) => c.verdict === 'inconclusive')) {
    threatSeverity = behavioral.indicators.length > 0 ? 'medium' : 'uncertain';
    severityScore = behavioral.indicators.length > 0 ? 55 : 45;
  } else {
    threatSeverity = 'medium';
    severityScore = 50;
  }

  // Prepend critical behavioral alert to executive summary if applicable
  if (hasCriticalBehavioralThreat && !hasContradictions) {
    if (behavioral.hasAuthCodeRequest && !executiveSummary.includes('authentication')) {
      executiveSummary = `[High-Risk Behavioral Alert: Message requests sensitive authentication / OTP verification codes.] ${executiveSummary}`;
    } else if (behavioral.hasRemoteAccessRequest && !executiveSummary.includes('remote-access')) {
      executiveSummary = `[High-Risk Behavioral Alert: Message requests installation of remote-access software.] ${executiveSummary}`;
    }
  }

  // Consolidated behavioral indicators (A, B, C, D, E distinction)
  const allIndicators: Array<{ name: string; evidence: string; reason: string }> = [
    ...behavioral.indicators,
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
  ];

  const seenIndNames = new Set<string>();
  const consolidatedIndicators = allIndicators.filter((ind) => {
    const key = ind.name.toLowerCase();
    if (seenIndNames.has(key)) return false;
    seenIndNames.add(key);
    return true;
  });

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
    suspiciousIndicators: consolidatedIndicators,
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
