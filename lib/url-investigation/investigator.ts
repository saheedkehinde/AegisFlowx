import dns from 'dns/promises';
import {
  UrlComponents,
  UrlIndicatorItem,
  UrlInvestigationReport,
  UrlVerdictOutcome,
} from '@/lib/url-investigation/types';
import { RedirectAnalysisResult, resolveUrlRedirects } from '@/lib/url-investigation/redirect-resolver';
import {
  isPrivateOrReservedIp,
  checkUrlhausThreatIntel,
  performDomainDnsLookup,
  searchSerper,
  searchPublicWebFallback,
  classifySourceRelevance,
} from '@/lib/fact-checker/web-researcher';
import { isGeminiSearchFallbackEnabled } from '@/lib/gemini/client';
import { searchGeminiGoogleSearch } from '@/lib/gemini/search-grounding';
import { redactSecrets } from '@/lib/model-config';
import {
  ResearchSource,
  ThreatIntelRecord,
  AudienceRecommendations,
  ThreatIntelMatchType,
} from '@/lib/fact-checker/types';

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'auth',
  'access_token',
  'auth_token',
  'key',
  'apikey',
  'api_key',
  'password',
  'pass',
  'code',
  'verification_code',
  'session',
  'session_id',
  'sessionid',
  'sig',
  'signature',
  'secret',
  'client_secret',
  'recovery_key',
  'refresh_token',
  'id_token',
  'jwt',
  'bearer',
]);

const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'rebrand.ly',
  'rb.gy',
  'shorturl.at',
  'v.gd',
  'buff.ly',
  't.ly',
  'bl.ink',
  'snip.ly',
]);

const FREE_HOSTING_PLATFORMS = [
  'site123.me',
  'pages.dev',
  'wixsite.com',
  'weebly.com',
  'webflow.io',
  'firebaseapp.com',
  '000webhostapp.com',
  'glitch.me',
  'repl.co',
  'vercel.app',
  'netlify.app',
  'github.io',
  'surge.sh',
];

const HIGH_REPUTATION_REDIRECT_HOSTS = new Set([
  'google.com',
  'www.google.com',
  'outlook.office.com',
  'teams.microsoft.com',
  'slack.com',
  't.co',
  'facebook.com',
  'linkedin.com',
]);

export function validateAndNormalizeUrl(rawInput: string): {
  isValid: boolean;
  error?: string;
  urlComponents?: UrlComponents;
  parsedUrl?: URL;
} {
  if (!rawInput || typeof rawInput !== 'string') {
    return { isValid: false, error: 'URL input cannot be empty.' };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length === 0) {
    return { isValid: false, error: 'URL input cannot be empty.' };
  }

  if (trimmed.length > 2048) {
    return { isValid: false, error: 'URL exceeds maximum permitted length of 2,048 characters.' };
  }

  if (trimmed.startsWith('//') || trimmed.startsWith('\\\\') || trimmed.includes('\\')) {
    return {
      isValid: false,
      error: 'Malformed or obfuscated URL format with prohibited backslashes or protocol-relative syntax.',
    };
  }

  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        isValid: false,
        error: `Unsupported URL scheme "${scheme}:". AegisFlow URL Intelligence exclusively supports "http:" and "https:" destinations. Executable or local protocols (e.g., javascript:, file:, data:) are prohibited for security.`,
      };
    }
  }

  let urlToParse = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    urlToParse = `https://${trimmed}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(urlToParse);
  } catch {
    return {
      isValid: false,
      error: 'Malformed URL structure. Please ensure the address contains a valid host (e.g., "https://example.com/path").',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      isValid: false,
      error: `Unsupported URL scheme "${parsed.protocol}". Only "http:" and "https:" destinations are supported.`,
    };
  }

  const hasCredentials = Boolean(parsed.username || parsed.password);
  if (hasCredentials) {
    return {
      isValid: false,
      error: 'Credential-bearing URLs (containing usernames or passwords in the authority component) are prohibited to prevent authentication leaks.',
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname.length === 0) {
    return { isValid: false, error: 'URL is missing a valid destination hostname.' };
  }

  const hasIpHostname =
    /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
    hostname.startsWith('[') ||
    isPrivateOrReservedIp(hostname);

  const isShortenedUrl = KNOWN_URL_SHORTENERS.has(hostname);

  const isFreeHostingSubdomain = FREE_HOSTING_PLATFORMS.some(
    (platform) => hostname.endsWith('.' + platform) || hostname === platform
  );

  const hostParts = hostname.split('.');
  const domain =
    hostParts.length > 2 && !hasIpHostname
      ? hostParts.slice(-2).join('.')
      : hostname;

  let redactedParamsCount = 0;
  const displayUrlObj = new URL(parsed.toString());
  for (const key of Array.from(displayUrlObj.searchParams.keys())) {
    if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
      displayUrlObj.searchParams.set(key, '[REDACTED]');
      redactedParamsCount++;
    }
  }

  const urlComponents: UrlComponents = {
    rawUrl: trimmed,
    normalizedUrl: parsed.toString(),
    displayUrl: displayUrlObj.toString(),
    protocol: parsed.protocol,
    hostname,
    domain,
    port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    pathname: parsed.pathname || '/',
    search: parsed.search || '',
    hash: parsed.hash || '',
    hasCredentials,
    hasIpHostname,
    isShortenedUrl,
    isFreeHostingSubdomain,
    redactedParamsCount,
  };

  return {
    isValid: true,
    urlComponents,
    parsedUrl: parsed,
  };
}

export async function screenUrlForSsrf(parsedUrl: URL): Promise<{
  safe: boolean;
  reason?: string;
  blockedIp?: string;
}> {
  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.corp') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.home') ||
    hostname.endsWith('.test') ||
    hostname.endsWith('.invalid')
  ) {
    return {
      safe: false,
      reason: `Destination hostname "${hostname}" is a private or internal network identifier. Outbound investigation to local network hosts is strictly prohibited.`,
    };
  }

  if (isPrivateOrReservedIp(hostname)) {
    return {
      safe: false,
      reason: `Destination host "${hostname}" is a loopback, private RFC-1918, link-local, or reserved IP address. Outbound network requests to internal addresses are blocked.`,
      blockedIp: hostname,
    };
  }

  try {
    const dnsTimeoutMs = 2500;
    const resolveWithTimeout = async <T>(promise: Promise<T>): Promise<T | null> => {
      return await Promise.race([
        promise,
        new Promise<null>((resolve) => setTimeout(() => resolve(null), dnsTimeoutMs)),
      ]);
    };

    const resolvedIps = (await resolveWithTimeout(dns.resolve4(hostname).catch(() => []))) || [];
    for (const ip of resolvedIps) {
      if (isPrivateOrReservedIp(ip)) {
        return {
          safe: false,
          reason: `Destination host "${hostname}" resolves to private or internal IPv4 address "${ip}". Access blocked by SSRF defense firewall.`,
          blockedIp: ip,
        };
      }
    }

    const resolvedIpv6 = (await resolveWithTimeout(dns.resolve6(hostname).catch(() => []))) || [];
    for (const ip of resolvedIpv6) {
      if (isPrivateOrReservedIp(ip)) {
        return {
          safe: false,
          reason: `Destination host "${hostname}" resolves to private IPv6 address "${ip}". Access blocked by SSRF defense firewall.`,
          blockedIp: ip,
        };
      }
    }
  } catch {
    // Handled in DNS intelligence stage
  }

  return { safe: true };
}

export function extractUrlIndicators(components: UrlComponents, redirectResult: RedirectAnalysisResult): UrlIndicatorItem[] {
  const indicators: UrlIndicatorItem[] = [];

  if (components.protocol === 'http:') {
    indicators.push({
      id: 'ind-protocol-unencrypted',
      category: 'protocol',
      severity: 'medium',
      title: 'Unencrypted HTTP Protocol',
      description:
        'The destination uses plain HTTP instead of encrypted HTTPS. Communications across this channel can be intercepted or manipulated in transit.',
      evidence: 'Protocol: http:',
    });
  } else {
    indicators.push({
      id: 'ind-protocol-https',
      category: 'protocol',
      severity: 'info',
      title: 'Transport Encryption Active (HTTPS)',
      description:
        'The connection utilizes TLS encryption. Note: HTTPS verifies transport encryption only and does not establish that the website operator is trustworthy.',
      evidence: 'Protocol: https:',
    });
  }

  if (components.hasIpHostname) {
    indicators.push({
      id: 'ind-ip-hostname',
      category: 'hostname',
      severity: 'high',
      title: 'Direct IP Address Used as Hostname',
      description:
        'The URL uses a raw IP address instead of a registered domain name. Legitimate corporate and consumer services almost exclusively use branded domains.',
      evidence: `Host: ${components.hostname}`,
    });
  }

  if (components.isShortenedUrl) {
    indicators.push({
      id: 'ind-shortener',
      category: 'infrastructure',
      severity: 'medium',
      title: 'Generic URL Shortener Detected',
      description:
        'URL shorteners obscure the real destination hostname and prevent recipient inspection before clicking. Scammers frequently deploy shorteners to bypass basic keyword filters.',
      evidence: `Shortener Service: ${components.hostname}`,
    });
  }

  if (components.isFreeHostingSubdomain) {
    indicators.push({
      id: 'ind-free-hosting',
      category: 'infrastructure',
      severity: 'medium',
      title: 'Free Hosting / Shared Cloud Subdomain',
      description:
        'The link points to a subdomain on a free website builder or platform-as-a-service. While platforms are legitimate, attackers routinely leverage free tiers to launch disposable phishing forms without registration costs.',
      evidence: `Host: ${components.hostname}`,
    });
  }

  if (redirectResult.isRedirect) {
    indicators.push({
      id: 'ind-redirect-chain',
      category: 'redirect',
      severity: redirectResult.suspiciousDomainChange ? 'high' : 'medium',
      title: redirectResult.suspiciousDomainChange ? 'Suspicious Cross-Domain Redirect' : 'URL Redirect Chain Detected',
      description: redirectResult.suspiciousDomainChange
        ? `The link redirects traffic across distinct administrative domains (from "${components.hostname}" to "${new URL(redirectResult.finalDestination).hostname}"). This is a common evasion technique.`
        : `The URL contains ${redirectResult.redirectChain.length} redirect hop(s) leading to a decoded destination.`,
      evidence: `Redirect hops: ${redirectResult.redirectChain.map((h) => h.hostname).join(' -> ')}`,
    });
  }

  if (redirectResult.redirectLoop) {
    indicators.push({
      id: 'ind-redirect-loop',
      category: 'redirect',
      severity: 'high',
      title: 'Redirect Loop Detected',
      description: 'The redirect sequence enters an infinite loop, preventing safe resolution of the final destination.',
      evidence: 'Infinite redirection cycle detected in chain',
    });
  }

  const fullPathLower = (components.pathname + components.search).toLowerCase();
  const credentialKeywords = [
    'login',
    'signin',
    'sign-in',
    'verify',
    'verification',
    'update-account',
    'security-check',
    'unfreeze',
    'wallet',
    'seedphrase',
    'seed-phrase',
    'recover',
    'banking',
    'portal-auth',
  ];

  const matchedKeywords = credentialKeywords.filter((k) => fullPathLower.includes(k));
  if (matchedKeywords.length > 0) {
    indicators.push({
      id: 'ind-credential-lures',
      category: 'path_or_query',
      severity: components.isFreeHostingSubdomain || components.hasIpHostname ? 'high' : 'medium',
      title: 'Credential or Account-Action Keywords in Path',
      description:
        'The URL path contains terminology strongly associated with authentication, account verification, or financial recovery.',
      evidence: `Matched terms: ${matchedKeywords.join(', ')} in "${components.pathname}"`,
    });
  }

  const executableMatch = components.pathname.match(/\.(exe|scr|bat|apk|iso|vbs|cmd|msi)$/i);
  if (executableMatch) {
    indicators.push({
      id: 'ind-executable-payload',
      category: 'path_or_query',
      severity: 'high',
      title: 'Executable File Download Payload',
      description:
        'The URL directly downloads an executable file format commonly associated with malware droppers, info-stealers, or remote access trojans (RATs).',
      evidence: `Extension: .${executableMatch[1].toLowerCase()} in path`,
    });
  }

  if (components.redactedParamsCount > 0) {
    indicators.push({
      id: 'ind-redacted-params',
      category: 'path_or_query',
      severity: 'info',
      title: 'Sensitive Access Tokens Omitted from Saved Display',
      description: `Detected ${components.redactedParamsCount} sensitive parameter(s) (e.g. auth tokens or session keys). These were sanitized in display records to protect credential privacy.`,
      evidence: `${components.redactedParamsCount} parameter(s) redacted`,
    });
  }

  return indicators;
}

export async function investigateUrl(
  rawInput: string,
  _userContext?: string
): Promise<UrlInvestigationReport> {
  const investigatedAt = new Date().toISOString();

  const validation = validateAndNormalizeUrl(rawInput);
  if (!validation.isValid || !validation.urlComponents || !validation.parsedUrl) {
    throw new Error(validation.error || 'Invalid URL provided.');
  }

  const { urlComponents, parsedUrl } = validation;

  const ssrfCheck = await screenUrlForSsrf(parsedUrl);
  if (!ssrfCheck.safe) {
    const blockedRecord: ThreatIntelRecord = {
      indicator: urlComponents.hostname,
      queriedIndicator: urlComponents.normalizedUrl,
      matchedIndicator: urlComponents.hostname,
      matchType: 'hostname',
      type: 'domain',
      provider: 'Heuristic Intelligence',
      status: 'unreachable',
      confidence: 'high',
      details: ssrfCheck.reason || 'Blocked internal destination.',
      retrievedAt: investigatedAt,
      importantNotice: 'Security Policy: Access to private, loopback, or internal networks is blocked.',
    };

    const redirectResult: RedirectAnalysisResult = {
      originalUrl: rawInput,
      decodedDestination: null,
      redirectChain: [{ hopNumber: 1, url: urlComponents.normalizedUrl, hostname: urlComponents.hostname, redirectType: 'final' }],
      finalDestination: urlComponents.normalizedUrl,
      isRedirect: false,
      suspiciousDomainChange: false,
      redirectLoop: false,
      resolvedSuccessfully: false,
      errorReason: ssrfCheck.reason,
    };

    return {
      id: `url-blocked-${Date.now()}`,
      investigatedAt,
      urlComponents,
      redirectResult,
      verdictOutcome: 'confirmed_malicious',
      overallSeverity: 'high',
      severityScore: 95,
      confidenceLevel: 'high',
      confidenceRationale: 'Destination is an internal, loopback, or private network host blocked by SSRF defense policy.',
      executiveSummary: `CRITICAL BLOCKED TARGET: The submitted URL "${urlComponents.displayUrl}" points to an internal network destination (${ssrfCheck.blockedIp || urlComponents.hostname}). Outbound investigation was halted to prevent Server-Side Request Forgery.`,
      threatIntel: [blockedRecord],
      domainIntelligence: null,
      indicators: [
        {
          id: 'ind-ssrf-blocked',
          category: 'infrastructure',
          severity: 'high',
          title: 'SSRF Firewall Block',
          description: ssrfCheck.reason || 'Destination resolves to private IP range.',
          evidence: `Host: ${urlComponents.hostname}`,
        },
      ],
      webEvidence: [],
      recommendedActions: {
        forIndividuals: [
          'Do not interact with or click this link; it attempts to direct network traffic to an internal system.',
          'Verify why an external message or communication referred you to an internal network address.',
        ],
        forOrganizations: [
          'Investigate potential SSRF attack attempts originating from external untrusted inputs.',
        ],
        forSecurityTeams: [
          'Log destination IP/hostname and inspect perimeter firewall logs for corresponding unauthorized requests.',
        ],
      },
      evidenceLimitations: [
        'Outbound telemetry was aborted because the destination violated private IP and internal network security policies.',
      ],
      modelUsed: 'AegisFlow Security Boundary Firewall',
    };
  }

  // Safe redirect investigation pipeline
  const redirectResult = await resolveUrlRedirects(rawInput);

  // Determine all targets to query in URLhaus:
  // 1. Original normalized URL / hostname
  // 2. Decoded destination URL / hostname (if present)
  // 3. Final destination URL / hostname (if different)
  const targetsToQuery = new Set<string>();
  targetsToQuery.add(urlComponents.normalizedUrl);
  targetsToQuery.add(urlComponents.hostname);

  if (redirectResult.decodedDestination) {
    try {
      const decUrl = new URL(redirectResult.decodedDestination);
      targetsToQuery.add(decUrl.toString());
      targetsToQuery.add(decUrl.hostname.toLowerCase());
    } catch {
      // ignore
    }
  }

  if (redirectResult.finalDestination && redirectResult.finalDestination !== urlComponents.normalizedUrl) {
    try {
      const finUrl = new URL(redirectResult.finalDestination);
      targetsToQuery.add(finUrl.toString());
      targetsToQuery.add(finUrl.hostname.toLowerCase());
    } catch {
      // ignore
    }
  }

  const threatIntelRecords: ThreatIntelRecord[] = [];
  const queriedIndicatorsSet = new Set<string>();

  for (const target of Array.from(targetsToQuery)) {
    if (queriedIndicatorsSet.has(target)) continue;
    queriedIndicatorsSet.add(target);

    const isDomainOnly = !target.includes('://') || !target.includes('/', target.indexOf('://') + 3);
    const queryType = isDomainOnly ? 'domain' : 'url';

    const rawIntel = await checkUrlhausThreatIntel(target, queryType);

    let matchType: ThreatIntelMatchType = 'no_match';
    if (rawIntel.status === 'malicious') {
      if (queryType === 'url') {
        matchType = target === urlComponents.normalizedUrl ? 'exact_url' : 'related';
      } else {
        matchType = target === urlComponents.hostname ? 'hostname' : 'domain';
      }
    }

    const enhancedIntel: ThreatIntelRecord = {
      ...rawIntel,
      queriedIndicator: target,
      matchedIndicator: rawIntel.status === 'malicious' ? rawIntel.indicator : 'None',
      matchType,
      providerResponseStatus: rawIntel.status === 'malicious' ? 'ok' : 'no_results',
    };

    // Avoid duplicate records for identical indicators
    if (!threatIntelRecords.some((r) => r.indicator === enhancedIntel.indicator)) {
      threatIntelRecords.push(enhancedIntel);
    }
  }

  // Domain DNS Intelligence on hostname and final destination hostname if different
  const domainIntelligence = await performDomainDnsLookup(urlComponents.hostname);
  const indicators = extractUrlIndicators(urlComponents, redirectResult);

  const serperKey = process.env.SERPER_API_KEY;
  let webEvidence: ResearchSource[] = [];
  const limitations: string[] = [];

  const targetHostnameForSearch = redirectResult.finalDestination
    ? new URL(redirectResult.finalDestination).hostname
    : urlComponents.hostname;
  const searchQuery = `"${targetHostnameForSearch}" scam phishing warning advisory`;

  if (serperKey && serperKey.trim().length > 5 && serperKey !== 'YOUR_SERPER_API_KEY') {
    const searchRes = await searchSerper(searchQuery, serperKey, 3);
    if (searchRes.sources.length > 0) {
      webEvidence = searchRes.sources.map((s) => {
        const classified = classifySourceRelevance(s, {
          candidateDomains: [targetHostnameForSearch, urlComponents.domain],
          candidateUrls: [urlComponents.normalizedUrl, redirectResult.finalDestination],
          submittedContent: urlComponents.rawUrl,
        });
        return {
          ...s,
          relevanceGrade: classified.relevanceGrade,
          relevanceExplanation: classified.relevanceExplanation,
          limitationNote: classified.limitationNote,
        };
      });
    }
    if (searchRes.rateLimited || searchRes.quotaExhausted) {
      limitations.push('Primary live search limit reached; continuing with secondary web intelligence.');
      if (isGeminiSearchFallbackEnabled() && webEvidence.length === 0) {
        const geminiRes = await searchGeminiGoogleSearch(searchQuery, 3);
        if (geminiRes.sources.length > 0) {
          webEvidence = geminiRes.sources.map((s) => {
            const classified = classifySourceRelevance(s, {
              candidateDomains: [targetHostnameForSearch, urlComponents.domain],
              candidateUrls: [urlComponents.normalizedUrl, redirectResult.finalDestination],
              submittedContent: urlComponents.rawUrl,
            });
            return {
              ...s,
              relevanceGrade: classified.relevanceGrade,
              relevanceExplanation: classified.relevanceExplanation,
              limitationNote: classified.limitationNote,
            };
          });
          limitations.push('Web reputation evidence retrieved via secondary search grounding.');
        }
      }
    }
  } else {
    let usedGrounding = false;
    if (isGeminiSearchFallbackEnabled()) {
      const geminiRes = await searchGeminiGoogleSearch(searchQuery, 3);
      if (geminiRes.sources.length > 0) {
        webEvidence = geminiRes.sources.map((s) => {
          const classified = classifySourceRelevance(s, {
            candidateDomains: [targetHostnameForSearch, urlComponents.domain],
            candidateUrls: [urlComponents.normalizedUrl, redirectResult.finalDestination],
            submittedContent: urlComponents.rawUrl,
          });
          return {
            ...s,
            relevanceGrade: classified.relevanceGrade,
            relevanceExplanation: classified.relevanceExplanation,
            limitationNote: classified.limitationNote,
          };
        });
        limitations.push('Web reputation evidence retrieved via secondary search grounding.');
        usedGrounding = true;
      }
    }

    if (!usedGrounding) {
      const fallbackSources = await searchPublicWebFallback(searchQuery, 2);
      if (fallbackSources.length > 0) {
        webEvidence = fallbackSources;
      }
      limitations.push('Utilizing open reference web index fallback for domain reputation.');
    }
  }

  if (domainIntelligence) {
    webEvidence.push({
      id: `src-dns-${targetHostnameForSearch}-${Date.now()}`,
      title: `DNS Telemetry: ${targetHostnameForSearch}`,
      url: `https://${targetHostnameForSearch}`,
      domain: targetHostnameForSearch,
      publisher: 'Authoritative Nameservers',
      snippet: `${domainIntelligence.notes} (Caveat: ${domainIntelligence.caveat})`,
      provenance: 'authoritative_dns',
      pageRetrievalStatus: 'snippet_only',
      retrievedAt: investigatedAt,
      isCached: false,
      sourceType: 'dns_telemetry',
      sourceCategory: 'security_advisory',
      reliability: 'authoritative',
      relevanceGrade: 'threat_or_dns_telemetry',
      relevanceExplanation: `Primary DNS zone routing resolution for "${targetHostnameForSearch}"`,
      limitationNote: domainIntelligence.caveat,
    });
  }

  // Attribution & Verdict Logic (Addressing Google / Wrapper Redirect Scenario)
  const isHighReputationWrapper = HIGH_REPUTATION_REDIRECT_HOSTS.has(urlComponents.hostname);
  const matchedMaliciousRecords = threatIntelRecords.filter((t) => t.status === 'malicious');
  const hasMaliciousIntel = matchedMaliciousRecords.length > 0;

  let verdictOutcome: UrlVerdictOutcome = 'no_known_threat_listing';
  let overallSeverity: 'high' | 'medium' | 'low' | 'uncertain' = 'uncertain';
  let severityScore = 45;
  let confidenceLevel: 'high' | 'moderate' | 'low' = 'moderate';
  let confidenceRationale = '';

  if (hasMaliciousIntel) {
    if (isHighReputationWrapper && !matchedMaliciousRecords.some((r) => r.queriedIndicator === urlComponents.normalizedUrl || r.queriedIndicator === urlComponents.hostname)) {
      // The wrapper itself is clean (e.g. google.com), but the destination or related redirect is malicious!
      verdictOutcome = 'potentially_compromised';
      overallSeverity = 'high';
      severityScore = 90;
      confidenceLevel = 'high';
      confidenceRationale = `High-reputation redirect wrapper ("${urlComponents.hostname}") routes to a destination cataloged as malicious in URLhaus.`;
    } else {
      verdictOutcome = 'confirmed_malicious';
      overallSeverity = 'high';
      severityScore = 96;
      confidenceLevel = 'high';
      confidenceRationale = 'Confirmed malicious indicator listed in active threat intelligence databases (URLhaus).';
    }
  } else if (redirectResult.suspiciousDomainChange || redirectResult.redirectLoop) {
    verdictOutcome = 'suspicious';
    overallSeverity = 'medium';
    severityScore = 65;
    confidenceLevel = 'moderate';
    confidenceRationale = 'Suspicious redirect behavior or cross-domain parameter redirection detected.';
  } else if (indicators.some((i) => i.severity === 'high')) {
    verdictOutcome = 'suspicious';
    overallSeverity = 'high';
    severityScore = 80;
    confidenceLevel = 'moderate';
    confidenceRationale = 'High-risk infrastructure or path indicators detected.';
  } else if (indicators.some((i) => i.severity === 'medium')) {
    verdictOutcome = 'suspicious';
    overallSeverity = 'medium';
    severityScore = 60;
    confidenceLevel = 'moderate';
    confidenceRationale = 'Elevated risk factors detected (shortened link, unencrypted transport, or shared cloud hosting).';
  } else if (domainIntelligence?.hasDnsRecords) {
    verdictOutcome = 'no_known_threat_listing';
    overallSeverity = 'low';
    severityScore = 20;
    confidenceLevel = 'moderate';
    confidenceRationale = 'Active DNS resolution with no active listings in global threat-intel feeds.';
  } else {
    verdictOutcome = 'insufficient_evidence';
    overallSeverity = 'uncertain';
    severityScore = 40;
    confidenceLevel = 'low';
    confidenceRationale = 'Insufficient telemetry to determine threat status.';
  }

  let executiveSummary = '';
  if (verdictOutcome === 'confirmed_malicious') {
    const matched = matchedMaliciousRecords[0];
    executiveSummary = `CONFIRMED MALICIOUS TARGET: The URL "${urlComponents.displayUrl}" (Matched indicator: "${matched?.matchedIndicator || urlComponents.hostname}", Match type: ${matched?.matchType || 'exact_url'}) is actively cataloged as malicious in URLhaus. Do not open this link or disclose any information.`;
  } else if (verdictOutcome === 'potentially_compromised') {
    const matched = matchedMaliciousRecords[0];
    executiveSummary = `POTENTIALLY COMPROMISED REDIRECT PATH: While the host "${urlComponents.hostname}" is a legitimate high-reputation service, investigation revealed a redirect parameter routing to "${redirectResult.decodedDestination || redirectResult.finalDestination}", which is cataloged as malicious in URLhaus (Matched indicator: "${matched?.matchedIndicator}"). Do not follow the redirect destination.`;
  } else if (verdictOutcome === 'suspicious') {
    executiveSummary = `SUSPICIOUS REDIRECT OR INFRASTRUCTURE: The link "${urlComponents.displayUrl}" exhibits suspicious characteristics such as ${
      redirectResult.suspiciousDomainChange ? 'cross-domain redirection' : 'elevated infrastructure risk'
    }. While unlisted in active malware feeds, caution is advised.`;
  } else if (verdictOutcome === 'no_known_threat_listing') {
    executiveSummary = `NO KNOWN THREAT LISTING: No active threat intelligence listings (URLhaus) were found for "${urlComponents.hostname}" or its redirect targets. Note: "No known threat listing" does NOT mean safe; newly staged phishing links frequently evade blocklists.`;
  } else {
    executiveSummary = `INSUFFICIENT EVIDENCE / UNRESOLVED: Insufficient evidence or unresolvable redirect structure for "${urlComponents.displayUrl}".`;
  }

  limitations.push('Threat intelligence feeds (URLhaus) detect known active malware and phishing campaigns; freshly deployed infrastructure often remains unlisted for 24-72 hours.');
  limitations.push('Absence of a positive threat match NEVER proves a website or link is legitimate.');
  limitations.push('DNS records verify network routing capabilities only; they do not authenticate the identity or intent of the site operator.');

  const recommendedActions: AudienceRecommendations = {
    forIndividuals: [
      verdictOutcome === 'confirmed_malicious' || verdictOutcome === 'potentially_compromised'
        ? 'Do not click or follow the redirect destination under any circumstances.'
        : 'Exercise heightened vigilance before navigating to this destination.',
      'Never input passwords, One-Time Passcodes (OTPs), PINs, or financial information on external links sent via unsolicited messages.',
      'If this link claims to be from an institution (bank, employer, courier), navigate independently by typing the official domain directly into your browser address bar.',
    ],
    forOrganizations: [
      verdictOutcome === 'confirmed_malicious' || verdictOutcome === 'potentially_compromised'
        ? `Block outbound gateway access to the malicious destination across corporate networks and VPNs.`
        : 'Monitor perimeter proxy logs for repeated outbound requests to this destination.',
      'Remind personnel to report unsolicited external messages containing unexpected verification links.',
    ],
    forSecurityTeams: [
      verdictOutcome === 'confirmed_malicious'
        ? `Submit confirmed phishing URL to threat sharing platforms (e.g., URLhaus, Google Safe Browsing, PhishTank).`
        : 'Conduct deeper sandbox or WHOIS registration analysis if this link is part of a targeted campaign.',
      `Log destination IP address(es) (${domainIntelligence?.ipAddresses.join(', ') || 'N/A'}) for threat hunting.`,
    ],
  };

  return {
    id: `url-intel-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    investigatedAt,
    urlComponents,
    redirectResult,
    verdictOutcome,
    overallSeverity,
    severityScore,
    confidenceLevel,
    confidenceRationale,
    executiveSummary: redactSecrets(executiveSummary),
    threatIntel: threatIntelRecords,
    domainIntelligence,
    indicators,
    webEvidence,
    recommendedActions,
    evidenceLimitations: limitations,
    modelUsed: 'Aegis AI URL Intelligence + Safe Redirect Pipeline + Threat Feeds',
  };
}
