import dns from 'dns/promises';
import {
  UrlComponents,
  UrlIndicatorItem,
  UrlInvestigationReport,
} from './types';
import {
  isPrivateOrReservedIp,
  checkUrlhausThreatIntel,
  performDomainDnsLookup,
  searchSerper,
  searchPublicWebFallback,
  classifySourceRelevance,
} from '@/lib/fact-checker/web-researcher';
import { resolveFeatherlessModel, redactSecrets } from '@/lib/model-config';
import {
  ResearchSource,
  ThreatIntelRecord,
  AudienceRecommendations,
} from '@/lib/fact-checker/types';

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'auth',
  'access_token',
  'key',
  'apikey',
  'api_key',
  'password',
  'pass',
  'code',
  'session',
  'session_id',
  'sessionid',
  'sig',
  'signature',
  'secret',
  'refresh_token',
  'id_token',
  'jwt',
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
  const hostname = parsedUrl.hostname.toLowerCase();

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

export function extractUrlIndicators(components: UrlComponents): UrlIndicatorItem[] {
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
  userContext?: string
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
      type: 'domain',
      provider: 'Heuristic Intelligence',
      status: 'unreachable',
      confidence: 'high',
      details: ssrfCheck.reason || 'Blocked internal destination.',
      retrievedAt: investigatedAt,
      importantNotice: 'Security Policy: Access to private, loopback, or internal networks is blocked.',
    };

    return {
      id: `url-blocked-${Date.now()}`,
      investigatedAt,
      urlComponents,
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

  const threatIntelRecords: ThreatIntelRecord[] = [];
  const [urlThreatIntel, domainThreatIntel] = await Promise.all([
    checkUrlhausThreatIntel(urlComponents.normalizedUrl, 'url'),
    checkUrlhausThreatIntel(urlComponents.hostname, 'domain'),
  ]);

  if (urlThreatIntel) threatIntelRecords.push(urlThreatIntel);
  if (domainThreatIntel && domainThreatIntel.indicator !== urlThreatIntel.indicator) {
    threatIntelRecords.push(domainThreatIntel);
  }

  const domainIntelligence = await performDomainDnsLookup(urlComponents.hostname);

  const indicators = extractUrlIndicators(urlComponents);

  const serperKey = process.env.SERPER_API_KEY;
  let webEvidence: ResearchSource[] = [];
  const limitations: string[] = [];

  const searchQuery = `"${urlComponents.hostname}" scam phishing warning advisory`;
  if (serperKey && serperKey.trim().length > 5 && serperKey !== 'YOUR_SERPER_API_KEY') {
    const searchRes = await searchSerper(searchQuery, serperKey, 3);
    if (searchRes.sources.length > 0) {
      webEvidence = searchRes.sources.map((s) => {
        const classified = classifySourceRelevance(s, {
          candidateDomains: [urlComponents.hostname, urlComponents.domain],
          candidateUrls: [urlComponents.normalizedUrl],
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
      limitations.push('Serper.dev search request limit reached; web reputation evidence was constrained.');
    }
  } else {
    const fallbackSources = await searchPublicWebFallback(searchQuery, 2);
    if (fallbackSources.length > 0) {
      webEvidence = fallbackSources;
    }
    limitations.push('Serper.dev API key unconfigured; utilizing open reference web index fallback.');
  }

  if (domainIntelligence) {
    webEvidence.push({
      id: `src-dns-${urlComponents.hostname}-${Date.now()}`,
      title: `DNS Telemetry: ${urlComponents.hostname}`,
      url: `https://${urlComponents.hostname}`,
      domain: urlComponents.hostname,
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
      relevanceExplanation: `Primary DNS zone routing resolution for "${urlComponents.hostname}"`,
      limitationNote: domainIntelligence.caveat,
    });
  }

  const hasMaliciousIntel = threatIntelRecords.some((t) => t.status === 'malicious');
  const hasCredentialLure = indicators.some((i) => i.id === 'ind-credential-lures' && i.severity === 'high');
  const hasExecutable = indicators.some((i) => i.id === 'ind-executable-payload');
  const hasDirectIp = urlComponents.hasIpHostname;
  const isFreePlatform = urlComponents.isFreeHostingSubdomain;
  const isHttpOnly = urlComponents.protocol === 'http:';

  let overallSeverity: 'high' | 'medium' | 'low' | 'uncertain' = 'uncertain';
  let severityScore = 45;
  let confidenceLevel: 'high' | 'moderate' | 'low' = 'moderate';
  let confidenceRationale = '';

  if (hasMaliciousIntel) {
    overallSeverity = 'high';
    severityScore = 96;
    confidenceLevel = 'high';
    confidenceRationale = 'Confirmed malicious indicator listed in active threat intelligence databases (URLhaus).';
  } else if (hasExecutable) {
    overallSeverity = 'high';
    severityScore = 90;
    confidenceLevel = 'high';
    confidenceRationale = 'Direct download link pointing to executable binary or archive payload.';
  } else if (hasDirectIp && (hasCredentialLure || isHttpOnly)) {
    overallSeverity = 'high';
    severityScore = 85;
    confidenceLevel = 'high';
    confidenceRationale = 'Direct IP hostname serving authentication or unencrypted transport endpoints.';
  } else if (isFreePlatform && hasCredentialLure) {
    overallSeverity = 'high';
    severityScore = 80;
    confidenceLevel = 'moderate';
    confidenceRationale = 'Free web-hosting platform subdomain hosting credential-harvesting or banking action path.';
  } else if (isFreePlatform || urlComponents.isShortenedUrl || hasCredentialLure || isHttpOnly) {
    overallSeverity = 'medium';
    severityScore = 60;
    confidenceLevel = 'moderate';
    confidenceRationale = 'Elevated risk factors detected (shortened link, unencrypted transport, or shared cloud hosting).';
  } else if (domainIntelligence?.hasDnsRecords && !hasMaliciousIntel) {
    overallSeverity = 'low';
    severityScore = 20;
    confidenceLevel = 'moderate';
    confidenceRationale = 'Active DNS resolution with no active listings in global threat-intel feeds.';
  }

  let executiveSummary = '';
  if (hasMaliciousIntel) {
    executiveSummary = `CRITICAL THREAT IDENTIFIED: The URL "${urlComponents.displayUrl}" is actively cataloged as malicious in global threat intelligence feeds (URLhaus). This indicator is associated with active phishing, credential interception, or malware delivery infrastructure. Do not open this link or disclose any information.`;
  } else if (overallSeverity === 'high') {
    executiveSummary = `HIGH RISK ADVISORY: Significant deceptive or infrastructure risk factors were identified for "${urlComponents.displayUrl}". The presence of ${
      hasDirectIp ? 'a raw IP address host' : isFreePlatform ? 'a disposable free hosting subdomain' : 'suspicious executable paths'
    } strongly matches common social engineering and credential-theft tactics. Independent verification is strongly advised.`;
  } else if (overallSeverity === 'medium') {
    executiveSummary = `SUSPICIOUS PATTERNS DETECTED: The link "${urlComponents.displayUrl}" exhibits moderate risk characteristics. While not currently flagged in active threat intelligence feeds, features such as ${
      urlComponents.isShortenedUrl
        ? 'URL shortening'
        : isFreePlatform
        ? 'third-party shared platform hosting'
        : 'unencrypted HTTP transport'
    } warrant caution. Avoid entering sensitive passwords or OTPs.`;
  } else {
    executiveSummary = `INCONCLUSIVE / NO THREAT RECORD: No known malicious distribution records were found for "${urlComponents.hostname}" in queried threat intelligence feeds (URLhaus), and authoritative DNS routing is active. However, an absence of records does NOT guarantee safety; newly staged phishing campaigns frequently evade blocklists during initial hours.`;
  }

  limitations.push('Threat intelligence feeds (URLhaus) detect known active malware and phishing campaigns; freshly deployed infrastructure often remains unlisted for 24-72 hours.');
  limitations.push('Absence of a positive threat match NEVER proves a website or link is legitimate.');
  limitations.push('DNS records verify network routing capabilities only; they do not authenticate the identity or intent of the site operator.');

  const recommendedActions: AudienceRecommendations = {
    forIndividuals: [
      overallSeverity === 'high'
        ? 'Do not open this URL or visit the destination website under any circumstances.'
        : 'Exercise heightened vigilance before navigating to this destination.',
      'Never input passwords, One-Time Passcodes (OTPs), PINs, or financial information on external links sent via unsolicited messages.',
      'If this link claims to be from an institution (bank, employer, courier), navigate independently by typing the official domain directly into your browser address bar.',
    ],
    forOrganizations: [
      overallSeverity === 'high'
        ? `Block outbound web gateway access to domain "${urlComponents.hostname}" across corporate networks and VPNs.`
        : 'Monitor perimeter proxy logs for repeated outbound requests to this destination.',
      'Remind personnel to report unsolicited external messages containing unexpected verification links.',
    ],
    forSecurityTeams: [
      overallSeverity === 'high'
        ? `Submit confirmed phishing URL to threat sharing platforms (e.g., URLhaus, Google Safe Browsing, PhishTank).`
        : 'Conduct deeper sandbox or WHOIS registration analysis if this link is part of a targeted campaign.',
      `Log destination IP address(es) (${domainIntelligence?.ipAddresses.join(', ') || 'N/A'}) for threat hunting.`,
    ],
  };

  const { model } = resolveFeatherlessModel();

  return {
    id: `url-intel-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    investigatedAt,
    urlComponents,
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
    modelUsed: `${model} + URLhaus + Authoritative DNS`,
  };
}
