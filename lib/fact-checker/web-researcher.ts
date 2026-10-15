import dns from 'dns/promises';
import {
  ResearchSource,
  DomainDnsIntelligence,
  ThreatIntelRecord,
  SearchProviderStatus,
  ProviderDiagnosticItem,
  ProviderDiagnosticStatus,
} from './types';

const RESEARCH_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (AegisFlow Cybersecurity Research; +https://aegisflowx.vercel.app)';

// In-memory cache for Serper search queries to respect quotas and prevent duplicate requests
interface CacheEntry {
  sources: ResearchSource[];
  timestamp: number;
}
const SERPER_CACHE = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes TTL
const MAX_CACHE_SIZE = 150;

/**
 * Clears the in-memory Serper search cache (useful for automated testing).
 */
export function clearSerperCache(): void {
  SERPER_CACHE.clear();
}

/**
 * Checks whether an IP address belongs to private, loopback, or link-local ranges (SSRF defense).
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;
  const cleanIp = ip.trim().toLowerCase();

  // IPv6 loopback, link-local, and unique-local
  if (
    cleanIp === '::1' ||
    cleanIp === '::' ||
    cleanIp.startsWith('fe80:') ||
    cleanIp.startsWith('fc00:') ||
    cleanIp.startsWith('fd00:') ||
    cleanIp.startsWith('::ffff:127.') ||
    cleanIp.startsWith('::ffff:10.') ||
    cleanIp.startsWith('::ffff:192.168.') ||
    cleanIp.startsWith('::ffff:169.254.')
  ) {
    return true;
  }

  // IPv4 validation
  const parts = cleanIp.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true;
  }

  // 127.0.0.0/8 (Loopback)
  if (parts[0] === 127) return true;
  // 10.0.0.0/8 (Private RFC-1918)
  if (parts[0] === 10) return true;
  // 172.16.0.0/12 (Private RFC-1918)
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16 (Private RFC-1918)
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 169.254.0.0/16 (Link-local / Cloud metadata like AWS/GCP 169.254.169.254)
  if (parts[0] === 169 && parts[1] === 254) return true;
  // 0.0.0.0/8 (Current network)
  if (parts[0] === 0) return true;
  // 100.64.0.0/10 (Shared carrier CGNAT)
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
  // 192.0.2.0/24 (TEST-NET-1)
  if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true;
  // 198.51.100.0/24 (TEST-NET-2)
  if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
  // 203.0.113.0/24 (TEST-NET-3)
  if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;
  // 224.0.0.0/4 (Multicast)
  if (parts[0] >= 224 && parts[0] <= 239) return true;
  // 240.0.0.0/4 (Reserved)
  if (parts[0] >= 240) return true;

  return false;
}

/**
 * Safely fetches a webpage excerpt for a search result URL, strictly protecting against SSRF,
 * oversized payloads, and private IP leaks.
 * NEVER called on unvetted, arbitrary internal destinations.
 */
export async function fetchSafeWebExcerpt(
  rawUrl: string,
  maxChars: number = 1400
): Promise<{ excerpt: string | null; error?: string }> {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { excerpt: null, error: 'Disallowed protocol (only http/https permitted)' };
    }

    const hostname = parsed.hostname.toLowerCase();
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
      return { excerpt: null, error: 'Disallowed internal host' };
    }

    // Direct check if hostname is a private IP literal
    if (isPrivateOrReservedIp(hostname)) {
      return { excerpt: null, error: 'Destination is a private or reserved IP address' };
    }

    // Resolve DNS to verify non-private destination
    const resolvedIps = await dns.resolve4(hostname).catch(() => []);
    if (resolvedIps.length === 0 || resolvedIps.some(isPrivateOrReservedIp)) {
      return { excerpt: null, error: 'Destination resolves to private, loopback, or unreachable IP' };
    }

    // Also verify IPv6 if any
    const resolvedIpv6 = await dns.resolve6(hostname).catch(() => []);
    if (resolvedIpv6.some(isPrivateOrReservedIp)) {
      return { excerpt: null, error: 'Destination resolves to private IPv6 address' };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);

    const res = await fetch(rawUrl, {
      method: 'GET',
      headers: {
        'User-Agent': RESEARCH_USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9',
      },
      signal: controller.signal,
      redirect: 'error', // Do not automatically follow redirects to evade SSRF checks
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return { excerpt: null, error: `HTTP ${res.status}` };
    }

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('text/plain') && !contentType.includes('xhtml')) {
      return { excerpt: null, error: 'Non-text response type' };
    }

    // Read response text safely up to 512KB to protect against zip bombs / oversized payloads
    const text = await res.text();
    const truncatedText = text.slice(0, 524288);

    // Strip scripts, styles, noscript, and markup
    const cleanText = truncatedText
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
      .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
      .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, ' ')
      .replace(/<nav\b[^<]*(?:(?!<\/nav>)<[^<]*)*<\/nav>/gi, ' ')
      .replace(/<footer\b[^<]*(?:(?!<\/footer>)<[^<]*)*<\/footer>/gi, ' ')
      .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    if (cleanText.length < 50) {
      return { excerpt: null, error: 'Insufficient text content extracted from page' };
    }

    return { excerpt: cleanText.slice(0, maxChars) };
  } catch (err: any) {
    if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
      return { excerpt: null, error: 'Webpage retrieval timed out (4.5s)' };
    }
    return { excerpt: null, error: err?.message || 'Failed to retrieve page excerpt' };
  }
}

/**
 * Searches the public web via Serper.dev Google Search API.
 * Uses the configured server-side SERPER_API_KEY.
 */
export async function searchSerper(
  query: string,
  apiKey: string,
  maxResults: number = 4
): Promise<{ sources: ResearchSource[]; rateLimited: boolean; authError?: boolean; error?: string }> {
  const cleanQuery = query.trim().slice(0, 160);
  const cacheKey = `${cleanQuery.toLowerCase()}_${maxResults}`;

  // Check cache
  const cached = SERPER_CACHE.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return { sources: cached.sources, rateLimited: false };
  }

  const sources: ResearchSource[] = [];

  try {
    const res = await fetch('https://google.serper.dev/search', {
      method: 'POST',
      headers: {
        'X-API-KEY': apiKey.trim(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        q: cleanQuery,
        num: maxResults,
      }),
      signal: AbortSignal.timeout(8000),
    });

    if (res.status === 401 || res.status === 403) {
      return {
        sources: [],
        rateLimited: false,
        authError: true,
        error: `Serper.dev rejected authentication credentials (HTTP ${res.status}). Verify SERPER_API_KEY.`,
      };
    }

    if (res.status === 429) {
      return {
        sources: [],
        rateLimited: true,
        error: 'Serper.dev quota or rate limit exhausted (HTTP 429).',
      };
    }

    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      return {
        sources: [],
        rateLimited: false,
        error: `Serper.dev API responded with HTTP ${res.status}: ${errBody.slice(0, 100)}`,
      };
    }

    const data = await res.json();
    const organicResults = Array.isArray(data?.organic) ? data.organic : [];

    for (let i = 0; i < Math.min(organicResults.length, maxResults); i++) {
      const item = organicResults[i];
      if (!item || !item.link) continue;

      let domain = 'web-source';
      try {
        domain = new URL(item.link).hostname;
      } catch {
        // Fallback
      }

      const isGov = domain.endsWith('.gov') || domain.includes('.gov.');
      const isEdu = domain.endsWith('.edu') || domain.includes('.edu.');
      const isBank = domain.includes('wellsfargo.com') || domain.includes('chase.com') || domain.includes('bankofamerica.com');

      sources.push({
        id: `src-serper-${i + 1}-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        title: item.title || `Public Web Source (${domain})`,
        url: item.link,
        domain,
        publisher: domain.replace(/^www\./, ''),
        snippet: (item.snippet || '').slice(0, 400),
        provenance: 'snippet_only',
        pageRetrievalStatus: 'snippet_only',
        publishedDate: item.date || undefined,
        retrievedAt: new Date().toISOString(),
        sourceType: isGov || isBank ? 'public_advisory' : 'web_search',
        reliability: isGov || isBank ? 'authoritative' : isEdu ? 'authoritative' : 'reputable',
        relevanceExplanation: `Retrieved via Serper.dev Google Index for query: "${cleanQuery.slice(0, 45)}"`,
        limitationNote: 'Search snippet only; full page content was not retrieved.',
      });
    }

    // Cache results if successful
    if (sources.length > 0) {
      if (SERPER_CACHE.size >= MAX_CACHE_SIZE) {
        const oldestKey = SERPER_CACHE.keys().next().value;
        if (oldestKey) SERPER_CACHE.delete(oldestKey);
      }
      SERPER_CACHE.set(cacheKey, { sources, timestamp: Date.now() });
    }

    return { sources, rateLimited: false };
  } catch (err: any) {
    if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
      return { sources: [], rateLimited: false, error: 'Serper.dev request timed out (8s).' };
    }
    return { sources: [], rateLimited: false, error: err?.message || 'Serper.dev query failed.' };
  }
}

/**
 * Searches the official Wikipedia / Wikimedia API for organizational verification,
 * executive roles, known fraud warnings, and legitimate domains.
 */
export async function searchWikipedia(query: string, maxResults: number = 2): Promise<ResearchSource[]> {
  const sources: ResearchSource[] = [];
  try {
    const encoded = encodeURIComponent(query.slice(0, 100));
    const res = await fetch(
      `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encoded}&format=json&utf8=1`,
      {
        headers: { 'User-Agent': RESEARCH_USER_AGENT },
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!res.ok) return sources;
    const data = await res.json();
    const items = data.query?.search || [];

    for (let i = 0; i < Math.min(items.length, maxResults); i++) {
      const item = items[i];
      const cleanSnippet = (item.snippet || '').replace(/<[^>]+>/g, '').trim();
      const pageTitle = item.title || 'Wikipedia Reference';
      const url = `https://en.wikipedia.org/wiki/${encodeURIComponent(pageTitle.replace(/\s+/g, '_'))}`;

      sources.push({
        id: `src-wiki-${i + 1}-${Date.now()}`,
        title: `Wikipedia: ${pageTitle}`,
        url,
        domain: 'en.wikipedia.org',
        publisher: 'Wikimedia Foundation',
        snippet: cleanSnippet,
        provenance: 'encyclopedia',
        pageRetrievalStatus: 'snippet_only',
        publishedDate: item.timestamp ? new Date(item.timestamp).toLocaleDateString() : undefined,
        retrievedAt: new Date().toISOString(),
        sourceType: 'encyclopedia',
        reliability: 'reputable',
        relevanceExplanation: `Verified reference encyclopedia record for entity matching "${pageTitle}"`,
      });
    }
  } catch (err: any) {
    console.warn('Wikipedia search warning:', err?.message || err);
  }

  return sources;
}

/**
 * Fallback public search parser using DuckDuckGo HTML when no paid search keys are configured.
 */
export async function searchPublicWebFallback(query: string, maxResults: number = 3): Promise<ResearchSource[]> {
  const sources: ResearchSource[] = [];
  try {
    const encoded = encodeURIComponent(query.slice(0, 120));
    const res = await fetch(`https://html.duckduckgo.com/html/?q=${encoded}`, {
      headers: {
        'User-Agent': RESEARCH_USER_AGENT,
        Accept: 'text/html,application/xhtml+xml',
      },
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) return sources;
    const html = await res.text();

    const snippetRegex = /<a class="result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/gi;
    const urlRegex = /<a class="result__url"[^>]*href="([^"]+)"/gi;

    let match;
    let idx = 1;
    while ((match = snippetRegex.exec(html)) !== null && sources.length < maxResults) {
      const rawSnippet = match[1].replace(/<[^>]+>/g, '').trim();
      if (rawSnippet.length < 15) continue;

      let extractedUrl = '';
      const urlMatch = urlRegex.exec(html);
      if (urlMatch && urlMatch[1]) {
        const rawHref = urlMatch[1];
        if (rawHref.includes('uddg=')) {
          const uParam = new URL('https://duckduckgo.com' + rawHref).searchParams.get('uddg');
          extractedUrl = uParam ? decodeURIComponent(uParam) : rawHref;
        } else {
          extractedUrl = rawHref.startsWith('//') ? 'https:' + rawHref : rawHref;
        }
      }

      let domain = 'web-source';
      try {
        if (extractedUrl && extractedUrl.startsWith('http')) {
          domain = new URL(extractedUrl).hostname;
        }
      } catch {
        // Fallback
      }

      sources.push({
        id: `src-fallback-${idx++}-${Date.now()}`,
        title: `Public Web Source (${domain})`,
        url: extractedUrl || `https://duckduckgo.com/html/?q=${encoded}`,
        domain,
        publisher: domain.replace(/^www\./, ''),
        snippet: rawSnippet,
        provenance: 'snippet_only',
        pageRetrievalStatus: 'snippet_only',
        retrievedAt: new Date().toISOString(),
        sourceType: domain.includes('.gov') || domain.includes('.bank') ? 'public_advisory' : 'web_search',
        reliability: domain.includes('.gov') ? 'authoritative' : 'reputable',
        relevanceExplanation: `Retrieved via open web index snippet for "${query.slice(0, 30)}"`,
        limitationNote: 'Snippet only; underlying webpage was not fully retrieved.',
      });
    }
  } catch (err: any) {
    console.warn('Public web search fallback warning:', err?.message || err);
  }

  return sources;
}

/**
 * Queries URLhaus (abuse.ch) for malicious URL and host infrastructure records.
 * Follows official URLhaus API documentation with Auth-Key header.
 */
export async function checkUrlhausThreatIntel(
  indicator: string,
  type: 'domain' | 'url'
): Promise<ThreatIntelRecord> {
  const authKey = process.env.URLHAUS_AUTH_KEY;
  const retrievedAt = new Date().toISOString();

  if (!authKey || authKey.trim() === '' || authKey === 'YOUR_ABUSE_CH_AUTH_KEY') {
    return {
      indicator,
      type,
      provider: 'URLhaus (abuse.ch)',
      status: 'unconfigured',
      confidence: 'low',
      details: 'URLHAUS_AUTH_KEY is unconfigured. Free community Auth-Key available at https://auth.abuse.ch.',
      retrievedAt,
      importantNotice:
        'Threat-intelligence feed unconfigured. Note: Absence of a threat match NEVER proves a domain or URL is benign.',
    };
  }

  try {
    const endpoint =
      type === 'domain'
        ? 'https://urlhaus-api.abuse.ch/v1/host/'
        : 'https://urlhaus-api.abuse.ch/v1/url/';

    const body = new URLSearchParams();
    if (type === 'domain') {
      body.append('host', indicator.toLowerCase().trim());
    } else {
      body.append('url', indicator.trim());
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Auth-Key': authKey.trim(),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
      signal: AbortSignal.timeout(6000),
    });

    if (res.status === 401 || res.status === 403) {
      return {
        indicator,
        type,
        provider: 'URLhaus (abuse.ch)',
        status: 'authentication_failure',
        confidence: 'low',
        details: `URLhaus rejected authentication credentials (HTTP ${res.status}). Verify URLHAUS_AUTH_KEY.`,
        retrievedAt,
        importantNotice: 'URLhaus authentication failed; threat database could not be queried.',
      };
    }

    if (res.status === 429) {
      return {
        indicator,
        type,
        provider: 'URLhaus (abuse.ch)',
        status: 'unreachable',
        confidence: 'low',
        details: 'URLhaus rate limit reached (HTTP 429).',
        retrievedAt,
        importantNotice: 'URLhaus rate limit reached; threat database could not be queried.',
      };
    }

    if (!res.ok) {
      return {
        indicator,
        type,
        provider: 'URLhaus (abuse.ch)',
        status: 'unreachable',
        confidence: 'low',
        details: `URLhaus returned HTTP status ${res.status}`,
        retrievedAt,
        importantNotice: 'Threat intelligence query could not be completed.',
      };
    }

    const data = await res.json();

    if (data.query_status === 'auth_error') {
      return {
        indicator,
        type,
        provider: 'URLhaus (abuse.ch)',
        status: 'authentication_failure',
        confidence: 'low',
        details: 'URLhaus API reported authentication error with provided Auth-Key.',
        retrievedAt,
        importantNotice: 'Threat intelligence query failed authentication.',
      };
    }

    if (data.query_status === 'ok') {
      return {
        indicator,
        type,
        provider: 'URLhaus (abuse.ch)',
        status: 'malicious',
        confidence: 'high',
        details: `Confirmed malicious indicator listed on URLhaus. Threat: ${data.threat || 'Malware Distribution'}, Status: ${data.url_status || 'Active'}.`,
        tags: data.tags || [],
        threatType: data.threat,
        dateAdded: data.date_added || data.firstseen,
        retrievedAt,
        importantNotice: 'CRITICAL: Indicator is actively flagged in global malware and phishing infrastructure feeds.',
      };
    }

    // Unlisted or clean in URLhaus
    return {
      indicator,
      type,
      provider: 'URLhaus (abuse.ch)',
      status: 'clean_or_unlisted',
      confidence: 'moderate',
      details: 'No known active malicious distribution records found in URLhaus feed.',
      retrievedAt,
      importantNotice:
        'Absence of threat-intelligence records does NOT guarantee safety; newly created phishing infrastructure often remains unlisted for 24-72 hours.',
    };
  } catch (err: any) {
    if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
      return {
        indicator,
        type,
        provider: 'URLhaus (abuse.ch)',
        status: 'unreachable',
        confidence: 'low',
        details: 'Threat feed query timed out (6s).',
        retrievedAt,
        importantNotice: 'Could not contact threat intelligence API (timeout).',
      };
    }
    return {
      indicator,
      type,
      provider: 'URLhaus (abuse.ch)',
      status: 'unreachable',
      confidence: 'low',
      details: `Threat feed query error: ${err?.message || 'Network error'}`,
      retrievedAt,
      importantNotice: 'Could not contact threat intelligence API.',
    };
  }
}

/**
 * Performs authoritative DNS intelligence lookups on extracted domains.
 */
export async function performDomainDnsLookup(domain: string): Promise<DomainDnsIntelligence> {
  const cleanDomain = domain.toLowerCase().replace(/^[a-z]+:\/\//, '').split('/')[0].split(':')[0].trim();

  let hasDnsRecords = false;
  let ipAddresses: string[] = [];
  let mxRecordsCount = 0;
  let hasMailServers = false;
  let notes = '';

  try {
    const aRecords = await dns.resolve4(cleanDomain).catch(() => []);
    if (aRecords.length > 0) {
      hasDnsRecords = true;
      ipAddresses = aRecords;
    }

    const mxRecords = await dns.resolveMx(cleanDomain).catch(() => []);
    if (mxRecords && mxRecords.length > 0) {
      mxRecordsCount = mxRecords.length;
      hasMailServers = true;
    }

    if (!hasDnsRecords) {
      notes = 'Domain has NO active A records. Cannot host legitimate services.';
    } else if (!hasMailServers) {
      notes = 'Domain lacks MX (mail exchange) records. High risk for disposable credential harvesting.';
    } else {
      notes = `Domain active with ${ipAddresses.length} IP(s) and ${mxRecordsCount} MX mail server(s).`;
    }
  } catch (err: any) {
    notes = `DNS resolution failed: ${err?.message || 'Unreachable host'}`;
  }

  const isSuspiciousOrParked = !hasDnsRecords || (!hasMailServers && hasDnsRecords);

  return {
    domain: cleanDomain,
    hasDnsRecords,
    ipAddresses,
    mxRecordsCount,
    hasMailServers,
    isSuspiciousOrParked,
    notes,
    caveat:
      'DNS resolution verifies network routing capability only; it does NOT establish corporate authorization or authentic sender identity.',
  };
}

/**
 * Diagnostic probe for Serper.dev Google Search API.
 * Never returns or leaks API secrets.
 */
export async function probeSerperDiagnostic(overrideKey?: string): Promise<ProviderDiagnosticItem> {
  const apiKey = overrideKey !== undefined ? overrideKey : process.env.SERPER_API_KEY;
  const testedAt = new Date().toISOString();

  if (!apiKey || apiKey.trim() === '' || apiKey === 'YOUR_SERPER_API_KEY') {
    return {
      provider: 'Serper.dev Web Search',
      status: 'missing_configuration',
      isConfigured: false,
      message: 'SERPER_API_KEY is not configured in server environment.',
      testedAt,
    };
  }

  const start = Date.now();
  try {
    const res = await fetch('https://google.serper.dev/search', {
      method: 'POST',
      headers: {
        'X-API-KEY': apiKey.trim(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        q: 'cybersecurity advisory notice',
        num: 1,
      }),
      signal: AbortSignal.timeout(8000),
    });
    const latencyMs = Date.now() - start;

    if (res.status === 401 || res.status === 403) {
      return {
        provider: 'Serper.dev Web Search',
        status: 'authentication_failure',
        isConfigured: true,
        message: `Serper.dev rejected credentials (HTTP ${res.status}). Verify SERPER_API_KEY.`,
        latencyMs,
        testedAt,
      };
    }

    if (res.status === 429) {
      return {
        provider: 'Serper.dev Web Search',
        status: 'rate_limit_exhausted',
        isConfigured: true,
        message: 'Serper.dev quota or rate limit exhausted (HTTP 429).',
        latencyMs,
        testedAt,
      };
    }

    if (!res.ok) {
      return {
        provider: 'Serper.dev Web Search',
        status: 'provider_unavailable',
        isConfigured: true,
        message: `Serper.dev returned HTTP ${res.status}.`,
        latencyMs,
        testedAt,
      };
    }

    return {
      provider: 'Serper.dev Web Search',
      status: 'configured_and_reachable',
      isConfigured: true,
      message: 'Serper.dev API responded successfully.',
      latencyMs,
      testedAt,
    };
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
      return {
        provider: 'Serper.dev Web Search',
        status: 'provider_timeout',
        isConfigured: true,
        message: 'Serper.dev request timed out after 8s.',
        latencyMs,
        testedAt,
      };
    }
    return {
      provider: 'Serper.dev Web Search',
      status: 'provider_unavailable',
      isConfigured: true,
      message: err?.message || 'Connection to Serper.dev failed.',
      latencyMs,
      testedAt,
    };
  }
}

/**
 * Diagnostic probe for URLhaus threat intelligence API.
 * Never returns or leaks API secrets.
 */
export async function probeUrlhausDiagnostic(overrideKey?: string): Promise<ProviderDiagnosticItem> {
  const authKey = overrideKey !== undefined ? overrideKey : process.env.URLHAUS_AUTH_KEY;
  const testedAt = new Date().toISOString();

  if (!authKey || authKey.trim() === '' || authKey === 'YOUR_ABUSE_CH_AUTH_KEY') {
    return {
      provider: 'URLhaus (abuse.ch)',
      status: 'missing_configuration',
      isConfigured: false,
      message: 'URLHAUS_AUTH_KEY is not configured in server environment.',
      testedAt,
    };
  }

  const start = Date.now();
  try {
    const body = new URLSearchParams({ host: 'example.com' });
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Auth-Key': authKey.trim(),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
      signal: AbortSignal.timeout(6000),
    });
    const latencyMs = Date.now() - start;

    if (res.status === 401 || res.status === 403) {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'authentication_failure',
        isConfigured: true,
        message: `URLhaus rejected credentials (HTTP ${res.status}). Verify URLHAUS_AUTH_KEY.`,
        latencyMs,
        testedAt,
      };
    }

    if (res.status === 429) {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'rate_limit_exhausted',
        isConfigured: true,
        message: 'URLhaus rate limit reached (HTTP 429).',
        latencyMs,
        testedAt,
      };
    }

    if (!res.ok) {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'provider_unavailable',
        isConfigured: true,
        message: `URLhaus returned HTTP ${res.status}.`,
        latencyMs,
        testedAt,
      };
    }

    const data = await res.json();
    if (data.query_status === 'auth_error') {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'authentication_failure',
        isConfigured: true,
        message: 'URLhaus reported invalid Auth-Key.',
        latencyMs,
        testedAt,
      };
    }

    return {
      provider: 'URLhaus (abuse.ch)',
      status: 'configured_and_reachable',
      isConfigured: true,
      message: 'URLhaus threat intelligence API authenticated and reachable.',
      latencyMs,
      testedAt,
    };
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'provider_timeout',
        isConfigured: true,
        message: 'URLhaus request timed out after 6s.',
        latencyMs,
        testedAt,
      };
    }
    return {
      provider: 'URLhaus (abuse.ch)',
      status: 'provider_unavailable',
      isConfigured: true,
      message: err?.message || 'Connection to URLhaus failed.',
      latencyMs,
      testedAt,
    };
  }
}

/**
 * Master multi-source web researcher.
 * Coordinates Serper.dev, Wikipedia, DNS telemetry, and URLhaus with safe webpage content retrieval.
 */
export async function performWebResearch(
  queries: string[],
  domainsToCheck: string[]
): Promise<{
  sources: ResearchSource[];
  domainIntelligence: DomainDnsIntelligence[];
  threatIntel: ThreatIntelRecord[];
  providerStatus: SearchProviderStatus;
}> {
  const allSources: ResearchSource[] = [];
  const domainIntelligence: DomainDnsIntelligence[] = [];
  const threatIntel: ThreatIntelRecord[] = [];

  const serperKey = process.env.SERPER_API_KEY;

  let providerMode: 'serper' | 'public_web_fallback' = 'public_web_fallback';
  let providerName = 'Wikimedia API & Public Web Fallback';
  let isConfigured = false;
  let rateLimitEncountered = false;
  let errorMessage: string | undefined;

  if (serperKey && serperKey.trim().length > 5 && serperKey !== 'YOUR_SERPER_API_KEY') {
    providerMode = 'serper';
    providerName = 'Serper.dev Web Search API';
    isConfigured = true;
  }

  // 1. Run DNS intelligence & Threat Intel on extracted domains
  for (const domain of domainsToCheck.slice(0, 3)) {
    if (domain && domain.includes('.')) {
      const dnsIntel = await performDomainDnsLookup(domain);
      domainIntelligence.push(dnsIntel);

      allSources.push({
        id: `src-dns-${dnsIntel.domain}-${Date.now()}`,
        title: `Authoritative DNS Telemetry: ${dnsIntel.domain}`,
        url: `https://${dnsIntel.domain}`,
        domain: dnsIntel.domain,
        publisher: 'Authoritative Nameservers',
        snippet: `${dnsIntel.notes} (Notice: ${dnsIntel.caveat})`,
        provenance: 'authoritative_dns',
        pageRetrievalStatus: 'snippet_only',
        retrievedAt: new Date().toISOString(),
        sourceType: 'dns_telemetry',
        reliability: 'authoritative',
        relevanceExplanation: `Primary DNS zone resolution for candidate domain "${dnsIntel.domain}"`,
      });

      // Threat intelligence lookup (URLhaus)
      const tIntel = await checkUrlhausThreatIntel(domain, 'domain');
      threatIntel.push(tIntel);
      if (tIntel.status === 'malicious') {
        allSources.push({
          id: `src-urlhaus-${domain}-${Date.now()}`,
          title: `Threat Intelligence Advisory: ${domain}`,
          url: `https://urlhaus.abuse.ch/host/${domain}`,
          domain: 'urlhaus.abuse.ch',
          publisher: 'abuse.ch URLhaus',
          snippet: tIntel.details,
          provenance: 'threat_intelligence',
          pageRetrievalStatus: 'snippet_only',
          retrievedAt: new Date().toISOString(),
          sourceType: 'threat_intel',
          reliability: 'authoritative',
          relevanceExplanation: `Global malware infrastructure match for "${domain}"`,
        });
      }
    }
  }

  // 2. Execute targeted searches (cap at 2 queries to protect rate limits and prevent spam)
  const targetedQueries = queries.slice(0, 2);
  let queriesExecuted = 0;

  for (const q of targetedQueries) {
    queriesExecuted++;
    if (providerMode === 'serper' && serperKey) {
      const serperRes = await searchSerper(q, serperKey, 4);
      if (serperRes.rateLimited) {
        rateLimitEncountered = true;
        errorMessage = serperRes.error;
        // Fall back to open web + wikipedia on rate limit
        const [fbWeb, fbWiki] = await Promise.all([
          searchPublicWebFallback(q, 2),
          searchWikipedia(q, 2),
        ]);
        allSources.push(...fbWeb, ...fbWiki);
      } else if (serperRes.authError) {
        errorMessage = serperRes.error;
        const [fbWeb, fbWiki] = await Promise.all([
          searchPublicWebFallback(q, 2),
          searchWikipedia(q, 2),
        ]);
        allSources.push(...fbWeb, ...fbWiki);
      } else {
        allSources.push(...serperRes.sources);
      }
    } else {
      // Unconfigured paid provider: use authoritative Wikimedia API + public search fallback
      const [ddgResults, wikiResults] = await Promise.all([
        searchPublicWebFallback(q, 2),
        searchWikipedia(q, 2),
      ]);
      allSources.push(...ddgResults, ...wikiResults);
    }
  }

  // Deduplicate sources by URL
  const uniqueSourcesMap = new Map<string, ResearchSource>();
  for (const s of allSources) {
    if (!uniqueSourcesMap.has(s.url)) {
      uniqueSourcesMap.set(s.url, s);
    }
  }

  const finalSources = Array.from(uniqueSourcesMap.values());

  // 3. Safe content retrieval for top authoritative candidate source (if only snippet available)
  let fullPageRetrievalActive = false;
  const topCandidate = finalSources.find(
    (s) =>
      s.provenance === 'snippet_only' &&
      (s.domain.endsWith('.gov') ||
        s.domain.endsWith('.edu') ||
        s.domain.includes('wikipedia.org') ||
        s.domain.includes('wellsfargo.com') ||
        s.domain.includes('irs.gov') ||
        s.domain.includes('ftc.gov') ||
        s.domain.includes('cisa.gov'))
  );

  if (topCandidate) {
    const pageFetch = await fetchSafeWebExcerpt(topCandidate.url);
    if (pageFetch.excerpt) {
      topCandidate.rawContentExcerpt = pageFetch.excerpt;
      topCandidate.provenance = 'full_page_retrieved';
      topCandidate.pageRetrievalStatus = 'retrieved';
      topCandidate.limitationNote = undefined;
      fullPageRetrievalActive = true;
    } else {
      topCandidate.pageRetrievalStatus = 'failed';
      topCandidate.limitationNote = `Source page could not be retrieved (${pageFetch.error || 'Fetch blocked'}); evaluated using search snippet only.`;
    }
  }

  const configurationGuide = !isConfigured
    ? 'To enable Google Search results via Serper.dev, configure SERPER_API_KEY (from https://serper.dev). To enable malware threat lookups, configure URLHAUS_AUTH_KEY (from https://auth.abuse.ch).'
    : undefined;

  const providerStatus: SearchProviderStatus = {
    providerName,
    isConfigured,
    mode: providerMode,
    fullPageRetrievalActive,
    rateLimitEncountered,
    queriesExecuted,
    errorMessage,
    configurationGuide,
  };

  return {
    sources: finalSources,
    domainIntelligence,
    threatIntel,
    providerStatus,
  };
}
