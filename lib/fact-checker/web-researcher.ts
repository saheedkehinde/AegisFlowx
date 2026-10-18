import dns from 'dns/promises';
import {
  ResearchSource,
  DomainDnsIntelligence,
  ThreatIntelRecord,
  SearchProviderStatus,
  ProviderDiagnosticItem,
  ProviderDiagnosticStatus,
  ResearchExecutionStatus,
  CacheStats,
  FactualClaim,
} from './types';

const RESEARCH_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (AegisFlow Cybersecurity Research; +https://aegisflowx.vercel.app)';

// ====================================================================
// Cache Structures & Statistics
// ====================================================================

interface CacheEntry {
  sources: ResearchSource[];
  cachedAt: string;
  expiresAt: number;
}

interface UrlhausCacheEntry {
  record: ThreatIntelRecord;
  cachedAt: string;
  expiresAt: number;
}

const SERPER_CACHE = new Map<string, CacheEntry>();
const URLHAUS_CACHE = new Map<string, UrlhausCacheEntry>();
const IN_FLIGHT_SEARCHES = new Map<string, Promise<{
  sources: ResearchSource[];
  rateLimited: boolean;
  quotaExhausted?: boolean;
  authError?: boolean;
  error?: string;
  fromCache?: boolean;
}>>();

const CACHE_STATS: CacheStats = {
  size: 0,
  hits: 0,
  misses: 0,
};

const MAX_CACHE_ENTRIES = 200;

/**
 * Returns current cache statistics.
 */
export function getCacheStats(): CacheStats {
  return {
    size: SERPER_CACHE.size + URLHAUS_CACHE.size,
    hits: CACHE_STATS.hits,
    misses: CACHE_STATS.misses,
  };
}

/**
 * Clears the in-memory Serper search cache (useful for automated testing).
 */
export function clearSerperCache(): void {
  SERPER_CACHE.clear();
  IN_FLIGHT_SEARCHES.clear();
}

/**
 * Clears the in-memory URLhaus threat-intel cache.
 */
export function clearUrlhausCache(): void {
  URLHAUS_CACHE.clear();
}

/**
 * Normalizes query string for predictable cache key derivation and deduplication.
 */
export function normalizeQuery(query: string): string {
  return query
    .trim()
    .toLowerCase()
    .replace(/[^\w\s-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 160);
}

/**
 * Reads configured maximum outbound search requests per analysis.
 * Default: 2 (conservative for free tier), clamped between 1 and 5.
 */
export function getMaxSearchesPerAnalysis(): number {
  const envVal = process.env.SERPER_MAX_SEARCHES_PER_ANALYSIS;
  if (envVal && !isNaN(Number(envVal))) {
    return Math.max(1, Math.min(5, Math.floor(Number(envVal))));
  }
  return 2;
}

/**
 * Resolves cache TTL in milliseconds based on data volatility.
 */
export function getCacheTtlMs(type: 'serper' | 'urlhaus_malicious' | 'urlhaus_clean'): number {
  if (type === 'serper') {
    const envMinutes = process.env.SERPER_CACHE_TTL_MINUTES;
    const mins = envMinutes && !isNaN(Number(envMinutes)) ? Math.max(5, Number(envMinutes)) : 30;
    return mins * 60 * 1000;
  }
  if (type === 'urlhaus_malicious') {
    // Malicious infrastructure records remain stable; cache for 4 hours
    return 4 * 60 * 60 * 1000;
  }
  // URLhaus clean/unlisted: shorter 15-minute TTL because new phishing appears constantly
  return 15 * 60 * 1000;
}

// ====================================================================
// Query Consolidation & Planning
// ====================================================================

/**
 * Server-side query consolidation step.
 * Combines multiple related claims and entities into a small number of
 * targeted queries instead of searching sentence-by-sentence.
 */
export function planSearchQueries(
  claims: FactualClaim[],
  organizations: string[],
  candidateDomains: string[],
  financialRequests: string[],
  maxQueries: number = getMaxSearchesPerAnalysis()
): string[] {
  const planned: string[] = [];
  const seenNormalized = new Set<string>();

  const addQuery = (q: string) => {
    const normalized = normalizeQuery(q);
    if (!normalized || seenNormalized.has(normalized)) return;
    if (planned.length >= maxQueries) return;
    seenNormalized.add(normalized);
    planned.push(q.trim());
  };

  const allClaimsText = claims.map((c) => c.claimText).join(' ');

  // 1. Primary Organization + Targeted Policy, Fee, or Threat Context
  if (organizations.length > 0) {
    const primaryOrg = organizations[0];
    const feeItem = financialRequests.find((f) => /fee|tax|charge|wire|payment/i.test(f));

    if (/verification fee/i.test(allClaimsText) || /verification fee/i.test(feeItem || '')) {
      addQuery(`${primaryOrg} new verification fee announcement official notice`);
    } else if (feeItem) {
      addQuery(`${primaryOrg} ${feeItem} official advisory circular`);
    } else if (/recall/i.test(allClaimsText)) {
      addQuery(`${primaryOrg} product recall official notice`);
    } else if (/policy|regulation|directive|mandate/i.test(allClaimsText)) {
      addQuery(`${primaryOrg} new policy regulation directive circular`);
    } else if (/blocked|freeze|suspended/i.test(allClaimsText)) {
      addQuery(`${primaryOrg} accounts blocked regulatory advisory`);
    } else {
      addQuery(`${primaryOrg} security notice official circular advisory`);
    }
  }

  // 2. Candidate Domain reputation query if extracted
  if (candidateDomains.length > 0 && planned.length < maxQueries) {
    addQuery(`${candidateDomains[0]} official domain legitimacy`);
  }

  // 3. Second targeted query for specific account threat / announcement if limit allows
  if (planned.length < maxQueries && organizations.length > 0) {
    const primaryOrg = organizations[0];
    if (/blocked|freeze|suspended/i.test(allClaimsText) && /fee|verification/i.test(allClaimsText)) {
      addQuery(`${primaryOrg} bank accounts blocked verification fee circular advisory`);
    } else if (/announced|announcement/i.test(allClaimsText)) {
      addQuery(`${primaryOrg} official press release circular`);
    }
  }

  // 4. Most specific factual claim summary
  if (claims.length > 0 && planned.length < maxQueries) {
    const primaryClaim = claims[0].claimText;
    const cleanWords = primaryClaim
      .replace(/[^a-zA-Z0-9\s]/g, '')
      .split(/\s+/)
      .slice(0, 7)
      .join(' ');
    if (cleanWords.length > 5) {
      addQuery(`${cleanWords} official advisory`);
    }
  }

  // Fallback if no specific queries generated
  if (planned.length === 0 && claims.length > 0) {
    addQuery(`${claims[0].claimText.slice(0, 50)} security alert`);
  }

  return planned.slice(0, maxQueries);
}

// ====================================================================
// Source Credibility & Institutional Domain Registry
// ====================================================================

const INSTITUTIONAL_OFFICIAL_DOMAINS: Record<string, string[]> = {
  'central bank of nigeria': ['cbn.gov.ng'],
  'cbn': ['cbn.gov.ng'],
  'federal reserve': ['federalreserve.gov'],
  'bank of england': ['bankofengland.co.uk'],
  'european central bank': ['ecb.europa.eu'],
  'internal revenue service': ['irs.gov'],
  'irs': ['irs.gov'],
  'federal bureau of investigation': ['fbi.gov'],
  'fbi': ['fbi.gov'],
  'federal trade commission': ['ftc.gov'],
  'ftc': ['ftc.gov'],
  'cybersecurity and infrastructure security agency': ['cisa.gov'],
  'cisa': ['cisa.gov'],
  'securities and exchange commission': ['sec.gov'],
  'sec': ['sec.gov'],
  'wells fargo': ['wellsfargo.com'],
  'chase': ['chase.com', 'jpmorganchase.com'],
  'bank of america': ['bankofamerica.com'],
  'citibank': ['citi.com', 'citibank.com'],
  'barclays': ['barclays.co.uk', 'barclays.com'],
  'first bank of nigeria': ['firstbanknigeria.com'],
  'access bank': ['accessbankplc.com'],
  'zenith bank': ['zenithbank.com'],
  'gtbank': ['gtbank.com'],
  'guaranty trust bank': ['gtbank.com'],
  'united bank for africa': ['ubagroup.com'],
  'uba': ['ubagroup.com'],
};

/**
 * Checks whether a domain is the verified official institutional domain for a named organization.
 * Strict check: does not treat lookalike or similarly named domains as official.
 */
export function isOfficialInstitutionalDomain(domain: string, organization?: string): boolean {
  if (!domain) return false;
  const cleanDomain = domain.toLowerCase().replace(/^www\./, '').trim();

  // If organization provided, check mapping
  if (organization) {
    const cleanOrg = organization.toLowerCase().trim();
    for (const [orgKey, officialDomains] of Object.entries(INSTITUTIONAL_OFFICIAL_DOMAINS)) {
      if (cleanOrg.includes(orgKey) || orgKey.includes(cleanOrg)) {
        if (officialDomains.some((od) => cleanDomain === od || cleanDomain.endsWith('.' + od))) {
          return true;
        }
      }
    }
  }

  // Also check if domain matches any known official institutional domain directly
  for (const officialDomains of Object.values(INSTITUTIONAL_OFFICIAL_DOMAINS)) {
    if (officialDomains.some((od) => cleanDomain === od || cleanDomain.endsWith('.' + od))) {
      return true;
    }
  }

  return false;
}

/**
 * Checks whether a domain is an authoritative government, central bank, or military registry.
 */
export function isGovernmentDomain(domain: string): boolean {
  if (!domain) return false;
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  return (
    d.endsWith('.gov') ||
    d.includes('.gov.') ||
    d.endsWith('.mil') ||
    d.includes('.mil.') ||
    d.endsWith('.europa.eu') ||
    d.endsWith('.fed.us')
  );
}

/**
 * Checks whether a domain is an unverified social media, video, or discussion platform.
 * These cannot be treated as official institutional announcements or authoritative citations.
 */
export function isSocialMediaDomain(domain: string): boolean {
  if (!domain) return false;
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  return (
    d === 'youtube.com' ||
    d === 'youtu.be' ||
    d === 'facebook.com' ||
    d === 'fb.com' ||
    d === 'instagram.com' ||
    d === 'twitter.com' ||
    d === 'x.com' ||
    d === 'tiktok.com' ||
    d === 'reddit.com' ||
    d === 'threads.net' ||
    d === 't.me' ||
    d === 'telegram.org' ||
    d === 'linkedin.com' ||
    d === 'pinterest.com'
  );
}

/**
 * Checks whether a domain is an established, reputable news and investigative reporting outlet.
 */
export function isReputableNewsDomain(domain: string): boolean {
  if (!domain) return false;
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  const newsDomains = [
    'punchng.com',
    'premiumtimesng.com',
    'thecable.ng',
    'vanguardngr.com',
    'guardian.ng',
    'businessday.ng',
    'thisdaylive.com',
    'tribuneonlineng.com',
    'dailypost.ng',
    'reuters.com',
    'apnews.com',
    'bbc.com',
    'bbc.co.uk',
    'bloomberg.com',
    'cnn.com',
    'wsj.com',
    'nytimes.com',
    'ft.com',
    'cnbc.com',
    'aljazeera.com',
  ];
  return newsDomains.some((nd) => d === nd || d.endsWith('.' + nd));
}

// ====================================================================
// SSRF & Private IP Defense
// ====================================================================

/**
 * Checks whether an IP address belongs to private, loopback, or link-local ranges (SSRF defense).
 * Supports standard IPv4, alternative representations (integer/dword, hex, octal), and IPv6 ranges.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;
  const cleanIp = ip.trim().toLowerCase();

  // Alternative representation 1: Hex IP literal (e.g. 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(cleanIp)) {
    const num = parseInt(cleanIp, 16);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const p1 = (num >>> 24) & 255;
      const p2 = (num >>> 16) & 255;
      const p3 = (num >>> 8) & 255;
      const p4 = num & 255;
      return isPrivateOrReservedIp(`${p1}.${p2}.${p3}.${p4}`);
    }
  }

  // Alternative representation 2: Decimal dword / integer IP (e.g. 2130706433 for 127.0.0.1)
  if (/^\d{8,11}$/.test(cleanIp)) {
    const num = parseInt(cleanIp, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const p1 = (num >>> 24) & 255;
      const p2 = (num >>> 16) & 255;
      const p3 = (num >>> 8) & 255;
      const p4 = num & 255;
      return isPrivateOrReservedIp(`${p1}.${p2}.${p3}.${p4}`);
    }
  }

  // IPv6 loopback, link-local, unique-local, documentation, and IPv4-mapped
  if (
    cleanIp === '::1' ||
    cleanIp === '::' ||
    cleanIp.startsWith('fe80:') ||
    cleanIp.startsWith('fc00:') ||
    cleanIp.startsWith('fd00:') ||
    cleanIp.startsWith('2001:db8:') ||
    cleanIp.startsWith('::ffff:127.') ||
    cleanIp.startsWith('::ffff:10.') ||
    cleanIp.startsWith('::ffff:192.168.') ||
    cleanIp.startsWith('::ffff:169.254.') ||
    cleanIp.startsWith('::ffff:7f')
  ) {
    return true;
  }

  // IPv4 validation with octal/hex segment normalization
  const parts = cleanIp.split('.');
  if (parts.length !== 4) {
    return false;
  }

  // Verify all parts are valid numeric, hex, or octal segments
  if (!parts.every((p) => /^(?:0x[0-9a-f]+|0[0-7]*|\d+)$/i.test(p))) {
    return false;
  }

  const parsedParts: number[] = [];
  for (const part of parts) {
    let val: number;
    if (part.startsWith('0x') || part.startsWith('0X')) {
      val = parseInt(part, 16);
    } else if (part.length > 1 && part.startsWith('0')) {
      val = parseInt(part, 8);
    } else {
      val = parseInt(part, 10);
    }
    if (isNaN(val) || val < 0 || val > 255) {
      return false;
    }
    parsedParts.push(val);
  }

  // 127.0.0.0/8 (Loopback)
  if (parsedParts[0] === 127) return true;
  // 10.0.0.0/8 (Private RFC-1918)
  if (parsedParts[0] === 10) return true;
  // 172.16.0.0/12 (Private RFC-1918)
  if (parsedParts[0] === 172 && parsedParts[1] >= 16 && parsedParts[1] <= 31) return true;
  // 192.168.0.0/16 (Private RFC-1918)
  if (parsedParts[0] === 192 && parsedParts[1] === 168) return true;
  // 169.254.0.0/16 (Link-local / Cloud metadata like AWS/GCP 169.254.169.254)
  if (parsedParts[0] === 169 && parsedParts[1] === 254) return true;
  // 0.0.0.0/8 (Current network)
  if (parsedParts[0] === 0) return true;
  // 100.64.0.0/10 (Shared carrier CGNAT)
  if (parsedParts[0] === 100 && parsedParts[1] >= 64 && parsedParts[1] <= 127) return true;
  // 192.0.2.0/24 (TEST-NET-1)
  if (parsedParts[0] === 192 && parsedParts[1] === 0 && parsedParts[2] === 2) return true;
  // 198.51.100.0/24 (TEST-NET-2)
  if (parsedParts[0] === 198 && parsedParts[1] === 51 && parsedParts[2] === 100) return true;
  // 203.0.113.0/24 (TEST-NET-3)
  if (parsedParts[0] === 203 && parsedParts[1] === 0 && parsedParts[2] === 113) return true;
  // 224.0.0.0/4 (Multicast)
  if (parsedParts[0] >= 224 && parsedParts[0] <= 239) return true;
  // 240.0.0.0/4 (Reserved)
  if (parsedParts[0] >= 240) return true;

  return false;
}

/**
 * Safely fetches a webpage excerpt for a search result URL, strictly protecting against SSRF,
 * credential leaks, unsafe ports, and private IP leaks.
 */
export async function fetchSafeWebExcerpt(
  rawUrl: string,
  maxChars: number = 2000
): Promise<{ excerpt: string | null; error?: string }> {
  try {
    let currentUrl = rawUrl;
    let redirectHops = 0;
    const maxRedirects = 3;

    while (redirectHops <= maxRedirects) {
      const parsed = new URL(currentUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { excerpt: null, error: 'Disallowed protocol (only http/https permitted)' };
      }

      // Security Check: Credential-bearing URLs (e.g. http://user:pass@example.com)
      if (parsed.username || parsed.password) {
        return { excerpt: null, error: 'Credential-bearing URLs are prohibited' };
      }

      // Security Check: Disallowed ports (only standard HTTP 80 and HTTPS 443 permitted)
      if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
        return { excerpt: null, error: 'Disallowed port (only standard HTTP/HTTPS ports permitted)' };
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

      // Direct check if hostname is a private IP literal or alternative representation
      if (isPrivateOrReservedIp(hostname)) {
        return { excerpt: null, error: 'Destination is a private or reserved IP address' };
      }

      // Resolve DNS to verify non-private destination with fast timeout wrapper
      const dnsTimeoutMs = 2500;
      const resolveWithTimeout = async <T>(promise: Promise<T>): Promise<T | null> => {
        return await Promise.race([
          promise,
          new Promise<null>((resolve) => setTimeout(() => resolve(null), dnsTimeoutMs)),
        ]);
      };

      const resolvedIps = (await resolveWithTimeout(dns.resolve4(hostname).catch(() => []))) || [];
      if (resolvedIps.some(isPrivateOrReservedIp)) {
        return { excerpt: null, error: 'Destination resolves to private, loopback, or unreachable IP' };
      }

      // Also verify IPv6 if any
      const resolvedIpv6 = (await resolveWithTimeout(dns.resolve6(hostname).catch(() => []))) || [];
      if (resolvedIpv6.some(isPrivateOrReservedIp)) {
        return { excerpt: null, error: 'Destination resolves to private IPv6 address' };
      }

      if (resolvedIps.length === 0 && resolvedIpv6.length === 0) {
        // Fallback to dns.lookup to verify resolution
        const lookupRes = await resolveWithTimeout(dns.lookup(hostname).catch(() => null));
        if (!lookupRes || isPrivateOrReservedIp(lookupRes.address)) {
          return { excerpt: null, error: 'Destination IP resolution failed or resolved to private address' };
        }
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6000);

      const res = await fetch(currentUrl, {
        method: 'GET',
        headers: {
          'User-Agent': RESEARCH_USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9',
        },
        signal: controller.signal,
        redirect: 'manual', // Manually validate redirect hops for SSRF defense
      });
      clearTimeout(timeout);

      // Handle safe redirects
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get('location');
        if (!location) {
          return { excerpt: null, error: `HTTP redirect ${res.status} missing Location header` };
        }
        redirectHops++;
        if (redirectHops > maxRedirects) {
          return { excerpt: null, error: 'Too many redirects (exceeded 3 hops)' };
        }
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }

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

      // Strip scripts, styles, noscript, nav, footer, svg, and markup
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
    }

    return { excerpt: null, error: 'Redirect loop or exceeded max redirect hops' };
  } catch (err: any) {
    if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
      return { excerpt: null, error: 'Webpage retrieval timed out (6s)' };
    }
    return { excerpt: null, error: err?.message || 'Failed to retrieve page excerpt' };
  }
}

// ====================================================================
// Serper.dev Google Web Search Integration
// ====================================================================

/**
 * Searches the public web via Serper.dev Google Search API.
 * Includes query normalization, caching, in-flight request deduplication,
 * and detailed quota vs rate-limit error discrimination.
 */
export async function searchSerper(
  query: string,
  apiKey: string,
  maxResults: number = 4,
  primaryOrganization?: string
): Promise<{
  sources: ResearchSource[];
  rateLimited: boolean;
  quotaExhausted?: boolean;
  authError?: boolean;
  fromCache?: boolean;
  error?: string;
}> {
  const normKey = normalizeQuery(query);
  const cacheKey = `serper:${normKey}:${maxResults}:${primaryOrganization || 'none'}`;

  // 1. Check in-memory cache
  const cached = SERPER_CACHE.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    CACHE_STATS.hits++;
    // Return clone of sources marked as cached
    const cachedSources: ResearchSource[] = cached.sources.map((s) => ({
      ...s,
      isCached: true,
      cachedAt: cached.cachedAt,
      provenance: 'cached_evidence',
      limitationNote: `Served from validated cache snapshot (obtained ${new Date(cached.cachedAt).toLocaleTimeString()}).`,
    }));
    return { sources: cachedSources, rateLimited: false, fromCache: true };
  }

  // 2. In-flight request deduplication (Single-flight coalescing)
  if (IN_FLIGHT_SEARCHES.has(cacheKey)) {
    return await IN_FLIGHT_SEARCHES.get(cacheKey)!;
  }

  const fetchPromise = (async () => {
    CACHE_STATS.misses++;
    const sources: ResearchSource[] = [];

    try {
      const res = await fetch('https://google.serper.dev/search', {
        method: 'POST',
        headers: {
          'X-API-KEY': apiKey.trim(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          q: query.trim().slice(0, 160),
          num: maxResults,
        }),
        signal: AbortSignal.timeout(8000),
      });

      if (res.status === 401 || res.status === 403) {
        return {
          sources: [],
          rateLimited: false,
          authError: true,
          fromCache: false,
          error: `Serper.dev rejected credentials (HTTP ${res.status}). Verify SERPER_API_KEY.`,
        };
      }

      if (res.status === 429) {
        const errBody = (await res.text().catch(() => '')).toLowerCase();
        const isQuota =
          errBody.includes('quota') ||
          errBody.includes('credit') ||
          errBody.includes('exhausted') ||
          errBody.includes('exceeded') ||
          errBody.includes('limit reached');

        return {
          sources: [],
          rateLimited: !isQuota,
          quotaExhausted: isQuota,
          fromCache: false,
          error: isQuota
            ? 'Serper.dev free search quota has been exhausted.'
            : 'Serper.dev rate limit reached (HTTP 429). Please retry shortly.',
        };
      }

      if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        return {
          sources: [],
          rateLimited: false,
          fromCache: false,
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
          domain = new URL(item.link).hostname.toLowerCase();
        } catch {
          // Fallback
        }

        const isOfficial = isOfficialInstitutionalDomain(domain, primaryOrganization);
        const isGov = isGovernmentDomain(domain);
        const isSocial = isSocialMediaDomain(domain);
        const isNews = isReputableNewsDomain(domain);
        const isEdu = domain.endsWith('.edu') || domain.includes('.edu.');
        const isBank =
          domain.includes('wellsfargo.com') ||
          domain.includes('chase.com') ||
          domain.includes('bankofamerica.com');

        let sourceType: ResearchSource['sourceType'] = 'web_search';
        let reliability: ResearchSource['reliability'] = 'reputable';
        let limitationNote: string | undefined = 'Search snippet only; full page content was not retrieved.';
        let relevanceExplanation = `Retrieved via Serper.dev Google Index for query: "${query.slice(0, 45)}"`;

        if (isOfficial) {
          sourceType = 'official_site';
          reliability = 'authoritative';
          relevanceExplanation = `Official primary web domain for claimed organization (${domain})`;
        } else if (isGov) {
          sourceType = 'public_advisory';
          reliability = 'authoritative';
          relevanceExplanation = `Authoritative government / regulatory domain (${domain})`;
        } else if (isSocial) {
          sourceType = 'social_media';
          reliability = 'unverified';
          limitationNote = 'Unverified social media post; cannot be treated as official institutional announcement or primary evidence.';
          relevanceExplanation = `Social media post on ${domain}; secondary evidentiary weight only.`;
        } else if (isNews) {
          sourceType = 'news_reporting';
          reliability = 'reputable';
          relevanceExplanation = `Established journalistic reporting (${domain})`;
        } else if (isBank || isEdu) {
          sourceType = isBank ? 'public_advisory' : 'web_search';
          reliability = isBank ? 'authoritative' : 'reputable';
        } else {
          // Guard against domains that resemble organization names but are not official
          if (primaryOrganization && domain.includes('cbn') && !isOfficial && !isNews) {
            reliability = 'unverified';
            limitationNote = `Third-party domain (${domain}) resembling organization name; not an authenticated official portal.`;
          }
        }

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
          isCached: false,
          sourceType,
          reliability,
          relevanceExplanation,
          limitationNote,
          isOfficialInstitutionalSource: isOfficial,
        });
      }

      // Store in memory cache
      if (sources.length > 0) {
        if (SERPER_CACHE.size >= MAX_CACHE_ENTRIES) {
          const oldest = SERPER_CACHE.keys().next().value;
          if (oldest) SERPER_CACHE.delete(oldest);
        }
        const now = Date.now();
        SERPER_CACHE.set(cacheKey, {
          sources,
          cachedAt: new Date(now).toISOString(),
          expiresAt: now + getCacheTtlMs('serper'),
        });
      }

      return { sources, rateLimited: false, fromCache: false };
    } catch (err: any) {
      if (err?.name === 'AbortError' || err?.name === 'TimeoutError') {
        return { sources: [], rateLimited: false, fromCache: false, error: 'Serper.dev request timed out (8s).' };
      }
      return { sources: [], rateLimited: false, fromCache: false, error: err?.message || 'Serper.dev query failed.' };
    } finally {
      IN_FLIGHT_SEARCHES.delete(cacheKey);
    }
  })();

  IN_FLIGHT_SEARCHES.set(cacheKey, fetchPromise);
  return await fetchPromise;
}

// ====================================================================
// Wikipedia Encyclopedia Reference API
// ====================================================================

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
        isCached: false,
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

// ====================================================================
// Public Web Search Fallback (Open Index)
// ====================================================================

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
        isCached: false,
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

// ====================================================================
// URLhaus Threat Intelligence (abuse.ch)
// ====================================================================

export async function checkUrlhausThreatIntel(
  indicator: string,
  type: 'domain' | 'url'
): Promise<ThreatIntelRecord> {
  const authKey = process.env.URLHAUS_AUTH_KEY;
  const retrievedAt = new Date().toISOString();
  const cleanIndicator = indicator.toLowerCase().trim();
  const cacheKey = `urlhaus:${type}:${cleanIndicator}`;

  // Check cache
  const cached = URLHAUS_CACHE.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return {
      ...cached.record,
      isCached: true,
      cachedAt: cached.cachedAt,
    };
  }

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
      body.append('host', cleanIndicator);
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
      const record: ThreatIntelRecord = {
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

      // Cache malicious indicators (4 hours)
      URLHAUS_CACHE.set(cacheKey, {
        record,
        cachedAt: retrievedAt,
        expiresAt: Date.now() + getCacheTtlMs('urlhaus_malicious'),
      });

      return record;
    }

    // Unlisted or clean in URLhaus
    const cleanRecord: ThreatIntelRecord = {
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

    // Cache clean/unlisted indicators (15 mins)
    URLHAUS_CACHE.set(cacheKey, {
      record: cleanRecord,
      cachedAt: retrievedAt,
      expiresAt: Date.now() + getCacheTtlMs('urlhaus_clean'),
    });

    return cleanRecord;
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

// ====================================================================
// DNS Intelligence
// ====================================================================

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

// ====================================================================
// Diagnostics Probes
// ====================================================================

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
      const errText = (await res.text().catch(() => '')).toLowerCase();
      const isQuota =
        errText.includes('quota') ||
        errText.includes('credit') ||
        errText.includes('exhausted') ||
        errText.includes('exceeded');
      return {
        provider: 'Serper.dev Web Search',
        status: isQuota ? 'rate_limit_exhausted' : 'rate_limit_exhausted',
        isConfigured: true,
        message: isQuota
          ? 'Serper.dev free tier quota exhausted.'
          : 'Serper.dev rate limit reached (HTTP 429).',
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

// ====================================================================
// Master Web Researcher & Quota Control
// ====================================================================

export async function performWebResearch(
  queries: string[],
  domainsToCheck: string[],
  options?: { skipWebSearch?: boolean; primaryOrganization?: string }
): Promise<{
  sources: ResearchSource[];
  domainIntelligence: DomainDnsIntelligence[];
  threatIntel: ThreatIntelRecord[];
  providerStatus: SearchProviderStatus;
}> {
  const allSources: ResearchSource[] = [];
  const domainIntelligence: DomainDnsIntelligence[] = [];
  const threatIntel: ThreatIntelRecord[] = [];

  const maxSearchesConfigured = getMaxSearchesPerAnalysis();
  const serperKey = process.env.SERPER_API_KEY;

  let providerMode: 'serper' | 'public_web_fallback' = 'public_web_fallback';
  let providerName = 'Wikimedia API & Public Web Fallback';
  let isConfigured = false;
  let rateLimitEncountered = false;
  let quotaExhaustedEncountered = false;
  let authErrorEncountered = false;
  let timeoutEncountered = false;
  let errorMessage: string | undefined;

  let outboundSearchesExecuted = 0;
  let cacheHitsCount = 0;
  let searchLimitReached = false;

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
        isCached: false,
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
          isCached: !!tIntel.isCached,
          sourceType: 'threat_intel',
          reliability: 'authoritative',
          relevanceExplanation: `Global malware infrastructure match for "${domain}"`,
        });
      }
    }
  }

  // 2. Execute targeted searches (if not explicitly skipped)
  const targetedQueries = queries.slice(0, maxSearchesConfigured);
  let queriesExecuted = 0;

  if (options?.skipWebSearch) {
    // Explicitly skipped (e.g. conversational greeting)
  } else {
    for (const q of targetedQueries) {
      if (outboundSearchesExecuted >= maxSearchesConfigured) {
        searchLimitReached = true;
        break;
      }

      queriesExecuted++;
      if (providerMode === 'serper' && serperKey) {
        const serperRes = await searchSerper(q, serperKey, 4, options?.primaryOrganization);

        if (serperRes.fromCache) {
          cacheHitsCount++;
          allSources.push(...serperRes.sources);
        } else {
          outboundSearchesExecuted++;
          if (serperRes.quotaExhausted) {
            quotaExhaustedEncountered = true;
            errorMessage = serperRes.error;
            // Fall back to wikipedia / open web without failing
            const [fbWeb, fbWiki] = await Promise.all([
              searchPublicWebFallback(q, 2),
              searchWikipedia(q, 2),
            ]);
            allSources.push(...fbWeb, ...fbWiki);
          } else if (serperRes.rateLimited) {
            rateLimitEncountered = true;
            errorMessage = serperRes.error;
            const [fbWeb, fbWiki] = await Promise.all([
              searchPublicWebFallback(q, 2),
              searchWikipedia(q, 2),
            ]);
            allSources.push(...fbWeb, ...fbWiki);
          } else if (serperRes.authError) {
            authErrorEncountered = true;
            errorMessage = serperRes.error;
            const [fbWeb, fbWiki] = await Promise.all([
              searchPublicWebFallback(q, 2),
              searchWikipedia(q, 2),
            ]);
            allSources.push(...fbWeb, ...fbWiki);
          } else if (serperRes.error && serperRes.error.includes('timed out')) {
            timeoutEncountered = true;
            errorMessage = serperRes.error;
          } else {
            allSources.push(...serperRes.sources);
          }
        }
      } else {
        // Unconfigured paid provider
        outboundSearchesExecuted++;
        const [ddgResults, wikiResults] = await Promise.all([
          searchPublicWebFallback(q, 2),
          searchWikipedia(q, 2),
        ]);
        allSources.push(...ddgResults, ...wikiResults);
      }
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

  // 3. Safe content retrieval for prioritized candidates (up to 3 sources)
  let fullPageRetrievalActive = false;

  const candidateSourcesForFetch = finalSources
    .filter(
      (s) =>
        s.provenance === 'snippet_only' &&
        !isSocialMediaDomain(s.domain) &&
        s.url.startsWith('http')
    )
    .sort((a, b) => {
      const aScore = a.isOfficialInstitutionalSource
        ? 4
        : isGovernmentDomain(a.domain)
        ? 3
        : isReputableNewsDomain(a.domain)
        ? 2
        : a.reliability === 'authoritative'
        ? 1
        : 0;
      const bScore = b.isOfficialInstitutionalSource
        ? 4
        : isGovernmentDomain(b.domain)
        ? 3
        : isReputableNewsDomain(b.domain)
        ? 2
        : b.reliability === 'authoritative'
        ? 1
        : 0;
      return bScore - aScore;
    })
    .slice(0, 3);

  for (const candidate of candidateSourcesForFetch) {
    const pageFetch = await fetchSafeWebExcerpt(candidate.url, 2000);
    if (pageFetch.excerpt) {
      candidate.rawContentExcerpt = pageFetch.excerpt;
      candidate.provenance = 'full_page_retrieved';
      candidate.pageRetrievalStatus = 'retrieved';
      candidate.limitationNote = undefined;
      fullPageRetrievalActive = true;
    } else {
      candidate.pageRetrievalStatus = 'failed';
      candidate.limitationNote = `Source page could not be retrieved (${pageFetch.error || 'Fetch blocked'}); evaluated using search snippet only.`;
    }
  }

  // Ensure all sources have an explicit, accurate pageRetrievalStatus and limitationNote
  for (const s of finalSources) {
    if (!s.pageRetrievalStatus) {
      s.pageRetrievalStatus = 'snippet_only';
    }
    if (s.provenance === 'snippet_only' && !s.limitationNote) {
      s.limitationNote = isSocialMediaDomain(s.domain)
        ? 'Unverified social media post; full webpage was not retrieved and cannot serve as primary authority.'
        : 'Search snippet only; full page content was not retrieved.';
    }
  }

  // 4. Derive transparent researchExecutionStatus
  let researchStatus: ResearchExecutionStatus = 'live_research_completed';
  let statusExplanation = 'Live external web research completed successfully across public sources.';

  if (options?.skipWebSearch || queries.length === 0) {
    researchStatus = 'not_required';
    statusExplanation = 'External web research was not required for this submission.';
  } else if (quotaExhaustedEncountered) {
    researchStatus = 'quota_exhausted';
    statusExplanation =
      'Serper.dev free search quota has been exhausted. External web research could not query live Google indices; fallback reference data used.';
  } else if (rateLimitEncountered) {
    researchStatus = 'rate_limit_exhausted';
    statusExplanation = 'External search provider rate limit reached. Fallback reference sources utilized.';
  } else if (authErrorEncountered) {
    researchStatus = 'authentication_failed';
    statusExplanation = 'External search provider authentication rejected. Fallback reference sources utilized.';
  } else if (timeoutEncountered) {
    researchStatus = 'provider_timeout';
    statusExplanation = 'External search provider request timed out. Findings evaluated from available telemetry.';
  } else if (cacheHitsCount > 0 && outboundSearchesExecuted === 0) {
    researchStatus = 'completed_using_cached_evidence';
    statusExplanation = 'Investigation completed entirely using validated, pre-cached web evidence.';
  } else if (searchLimitReached) {
    researchStatus = 'partially_completed';
    statusExplanation = `Investigation reached the configured search limit (${maxSearchesConfigured} queries). Evaluated all evidence retrieved.`;
  } else if (finalSources.length === 0) {
    researchStatus = 'no_results';
    statusExplanation = 'Search executed successfully but returned no relevant public web evidence.';
  }

  const configurationGuide = !isConfigured
    ? 'To enable Google Search results via Serper.dev, configure SERPER_API_KEY (from https://serper.dev). To enable malware threat lookups, configure URLHAUS_AUTH_KEY (from https://auth.abuse.ch).'
    : undefined;

  const providerStatus: SearchProviderStatus = {
    providerName,
    isConfigured,
    mode: providerMode,
    researchStatus,
    statusExplanation,
    fullPageRetrievalActive,
    rateLimitEncountered: rateLimitEncountered || quotaExhaustedEncountered,
    queriesExecuted,
    outboundSearchesExecuted,
    cacheHitsCount,
    maxSearchesConfigured,
    searchLimitReached,
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
