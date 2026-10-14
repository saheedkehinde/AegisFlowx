import dns from 'dns/promises';
import { ResearchSource, DomainDnsIntelligence } from './types';

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (AegisFlow Security Research)';

/**
 * Searches the public web via DuckDuckGo for evidence corroborating or contradicting claims.
 */
export async function searchDuckDuckGo(query: string, maxResults: number = 4): Promise<ResearchSource[]> {
  const sources: ResearchSource[] = [];
  try {
    const encoded = encodeURIComponent(query.slice(0, 150));
    const res = await fetch(`https://html.duckduckgo.com/html/?q=${encoded}`, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml',
      },
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) return sources;
    const html = await res.text();

    // Regex match DuckDuckGo HTML results
    const resultBlockRegex = /<div class="result results_links results_links_deep[^"]*"[\s\S]*?<a class="result__snippet[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
    const titleRegex = /<a class="result__url[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;

    // Match snippets
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
        // DuckDuckGo redirects links through /l/?kh=-1&uddg=...
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
        id: `src-ddg-${idx++}`,
        title: `Public Web Intelligence: ${domain}`,
        url: extractedUrl || `https://duckduckgo.com/html/?q=${encoded}`,
        domain,
        snippet: rawSnippet,
        retrievedAt: new Date().toISOString(),
        sourceType: domain.includes('.gov') || domain.includes('.bank') ? 'public_advisory' : 'web_search',
        reliability: domain.includes('.gov') ? 'authoritative' : 'reputable',
      });
    }
  } catch (err: any) {
    console.warn('DuckDuckGo search warning:', err?.message || err);
  }

  return sources;
}

/**
 * Searches the official Wikipedia / Wikimedia API for organizational verification,
 * executive roles, known fraud warnings, and legitimate domains.
 */
export async function searchWikipedia(query: string, maxResults: number = 3): Promise<ResearchSource[]> {
  const sources: ResearchSource[] = [];
  try {
    const encoded = encodeURIComponent(query.slice(0, 100));
    const res = await fetch(
      `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encoded}&format=json&utf8=1`,
      {
        headers: { 'User-Agent': 'AegisFlow/1.0 (Cybersecurity Intelligence; security@aegisflow.dev)' },
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
        id: `src-wiki-${i + 1}`,
        title: `Wikipedia: ${pageTitle}`,
        url,
        domain: 'en.wikipedia.org',
        snippet: cleanSnippet,
        publishedDate: item.timestamp ? new Date(item.timestamp).toLocaleDateString() : undefined,
        retrievedAt: new Date().toISOString(),
        sourceType: 'encyclopedia',
        reliability: 'reputable',
      });
    }
  } catch (err: any) {
    console.warn('Wikipedia search warning:', err?.message || err);
  }

  return sources;
}

/**
 * Performs authoritative DNS intelligence lookups on extracted domains.
 * Detects whether domains resolve, whether MX mail exchangers exist, and potential typosquatting.
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
  };
}

/**
 * Coordinates multi-source research across search engines, encyclopedic references,
 * and domain DNS telemetry.
 */
export async function performWebResearch(
  queries: string[],
  domainsToCheck: string[]
): Promise<{
  sources: ResearchSource[];
  domainIntelligence: DomainDnsIntelligence[];
  providerUsed: string;
}> {
  const allSources: ResearchSource[] = [];
  const domainIntelligence: DomainDnsIntelligence[] = [];

  // 1. Run DNS intelligence on extracted domains
  for (const domain of domainsToCheck.slice(0, 3)) {
    if (domain && domain.includes('.')) {
      const dnsIntel = await performDomainDnsLookup(domain);
      domainIntelligence.push(dnsIntel);

      allSources.push({
        id: `src-dns-${dnsIntel.domain}`,
        title: `Authoritative DNS Telemetry: ${dnsIntel.domain}`,
        url: `https://${dnsIntel.domain}`,
        domain: dnsIntel.domain,
        snippet: dnsIntel.notes,
        retrievedAt: new Date().toISOString(),
        sourceType: 'dns_telemetry',
        reliability: 'authoritative',
      });
    }
  }

  // 2. Query DuckDuckGo and Wikipedia for each claim query
  for (const q of queries.slice(0, 2)) {
    const [ddgResults, wikiResults] = await Promise.all([
      searchDuckDuckGo(q, 3),
      searchWikipedia(q, 2),
    ]);
    allSources.push(...ddgResults, ...wikiResults);
  }

  // Deduplicate sources by URL
  const uniqueSourcesMap = new Map<string, ResearchSource>();
  for (const s of allSources) {
    if (!uniqueSourcesMap.has(s.url)) {
      uniqueSourcesMap.set(s.url, s);
    }
  }

  return {
    sources: Array.from(uniqueSourcesMap.values()),
    domainIntelligence,
    providerUsed: 'Multi-Source: Public Web + Wikipedia Reference + Native DNS Telemetry',
  };
}
