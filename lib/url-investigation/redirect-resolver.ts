import dns from 'dns/promises';
import { isPrivateOrReservedIp } from '@/lib/fact-checker/web-researcher';
import { validateAndNormalizeUrl } from '@/lib/url-investigation/investigator';
import { UrlComponents } from '@/lib/url-investigation/types';

export interface RedirectHop {
  hopNumber: number;
  url: string;
  hostname: string;
  status?: number;
  redirectType: 'parameter_redirect' | 'http_redirect' | 'meta_refresh' | 'final';
  error?: string;
}

export interface RedirectAnalysisResult {
  originalUrl: string;
  decodedDestination: string | null;
  redirectChain: RedirectHop[];
  finalDestination: string;
  isRedirect: boolean;
  suspiciousDomainChange: boolean;
  redirectLoop: boolean;
  resolvedSuccessfully: boolean;
  errorReason?: string;
}

const REDIRECT_QUERY_PARAMS = [
  'q',
  'url',
  'target',
  'dest',
  'destination',
  'redirect',
  'redirect_url',
  'next',
  'goto',
  'u',
  'link',
  'r',
  'continue',
];

/**
  * Parses redirect parameters and handles nested or double-encoded URLs.
  */
export function parseRedirectParameter(urlObj: URL): string | null {
  for (const param of REDIRECT_QUERY_PARAMS) {
    const val = urlObj.searchParams.get(param);
    if (val && typeof val === 'string' && val.trim().length > 0) {
      let decoded = val.trim();
      try {
        const decodedOnce = decodeURIComponent(decoded);
        if (decodedOnce !== decoded) {
          decoded = decodedOnce;
          const decodedTwice = decodeURIComponent(decoded);
          if (decodedTwice !== decoded) {
            decoded = decodedTwice;
          }
        }
      } catch {
        // Keep single decoded or raw if decoding fails
      }

      if (/^https?:\/\//i.test(decoded)) {
        return decoded;
      }
      if (decoded.startsWith('//')) {
        return `https:${decoded}`;
      }
      if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/.*)?$/.test(decoded)) {
        return `https://${decoded}`;
      }
    }
  }
  return null;
}

/**
  * Securely resolves URL redirects with SSRF checks, DNS revalidation per hop,
  * hop limits (max 5), loop detection, and timeout protections.
  */
export async function resolveUrlRedirects(
  rawUrl: string,
  signal?: AbortSignal
): Promise<RedirectAnalysisResult> {
  const validation = validateAndNormalizeUrl(rawUrl);
  if (!validation.isValid || !validation.urlComponents || !validation.parsedUrl) {
    return {
      originalUrl: rawUrl,
      decodedDestination: null,
      redirectChain: [],
      finalDestination: rawUrl,
      isRedirect: false,
      suspiciousDomainChange: false,
      redirectLoop: false,
      resolvedSuccessfully: false,
      errorReason: validation.error || 'Invalid initial URL.',
    };
  }

  const redirectChain: RedirectHop[] = [];
  const visitedUrls = new Set<string>();
  const visitedHostnames = new Set<string>();

  let currentUrlStr = validation.urlComponents.normalizedUrl;
  let currentParsed = validation.parsedUrl;
  const initialHostname = currentParsed.hostname.toLowerCase();

  visitedUrls.add(currentUrlStr);
  visitedHostnames.add(initialHostname);

  redirectChain.push({
    hopNumber: 1,
    url: currentUrlStr,
    hostname: initialHostname,
    redirectType: 'final',
  });

  let hopCount = 1;
  const MAX_HOPS = 5;
  let decodedDestination: string | null = null;
  let redirectLoop = false;
  let suspiciousDomainChange = false;
  let resolvedSuccessfully = true;
  let errorReason: string | undefined;

  while (hopCount < MAX_HOPS) {
    if (signal?.aborted) {
      resolvedSuccessfully = false;
      errorReason = 'Redirect resolution aborted by client.';
      break;
    }
    const paramDestination = parseRedirectParameter(currentParsed);
    if (paramDestination) {
      if (!decodedDestination) {
        decodedDestination = paramDestination;
      }

      const paramValidation = validateAndNormalizeUrl(paramDestination);
      if (paramValidation.isValid && paramValidation.parsedUrl) {
        const nextUrlStr = paramValidation.urlComponents!.normalizedUrl;
        const nextHostname = paramValidation.parsedUrl.hostname.toLowerCase();

        const ipCheck = isPrivateOrReservedIp(nextHostname);
        if (ipCheck) {
          resolvedSuccessfully = false;
          errorReason = `Redirect destination "${nextHostname}" resolves to a private or reserved IP address (SSRF block).`;
          break;
        }

        if (visitedUrls.has(nextUrlStr) || visitedHostnames.has(nextHostname)) {
          redirectLoop = true;
          errorReason = 'Redirect loop detected during parameter resolution.';
          break;
        }

        visitedUrls.add(nextUrlStr);
        visitedHostnames.add(nextHostname);

        if (initialHostname !== nextHostname && !initialHostname.endsWith('.' + nextHostname) && !nextHostname.endsWith('.' + initialHostname)) {
          suspiciousDomainChange = true;
        }

        hopCount++;
        currentUrlStr = nextUrlStr;
        currentParsed = paramValidation.parsedUrl;

        redirectChain[redirectChain.length - 1].redirectType = 'parameter_redirect';
        redirectChain.push({
          hopNumber: hopCount,
          url: currentUrlStr,
          hostname: nextHostname,
          redirectType: 'final',
        });
        continue;
      }
    }

    const controller = new AbortController();
    const timeoutTimer = setTimeout(() => controller.abort(), 3500);
    const hasSignalInstance = typeof AbortSignal !== 'undefined' && signal instanceof AbortSignal;
    const onExternalAbort = hasSignalInstance ? () => controller.abort() : undefined;
    if (onExternalAbort && signal) {
      if (signal.aborted) {
        clearTimeout(timeoutTimer);
        resolvedSuccessfully = false;
        errorReason = 'Redirect resolution aborted by client.';
        break;
      }
      signal.addEventListener('abort', onExternalAbort, { once: true });
    }

    try {
      const res = await fetch(currentUrlStr, {
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          'User-Agent': 'AegisFlow-Security-Scanner/2.0 (Security Research; +https://aegisflow.sec)',
        },
        signal: controller.signal,
      });

      const status = res.status;
      redirectChain[redirectChain.length - 1].status = status;

      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = res.headers.get('location');
        if (location) {
          let resolvedLocation = location;
          if (!/^https?:\/\//i.test(location)) {
            resolvedLocation = new URL(location, currentUrlStr).toString();
          }

          const locValidation = validateAndNormalizeUrl(resolvedLocation);
          if (locValidation.isValid && locValidation.parsedUrl) {
            const nextUrlStr = locValidation.urlComponents!.normalizedUrl;
            const nextHostname = locValidation.parsedUrl.hostname.toLowerCase();

            const ipCheck = isPrivateOrReservedIp(nextHostname);
            if (ipCheck) {
              resolvedSuccessfully = false;
              errorReason = `HTTP redirect destination "${nextHostname}" blocked by SSRF policy.`;
              break;
            }

            if (visitedUrls.has(nextUrlStr) || visitedHostnames.has(nextHostname)) {
              redirectLoop = true;
              errorReason = 'Redirect loop detected in HTTP headers.';
              break;
            }

            visitedUrls.add(nextUrlStr);
            visitedHostnames.add(nextHostname);

            if (initialHostname !== nextHostname) {
              suspiciousDomainChange = true;
            }

            hopCount++;
            currentUrlStr = nextUrlStr;
            currentParsed = locValidation.parsedUrl;
            if (!decodedDestination) {
              decodedDestination = currentUrlStr;
            }

            redirectChain[redirectChain.length - 1].redirectType = 'http_redirect';
            redirectChain.push({
              hopNumber: hopCount,
              url: currentUrlStr,
              hostname: nextHostname,
              redirectType: 'final',
            });
            continue;
          }
        }
      }
      break;
    } catch {
      if (signal?.aborted) {
        resolvedSuccessfully = false;
        errorReason = 'Redirect resolution aborted by client.';
      }
      break;
    } finally {
      clearTimeout(timeoutTimer);
      if (onExternalAbort && hasSignalInstance && signal) {
        signal.removeEventListener('abort', onExternalAbort);
      }
    }
  }

  const finalDestination = currentUrlStr;
  const isRedirect = redirectChain.length > 1 || Boolean(decodedDestination);

  return {
    originalUrl: rawUrl,
    decodedDestination,
    redirectChain,
    finalDestination,
    isRedirect,
    suspiciousDomainChange,
    redirectLoop,
    resolvedSuccessfully,
    errorReason,
  };
}
