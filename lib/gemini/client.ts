import { GoogleGenAI, ThinkingLevel } from '@google/genai';
import { redactSecrets } from '@/lib/model-config';
import { ProviderDiagnosticItem, ProviderDiagnosticStatus } from '@/lib/fact-checker/types';

/**
 * Server-only Gemini API client configuration and initialization.
 * Follows official GoogleGenAI guidelines:
 * - Shared server-side singleton client
 * - 'User-Agent': 'aistudio-build' in httpOptions
 * - Never expose API keys to browser, client bundles, or logs
 */

export const DEFAULT_GEMINI_MODEL = 'gemini-3.8-flash';

let cachedAiClient: GoogleGenAI | null = null;
let cachedApiKey: string | null = null;

/**
 * Returns true if a valid, non-placeholder GEMINI_API_KEY is present in the environment.
 */
export function isGeminiConfigured(): boolean {
  const key = process.env.GEMINI_API_KEY;
  return Boolean(
    key &&
    key.trim().length > 10 &&
    key !== 'MY_GEMINI_API_KEY' &&
    key !== 'YOUR_GEMINI_API_KEY'
  );
}

/**
 * Checks if general Gemini AI reasoning fallback is enabled.
 * Defaults to true when GEMINI_API_KEY is configured unless explicitly set to 'false'.
 */
export function isGeminiFallbackEnabled(): boolean {
  if (!isGeminiConfigured()) return false;
  const envVal = process.env.GEMINI_FALLBACK_ENABLED;
  if (envVal !== undefined && (envVal.toLowerCase() === 'false' || envVal === '0')) {
    return false;
  }
  return true;
}

/**
 * Checks if Gemini Google Search grounding fallback is enabled.
 * Defaults to true when Gemini is configured and general fallback is enabled,
 * unless explicitly disabled via GEMINI_SEARCH_FALLBACK_ENABLED='false'.
 */
export function isGeminiSearchFallbackEnabled(): boolean {
  if (!isGeminiFallbackEnabled()) return false;
  const envVal = process.env.GEMINI_SEARCH_FALLBACK_ENABLED;
  if (envVal !== undefined && (envVal.toLowerCase() === 'false' || envVal === '0')) {
    return false;
  }
  return true;
}

/**
 * Checks if Gemini document & screenshot interpretation fallback is enabled.
 * Safe default: enabled if GEMINI_API_KEY is configured and GEMINI_DOCUMENT_FALLBACK_ENABLED
 * is not set to 'false'.
 */
export function isGeminiDocumentFallbackEnabled(): boolean {
  if (!isGeminiFallbackEnabled()) return false;
  const envVal = process.env.GEMINI_DOCUMENT_FALLBACK_ENABLED;
  if (envVal !== undefined && (envVal.toLowerCase() === 'false' || envVal === '0')) {
    return false;
  }
  return true;
}

/**
 * Returns the resolved Gemini model identifier.
 * Defaults to 'gemini-3.8-flash'.
 */
export function getResolvedGeminiModel(): string {
  const envModel = process.env.GEMINI_MODEL;
  if (envModel && envModel.trim().length > 0 && !envModel.startsWith('AIza') && !envModel.startsWith('rc_')) {
    return envModel.trim();
  }
  return DEFAULT_GEMINI_MODEL;
}

/**
 * Returns the initialized GoogleGenAI client singleton.
 * Throws a sanitized error if not configured.
 */
export function getGeminiClient(): GoogleGenAI {
  const key = process.env.GEMINI_API_KEY;

  if (!key || !isGeminiConfigured()) {
    throw new Error('Gemini API is not configured on the server (GEMINI_API_KEY missing or placeholder).');
  }

  if (!cachedAiClient || cachedApiKey !== key) {
    cachedAiClient = new GoogleGenAI({
      apiKey: key.trim(),
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
    cachedApiKey = key;
  }

  return cachedAiClient;
}

/**
 * Sanitizes errors thrown during Gemini API operations to ensure
 * no credential patterns or raw stack traces leak to callers.
 */
export function sanitizeGeminiError(error: unknown): string {
  if (!error) return 'Unknown upstream error during Gemini operation.';
  const msg = error instanceof Error ? error.message : String(error);
  return redactSecrets(msg);
}

/**
 * Performs a live, non-destructive probe against the Gemini API to verify operational readiness.
 * Never claims Gemini is operational until a real configured API test succeeds.
 * If the key is missing or placeholder, returns status 'missing_configuration' with isConfigured: false.
 */
export async function probeGeminiDiagnostic(overrideKey?: string): Promise<ProviderDiagnosticItem> {
  const testedAt = new Date().toISOString();
  const configured = overrideKey !== undefined ? Boolean(overrideKey && overrideKey.trim().length > 10 && !overrideKey.includes('PLACEHOLDER') && !overrideKey.includes('MY_GEMINI_API_KEY') && !overrideKey.includes('YOUR_GEMINI_API_KEY')) : isGeminiConfigured();

  if (!configured) {
    return {
      provider: 'Google Gemini',
      status: 'missing_configuration',
      isConfigured: false,
      message: 'GEMINI_API_KEY is not configured or using placeholder; fallback remains inactive while primary providers operate normally.',
      testedAt,
    };
  }

  const start = Date.now();
  const model = getResolvedGeminiModel();

  try {
    let ai: GoogleGenAI;
    if (overrideKey) {
      ai = new GoogleGenAI({
        apiKey: overrideKey.trim(),
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    } else {
      ai = getGeminiClient();
    }

    const probePromise = ai.models.generateContent({
      model,
      contents: 'Ping probe. Respond with OK.',
      config: {
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      },
    });

    const timeoutPromise = new Promise<never>((_, reject) => {
      const timer = setTimeout(() => reject(new Error('Gemini API probe timed out after 6000ms.')), 6000);
      probePromise.finally(() => clearTimeout(timer));
    });

    const res = await Promise.race([probePromise, timeoutPromise]);
    const latencyMs = Date.now() - start;

    if (res && res.text !== undefined && res.text.trim().length > 0) {
      return {
        provider: 'Google Gemini',
        status: 'configured_and_reachable',
        isConfigured: true,
        message: `Gemini API responded successfully with model ${model}.`,
        latencyMs,
        testedAt,
      };
    }

    return {
      provider: 'Google Gemini',
      status: 'provider_unavailable',
      isConfigured: true,
      message: `Gemini API probe returned empty text for model ${model}.`,
      latencyMs,
      testedAt,
    };
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    const sanitized = sanitizeGeminiError(err?.message || err);

    let status: ProviderDiagnosticStatus = 'provider_unavailable';
    if (/permission_denied|api_key_invalid|invalid_argument|unauthenticated|401|403/i.test(sanitized)) {
      status = 'authentication_failure';
    } else if (/resource_exhausted|quota|429/i.test(sanitized)) {
      status = 'rate_limit_exhausted';
    } else if (/deadline|timeout|aborterror|504/i.test(sanitized)) {
      status = 'provider_timeout';
    }

    return {
      provider: 'Google Gemini',
      status,
      isConfigured: true,
      message: sanitized.slice(0, 160),
      latencyMs,
      testedAt,
    };
  }
}
