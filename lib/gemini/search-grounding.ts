import { getGeminiClient, getResolvedGeminiModel, isGeminiSearchFallbackEnabled, sanitizeGeminiError } from './client';
import { ResearchSource } from '@/lib/fact-checker/types';

export interface GeminiSearchGroundingResult {
  sources: ResearchSource[];
  groundingQueriesUsed?: string[];
  groundedSummary?: string;
  success: boolean;
  aborted?: boolean;
  error?: string;
}

function isAbortSignalInstance(signal?: AbortSignal): signal is AbortSignal {
  return typeof AbortSignal !== 'undefined' && signal instanceof AbortSignal;
}

function createAbortError(message: string = 'Search grounding aborted by client.'): Error {
  const err = new Error(message);
  err.name = 'AbortError';
  return err;
}

/**
 * Executes a web search using Gemini's official Google Search grounding tool.
 * Only called as a secondary fallback when Serper is exhausted, timed out, or unavailable.
 * Normalizes genuine grounding chunks into AegisFlow's standard ResearchSource model.
 * Never invents, hallucinates, or fabricates search results or citations.
 */
export async function searchGeminiGoogleSearch(
  query: string,
  maxResults: number = 4,
  signal?: AbortSignal
): Promise<GeminiSearchGroundingResult> {
  if (signal?.aborted) {
    return {
      sources: [],
      success: false,
      aborted: true,
      error: 'Search grounding aborted by client.',
    };
  }

  if (!isGeminiSearchFallbackEnabled()) {
    return {
      sources: [],
      success: false,
      error: 'Gemini Google Search grounding fallback is not enabled or configured.',
    };
  }

  const cleanQuery = query.trim().slice(0, 200);
  if (!cleanQuery) {
    return {
      sources: [],
      success: false,
      error: 'Cannot execute search with empty query string.',
    };
  }

  let abortListener: (() => void) | undefined;
  let safetyTimer: ReturnType<typeof setTimeout> | undefined;

  try {
    const ai = getGeminiClient();
    const model = getResolvedGeminiModel();

    const prompt = `Search for official public announcements, security advisories, news reporting, and regulatory publications regarding: "${cleanQuery}".
Summarize the findings concisely based strictly on retrieved search results.`;

    const abortPromise = new Promise<never>((_, reject) => {
      safetyTimer = setTimeout(() => {
        reject(new Error('Gemini Google Search grounding timed out after 15s.'));
      }, 15000);

      if (isAbortSignalInstance(signal)) {
        if (signal.aborted) {
          reject(createAbortError());
          return;
        }
        abortListener = () => reject(createAbortError());
        signal.addEventListener('abort', abortListener, { once: true });
      }
    });

    const response = await Promise.race([
      ai.models.generateContent({
        model,
        contents: prompt,
        config: {
          tools: [{ googleSearch: {} }],
        },
      }),
      abortPromise,
    ]);

    if (signal?.aborted) {
      return {
        sources: [],
        success: false,
        aborted: true,
        error: 'Search grounding aborted by client.',
      };
    }

    const candidate = response.candidates?.[0];
    const groundingMetadata = candidate?.groundingMetadata;
    const groundingChunks = groundingMetadata?.groundingChunks || [];
    const webSearchQueries = groundingMetadata?.webSearchQueries || [];
    const groundedSummary = (response.text || '').trim();

    const sources: ResearchSource[] = [];
    const seenUris = new Set<string>();

    for (let i = 0; i < groundingChunks.length && sources.length < maxResults; i++) {
      const chunk = groundingChunks[i];
      const web = chunk?.web;

      if (!web || !web.uri || typeof web.uri !== 'string') {
        continue;
      }

      const rawUri = web.uri.trim();
      if (!rawUri.startsWith('http://') && !rawUri.startsWith('https://')) {
        continue;
      }

      if (seenUris.has(rawUri)) {
        continue;
      }
      seenUris.add(rawUri);

      let domain = 'google-grounded-source';
      try {
        const parsedUrl = new URL(rawUri);
        domain = parsedUrl.hostname.toLowerCase().replace(/^www\./, '');
      } catch {
        // Skip unparseable URLs
        continue;
      }

      const rawTitle = typeof web.title === 'string' && web.title.trim().length > 0
        ? web.title.trim()
        : `Grounded Web Source (${domain})`;

      // Extract a relevant snippet from the model's grounded summary if available
      let snippet = groundedSummary;
      if (snippet.length > 280) {
        snippet = snippet.slice(0, 280) + '...';
      }
      if (!snippet) {
        snippet = `Google Search grounding reference retrieved for query "${cleanQuery}".`;
      }

      sources.push({
        id: `src-gemini-grounding-${sources.length + 1}-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        title: rawTitle,
        url: rawUri,
        domain,
        publisher: domain,
        snippet,
        provenance: 'snippet_only',
        pageRetrievalStatus: 'snippet_only',
        retrievedAt: new Date().toISOString(),
        isCached: false,
        sourceType: 'web_search',
        sourceCategory: 'reputable_reporting',
        reliability: 'reputable',
        relevanceGrade: 'supporting_guidance',
        relevanceExplanation: `Grounding source returned via Google Search grounding for query "${cleanQuery}"`,
        limitationNote: 'Sourced via secondary web search grounding fallback.',
      });
    }

    return {
      sources,
      groundingQueriesUsed: webSearchQueries,
      groundedSummary,
      success: true,
    };
  } catch (error: unknown) {
    if (signal?.aborted || (error instanceof Error && error.name === 'AbortError')) {
      return {
        sources: [],
        success: false,
        aborted: true,
        error: 'Search grounding aborted by client.',
      };
    }
    const sanitizedMsg = sanitizeGeminiError(error);
    console.warn('Gemini Google Search grounding fallback failed:', sanitizedMsg);
    return {
      sources: [],
      success: false,
      error: sanitizedMsg,
    };
  } finally {
    if (safetyTimer) {
      clearTimeout(safetyTimer);
    }
    if (abortListener && isAbortSignalInstance(signal)) {
      signal.removeEventListener('abort', abortListener);
    }
  }
}
