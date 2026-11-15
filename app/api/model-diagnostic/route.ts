import { NextResponse } from 'next/server';
import {
  getSafeModelConfig,
  getFeatherlessHeaders,
  redactSecrets,
  VERIFIED_PRIMARY_MODEL,
  VERIFIED_FALLBACK_TEXT_MODEL,
} from '@/lib/model-config';
import {
  probeSerperDiagnostic,
  probeUrlhausDiagnostic,
} from '@/lib/fact-checker/web-researcher';
import {
  isGeminiConfigured,
  isGeminiFallbackEnabled,
  isGeminiSearchFallbackEnabled,
  getResolvedGeminiModel,
  probeGeminiDiagnostic,
} from '@/lib/gemini/client';

import { verifyAdminUser } from '@/lib/admin-auth';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const adminAuth = await verifyAdminUser(req);
  if (!adminAuth.isAdmin) {
    return NextResponse.json({
      status: 'online',
      engine: 'Aegis AI',
      operational: true,
      timestamp: new Date().toISOString(),
    });
  }

  const config = getSafeModelConfig();
  const apiKey = process.env.FEATHERLESS_API_KEY;

  if (!apiKey || apiKey === 'YOUR_FEATHERLESS_API_KEY') {
    const isGeminiReady = isGeminiFallbackEnabled();
    const geminiDiag = await probeGeminiDiagnostic();
    const isOperational = isGeminiReady && geminiDiag.status === 'configured_and_reachable';
    return NextResponse.json({
      status: isOperational ? 'degraded' : 'unconfigured',
      provider: isOperational ? 'Gemini (Active Fallback)' : config.provider,
      configuredModel: isOperational ? getResolvedGeminiModel() : config.primaryModel,
      apiKeyConfigured: false,
      geminiFallback: {
        isConfigured: isGeminiConfigured(),
        aiFallbackEnabled: isGeminiFallbackEnabled(),
        searchFallbackEnabled: isGeminiSearchFallbackEnabled(),
        model: getResolvedGeminiModel(),
        status: isGeminiConfigured() ? geminiDiag.status : 'not_configured',
        diagnostic: geminiDiag,
      },
      message: isOperational
        ? 'FEATHERLESS_API_KEY is not set; Gemini fallback is active and verified.'
        : 'FEATHERLESS_API_KEY is not set or using placeholder.',
      timestamp: new Date().toISOString(),
    });
  }

  // Perform a minimal, non-destructive probe to test provider responsiveness
  const probeModel = config.primaryModel;
  let status: 'online' | 'degraded' | 'error' = 'online';
  let latencyMs = 0;
  let detail = 'Operational';
  let activeModel = probeModel;

  const start = Date.now();
  try {
    const res = await fetch('https://api.featherless.ai/v1/chat/completions', {
      method: 'POST',
      headers: getFeatherlessHeaders(apiKey),
      body: JSON.stringify({
        model: probeModel,
        messages: [{ role: 'user', content: 'Respond with OK.' }],
        max_tokens: 5,
        temperature: 0,
      }),
      signal: AbortSignal.timeout(12000),
    });

    latencyMs = Date.now() - start;

    if (res.ok) {
      status = 'online';
      detail = 'Model responded successfully';
    } else {
      const errText = await res.text().catch(() => '');
      const sanitized = redactSecrets(errText);

      if (res.status === 404 || sanitized.includes('model_not_found')) {
        status = 'degraded';
        detail = `Primary model unavailable (${res.status}). Fallback ${VERIFIED_FALLBACK_TEXT_MODEL} ready.`;
      } else if (res.status === 401 || res.status === 403) {
        status = 'error';
        detail = `Provider rejected authentication (${res.status}). Verify key credentials.`;
      } else if (res.status === 429 || sanitized.includes('capacity_exhausted')) {
        status = 'degraded';
        detail = 'Provider capacity limit reached; automatic fallback enabled.';
      } else {
        status = 'error';
        detail = `Upstream status ${res.status}: ${sanitized.slice(0, 100)}`;
      }
    }
  } catch (err: any) {
    latencyMs = Date.now() - start;
    status = 'error';
    detail = `Connection error: ${redactSecrets(err?.message || 'Network timeout')}`;
  }

  const [serperDiag, urlhausDiag, geminiDiag] = await Promise.all([
    probeSerperDiagnostic(),
    probeUrlhausDiagnostic(),
    probeGeminiDiagnostic(),
  ]);

  return NextResponse.json({
    status,
    provider: config.provider,
    configuredModel: config.primaryModel,
    activeModel,
    fallbackTextModel: VERIFIED_FALLBACK_TEXT_MODEL,
    fallbackVisionModel: config.fallbackVisionModel,
    apiKeyConfigured: true,
    latencyMs,
    detail,
    serper: serperDiag,
    urlhaus: urlhausDiag,
    geminiFallback: {
      isConfigured: isGeminiConfigured(),
      aiFallbackEnabled: isGeminiFallbackEnabled(),
      searchFallbackEnabled: isGeminiSearchFallbackEnabled(),
      model: getResolvedGeminiModel(),
      status: isGeminiConfigured() ? geminiDiag.status : 'not_configured',
      diagnostic: geminiDiag,
    },
    timestamp: new Date().toISOString(),
  });
}
