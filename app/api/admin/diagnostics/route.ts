import { NextRequest, NextResponse } from 'next/server';
import { verifyAdminUser } from '@/lib/admin-auth';
import {
  getSafeModelConfig,
  getFeatherlessHeaders,
  redactSecrets,
  VERIFIED_FALLBACK_TEXT_MODEL,
} from '@/lib/model-config';
import {
  probeSerperDiagnostic,
  probeUrlhausDiagnostic,
  getMaxSearchesPerAnalysis,
  getCacheStats,
  getCacheTtlMs,
} from '@/lib/fact-checker/web-researcher';
import { ProviderDiagnosticItem } from '@/lib/fact-checker/types';
import {
  isGeminiConfigured,
  isGeminiFallbackEnabled,
  isGeminiSearchFallbackEnabled,
  isGeminiDocumentFallbackEnabled,
  getResolvedGeminiModel,
  probeGeminiDiagnostic,
} from '@/lib/gemini/client';
import { getProviderTelemetry } from '@/lib/provider-orchestrator';
import { probeRateLimiterHealth } from '@/lib/rate-limit';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  // Server-side administrator verification
  const adminAuth = await verifyAdminUser(req);
  if (!adminAuth.isAdmin) {
    return NextResponse.json(
      {
        error: 'Forbidden: Administrator privileges required to access internal provider diagnostics.',
      },
      { status: 403 }
    );
  }

  const modelConfig = getSafeModelConfig();
  const featherlessKey = process.env.FEATHERLESS_API_KEY;

  // 1. Probe Featherless AI
  let featherlessDiagnostic: ProviderDiagnosticItem = {
    provider: 'Featherless AI',
    status: 'missing_configuration',
    isConfigured: false,
    message: 'FEATHERLESS_API_KEY is not configured on the server.',
  };

  if (featherlessKey && featherlessKey !== 'YOUR_FEATHERLESS_API_KEY') {
    const start = Date.now();
    try {
      const res = await fetch('https://api.featherless.ai/v1/chat/completions', {
        method: 'POST',
        headers: getFeatherlessHeaders(featherlessKey),
        body: JSON.stringify({
          model: modelConfig.primaryModel,
          messages: [{ role: 'user', content: 'Respond with OK.' }],
          max_tokens: 5,
          temperature: 0,
        }),
        signal: AbortSignal.timeout(12000),
      });
      const latencyMs = Date.now() - start;

      if (res.ok) {
        featherlessDiagnostic = {
          provider: 'Featherless AI',
          status: 'configured_and_reachable',
          isConfigured: true,
          message: `Active model ${modelConfig.primaryModel} responded normally.`,
          latencyMs,
          testedAt: new Date().toISOString(),
        };
      } else {
        const errText = await res.text().catch(() => '');
        const sanitized = redactSecrets(errText);

        if (res.status === 401 || res.status === 403) {
          featherlessDiagnostic = {
            provider: 'Featherless AI',
            status: 'authentication_failure',
            isConfigured: true,
            message: `Authentication rejected (HTTP ${res.status}). Verify API key.`,
            latencyMs,
            testedAt: new Date().toISOString(),
          };
        } else if (res.status === 429) {
          featherlessDiagnostic = {
            provider: 'Featherless AI',
            status: 'rate_limit_exhausted',
            isConfigured: true,
            message: 'Capacity or rate limit reached on provider.',
            latencyMs,
            testedAt: new Date().toISOString(),
          };
        } else {
          featherlessDiagnostic = {
            provider: 'Featherless AI',
            status: 'provider_unavailable',
            isConfigured: true,
            message: `Provider returned HTTP ${res.status}: ${sanitized.slice(0, 100)}`,
            latencyMs,
            testedAt: new Date().toISOString(),
          };
        }
      }
    } catch (err: any) {
      const latencyMs = Date.now() - start;
      const isTimeout = err?.name === 'AbortError' || err?.name === 'TimeoutError';
      featherlessDiagnostic = {
        provider: 'Featherless AI',
        status: isTimeout ? 'provider_timeout' : 'provider_unavailable',
        isConfigured: true,
        message: `Connection failed: ${redactSecrets(err?.message || 'Network timeout')}`,
        latencyMs,
        testedAt: new Date().toISOString(),
      };
    }
  }

  // 2. Probe Serper.dev, 3. Probe URLhaus, 4. Probe Gemini, and 5. Probe Rate-Limit Storage in parallel
  const [serperDiagnostic, urlhausDiagnostic, geminiDiagnostic, rateLimiterDiagnostic] = await Promise.all([
    probeSerperDiagnostic(),
    probeUrlhausDiagnostic(),
    probeGeminiDiagnostic(),
    probeRateLimiterHealth(),
  ]);

  // Overall status aggregation (governed by primary providers)
  let overallStatus: 'operational' | 'degraded' | 'error' = 'operational';
  if (
    featherlessDiagnostic.status === 'authentication_failure' ||
    featherlessDiagnostic.status === 'provider_unavailable'
  ) {
    overallStatus = 'error';
  } else if (
    featherlessDiagnostic.status !== 'configured_and_reachable' ||
    serperDiagnostic.status !== 'configured_and_reachable' ||
    urlhausDiagnostic.status !== 'configured_and_reachable'
  ) {
    overallStatus = 'degraded';
  }
  const telemetry = getProviderTelemetry();

  return NextResponse.json({
    overallStatus,
    timestamp: new Date().toISOString(),
    adminUser: adminAuth.user?.email || 'authenticated-admin',
    authorization: {
      authSource: adminAuth.authSource,
      role: adminAuth.user?.role || 'admin',
      userRolesTableStatus: adminAuth.userRolesTableStatus,
    },
    providers: {
      featherless: featherlessDiagnostic,
      serper: serperDiagnostic,
      urlhaus: urlhausDiagnostic,
    },
    geminiFallback: {
      isConfigured: isGeminiConfigured(),
      aiFallbackEnabled: isGeminiFallbackEnabled(),
      searchFallbackEnabled: isGeminiSearchFallbackEnabled(),
      documentFallbackEnabled: isGeminiDocumentFallbackEnabled(),
      model: getResolvedGeminiModel(),
      status: isGeminiConfigured() ? geminiDiagnostic.status : 'not_configured',
      diagnostic: geminiDiagnostic,
      telemetry,
    },
    searchLimits: {
      maxSearchesPerAnalysis: getMaxSearchesPerAnalysis(),
      cacheTtlMinutes: Math.round(getCacheTtlMs('serper') / 60000),
    },
    cacheStats: getCacheStats(),
    rateLimiter: rateLimiterDiagnostic,
    activeModelConfig: {
      primaryModel: modelConfig.primaryModel,
      fallbackTextModel: VERIFIED_FALLBACK_TEXT_MODEL,
      fallbackVisionModel: modelConfig.fallbackVisionModel,
      geminiFallbackModel: getResolvedGeminiModel(),
    },
  });
}
