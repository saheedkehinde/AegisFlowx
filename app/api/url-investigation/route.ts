import { NextRequest, NextResponse } from 'next/server';
import {
  validateAndNormalizeUrl,
  screenUrlForSsrf,
  investigateUrl,
} from '@/lib/url-investigation/investigator';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';
import { redactSecrets } from '@/lib/model-config';
import { normalizeIndicators } from '@/lib/vault-normalization';
import {
  enforceApiRateLimit,
  buildRateLimitErrorResponse,
  attachRateLimitHeaders,
} from '@/lib/rate-limit';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    // 1. Enforce distributed/hardened rate limiting before request parsing, DNS SSRF checks, or external calls
    const rateLimit = await enforceApiRateLimit(req, 'url_investigation');
    if (!rateLimit.allowed) {
      return buildRateLimitErrorResponse(rateLimit);
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        { error: 'Invalid request payload. Expected JSON body with a "url" field.' },
        { status: 400 }
      );
    }

    const rawUrl = body.url ?? body.target ?? body.link ?? '';
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
      return NextResponse.json(
        { error: 'URL input cannot be empty. Please provide a link to investigate.' },
        { status: 400 }
      );
    }

    // 2. Authoritative Server-Side Syntax & Scheme Validation
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.isValid || !validation.parsedUrl) {
      return NextResponse.json(
        { error: validation.error || 'Invalid URL format provided.' },
        { status: 400 }
      );
    }

    // 3. Authoritative Server-Side SSRF Screening (Loopback, RFC1918, Cloud Metadata)
    const ssrfCheck = await screenUrlForSsrf(validation.parsedUrl);
    if (!ssrfCheck.safe) {
      return NextResponse.json(
        {
          error: `Investigation blocked by SSRF Security Safeguards: ${ssrfCheck.reason}`,
        },
        { status: 400 }
      );
    }

    // 4. Perform full URL Threat & Web Intelligence Pipeline
    const report = await investigateUrl(rawUrl);

    let savedToVault = false;

    // 5. Persist to Supabase Vault if user is authenticated
    try {
      const supabase = await createServerSupabaseClient();
      if (supabase) {
        const {
          data: { user },
          error: userError,
        } = await supabase.auth.getUser();

        if (user && !userError) {
          const targetSnippet = `[URL] ${report.urlComponents.displayUrl || report.urlComponents.rawUrl}`;
          const snippet = targetSnippet.slice(0, 140);

          const recentWindow = new Date(Date.now() - 10 * 60 * 1000).toISOString();
          const { data: existingRecords } = await supabase
            .from('analysis_history')
            .select('id')
            .eq('user_id', user.id)
            .eq('input_snippet', snippet)
            .gte('created_at', recentWindow)
            .limit(1);

          if (!existingRecords || existingRecords.length === 0) {
            await supabase.from('analysis_history').insert({
              user_id: user.id,
              input_type: 'url_investigation',
              input_snippet: snippet,
              threat_severity: report.overallSeverity,
              severity_score: report.severityScore,
              summary: report.executiveSummary,
              indicators: normalizeIndicators(report.indicators),
              recommended_actions: [
                ...(report.recommendedActions?.forIndividuals || []),
                ...(report.recommendedActions?.forSecurityTeams || []),
                ...(report.recommendedActions?.forOrganizations || []),
              ],
              limitations: report.evidenceLimitations,
              evidence_sufficiency: report.webEvidence.length > 0 || report.threatIntel.length > 0 ? 'sufficient' : 'moderate',
              model_confidence: report.confidenceLevel,
              confidence_rationale: report.confidenceRationale,
              model_name: report.modelUsed,
              iocs: {
                urls: [report.urlComponents.normalizedUrl],
                emails: [],
                phoneNumbers: [],
                keywords: [report.urlComponents.hostname, report.urlComponents.domain],
                threatIntel: report.threatIntel,
                domainIntelligence: report.domainIntelligence,
                urlComponents: report.urlComponents,
              },
            });
            savedToVault = true;
          } else {
            savedToVault = true;
          }
        }
      }
      } catch (dbErr: any) {
      console.warn('Non-fatal error persisting URL investigation to Supabase vault:', redactSecrets(dbErr?.message || ''));
    }

    report.savedToVault = savedToVault;

    // Final safety sanitation: ensure zero API keys or credentials exist in payload
    const safeReportJson = redactSecrets(JSON.stringify(report));
    const safeReport = JSON.parse(safeReportJson);

    return attachRateLimitHeaders(NextResponse.json({ report: safeReport, savedToVault }), rateLimit);
  } catch (err: any) {
    console.error('Unhandled error during URL investigation:', redactSecrets(err?.message || 'unknown_error'));
    return NextResponse.json(
      { error: redactSecrets(err?.message || 'An unexpected error occurred during URL intelligence screening.') },
      { status: 500 }
    );
  }
}
