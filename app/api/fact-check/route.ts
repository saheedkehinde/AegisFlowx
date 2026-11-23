import { NextRequest, NextResponse } from 'next/server';
import { generateFactCheckReport } from '@/lib/fact-checker/fact-checker';
import { createClient as createServerSupabaseClient } from '@/lib/supabase/server';
import {
  enforceApiRateLimit,
  buildRateLimitErrorResponse,
  attachRateLimitHeaders,
} from '@/lib/rate-limit';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    // 1. Enforce distributed/hardened rate limiting before request parsing or search/AI calls
    const rateLimit = await enforceApiRateLimit(req, 'fact_check');
    if (!rateLimit.allowed) {
      return buildRateLimitErrorResponse(rateLimit);
    }

    const body = await req.json().catch(() => null);

    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        { error: 'Invalid request payload. Expected JSON body with a "text" field.' },
        { status: 400 }
      );
    }

    const rawText = body.text ?? body.message ?? body.content ?? body.claim ?? '';
    const text = typeof rawText === 'string' ? rawText.trim() : '';
    const rawContext = body.context ?? body.userContext ?? '';
    const context = typeof rawContext === 'string' ? rawContext.trim() : '';

    if (!text || text.length === 0) {
      return NextResponse.json(
        { error: 'Text cannot be empty. Please provide content to fact-check.' },
        { status: 400 }
      );
    }

    if (text.length > 6000) {
      return NextResponse.json(
        { error: 'Submitted content exceeds 6,000 characters limit for web research.' },
        { status: 400 }
      );
    }

    // 2. Generate evidence-based fact-checking report with pre-search assessment
    const report = await generateFactCheckReport(text, context);

    // 3. Save to Supabase private investigation history if user is authenticated
    try {
      const supabase = await createServerSupabaseClient();
      if (supabase) {
        const {
          data: { user },
          error: userError,
        } = await supabase.auth.getUser();

        if (user && !userError) {
          const snippet = `[Fact-Check] ${text.slice(0, 140)}`;
          const hasContradictions = report.extractedClaims.some(
            (c) => c.verdict === 'contradicted'
          );

          const historyModelName =
            report.searchProviderStatus?.researchStatus === 'live_research_completed'
              ? 'Aegis AI Live Research & Reasoning'
              : report.searchProviderStatus?.researchStatus === 'completed_using_cached_evidence'
              ? 'Aegis AI Verified Threat Intelligence'
              : report.searchProviderStatus?.researchStatus === 'not_required'
              ? 'Aegis AI Pre-Search Rule Engine'
              : 'Aegis AI Evidence Engine';

          // Prevent duplicate history insertions on quick retries
          const recentWindow = new Date(Date.now() - 15 * 60 * 1000).toISOString();
          const { data: existingRecords } = await supabase
            .from('analysis_history')
            .select('id')
            .eq('user_id', user.id)
            .eq('input_snippet', snippet)
            .gte('created_at', recentWindow)
            .limit(1);

          if (!existingRecords || existingRecords.length === 0) {
            const dbEvidenceSufficiency =
              report.evidenceSufficiency === 'sufficient' || report.evidenceSufficiency === 'moderate'
                ? report.evidenceSufficiency
                : 'sparse';

            await supabase.from('analysis_history').insert({
              user_id: user.id,
              input_type: 'fact_check',
              input_snippet: snippet,
              threat_severity: report.threatSeverity || (hasContradictions ? 'high' : 'medium'),
              severity_score: report.severityScore ?? (hasContradictions ? 85 : 45),
              summary: report.executiveSummary,
              indicators: report.suspiciousIndicators,
              recommended_actions: report.recommendations.forIndividuals,
              limitations: report.researchLimitations,
              evidence_sufficiency: dbEvidenceSufficiency,
              model_confidence: report.confidenceLevel,
              confidence_rationale: report.confidenceRationale,
              model_name: historyModelName,
              iocs: {
                urls: report.sources.map((s) => s.url),
                emails: [],
                phoneNumbers: [],
                keywords: report.extractedClaims.map((c) => c.claimText.slice(0, 30)),
                factCheckReport: report,
              },
            });
          }
        }
      }
    } catch (dbErr: any) {
      console.warn('Non-fatal error persisting fact check to history:', dbErr?.message);
    }

    return attachRateLimitHeaders(NextResponse.json({ report }), rateLimit);
  } catch (err: any) {
    console.error('Unhandled error during fact-checking:', err);
    return NextResponse.json(
      { error: err?.message || 'An unexpected error occurred during web research fact-checking.' },
      { status: 500 }
    );
  }
}
